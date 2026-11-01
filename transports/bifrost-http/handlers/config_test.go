package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/network"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configtables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/modelcatalog"
	"github.com/maximhq/bifrost/framework/oauth2"
	"github.com/maximhq/bifrost/plugins/compat"
	"github.com/maximhq/bifrost/plugins/governance"
	"github.com/maximhq/bifrost/transports/v2/bifrost-http/lib"
)

type inferenceSetupAccount struct {
	wsSpanTestAccount
	url string
}

func (a inferenceSetupAccount) GetConfigForProvider(p schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	c, err := a.wsSpanTestAccount.GetConfigForProvider(p)
	if err == nil {
		c.NetworkConfig.BaseURL = a.url
		c.NetworkConfig.AllowPrivateNetwork = true
	}
	return c, err
}

func TestUpdateConfig_InferenceAuthBlocksUpstream(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	h := &ConfigHandler{store: cfg, configManager: setupConfigManager{store: store}}
	setup := putConfigCtx(`{"client_config":{"log_retention_days":7,"enforce_auth_on_inference":true}}`)
	h.updateConfig(setup)
	require.Equal(t, 200, setup.Response.StatusCode(), string(setup.Response.Body()))

	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/chat/completions":
			fmt.Fprint(w, `{"id":"chat-test","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
		case "/files":
			fmt.Fprint(w, `{"object":"list","data":[]}`)
		default:
			fmt.Fprint(w, `{"id":"resp_test","object":"response","status":"completed","model":"gpt-4o-mini","output":[]}`)
		}
	}))
	defer upstream.Close()
	log := bifrost.NewDefaultLogger(schemas.LogLevelError)
	plugin, err := governance.Init(t.Context(), &governance.Config{IsVkMandatory: &cfg.ClientConfig.EnforceAuthOnInference}, log, nil,
		&configstore.GovernanceConfig{VirtualKeys: []configtables.TableVirtualKey{{
			ID: "setup-vk", Name: "setup-vk", Value: *schemas.NewSecretVar("sk-bf-setup"), IsActive: new(true),
			ProviderConfigs: []configtables.TableVirtualKeyProviderConfig{{Provider: "openai", AllowedModels: schemas.WhiteList{"*"}, AllowAllKeys: true}},
		}}}, nil, nil, nil)
	require.NoError(t, err)
	client, err := bifrost.Init(t.Context(), schemas.BifrostConfig{
		Account: inferenceSetupAccount{url: upstream.URL}, Logger: log, LLMPlugins: []schemas.LLMPlugin{plugin},
	})
	require.NoError(t, err)
	defer client.Shutdown()
	for _, operation := range []string{"chat", "files", "responses"} {
		for _, credential := range []string{"", "sk-bf-setup"} {
			t.Run(operation+"/"+credential, func(t *testing.T) {
				ctx := schemas.NewBifrostContext(t.Context(), schemas.NoDeadline)
				if credential != "" {
					ctx.SetValue(schemas.BifrostContextKeyVirtualKey, credential)
				}
				lib.SettleIdentity(ctx)
				before := calls.Load()
				var failure *schemas.BifrostError
				switch operation {
				case "chat":
					_, failure = client.ChatCompletionRequest(ctx, &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "gpt-4o-mini", Input: []schemas.ChatMessage{{Role: schemas.ChatMessageRoleUser, Content: &schemas.ChatMessageContent{ContentStr: new("hi")}}}})
				case "files":
					_, failure = client.FileListRequest(ctx, &schemas.BifrostFileListRequest{Provider: schemas.OpenAI})
				case "responses":
					_, failure = client.ResponsesRetrieveRequest(ctx, &schemas.BifrostResponsesRetrieveRequest{Provider: schemas.OpenAI, ResponseID: "resp_test"})
				}
				if credential == "" {
					require.NotNil(t, failure)
					require.NotNil(t, failure.StatusCode)
					assert.Equal(t, 401, *failure.StatusCode)
					assert.Equal(t, "virtual_key_required", *failure.Type)
					assert.Equal(t, before, calls.Load(), "anonymous request must not reach upstream")
				} else {
					require.Nil(t, failure, "%+v", failure)
					assert.Equal(t, before+1, calls.Load())
				}
			})
		}
	}
}

type setupConfigManager struct {
	stubConfigManager
	store      configstore.ConfigStore
}

type inferenceSetupFailureStore struct {
	configstore.ConfigStore
	fail string
}

func (s inferenceSetupFailureStore) GetAuthConfig(ctx context.Context) (*configstore.AuthConfig, error) {
	if s.fail == "read" {
		return nil, errors.New("auth lookup failed")
	}
	return s.ConfigStore.GetAuthConfig(ctx)
}
func (s inferenceSetupFailureStore) UpdateClientConfig(ctx context.Context, c *configstore.ClientConfig) error {
	if s.fail == "write" {
		return errors.New("client persistence failed")
	}
	return s.ConfigStore.UpdateClientConfig(ctx, c)
}

func TestUpdateConfig_InferenceAuthStoreFailures(t *testing.T) {
	SetLogger(&mockLogger{})
	for _, failure := range []string{"write"} {
		t.Run(failure, func(t *testing.T) {
			store := newRealOAuth2Store(t)
			cfg := newTestOAuth2Config(inferenceSetupFailureStore{store, failure}, configtables.MCPServerAuthModeHeaders, false)
			require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
			h := &ConfigHandler{store: cfg, configManager: setupConfigManager{store: store}}
			ctx := putConfigCtx(`{"client_config":{"log_retention_days":7,"enforce_auth_on_inference":true}}`)
			h.updateConfig(ctx)
			require.Equal(t, 500, ctx.Response.StatusCode())
			persisted, err := store.GetClientConfig(bgCtx())
			require.NoError(t, err)
			assert.False(t, persisted.EnforceAuthOnInference)
			assert.False(t, cfg.ClientConfig.EnforceAuthOnInference)
			auth, err := store.GetAuthConfig(bgCtx())
			require.NoError(t, err)
			assert.Nil(t, auth)
		})
	}
}

func (m setupConfigManager) UpdateAuthConfig(ctx context.Context, auth *configstore.AuthConfig) error {
	return m.store.UpdateAuthConfig(ctx, auth)
}

func TestUpdateConfigRefusesSharedCredentialsWithoutMutation(t *testing.T) {
	SetLogger(&mockLogger{})
	for _, body := range []string{
		`{"client_config":{"enforce_auth_on_inference":true},"auth_config":{"is_enabled":true,"admin_username":"admin","admin_password":"StrongPassword1!"}}`,
		`{"auth_config":{"is_enabled":false}}`,
		`{"auth_config":{}}`,
	} {
		store := newRealOAuth2Store(t)
		cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
		require.NoError(t, store.UpdateClientConfig(t.Context(), cfg.ClientConfig))
		h := &ConfigHandler{store: cfg, configManager: setupConfigManager{store: store}}
		ctx := putConfigCtx(body)
		h.updateConfig(ctx)
		require.Equal(t, 400, ctx.Response.StatusCode(), string(ctx.Response.Body()))
		assert.Contains(t, string(ctx.Response.Body()), "createsuperadmin")
		assert.False(t, cfg.ClientConfig.EnforceAuthOnInference)
		stored, err := store.GetClientConfig(t.Context())
		require.NoError(t, err)
		assert.False(t, stored.EnforceAuthOnInference)
		policy, err := store.GetAuthConfig(t.Context())
		require.NoError(t, err)
		assert.Nil(t, policy)
	}
}

func TestUpdateConfig_A2AExternalClientURLPresence(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.A2AExternalClientURL = schemas.NewSecretVar("https://bifrost.example.com")
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	require.NotNil(t, cfg.ClientConfig.A2AExternalClientURL)
	assert.Equal(t, "https://bifrost.example.com", cfg.ClientConfig.A2AExternalClientURL.GetValue())
	persisted, err := store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted.A2AExternalClientURL)
	assert.Equal(t, "https://bifrost.example.com", persisted.A2AExternalClientURL.GetValue())

	cleared := putConfigCtx(`{"client_config":{"log_retention_days":8,"a2a_external_client_url":null}}`)
	h.updateConfig(cleared)
	require.Equal(t, fasthttp.StatusOK, cleared.Response.StatusCode(), string(cleared.Response.Body()))
	assert.Nil(t, cfg.ClientConfig.A2AExternalClientURL)
	persisted, err = store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted.A2AExternalClientURL)
	assert.Empty(t, persisted.A2AExternalClientURL.GetValue())
}

// enforce_vk_object_ownership defaults to true when a body omits it, so the handler copies it only
// when sent: a partial save from an API client must not turn a stored false back on.
func TestUpdateConfig_EnforceVKObjectOwnershipPresence(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.EnforceVKObjectOwnership = false
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
	stored := func() bool {
		t.Helper()
		persisted, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return persisted.EnforceVKObjectOwnership
	}

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	assert.False(t, cfg.ClientConfig.EnforceVKObjectOwnership, "an omitted field keeps the live value")
	assert.False(t, stored(), "an omitted field keeps the stored value")

	enabled := putConfigCtx(`{"client_config":{"log_retention_days":8,"enforce_vk_object_ownership":true}}`)
	h.updateConfig(enabled)
	require.Equal(t, fasthttp.StatusOK, enabled.Response.StatusCode(), string(enabled.Response.Body()))
	assert.True(t, cfg.ClientConfig.EnforceVKObjectOwnership)
	assert.True(t, stored())

	disabled := putConfigCtx(`{"client_config":{"log_retention_days":8,"enforce_vk_object_ownership":false}}`)
	h.updateConfig(disabled)
	require.Equal(t, fasthttp.StatusOK, disabled.Response.StatusCode(), string(disabled.Response.Body()))
	assert.False(t, cfg.ClientConfig.EnforceVKObjectOwnership)
	assert.False(t, stored())
	// null would decode as the default (true) and pass the presence check, so it is refused
	// before anything changes; other non-boolean values already fail decoding.
	for _, body := range []string{
		`{"client_config":{"log_retention_days":8,"enforce_vk_object_ownership":null}}`,
		`{"client_config":{"log_retention_days":8,"enforce_vk_object_ownership":"yes"}}`,
	} {
		refused := putConfigCtx(body)
		h.updateConfig(refused)
		assert.Equal(t, fasthttp.StatusBadRequest, refused.Response.StatusCode(), "%s: %s", body, refused.Response.Body())
		assert.False(t, cfg.ClientConfig.EnforceVKObjectOwnership, "%s left the live value unchanged", body)
		assert.False(t, stored(), "%s left the stored value unchanged", body)
	}
}

// TestUpdateConfig_SkipAccessProfileUserVirtualKeyLifecyclePresence pins that each access-profile
// user-key setting is copied only when sent, so a partial save from an API client can't silently hand
// user key lifecycle back to access profiles, and that the two move independently.
func TestUpdateConfig_SkipAccessProfileUserVirtualKeyLifecyclePresence(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.SkipAccessProfileUserVirtualKeyCreation = true
	cfg.ClientConfig.SkipAccessProfileUserVirtualKeyDeletion = true
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
	stored := func() (creation, deletion bool) {
		t.Helper()
		persisted, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return persisted.SkipAccessProfileUserVirtualKeyCreation, persisted.SkipAccessProfileUserVirtualKeyDeletion
	}
	put := func(body string) {
		t.Helper()
		req := putConfigCtx(body)
		h.updateConfig(req)
		require.Equal(t, fasthttp.StatusOK, req.Response.StatusCode(), string(req.Response.Body()))
	}

	put(`{"client_config":{"log_retention_days":8}}`)
	creation, deletion := stored()
	assert.True(t, creation && deletion, "omitted fields keep the stored values")
	assert.True(t, cfg.ClientConfig.SkipAccessProfileUserVirtualKeyCreation && cfg.ClientConfig.SkipAccessProfileUserVirtualKeyDeletion, "omitted fields keep the live values")

	put(`{"client_config":{"log_retention_days":8,"skip_access_profile_user_virtual_key_creation":false}}`)
	creation, deletion = stored()
	assert.False(t, creation)
	assert.True(t, deletion, "turning creation back on leaves deletion alone")
	assert.False(t, cfg.ClientConfig.SkipAccessProfileUserVirtualKeyCreation)

	put(`{"client_config":{"log_retention_days":8,"skip_access_profile_user_virtual_key_deletion":false}}`)
	creation, deletion = stored()
	assert.False(t, creation)
	assert.False(t, deletion)
	assert.False(t, cfg.ClientConfig.SkipAccessProfileUserVirtualKeyDeletion)

	put(`{"client_config":{"log_retention_days":8,"skip_access_profile_user_virtual_key_creation":true,"skip_access_profile_user_virtual_key_deletion":true}}`)
	creation, deletion = stored()
	assert.True(t, creation && deletion)

	// null would decode as false and pass the presence check, silently handing user key creation or
	// deletion back to access profiles, so it is refused before anything changes.
	for _, body := range []string{
		`{"client_config":{"log_retention_days":8,"skip_access_profile_user_virtual_key_creation":null}}`,
		`{"client_config":{"log_retention_days":8,"skip_access_profile_user_virtual_key_deletion":null}}`,
	} {
		refused := putConfigCtx(body)
		h.updateConfig(refused)
		assert.Equal(t, fasthttp.StatusBadRequest, refused.Response.StatusCode(), "%s: %s", body, refused.Response.Body())
		creation, deletion = stored()
		assert.True(t, creation && deletion, "%s left the stored values unchanged", body)
		assert.True(t, cfg.ClientConfig.SkipAccessProfileUserVirtualKeyCreation && cfg.ClientConfig.SkipAccessProfileUserVirtualKeyDeletion, "%s left the live values unchanged", body)
	}
}

// extra_fields_placement is copied only when sent, so a partial save keeps the stored value,
// and anything other than body/headers is refused before any live mutation.
func TestUpdateConfig_ExtraFieldsPlacement(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
	stored := func() configtables.ExtraFieldsPlacement {
		t.Helper()
		persisted, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return persisted.ExtraFieldsPlacement
	}

	headers := putConfigCtx(`{"client_config":{"log_retention_days":8,"extra_fields_placement":"headers"}}`)
	h.updateConfig(headers)
	require.Equal(t, fasthttp.StatusOK, headers.Response.StatusCode(), string(headers.Response.Body()))
	assert.True(t, cfg.ShouldSendExtraFieldsInHeaders())
	assert.Equal(t, configtables.ExtraFieldsPlacementHeaders, stored())

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	assert.True(t, cfg.ShouldSendExtraFieldsInHeaders(), "an omitted field keeps the live value")
	assert.Equal(t, configtables.ExtraFieldsPlacementHeaders, stored(), "an omitted field keeps the stored value")

	// Only an omitted field keeps the stored value: an explicit empty string or null is a
	// supplied value, and anything other than body/headers is refused before any change.
	for _, body := range []string{
		`{"client_config":{"log_retention_days":8,"extra_fields_placement":"trailers"}}`,
		`{"client_config":{"log_retention_days":8,"extra_fields_placement":""}}`,
		`{"client_config":{"log_retention_days":8,"extra_fields_placement":null}}`,
	} {
		refused := putConfigCtx(body)
		h.updateConfig(refused)
		assert.Equal(t, fasthttp.StatusBadRequest, refused.Response.StatusCode(), "%s: %s", body, refused.Response.Body())
		assert.True(t, cfg.ShouldSendExtraFieldsInHeaders(), "%s left the live value unchanged", body)
		assert.Equal(t, configtables.ExtraFieldsPlacementHeaders, stored(), "%s left the stored value unchanged", body)
	}

	body := putConfigCtx(`{"client_config":{"log_retention_days":8,"extra_fields_placement":"body"}}`)
	h.updateConfig(body)
	require.Equal(t, fasthttp.StatusOK, body.Response.StatusCode(), string(body.Response.Body()))
	assert.False(t, cfg.ShouldSendExtraFieldsInHeaders())
	assert.Equal(t, configtables.ExtraFieldsPlacementBody, stored())
}

// TestUpdateConfig_MCPOAuthPrivateAllowlist pins how PUT /api/config handles
// mcp_oauth_private_allowlist: an authenticated admin sets it and it is
// persisted; an omitted field keeps it; a caller admitted with auth bypassed
// may resend the current value (the dashboard saves the whole client config)
// but not change it; entries the policy can never honor are refused.
func TestUpdateConfig_MCPOAuthPrivateAllowlist(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
	persistedAllowlist := func() []string {
		t.Helper()
		persisted, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return persisted.MCPOAuthPrivateAllowlist
	}

	set := putConfigCtx(`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":["localhost","127.0.0.1","10.0.0.0/8"]}}`)
	h.updateConfig(set)
	require.Equal(t, fasthttp.StatusOK, set.Response.StatusCode(), string(set.Response.Body()))
	want := []string{"localhost", "127.0.0.1", "10.0.0.0/8"}
	assert.Equal(t, want, cfg.ClientConfig.MCPOAuthPrivateAllowlist)
	assert.Equal(t, want, persistedAllowlist())

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	omitted.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	assert.Equal(t, want, persistedAllowlist(), "an omitted allowlist must be kept")

	resent := putConfigCtx(`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":["localhost","127.0.0.1","10.0.0.0/8"]}}`)
	resent.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
	h.updateConfig(resent)
	require.Equal(t, fasthttp.StatusOK, resent.Response.StatusCode(), string(resent.Response.Body()))

	for _, body := range []string{
		`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":["localhost","192.168.0.0/16"]}}`,
		`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":[]}}`,
	} {
		changed := putConfigCtx(body)
		changed.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
		h.updateConfig(changed)
		require.Equal(t, fasthttp.StatusForbidden, changed.Response.StatusCode(), string(changed.Response.Body()))
		assert.Contains(t, string(changed.Response.Body()), "mcp_oauth_private_allowlist requires an authenticated admin session")
		assert.Equal(t, want, persistedAllowlist(), "an auth-bypassed caller must not change the allowlist")
	}

	for _, entry := range []string{"169.254.169.254", "0.0.0.0/0", "metadata.google.internal", "http://localhost:3000"} {
		invalid := putConfigCtx(`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":["` + entry + `"]}}`)
		h.updateConfig(invalid)
		require.Equal(t, fasthttp.StatusBadRequest, invalid.Response.StatusCode(), entry+": "+string(invalid.Response.Body()))
		assert.Equal(t, want, persistedAllowlist())
	}

	cleared := putConfigCtx(`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":[]}}`)
	h.updateConfig(cleared)
	require.Equal(t, fasthttp.StatusOK, cleared.Response.StatusCode(), string(cleared.Response.Body()))
	assert.Empty(t, persistedAllowlist())
}

// failingReloadConfigManager fails the post-save reload, as a config store read
// error would.
type failingReloadConfigManager struct{ stubConfigManager }

func (failingReloadConfigManager) ReloadClientConfigFromConfigStore(context.Context) error {
	return errors.New("config store read failed")
}

// TestUpdateConfig_MCPOAuthPrivateAllowlistRemovalSurvivesFailedReload pins
// that a saved allowlist removal takes effect even when the reload after the
// save fails: the OAuth chain must stop reaching the removed host rather than
// keep the old list until a later reload succeeds.
func TestUpdateConfig_MCPOAuthPrivateAllowlistRemovalSurvivesFailedReload(t *testing.T) {
	SetLogger(&mockLogger{})
	oauth2.SetDiscoveryDialContextForTests(nil)
	t.Cleanup(func() {
		oauth2.SetDiscoveryDialContextForTests((&net.Dialer{}).DialContext)
		require.NoError(t, lib.ApplyMCPOAuthPrivateAllowlist(nil))
	})

	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.MCPOAuthPrivateAllowlist = []string{"127.0.0.1"}
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	require.NoError(t, lib.ApplyMCPOAuthPrivateAllowlist(cfg.ClientConfig.MCPOAuthPrivateAllowlist))

	h := &ConfigHandler{store: cfg, configManager: failingReloadConfigManager{}}
	removal := putConfigCtx(`{"client_config":{"log_retention_days":8,"mcp_oauth_private_allowlist":[]}}`)
	h.updateConfig(removal)
	require.Equal(t, fasthttp.StatusInternalServerError, removal.Response.StatusCode(), string(removal.Response.Body()))
	persisted, err := store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	require.Empty(t, persisted.MCPOAuthPrivateAllowlist, "the removal is saved before the reload runs")

	server := newLoopbackOAuthMCPServer(t)
	provider := oauth2.NewOAuth2Provider(store, bifrost.NewDefaultLogger(schemas.LogLevelError))
	mcpCfg := &lib.Config{ConfigStore: store, ClientConfig: &configstore.ClientConfig{}, OAuthProvider: provider}
	mh := &MCPHandler{store: mcpCfg, mcpManager: failingMCPManager{}, oauthHandler: NewOAuthHandler(provider, nil, mcpCfg)}
	var req fasthttp.Request
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/json")
	req.Header.SetHost("bifrost.example.com")
	req.SetBodyString(`{"name":"local_oauth","connection_type":"http","connection_string":"` + server.URL + `/mcp","auth_type":"oauth","oauth_config":{}}`)
	add := initCtx(&req)
	mh.addMCPClient(add)

	body := string(add.Response.Body())
	require.Equal(t, fasthttp.StatusInternalServerError, add.Response.StatusCode(), "a host removed from the saved allowlist must not stay reachable: %s", body)
	assert.Contains(t, body, "blocked connection to non-public address")
}

// TestUpdateConfig_EmptyDatasheetURLsResetToDefaults pins the regression where
// PUT /api/config rejected an empty pricing_url with "URL cannot be empty".
// The custom pricing page sends "" when the user clears the field; an empty
// pricing_url or model_parameters_url means "use the built-in datasheet URL".
func TestUpdateConfig_EmptyDatasheetURLsResetToDefaults(t *testing.T) {
	// The datasheet server below is loopback-bound; the accessibility check refuses loopback
	// by default, so route its dial through a plain dialer for this test only.
	prevDial := checkURLAccessibilityDialContext
	checkURLAccessibilityDialContext = (&net.Dialer{}).DialContext
	t.Cleanup(func() { checkURLAccessibilityDialContext = prevDial })
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	// A loopback datasheet server passes the accessibility check; file:// URLs
	// are refused over the API (TestUpdateConfig_RejectsFileURLsOverAPI).
	customURL := newDatasheetServer(t).URL

	save := func(t *testing.T, pricingURL, modelParamsURL string) {
		t.Helper()
		ctx := putConfigCtx(`{"client_config":{"log_retention_days":7},"framework_config":{"pricing_url":"` + pricingURL + `","model_parameters_url":"` + modelParamsURL + `"}}`)
		h.updateConfig(ctx)
		require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	}

	save(t, customURL, customURL)
	persisted, err := store.GetFrameworkConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, customURL, *persisted.PricingURL)
	assert.Equal(t, customURL, *persisted.ModelParametersURL)

	save(t, "", "")
	persisted, err = store.GetFrameworkConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, modelcatalog.DefaultPricingURL, *persisted.PricingURL, "empty pricing_url must reset to the default")
	assert.Equal(t, modelcatalog.DefaultModelParametersURL, *persisted.ModelParametersURL, "empty model_parameters_url must reset to the default")
	assert.Equal(t, modelcatalog.DefaultPricingURL, *cfg.FrameworkConfig.Pricing.PricingURL)
	assert.Equal(t, modelcatalog.DefaultModelParametersURL, *cfg.FrameworkConfig.Pricing.ModelParametersURL)
}

// failingFrameworkConfigStore makes the framework config write fail while every
// other store call goes through to the real store.
type failingFrameworkConfigStore struct {
	configstore.ConfigStore
}

func (failingFrameworkConfigStore) UpdateFrameworkConfig(context.Context, *configtables.TableFrameworkConfig) error {
	return errors.New("simulated store failure")
}

// TestUpdateConfig_FrameworkConfigStoreFailureLeavesRuntimeUnchanged pins the
// ordering in updateConfig: the framework config is persisted before it is
// published to runtime, so a failed store write does not leave the in-memory
// config pointing at URLs the database never saved.
func TestUpdateConfig_FrameworkConfigStoreFailureLeavesRuntimeUnchanged(t *testing.T) {
	// The datasheet server below is loopback-bound; the accessibility check refuses loopback
	// by default, so route its dial through a plain dialer for this test only.
	prevDial := checkURLAccessibilityDialContext
	checkURLAccessibilityDialContext = (&net.Dialer{}).DialContext
	t.Cleanup(func() { checkURLAccessibilityDialContext = prevDial })
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(failingFrameworkConfigStore{store}, configtables.MCPServerAuthModeHeaders, false)
	before := cfg.FrameworkConfig
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	ctx := putConfigCtx(`{"client_config":{"log_retention_days":7},"framework_config":{"pricing_url":"` + newDatasheetServer(t).URL + `"}}`)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Same(t, before, cfg.FrameworkConfig, "runtime framework config must not change when the store write fails")
}

// TestUpdateProxyConfig_InterceptionGuardWhenAuthBypassed pins that the fail-open bypass
// cannot point the global proxy at a caller-chosen host or turn off its TLS verification:
// either lets a third party read provider credentials for every proxied request. Saving
// other fields against the stored proxy URL must still go through.
func TestUpdateProxyConfig_InterceptionGuardWhenAuthBypassed(t *testing.T) {
	SetLogger(&mockLogger{})
	const storedURL = "http://10.0.0.5:3128"
	cases := []struct {
		name    string
		body    string
		want403 bool
	}{
		{name: "same url, timeout edit", body: `{"enabled":true,"type":"http","url":"` + storedURL + `","timeout":30,"enable_for_inference":true}`, want403: false},
		{name: "url changed", body: `{"enabled":true,"type":"http","url":"http://evil.example.com:8080","timeout":10,"enable_for_inference":true}`, want403: true},
		{name: "skip_tls_verify turned on", body: `{"enabled":true,"type":"http","url":"` + storedURL + `","timeout":10,"skip_tls_verify":true,"enable_for_inference":true}`, want403: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newRealOAuth2Store(t)
			require.NoError(t, store.UpdateProxyConfig(context.Background(), &configtables.GlobalProxyConfig{
				Enabled: true, Type: "http", URL: storedURL, Timeout: 10, EnableForInference: true,
			}))
			cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
			h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

			ctx := newTestRequestCtx(tc.body)
			ctx.Request.Header.SetMethod(fasthttp.MethodPut)
			ctx.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)

			h.updateProxyConfig(ctx)

			got403 := ctx.Response.StatusCode() == fasthttp.StatusForbidden
			require.Equal(t, tc.want403, got403, "status %d; body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
			stored, err := store.GetProxyConfig(context.Background())
			require.NoError(t, err)
			if tc.want403 {
				assert.Equal(t, storedURL, stored.URL)
				assert.False(t, stored.SkipTLSVerify)
				assert.Equal(t, 10, stored.Timeout)
			} else {
				require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), "body=%s", ctx.Response.Body())
				assert.Equal(t, 30, stored.Timeout)
			}
		})
	}
}

// A per-server cap larger than the total it must fit inside can never be satisfied, so it is
// rejected rather than stored and silently clamped later.
func TestValidateMCPInstructionCaps(t *testing.T) {
	assert.NoError(t, validateMCPInstructionCaps(0, 0), "0/0 means use the built-in defaults")
	assert.NoError(t, validateMCPInstructionCaps(4096, 16384))
	assert.NoError(t, validateMCPInstructionCaps(0, 2048), "a total alone is fine")
	assert.NoError(t, validateMCPInstructionCaps(2048, 0), "a per-client cap alone is fine")

	assert.Error(t, validateMCPInstructionCaps(-1, 0))
	assert.Error(t, validateMCPInstructionCaps(0, -1))
	assert.Error(t, validateMCPInstructionCaps(1<<21, 0), "a cap in the megabytes is a typo")
	assert.Error(t, validateMCPInstructionCaps(0, 1<<21))
	err := validateMCPInstructionCaps(20000, 16384)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not exceed")
}

// newDatasheetServer serves an empty JSON datasheet on loopback.
func newDatasheetServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCheckURLAccessibility_RejectsFileURLs: file:// datasheet and catalog
// URLs are an operator feature of config.json (air-gapped deployments) and are
// refused when they arrive over the HTTP API, whatever the path points at.
func TestCheckURLAccessibility_RejectsFileURLs(t *testing.T) {
	for _, raw := range []string{"file:///etc/hostname", "file://./pricing.json", "file:pricing.json", "FILE:///etc/hostname"} {
		err := checkURLAccessibility(raw)
		require.Error(t, err, raw)
		assert.Contains(t, err.Error(), "config.json", raw)
	}
}

// TestCheckURLAccessibility_ReachesConfiguredPrivateProxy pins that the URL check works
// behind a global API proxy on a private or loopback address. The proxy is dialed with
// the private-network policy; a direct dial keeps the public-only check, so saving a
// URL override does not fail just because the proxy is self-hosted.
func TestCheckURLAccessibility_ReachesConfiguredPrivateProxy(t *testing.T) {
	SetLogger(&mockLogger{})
	var seen atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.Host)
		_, _ = w.Write([]byte("{}"))
	}))
	defer proxy.Close()
	network.SetDefaultHTTPClientFactory(network.NewHTTPClientFactory(&network.GlobalProxyConfig{
		Enabled: true, Type: network.GlobalProxyTypeHTTP, URL: proxy.URL, EnableForAPI: true,
	}, nil))
	t.Cleanup(func() { network.SetDefaultHTTPClientFactory(nil) })

	if err := checkURLAccessibility("http://203.0.113.10/pricing.json"); err != nil {
		t.Fatalf("a loopback API proxy must be usable for the URL check, got %v", err)
	}
	if got, _ := seen.Load().(string); got != "203.0.113.10" {
		t.Fatalf("proxy saw target %q, want 203.0.113.10", got)
	}
}

// TestCheckURLAccessibility_RefusesRedirectToLinkLocal: the entry host is a
// reachable loopback server whose 302 points at the cloud metadata address.
// The hop must be refused, and the caller-facing error must not name the
// target or carry the transport detail.
func TestCheckURLAccessibility_RefusesRedirectToLinkLocal(t *testing.T) {
	SetLogger(&mockLogger{})
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirect.Close()

	err := checkURLAccessibility(redirect.URL)
	require.Error(t, err)
	assert.Equal(t, "url is not reachable", err.Error())
}

// TestCheckURLAccessibility_DoesNotReflectTransportErrors: a non-HTTP service
// greets with a banner that net/http folds into its parse error. That detail
// is for the debug log, never for the response body.
func TestCheckURLAccessibility_DoesNotReflectTransportErrors(t *testing.T) {
	SetLogger(&mockLogger{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu0.1\r\n"))
			conn.Close()
		}
	}()

	err = checkURLAccessibility("http://" + ln.Addr().String() + "/")
	require.Error(t, err)
	assert.Equal(t, "url is not reachable", err.Error())
	assert.NotContains(t, strings.ToLower(err.Error()), "openssh")

	// A refused port reads the same as a banner: no open/closed oracle.
	ln.Close()
	err = checkURLAccessibility("http://" + ln.Addr().String() + "/")
	require.Error(t, err)
	assert.Equal(t, "url is not reachable", err.Error())
}

// TestUpdateConfig_RejectsOAuthModeWithoutIssuerURL pins the HTTP side of the issuer_url
// rule the OpenAPI description states: enabling issuance over PUT /api/config without a
// pinned issuer is refused with 400 and names the field. The startup side (a config.json
// doing the same fails validation at boot) is pinned by
// TestLoadConfig_OAuthDiscoveryWithoutIssuerURLFailsBoot in lib.
func TestUpdateConfig_RejectsOAuthModeWithoutIssuerURL(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	// The shared fixture pins an issuer so the issuance tests clear this rule; this test is
	// about the rule itself, so start from a headers-mode config with no issuer stored.
	cfg.ClientConfig.OAuth2ServerConfig = nil
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	for _, mode := range []string{"both", "oauth"} {
		t.Run(mode, func(t *testing.T) {
			ctx := putConfigCtx(`{"client_config":{"log_retention_days":7,"mcp_server_auth_mode":"` + mode + `"}}`)
			h.updateConfig(ctx)
			require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
			assert.Contains(t, string(ctx.Response.Body()), "issuer_url")
		})
	}
}

// TestUpdateConfig_RejectsFileURLsOverAPI pins the API-side rule for all three
// catalog URLs: PUT /api/config answers 400 and persists nothing.
func TestUpdateConfig_RejectsFileURLsOverAPI(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	for _, field := range []string{"pricing_url", "model_parameters_url", "mcp_library_url"} {
		t.Run(field, func(t *testing.T) {
			ctx := putConfigCtx(`{"client_config":{"log_retention_days":7},"framework_config":{"` + field + `":"file:///etc/hostname"}}`)
			h.updateConfig(ctx)
			require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
			assert.Contains(t, string(ctx.Response.Body()), "config.json")
		})
	}
	persisted, err := store.GetFrameworkConfig(bgCtx())
	require.NoError(t, err)
	if persisted != nil {
		for _, got := range []*string{persisted.PricingURL, persisted.ModelParametersURL, persisted.MCPLibraryURL} {
			if got != nil {
				assert.NotContains(t, *got, "file://")
			}
		}
	}
}

// TestUpdateProxyConfig_RejectsLinkLocalURL pins that the global proxy URL is held to the
// same destination rule as a provider base URL. Every proxied request carries its provider
// credentials to this host, so an address that can never be a legitimate egress proxy
// (link-local such as the cloud metadata endpoint, or unspecified) is refused even for a
// genuinely authenticated admin. Private and loopback hosts stay allowed: a self-hosted
// proxy on the local network is the normal setup.
func TestUpdateProxyConfig_RejectsLinkLocalURL(t *testing.T) {
	SetLogger(&mockLogger{})
	cases := []struct {
		name       string
		url        string
		wantStatus int
	}{
		{name: "link-local metadata endpoint", url: "http://169.254.169.254:80", wantStatus: fasthttp.StatusBadRequest},
		{name: "unspecified address", url: "http://0.0.0.0:3128", wantStatus: fasthttp.StatusBadRequest},
		{name: "private network proxy", url: "http://10.0.0.5:3128", wantStatus: fasthttp.StatusOK},
		{name: "loopback proxy", url: "http://127.0.0.1:3128", wantStatus: fasthttp.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newRealOAuth2Store(t)
			cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
			h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

			ctx := newTestRequestCtx(`{"enabled":true,"type":"http","url":"` + tc.url + `","timeout":0}`)
			ctx.Request.Header.SetMethod(fasthttp.MethodPut)

			h.updateProxyConfig(ctx)

			require.Equal(t, tc.wantStatus, ctx.Response.StatusCode(), "body=%s", ctx.Response.Body())
			stored, err := store.GetProxyConfig(context.Background())
			if tc.wantStatus == fasthttp.StatusOK {
				require.NoError(t, err)
				assert.Equal(t, tc.url, stored.URL)
				return
			}
			if err != nil {
				require.ErrorIs(t, err, configstore.ErrNotFound)
				return
			}
			if stored != nil {
				assert.Empty(t, stored.URL, "a rejected proxy URL must not be persisted")
			}
		})
	}
}

// recordingToolManagerConfig records the code mode limits handed to the MCP hot reload.
type recordingToolManagerConfig struct {
	stubConfigManager
	calls  int
	limits *schemas.MCPCodeModeLimits
}

func (r *recordingToolManagerConfig) UpdateMCPToolManagerConfig(_ context.Context, _ int, _ int, _ string, _ bool, _ int, _ int, limits *schemas.MCPCodeModeLimits) error {
	r.calls++
	r.limits = limits
	return nil
}

func TestUpdateConfig_MCPCodeModeLimits(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.MCPConfig = &schemas.MCPConfig{}
	recorder := &recordingToolManagerConfig{}
	h := &ConfigHandler{store: cfg, configManager: recorder}

	save := func(t *testing.T, limitsJSON string) *fasthttp.RequestCtx {
		t.Helper()
		body := `{"client_config":{"log_retention_days":7}}`
		if limitsJSON != "" {
			body = `{"client_config":{"log_retention_days":7,"mcp_code_mode_limits":` + limitsJSON + `}}`
		}
		ctx := putConfigCtx(body)
		h.updateConfig(ctx)
		return ctx
	}
	persisted := func(t *testing.T) *schemas.MCPCodeModeLimits {
		t.Helper()
		stored, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return stored.MCPCodeModeLimits
	}
	limits := &schemas.MCPCodeModeLimits{MaxSteps: 5_000_000, MaxToolCalls: 500}

	ctx := save(t, `{"max_steps":5000000,"max_tool_calls":500}`)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, limits, persisted(t), "limits must persist")
	assert.Equal(t, limits, cfg.ClientConfig.MCPCodeModeLimits, "limits must apply in memory")
	assert.Equal(t, limits, cfg.MCPConfig.ToolManagerConfig.CodeModeLimits, "the in-memory MCP config must carry the limits")
	assert.Equal(t, limits, recorder.limits, "limits must be hot-reloaded")

	calls := recorder.calls
	ctx = save(t, "")
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, limits, persisted(t), "an update that omits the limits must keep them")
	assert.Equal(t, calls, recorder.calls, "an update that omits the limits must not reload")

	for _, invalid := range []string{`{"max_steps":-1}`, `{"max_nesting_depth":5000}`, `{"max_value_bytes":10}`} {
		ctx = save(t, invalid)
		require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), "%s: %s", invalid, ctx.Response.Body())
		assert.Equal(t, limits, persisted(t), "rejected limits %s must not persist", invalid)
	}

	// A save rejected after the MCP section must not have reloaded or published the limits.
	calls = recorder.calls
	ctx = putConfigCtx(`{"client_config":{"log_retention_days":0,"mcp_code_mode_limits":{"max_tool_calls":7}}}`)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, calls, recorder.calls, "a rejected save must not hot-reload the limits")
	assert.Equal(t, limits, recorder.limits, "a rejected save must leave the runtime limits alone")
	assert.Equal(t, limits, cfg.MCPConfig.ToolManagerConfig.CodeModeLimits, "a rejected save must leave the in-memory MCP config alone")
	assert.Equal(t, limits, persisted(t), "a rejected save must not persist")

	ctx = save(t, `{}`)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, &schemas.MCPCodeModeLimits{}, persisted(t), "empty limits must reset to the defaults")
	assert.Equal(t, &schemas.MCPCodeModeLimits{}, recorder.limits, "the reset must be hot-reloaded")
}

// recordingCompatConfigManager records compat plugin reloads and removals.
type recordingCompatConfigManager struct {
	stubConfigManager
	reloaded   []*compat.Config
	removed    []string
	failReload bool
}

func (m *recordingCompatConfigManager) ReloadPlugin(_ context.Context, name string, _ *string, cfg any, _ *schemas.PluginPlacement, _ *int) error {
	if name == compat.PluginName {
		m.reloaded = append(m.reloaded, cfg.(*compat.Config))
		if m.failReload {
			return errors.New("compat reload failed")
		}
	}
	return nil
}

func (m *recordingCompatConfigManager) RemovePlugin(_ context.Context, name string) error {
	m.removed = append(m.removed, name)
	return nil
}

// TestUpdateConfig_CompatAllFlagsOffKeepsPluginLoaded pins that disabling every
// compat flag reloads the plugin instead of removing it, so per-request compat
// header overrides keep working.
func TestUpdateConfig_CompatAllFlagsOffKeepsPluginLoaded(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.Compat = configstore.CompatConfig{ConvertTextToChat: true}
	cm := &recordingCompatConfigManager{}
	h := &ConfigHandler{store: cfg, configManager: cm}

	ctx := putConfigCtx(`{"client_config":{"log_retention_days":7,"compat":{"convert_text_to_chat":false,"convert_chat_to_responses":false,"should_drop_params":false,"should_convert_params":false,"azure_deepseek":false,"force_reasoning_only_models_to_responses":false}}}`)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	assert.NotContains(t, cm.removed, compat.PluginName, "compat plugin must stay loaded for per-request overrides")
	require.Len(t, cm.reloaded, 1, "compat plugin must be reloaded with the new config")
	assert.Equal(t, compat.Config{}, *cm.reloaded[0])
}

const compatAllOffPayload = `{"client_config":{"log_retention_days":7,"compat":{"convert_text_to_chat":false,"convert_chat_to_responses":false,"should_drop_params":false,"should_convert_params":false,"azure_deepseek":false,"force_reasoning_only_models_to_responses":false}}}`

// TestUpdateConfig_CompatReloadWaitsForPersistence pins that a failed save never
// reaches the compat plugin, so runtime compat cannot run ahead of the database.
func TestUpdateConfig_CompatReloadWaitsForPersistence(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(inferenceSetupFailureStore{store, "write"}, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.Compat = configstore.CompatConfig{ConvertTextToChat: true}
	cm := &recordingCompatConfigManager{}
	h := &ConfigHandler{store: cfg, configManager: cm}

	ctx := putConfigCtx(compatAllOffPayload)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	assert.Empty(t, cm.reloaded, "compat plugin must not change when the save fails")
	assert.True(t, cfg.ClientConfig.Compat.ConvertTextToChat, "in-memory compat must stay unchanged")
}

// TestUpdateConfig_CompatReloadFailureRestoresPersistedConfig pins that a failed
// compat reload after a successful save rolls the persisted compat setting back.
func TestUpdateConfig_CompatReloadFailureRestoresPersistedConfig(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.Compat = configstore.CompatConfig{ConvertTextToChat: true}
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	cm := &recordingCompatConfigManager{failReload: true}
	h := &ConfigHandler{store: cfg, configManager: cm}

	ctx := putConfigCtx(compatAllOffPayload)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	persisted, err := store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	assert.True(t, persisted.Compat.ConvertTextToChat, "persisted compat must be restored after a failed reload")
	assert.True(t, cfg.ClientConfig.Compat.ConvertTextToChat, "in-memory compat must stay unchanged")
}

// failingRestoreStore fails every UpdateClientConfig after the first, so the
// compensating restore write fails.
type failingRestoreStore struct {
	configstore.ConfigStore
	writes *int
}

func (s failingRestoreStore) UpdateClientConfig(ctx context.Context, c *configstore.ClientConfig) error {
	*s.writes++
	if *s.writes > 1 {
		return errors.New("restore write failed")
	}
	return s.ConfigStore.UpdateClientConfig(ctx, c)
}

// TestUpdateConfig_CompatReloadFailureReportsFailedRestore pins that a failed restore
// is reported as a server error instead of the clean-rollback 400.
func TestUpdateConfig_CompatReloadFailureReportsFailedRestore(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	writes := 0
	cfg := newTestOAuth2Config(failingRestoreStore{store, &writes}, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.Compat = configstore.CompatConfig{ConvertTextToChat: true}
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	cm := &recordingCompatConfigManager{failReload: true}
	h := &ConfigHandler{store: cfg, configManager: cm}

	ctx := putConfigCtx(compatAllOffPayload)
	h.updateConfig(ctx)
	require.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Contains(t, string(ctx.Response.Body()), "could not be restored")
	assert.Equal(t, 2, writes, "the handler must attempt the restore write")
	assert.True(t, cfg.ClientConfig.Compat.ConvertTextToChat, "in-memory compat must stay unchanged")
}

// TestGetConfigSkillsMarketplaceURL exposes the live resolved URL used by marketplace serving.
func TestGetConfigSkillsMarketplaceURL(t *testing.T) {
	t.Setenv("BIFROST_TEST_SKILLS_URL", "https://skills.example/prefix/")
	for _, value := range []string{"", "http://127.0.0.1:8080", "env.BIFROST_TEST_SKILLS_URL"} {
		t.Run(value, func(t *testing.T) {
			cfg := &lib.Config{ClientConfig: &configstore.ClientConfig{SkillsExternalClientURL: schemas.NewSecretVar(value)}}
			h := &ConfigHandler{store: cfg}
			ctx := &fasthttp.RequestCtx{}
			h.getConfig(ctx)
			require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
			var response struct {
				MarketplaceURL *string `json:"skills_marketplace_base_url"`
			}
			require.NoError(t, json.Unmarshal(ctx.Response.Body(), &response))
			require.NotNil(t, response.MarketplaceURL, "the field must be present even when marketplace serving is disabled")
			require.Equal(t, strings.TrimRight(cfg.ClientConfig.SkillsExternalClientURL.GetValue(), "/"), *response.MarketplaceURL)
		})
	}
}

// TestUpdateConfig_SkillsExternalClientURLPresence pins persistence and partial-update semantics.
func TestUpdateConfig_SkillsExternalClientURLPresence(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	cfg.ClientConfig.SkillsExternalClientURL = schemas.NewSecretVar("https://bifrost.example.com")
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	require.NotNil(t, cfg.ClientConfig.SkillsExternalClientURL)
	assert.Equal(t, "https://bifrost.example.com", cfg.ClientConfig.SkillsExternalClientURL.GetValue())
	persisted, err := store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted.SkillsExternalClientURL)
	assert.Equal(t, "https://bifrost.example.com", persisted.SkillsExternalClientURL.GetValue())

	cleared := putConfigCtx(`{"client_config":{"log_retention_days":8,"skills_external_client_url":null}}`)
	h.updateConfig(cleared)
	require.Equal(t, fasthttp.StatusOK, cleared.Response.StatusCode(), string(cleared.Response.Body()))
	assert.Nil(t, cfg.ClientConfig.SkillsExternalClientURL)
	persisted, err = store.GetClientConfig(bgCtx())
	require.NoError(t, err)
	require.NotNil(t, persisted.SkillsExternalClientURL)
	assert.Empty(t, persisted.SkillsExternalClientURL.GetValue())
}

// TestUpdateConfigRejectsPrivateSkillsURLComponents prevents public catalogs from exposing URL credentials.
func TestUpdateConfigRejectsPrivateSkillsURLComponents(t *testing.T) {
	SetLogger(&mockLogger{})
	for _, value := range []string{"https://user:password@example.com", "https://example.com?token=private", "https://example.com?"} {
		store := newRealOAuth2Store(t)
		cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
		h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
		ctx := putConfigCtx(fmt.Sprintf(`{"client_config":{"log_retention_days":8,"skills_external_client_url":%q}}`, value))
		h.updateConfig(ctx)
		require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
		require.Contains(t, string(ctx.Response.Body()), "skills_external_client_url")
		require.NotContains(t, string(ctx.Response.Body()), value)
	}
}

// TestUpdateConfig_A2APrivateAllowlist pins how PUT /api/config handles
// a2a_private_allowlist: an authenticated admin sets it and it is
// persisted; an omitted field keeps it; a caller admitted with auth bypassed
// may resend the current value (the dashboard saves the whole client config)
// but not change it; entries the policy can never honor are refused.
func TestUpdateConfig_A2APrivateAllowlist(t *testing.T) {
	SetLogger(&mockLogger{})
	store := newRealOAuth2Store(t)
	cfg := newTestOAuth2Config(store, configtables.MCPServerAuthModeHeaders, false)
	require.NoError(t, store.UpdateClientConfig(bgCtx(), cfg.ClientConfig))
	h := &ConfigHandler{store: cfg, configManager: stubConfigManager{}}
	persistedAllowlist := func() []string {
		t.Helper()
		persisted, err := store.GetClientConfig(bgCtx())
		require.NoError(t, err)
		return persisted.A2APrivateAllowlist
	}

	set := putConfigCtx(`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":["localhost","127.0.0.1","10.0.0.0/8"]}}`)
	h.updateConfig(set)
	require.Equal(t, fasthttp.StatusOK, set.Response.StatusCode(), string(set.Response.Body()))
	want := []string{"localhost", "127.0.0.1", "10.0.0.0/8"}
	assert.Equal(t, want, cfg.ClientConfig.A2APrivateAllowlist)
	assert.Equal(t, want, persistedAllowlist())

	omitted := putConfigCtx(`{"client_config":{"log_retention_days":8}}`)
	omitted.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
	h.updateConfig(omitted)
	require.Equal(t, fasthttp.StatusOK, omitted.Response.StatusCode(), string(omitted.Response.Body()))
	assert.Equal(t, want, persistedAllowlist(), "an omitted allowlist must be kept")

	resent := putConfigCtx(`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":["localhost","127.0.0.1","10.0.0.0/8"]}}`)
	resent.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
	h.updateConfig(resent)
	require.Equal(t, fasthttp.StatusOK, resent.Response.StatusCode(), string(resent.Response.Body()))

	for _, body := range []string{
		`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":["localhost","192.168.0.0/16"]}}`,
		`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":[]}}`,
	} {
		changed := putConfigCtx(body)
		changed.SetUserValue(schemas.BifrostContextKeyAuthBypassed, true)
		h.updateConfig(changed)
		require.Equal(t, fasthttp.StatusForbidden, changed.Response.StatusCode(), string(changed.Response.Body()))
		assert.Contains(t, string(changed.Response.Body()), "a2a_private_allowlist requires an authenticated admin session")
		assert.Equal(t, want, persistedAllowlist(), "an auth-bypassed caller must not change the allowlist")
	}

	for _, entry := range []string{"169.254.169.254", "0.0.0.0/0", "metadata.google.internal", "http://localhost:3000"} {
		invalid := putConfigCtx(`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":["` + entry + `"]}}`)
		h.updateConfig(invalid)
		require.Equal(t, fasthttp.StatusBadRequest, invalid.Response.StatusCode(), entry+": "+string(invalid.Response.Body()))
		assert.Equal(t, want, persistedAllowlist())
	}

	cleared := putConfigCtx(`{"client_config":{"log_retention_days":8,"a2a_private_allowlist":[]}}`)
	h.updateConfig(cleared)
	require.Equal(t, fasthttp.StatusOK, cleared.Response.StatusCode(), string(cleared.Response.Body()))
	assert.Empty(t, persistedAllowlist())
}
