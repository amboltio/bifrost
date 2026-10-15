package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/identity"
	"github.com/valyala/fasthttp"
)

type initialAdminStore interface {
	configstore.DashboardIdentityStateStore
	CreateInitialSuperAdmin(context.Context, *tables.TableUser, *tables.TableCredential) (*tables.TableUser, error)
}

func (h *SessionHandler) setupAdmin(ctx *fasthttp.RequestCtx) {
	store, ok := h.configStore.(initialAdminStore)
	if !ok || h.setupLock == nil {
		SendError(ctx, 503, "User setup is unavailable")
		return
	}
	state, err := store.GetDashboardIdentityState(ctx)
	if err != nil {
		SendError(ctx, 503, "Authentication state unavailable")
		return
	}
	if state.Initialized {
		SendError(ctx, 409, "Setup is already complete")
		return
	}
	if !allowSessionStateChange(ctx) {
		SendError(ctx, 403, "Invalid request origin")
		return
	}
	header := string(ctx.Request.Header.Peek(SetupTokenHeader))
	valid := h.setupLock.CheckConfiguredSetupToken(header)
	if header == "" {
		valid = h.setupLock.validSetupSession(string(ctx.Request.Header.Cookie(SetupSessionCookie)), time.Now())
	}
	if !valid {
		SendError(ctx, 403, "Invalid setup proof")
		return
	}
	var payload struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, 400, "Invalid request payload")
		return
	}
	email := strings.TrimSpace(payload.Email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		SendError(ctx, 400, "A valid email address is required")
		return
	}
	hash, err := identity.NewPasswordService().Hash(payload.Password)
	if err != nil {
		SendError(ctx, 400, err.Error())
		return
	}
	_, err = store.CreateInitialSuperAdmin(ctx, &tables.TableUser{ID: uuid.NewString(), Email: &email, DisplayName: strings.TrimSpace(payload.DisplayName), Status: tables.UserStatusActive}, &tables.TableCredential{ID: uuid.NewString(), Kind: tables.CredentialKindPassword, SecretHash: hash, IsActive: true, Version: 1})
	if errors.Is(err, configstore.ErrAlreadyExists) {
		SendError(ctx, 409, "Setup is already complete")
		return
	}
	if err != nil {
		SendError(ctx, 500, "Failed to create administrator")
		return
	}
	policy, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, 503, "Administrator created; sign in after authentication settings are available")
		return
	}
	h.setupLock.UpdateAuthConfig(policy)
	h.setupLock.identityInitialized.Store(true)
	h.setupLock.ClearBootstrapToken()
	setSetupSessionCookie(ctx, "", time.Now().Add(-time.Hour))
	SendJSON(ctx, map[string]string{"status": "created"})
	ctx.SetStatusCode(fasthttp.StatusCreated)
}
