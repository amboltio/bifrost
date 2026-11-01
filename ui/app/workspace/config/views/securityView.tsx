import { Link } from "@tanstack/react-router";
import PageTitle from "@/components/pageTitle";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SecretVarInput } from "@/components/ui/secretVarInput";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { IS_ENTERPRISE } from "@/lib/constants/config";
import { getErrorMessage, useGetCoreConfigQuery, useUpdateCoreConfigMutation } from "@/lib/store";
import { CoreConfig, DefaultCoreConfig } from "@/lib/types/config";
import { SecretVar } from "@/lib/types/schemas";
import { parseArrayFromText } from "@/lib/utils/array";
import { formatCooldown } from "@/lib/utils/duration";
import { isSecretVarSet } from "@/lib/utils/secretVarForm";
import { validateOrigins } from "@/lib/utils/validation";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertTriangle } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

// Go duration string: one or more <number><unit> segments, e.g. "5m", "1h30m".
const COOLDOWN_PATTERN = /^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/;

const secretVarEquals = (a?: SecretVar, b?: SecretVar) =>
	(a?.value ?? "") === (b?.value ?? "") && (a?.ref ?? "") === (b?.ref ?? "") && (a?.type ?? "plain_text") === (b?.type ?? "plain_text");

export default function SecurityView() {
	const hasSettingsUpdateAccess = useRbac(RbacResource.Settings, RbacOperation.Update);
	const { data: bifrostConfig } = useGetCoreConfigQuery({ fromDB: true });
	const config = bifrostConfig?.client_config;
	const [updateCoreConfig, { isLoading }] = useUpdateCoreConfigMutation();
	const [localConfig, setLocalConfig] = useState<CoreConfig>(DefaultCoreConfig);
	const [localValues, setLocalValues] = useState<{
		allowed_origins: string;
		allowed_headers: string;
		required_headers: string;
		whitelisted_routes: string;
		vk_rotation_cooldown: string;
	}>({
		allowed_origins: "",
		allowed_headers: "",
		required_headers: "",
		whitelisted_routes: "",
		vk_rotation_cooldown: "",
	});

	useEffect(() => {
		if (bifrostConfig && config) {
			setLocalConfig(config);
			setLocalValues({
				allowed_origins: config?.allowed_origins?.join(", ") || "",
				allowed_headers: config?.allowed_headers?.join(", ") || "",
				required_headers: config?.required_headers?.join(", ") || "",
				whitelisted_routes: config?.whitelisted_routes?.join(", ") || "",
				vk_rotation_cooldown: formatCooldown(config?.vk_rotation_cooldown),
			});
		}
	}, [config, bifrostConfig]);

	const hasChanges = useMemo(() => {
		if (!config) return false;
		const localOrigins = localConfig.allowed_origins?.slice().sort().join(",");
		const serverOrigins = config.allowed_origins?.slice().sort().join(",");
		const originsChanged = localOrigins !== serverOrigins;

		const localHeaders = localConfig.allowed_headers?.slice().sort().join(",");
		const serverHeaders = config.allowed_headers?.slice().sort().join(",");
		const headersChanged = localHeaders !== serverHeaders;

		const localRequired = localConfig.required_headers?.slice().sort().join(",");
		const serverRequired = config.required_headers?.slice().sort().join(",");
		const requiredChanged = localRequired !== serverRequired;

		const localWhitelistedRoutes = localConfig.whitelisted_routes?.slice().sort().join(",");
		const serverWhitelistedRoutes = config.whitelisted_routes?.slice().sort().join(",");
		const whitelistedRoutesChanged = localWhitelistedRoutes !== serverWhitelistedRoutes;

		const enforceAuthOnInferenceChanged = localConfig.enforce_auth_on_inference !== config.enforce_auth_on_inference;
		const allowDirectKeysChanged = localConfig.allow_direct_keys !== config.allow_direct_keys;
		const deleteExpiredVirtualKeysChanged = localConfig.delete_expired_virtual_keys !== config.delete_expired_virtual_keys;
		const enforceVKObjectOwnershipChanged =
			(localConfig.enforce_vk_object_ownership ?? true) !== (config.enforce_vk_object_ownership ?? true);
		const skipAccessProfileUserVirtualKeyCreationChanged =
			IS_ENTERPRISE &&
			(localConfig.skip_access_profile_user_virtual_key_creation ?? false) !==
				(config.skip_access_profile_user_virtual_key_creation ?? false);
		const skipAccessProfileUserVirtualKeyDeletionChanged =
			IS_ENTERPRISE &&
			(localConfig.skip_access_profile_user_virtual_key_deletion ?? false) !==
				(config.skip_access_profile_user_virtual_key_deletion ?? false);
		const dualCredentialConflictBehaviorChanged =
			(localConfig.dual_credential_conflict_behavior || "prefer_idp") !== (config.dual_credential_conflict_behavior || "prefer_idp");
		const vkRotationCooldownChanged = formatCooldown(localConfig.vk_rotation_cooldown) !== formatCooldown(config.vk_rotation_cooldown);
		const issuerURLChanged = !secretVarEquals(localConfig.oauth2_server_config?.issuer_url, config.oauth2_server_config?.issuer_url);

		return (
			originsChanged ||
			headersChanged ||
			requiredChanged ||
			whitelistedRoutesChanged ||
			enforceAuthOnInferenceChanged ||
			allowDirectKeysChanged ||
			deleteExpiredVirtualKeysChanged ||
			enforceVKObjectOwnershipChanged ||
			skipAccessProfileUserVirtualKeyCreationChanged ||
			skipAccessProfileUserVirtualKeyDeletionChanged ||
			dualCredentialConflictBehaviorChanged ||
			vkRotationCooldownChanged ||
			issuerURLChanged
		);
	}, [config, localConfig]);

	const needsRestart = useMemo(() => {
		if (!config) return false;

		const localOrigins = localConfig.allowed_origins?.slice().sort().join(",");
		const serverOrigins = config.allowed_origins?.slice().sort().join(",");
		const originsChanged = localOrigins !== serverOrigins;

		const localHeaders = localConfig.allowed_headers?.slice().sort().join(",");
		const serverHeaders = config.allowed_headers?.slice().sort().join(",");
		const headersChanged = localHeaders !== serverHeaders;

		const enforceAuthOnInferenceChanged = localConfig.enforce_auth_on_inference !== config.enforce_auth_on_inference && IS_ENTERPRISE;

		return originsChanged || headersChanged || enforceAuthOnInferenceChanged;
	}, [config, localConfig]);

	const handleAllowedOriginsChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, allowed_origins: value }));
		setLocalConfig((prev) => ({ ...prev, allowed_origins: parseArrayFromText(value) }));
	}, []);

	const handleAllowedHeadersChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, allowed_headers: value }));
		setLocalConfig((prev) => ({ ...prev, allowed_headers: parseArrayFromText(value) }));
	}, []);

	const handleRequiredHeadersChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, required_headers: value }));
		setLocalConfig((prev) => ({ ...prev, required_headers: parseArrayFromText(value) }));
	}, []);

	const handleWhitelistedRoutesChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, whitelisted_routes: value }));
		setLocalConfig((prev) => ({ ...prev, whitelisted_routes: parseArrayFromText(value) }));
	}, []);

	const handleConfigChange = useCallback((field: keyof CoreConfig, value: boolean) => {
		setLocalConfig((prev) => ({ ...prev, [field]: value }));
	}, []);

	const handleVkRotationCooldownChange = useCallback((value: string) => {
		setLocalValues((prev) => ({ ...prev, vk_rotation_cooldown: value }));
		// The backend accepts Go duration strings; empty input means 0 (disabled).
		setLocalConfig((prev) => ({ ...prev, vk_rotation_cooldown: value.trim() === "" ? 0 : value.trim() }));
	}, []);

	const handleSave = useCallback(async () => {
		try {
			const validation = validateOrigins(localConfig.allowed_origins);

			if (!validation.isValid && localConfig.allowed_origins.length > 0) {
				toast.error(
					`Invalid origins: ${validation.invalidOrigins.join(", ")}. Origins must be valid URLs like https://example.com, wildcard patterns like https://*.example.com, or "*" to allow all origins`,
				);
				return;
			}
			const oauthModeActive = localConfig.mcp_server_auth_mode === "both" || localConfig.mcp_server_auth_mode === "oauth";
			if (oauthModeActive && !isSecretVarSet(localConfig.oauth2_server_config?.issuer_url)) {
				toast.error("Issuer URL is required while MCP auth mode is OAuth or Both. Switch MCP auth to Headers in MCP Settings to clear it.");
				return;
			}
			const cooldownInput = localValues.vk_rotation_cooldown.trim();
			if (cooldownInput !== "" && cooldownInput !== "0" && !COOLDOWN_PATTERN.test(cooldownInput)) {
				toast.error('Rotation cooldown must be a duration like "30s", "5m", or "1h30m" (leave empty to disable).');
				return;
			}
			await updateCoreConfig({
				client_config: localConfig,
			}).unwrap();
			toast.success("Security settings updated successfully.");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	}, [localConfig, localValues.vk_rotation_cooldown, updateCoreConfig]);

	return (
		<div className="mx-auto w-full max-w-4xl space-y-4">
			<PageTitle title="Security Settings">Configure security and access control settings.</PageTitle>

			<div className="space-y-4">
				<Alert data-testid="security-users-notice">
					<AlertDescription>
						Manage dashboard accounts and passwords in{" "}
						<Link to="/workspace/governance/users" className="underline" data-testid="security-manage-users">
							Users
						</Link>
						. An operator can create a superadmin from the server terminal with <code>createsuperadmin --app-dir PATH</code>.
					</AlertDescription>
				</Alert>
				{/* Enable Auth on Inference */}
				<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
					<div className="space-y-0.5">
						<label htmlFor="enforce-auth-on-inference" className="text-sm font-medium">
							{IS_ENTERPRISE ? "Enable Auth on Inference" : "Enforce Virtual Keys on Inference"}
						</label>
						<p className="text-muted-foreground text-sm">
							{IS_ENTERPRISE
								? "Require authentication (virtual key, API key, or user token) for all inference endpoints."
								: "Require a virtual key for all inference requests."}{" "}
							See{" "}
							<a
								href="https://docs.getbifrost.ai/features/governance/virtual-keys"
								target="_blank"
								rel="noopener noreferrer"
								className="text-primary underline"
								data-testid="security-virtual-keys-docs-link"
							>
								documentation
							</a>{" "}
							to set up a virtual key before enabling this. Calls without a valid credential will return 401.
						</p>
					</div>
					<Switch
						id="enforce-auth-on-inference"
						data-testid="enforce-auth-on-inference-switch"
						checked={localConfig.enforce_auth_on_inference}
						disabled={!bifrostConfig}
						onCheckedChange={(checked) => handleConfigChange("enforce_auth_on_inference", checked)}
					/>
				</div>
				{!config?.enforce_auth_on_inference && (
					<Alert variant="destructive" data-testid="inference-auth-off-warning">
						<AlertTriangle className="h-4 w-4" />
						<AlertDescription>
							The dashboard is authentication protected, but this is a separate control: anyone who can reach this gateway can still call
							inference endpoints (e.g. chat completions) with no credential at all, spending your provider budget and reading provider-side
							state your key has access to. Turn this on unless you've deliberately chosen to leave inference open.
						</AlertDescription>
					</Alert>
				)}
				{/* Dual Credential Conflict Behavior */}
				{IS_ENTERPRISE && (
					<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="dual-credential-conflict-behavior" className="text-sm font-medium">
								Dual Credential Conflict Behavior
							</label>
							<p className="text-muted-foreground text-sm">
								How to handle inference requests that present both an identity provider access token (<b>Authorization: Bearer</b>) and a
								virtual key (<b>x-bf-vk</b>). <b>Prefer IDP token</b> uses the user token for identity, <b>Prefer virtual key</b> drops the
								IDP token and authenticates via the virtual key, and <b>Reject request</b> returns a 400 error.
							</p>
						</div>
						<Select
							value={localConfig.dual_credential_conflict_behavior || "prefer_idp"}
							onValueChange={(value) =>
								setLocalConfig((prev) => ({
									...prev,
									dual_credential_conflict_behavior: value as CoreConfig["dual_credential_conflict_behavior"],
								}))
							}
						>
							<SelectTrigger
								id="dual-credential-conflict-behavior"
								data-testid="dual-credential-conflict-behavior-select"
								className="w-full sm:w-[180px]"
							>
								<SelectValue />
							</SelectTrigger>
							<SelectContent>
								<SelectItem value="prefer_idp">Prefer IDP token</SelectItem>
								<SelectItem value="prefer_vk">Prefer virtual key</SelectItem>
								<SelectItem value="error">Reject request</SelectItem>
							</SelectContent>
						</Select>
					</div>
				)}
				{/* Allow Direct API Keys */}
				<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
					<div className="space-y-0.5">
						<label htmlFor="allow-direct-keys" className="text-sm font-medium">
							Allow Direct API Keys
						</label>
						<p className="text-muted-foreground text-sm">
							When enabled, callers can pass a provider API key directly in the <b>Authorization</b>, <b>x-api-key</b>, or{" "}
							<b>x-goog-api-key</b> header alongside <b>x-bf-direct-key: true</b>. Bifrost will use that key directly, bypassing the
							registered key pool.
						</p>
					</div>
					<Switch
						id="allow-direct-keys"
						data-testid="security-allow-direct-keys-switch"
						checked={localConfig.allow_direct_keys}
						onCheckedChange={(checked) => handleConfigChange("allow_direct_keys", checked)}
					/>
				</div>
				{/* Cooldown After Virtual Key Rotation */}
				<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
					<div className="space-y-0.5">
						<label htmlFor="vk-rotation-cooldown" className="text-sm font-medium">
							Scheduled Rotation Grace Period
						</label>
						<p className="text-muted-foreground text-sm">
							Scheduled rotations can keep the previous value valid while callers switch keys. Manual rotations always revoke the old key
							immediately. Use <b>30s</b>, <b>5m</b>, or <b>1h</b>. Leave empty (or 0) to disable the scheduled grace period. Maximum 30
							days.
						</p>
					</div>
					<Input
						id="vk-rotation-cooldown"
						data-testid="security-vk-rotation-cooldown-input"
						className="w-[180px]"
						placeholder="5m"
						value={localValues.vk_rotation_cooldown}
						onChange={(e) => handleVkRotationCooldownChange(e.target.value)}
					/>
				</div>
				{/* Delete Expired Virtual Keys */}
				<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
					<div className="space-y-0.5">
						<label htmlFor="delete-expired-virtual-keys" className="text-sm font-medium">
							Delete Expired Virtual Keys
						</label>
						<p className="text-muted-foreground text-sm">
							When enabled, a daily cleanup job deletes every virtual key whose expiry has passed and posts a notification listing the
							removed keys. Each key can override this from its <b>Delete after expire</b> switch: a key set to off is kept, and a key set
							to on is deleted even while this is disabled.
						</p>
					</div>
					<Switch
						id="delete-expired-virtual-keys"
						data-testid="security-delete-expired-virtual-keys-switch"
						checked={localConfig.delete_expired_virtual_keys}
						onCheckedChange={(checked) => handleConfigChange("delete_expired_virtual_keys", checked)}
					/>
				</div>
				{/* Restrict Provider Objects to the Creating Virtual Key */}
				<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
					<div className="space-y-0.5">
						<label htmlFor="enforce-vk-object-ownership" className="text-sm font-medium">
							Restrict Provider Objects to the Creating Virtual Key
						</label>
						<p className="text-muted-foreground text-sm">
							When enabled, files, batches, videos, containers, cached contents and live sessions created with a virtual key can only be
							read, listed or deleted with that same key. Other virtual keys get a not-found error and do not see them in lists. Requests
							without a virtual key are not affected. The creating key is recorded even while this is disabled, so enabling it again also
							covers objects created in the meantime, except any whose creating key could not be recorded.
						</p>
					</div>
					<Switch
						id="enforce-vk-object-ownership"
						data-testid="security-enforce-vk-object-ownership-switch"
						checked={localConfig.enforce_vk_object_ownership ?? true}
						onCheckedChange={(checked) => handleConfigChange("enforce_vk_object_ownership", checked)}
					/>
				</div>
				{/* Access profiles creating and deleting users' virtual keys, each switched separately */}
				{IS_ENTERPRISE && (
					<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="skip-access-profile-user-virtual-key-creation" className="text-sm font-medium">
								Don&apos;t Create User Virtual Keys for Access Profiles
							</label>
							<p className="text-muted-foreground text-sm">
								When enabled, a user&apos;s first access profile doesn&apos;t create a virtual key for them. Keys the user already owns, or
								that you add for them, are still governed by the profile while they hold one.
							</p>
						</div>
						<Switch
							id="skip-access-profile-user-virtual-key-creation"
							data-testid="security-skip-access-profile-user-virtual-key-creation-switch"
							checked={localConfig.skip_access_profile_user_virtual_key_creation ?? false}
							onCheckedChange={(checked) => handleConfigChange("skip_access_profile_user_virtual_key_creation", checked)}
						/>
					</div>
				)}
				{IS_ENTERPRISE && (
					<div className="flex items-center justify-between space-x-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="skip-access-profile-user-virtual-key-deletion" className="text-sm font-medium">
								Don&apos;t Delete User Virtual Keys When Access Profiles Are Removed
							</label>
							<p className="text-muted-foreground text-sm">
								When enabled, removing a user&apos;s last access profile keeps their virtual keys as ordinary keys, with none of the
								profile&apos;s providers or access. Deleting the user still deletes their keys.
							</p>
						</div>
						<Switch
							id="skip-access-profile-user-virtual-key-deletion"
							data-testid="security-skip-access-profile-user-virtual-key-deletion-switch"
							checked={localConfig.skip_access_profile_user_virtual_key_deletion ?? false}
							onCheckedChange={(checked) => handleConfigChange("skip_access_profile_user_virtual_key_deletion", checked)}
						/>
					</div>
				)}
				{/* OAuth issuer URL: shared by MCP OAuth and Cross App Access */}
				<div className="space-y-2 rounded-sm border p-4" data-testid="oauth2-issuer-url-section">
					<div className="space-y-0.5">
						<label htmlFor="oauth2-issuer-url" className="text-sm font-medium">
							OAuth Issuer URL
						</label>
						<p className="text-muted-foreground text-sm">
							Stable public URL of Bifrost's OAuth authorization server, advertised in discovery documents and set as the{" "}
							<code className="text-xs">iss</code> claim of every token Bifrost issues. MCP OAuth (required in OAuth and Both modes) and
							Cross App Access use it. Bifrost never derives it from the request <code className="text-xs">Host</code> header, because that
							header is caller-controlled. Supports env var syntax (e.g. <code className="text-xs">env.BIFROST_ISSUER_URL</code>).
						</p>
					</div>
					<SecretVarInput
						id="oauth2-issuer-url"
						data-testid="oauth2-issuer-url-input"
						placeholder="https://bifrost.example.com or env.BIFROST_ISSUER_URL"
						value={localConfig.oauth2_server_config?.issuer_url}
						onChange={(value: SecretVar) =>
							setLocalConfig((prev) => ({ ...prev, oauth2_server_config: { ...prev.oauth2_server_config, issuer_url: value } }))
						}
						disabled={!hasSettingsUpdateAccess}
					/>
					{isSecretVarSet(config?.oauth2_server_config?.issuer_url) &&
						!secretVarEquals(localConfig.oauth2_server_config?.issuer_url, config?.oauth2_server_config?.issuer_url) && (
							<Alert variant="warning" data-testid="oauth2-issuer-url-change-warning">
								<AlertTriangle className="size-4" />
								<AlertDescription>
									Changing the issuer invalidates the access tokens Bifrost has issued. MCP clients refresh them automatically, and Cross
									App Access apps request new ones.
								</AlertDescription>
							</Alert>
						)}
				</div>
				{/* Allowed Origins */}
				{needsRestart && <RestartWarning />}
				<div>
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="allowed-origins" className="text-sm font-medium">
								Allowed Origins
							</label>
							<p className="text-muted-foreground text-sm">
								Comma-separated list of allowed origins for CORS and WebSocket connections. Localhost origins are always allowed. Each
								origin must be a complete URL with protocol (e.g., https://app.example.com, http://10.0.0.100:3000). Wildcards are supported
								for subdomains (e.g., https://*.example.com) or use "*" to allow all origins.
							</p>
						</div>
						<Textarea
							id="allowed-origins"
							className="h-24"
							placeholder="https://app.example.com, https://*.example.com, *"
							value={localValues.allowed_origins}
							onChange={(e) => handleAllowedOriginsChange(e.target.value)}
						/>
					</div>
				</div>
				{/* Allowed Headers */}
				<div>
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="allowed-headers" className="text-sm font-medium">
								Allowed Headers
							</label>
							<p className="text-muted-foreground text-sm">Comma-separated list of allowed headers for CORS.</p>
						</div>
						<Textarea
							id="allowed-headers"
							className="h-24"
							placeholder="X-Stainless-Timeout"
							value={localValues.allowed_headers}
							onChange={(e) => handleAllowedHeadersChange(e.target.value)}
						/>
					</div>
				</div>
				{/* Required Headers */}
				<div>
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="required-headers" className="text-sm font-medium">
								Required Headers
							</label>
							<p className="text-muted-foreground text-sm">
								Comma-separated list of headers that must be present on every request. Requests missing any of these headers will be
								rejected with a 400 error. Header names are case-insensitive.
							</p>
						</div>
						<Textarea
							id="required-headers"
							data-testid="required-headers-textarea"
							className="h-24"
							placeholder="X-Tenant-ID, X-Custom-Header"
							value={localValues.required_headers}
							onChange={(e) => handleRequiredHeadersChange(e.target.value)}
						/>
					</div>
				</div>
				{/* Whitelisted Routes */}
				<div>
					<div className="space-y-2 rounded-sm border p-4">
						<div className="space-y-0.5">
							<label htmlFor="whitelisted-routes" className="text-sm font-medium">
								Whitelisted Routes
							</label>
							<p className="text-muted-foreground text-sm">
								Comma-separated list of routes that bypass the auth middleware. Requests to these routes will not require authentication.
								System routes like <b>/health</b>, <b>/api/session/login</b>, and <b>/api/session/is-auth-enabled</b> are always whitelisted
								regardless of this setting.
							</p>
						</div>
						<Textarea
							id="whitelisted-routes"
							data-testid="whitelisted-routes-textarea"
							className="h-24"
							placeholder="/api/custom-webhook, /api/public-endpoint"
							value={localValues.whitelisted_routes}
							onChange={(e) => handleWhitelistedRoutesChange(e.target.value)}
						/>
					</div>
				</div>
			</div>
			<div className="bg-card sticky bottom-0 flex justify-end py-2">
				<Button onClick={handleSave} disabled={!hasChanges || isLoading || !hasSettingsUpdateAccess} data-testid="security-save-btn">
					{isLoading ? "Saving..." : "Save Changes"}
				</Button>
			</div>
		</div>
	);
}

const RestartWarning = () => {
	return (
		<Alert variant="destructive" className="mt-2">
			<AlertTriangle className="h-4 w-4" />
			<AlertDescription>Need to restart Bifrost to apply changes.</AlertDescription>
		</Alert>
	);
};