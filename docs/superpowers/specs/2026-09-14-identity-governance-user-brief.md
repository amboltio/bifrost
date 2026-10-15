Implementation plan: local email/password + Enterprise SSO/IdPs + all governance features
Assumptions

I interpret your request as implementing:

    A multi-user email/password login, not merely retaining the existing single configured admin username/password.

    1.1: Enterprise OAuth 2.0 / OIDC SSO.

    1.4: The documented identity-provider integrations: Okta, Microsoft Entra ID, Keycloak, Zitadel, Google Workspace, Auth0, and generic OIDC.

    All of section 2: users, business units, hierarchical governance, access profiles, projects, RBAC, DAC, virtual-key assignments/auditing, and user-level analytics.

I would implement these as an OSS-native identity and governance subsystem, rather than copying code from the separate bifrost-enterprise repository. The current repository explicitly says that access profiles, SCIM configuration, business units, and several related configuration structures are presently defined outside OSS.
1. Recommended target architecture
1.1 One user identity model, multiple login methods

Do not create separate “local users” and “SSO users” that governance must handle differently. Use one canonical user entity:

User
├── id
├── email
├── display_name
├── status
├── password credential (optional)
├── one or more external identities (optional)
├── roles
├── teams
├── business units
├── access profiles
├── virtual keys
└── projects

Authentication methods then resolve to the same user.id:

Email/password ──────────┐
OIDC / Okta ─────────────┤
OIDC / Entra ────────────┤
OIDC / Keycloak ─────────┼──> canonical User ──> RBAC + DAC + governance
OIDC / Zitadel ──────────┤
OIDC / Google ───────────┤
OIDC / Auth0 ────────────┤
Generic OIDC ────────────┘

This avoids duplicating authorization logic and ensures that a user receives the same teams, limits, access profiles, and projects regardless of how they authenticate.
1.2 Authentication and authorization must be separate

Use three explicit stages:

    Authentication: Who is making the request?

    Authorization: May this user perform the requested operation?

    Governance: Which providers, models, MCP tools, budgets, and rate limits apply?

The desired request pipeline should become:

Request
  → authenticate session/API credential
  → resolve canonical user
  → load roles and permissions
  → enforce RBAC operation
  → resolve DAC visibility scope
  → resolve governance grant
      → direct user policy
      → access profiles
      → teams
      → business units
      → customers
      → virtual key
      → project
  → intersect access restrictions
  → select accounting targets
  → execute request
  → update usage
  → write access/audit event

1.3 Reuse the existing session transport

The repository already has:

    /api/session/login.

    /api/session/logout.

    /api/session/is-auth-enabled.

    Database-backed opaque session tokens.

    HTTP-only cookies.

    WebSocket session tickets.

Those routes are registered in the existing session handler.
Login currently checks one configured admin username and password, creates a random 30-day session, and puts it in an HTTP-only cookie.

The safest migration is therefore to evolve the existing session mechanism, not introduce an unrelated JWT stack for the dashboard.
2. Phase 0 — design and compatibility decisions

Before writing migrations, make the following decisions explicit.
2.1 Authentication mode

Support a configuration like:

{
  "auth_config": {
    "enabled": true,
    "local_login": {
      "enabled": true,
      "allow_registration": false,
      "session_ttl": "12h"
    },
    "oidc": {
      "enabled": true
    }
  }
}

Allow three modes:

    Local login only.

    SSO only.

    Local login and SSO together.

For security, self-registration should default to false. Administrators should create or invite local users.
2.2 Legacy admin migration

The existing configured admin must remain usable during migration.

Recommended behavior:

    On first startup after the migration, detect the legacy configured admin credential.

    Create a canonical local user with the built-in super-admin role.

    Copy the existing password hash without needing the plaintext password.

    Mark the migration complete.

    Keep a one-release compatibility fallback.

    Remove legacy credential authentication in the next major version.

The current authentication logic uses encrypt.CompareHash against the stored admin password.
2.3 Identity-linking rules

Use strict defaults:

    Normalize email to trimmed lowercase for comparison.

    Never automatically merge accounts solely because two IdPs return the same email unless the email is verified.

    Prefer immutable OIDC identity (issuer, subject) over email.

    Permit administrators to link or unlink identities.

    Refuse automatic linking if an existing identity conflicts.

    Keep an audit trail for account linking.

    Do not allow the final login method for the final super-admin to be removed.

2.4 Governance conflict semantics

Define these before implementing the resolver:

    Permissions: union of permissions from assigned roles.

    DAC: most permissive applicable scope, unless policy requires role-specific restrictions.

    Provider/model/MCP access: intersection of all mandatory restrictions.

    Budgets/rate limits: enforce every applicable limit; the tightest remaining limit naturally wins.

    Explicit deny: deny wins over allow.

    Disabled or expired entity: fail closed.

    Project restrict: intersect project access with caller access.

    Project extend: add project-granted access, but never bypass platform safety restrictions.

    Accounting: update all configured ledgers atomically or fail the request.

3. Phase 1 — canonical user and credential data model
3.1 Add identity tables

Create tables under framework/configstore/tables/:
users

id
email_normalized       unique
email_display
display_name
status                 invited | active | suspended | disabled
email_verified
created_by
created_at
updated_at
last_login_at

local_credentials

user_id                unique FK
password_hash
password_changed_at
failed_attempts
locked_until
must_change_password
created_at
updated_at

Keep password hashes separate from user profile data so APIs cannot accidentally serialize them.
external_identities

id
user_id
provider_id
issuer
subject
email_at_provider
claims_snapshot        optional, sanitized
last_login_at
created_at
updated_at

UNIQUE(issuer, subject)

user_sessions

Extend or replace the current generic session row with:

token_hash
user_id
auth_method            password | oidc
provider_id            nullable
created_at
expires_at
last_seen_at
revoked_at
ip_hash                 optional
user_agent              optional

Do not continue storing session bearer tokens in plaintext. Store a SHA-256/HMAC digest and send the raw random token only to the client.
3.2 Database support

Implement migrations for both OSS-supported config stores:

    SQLite.

    PostgreSQL.

Repository conventions currently expose table models and config-store interfaces under framework/configstore. Existing session storage is represented by the sessions table.
3.3 Config-store interfaces

Add focused interfaces rather than one giant identity store:

type UserStore interface { ... }
type CredentialStore interface { ... }
type IdentityProviderStore interface { ... }
type SessionStore interface { ... }
type MembershipStore interface { ... }
type RBACStore interface { ... }
type GovernanceAssignmentStore interface { ... }

Required operations include:

    Get user by ID.

    Get user by normalized email.

    Create/update/disable user.

    Verify atomic uniqueness.

    Get credential hash.

    Update failure counters.

    Create/revoke/rotate session.

    Revoke every session for a user.

    Link and unlink an external identity.

    Resolve user by (issuer, subject).

3.4 Password hashing

Use a dedicated password package with:

    Argon2id as the recommended default.

    Unique random salt per password.

    A versioned encoded hash containing algorithm parameters.

    Constant-time verification.

    Rehash-on-login when parameters change.

If retaining the existing hash format for compatibility, implement:

verify existing hash
→ if valid and legacy format
→ write new Argon2id hash
→ continue login

Never encrypt reversible passwords.
4. Phase 2 — local email/password authentication
4.1 Replace username login with email login

Evolve the request from:

{
  "username": "...",
  "password": "..."
}

to:

{
  "email": "person@example.com",
  "password": "..."
}

For one compatibility release, accept either email or legacy username.

The frontend API currently types the login request as username and password.
The OSS login page also currently presents a username field.
4.2 Local-auth endpoints

Implement:

POST   /api/session/login
POST   /api/session/logout
GET    /api/session
GET    /api/session/is-auth-enabled
POST   /api/session/change-password
POST   /api/session/logout-all

Administrative user endpoints:

GET    /api/governance/users
POST   /api/governance/users
GET    /api/governance/users/{id}
PUT    /api/governance/users/{id}
DELETE /api/governance/users/{id}
POST   /api/governance/users/{id}/reset-password
POST   /api/governance/users/{id}/revoke-sessions

Initially, “delete user” should soft-disable rather than physically delete because logs and audit events need stable attribution.
4.3 Password security

Implement:

    Minimum length of at least 12 characters.

    Maximum accepted input length to prevent hashing DoS.

    No composition rules such as forced symbols.

    Common-password screening.

    Per-account rate limiting.

    Per-IP rate limiting.

    Exponential delay or temporary lockout.

    Generic login failure message.

    Session rotation on successful authentication.

    Session revocation after password change.

    Secure, HTTP-only, same-site cookies.

    Configurable session lifetime.

    CSRF protection for cookie-authenticated state changes.

The existing cookie is HTTP-only and SameSite Lax, and conditionally receives Secure from X-Forwarded-Proto.
Preserve those controls, but centralize proxy-awareness and cookie construction so every authentication path behaves consistently.
4.4 Account recovery

For the first simple release, avoid requiring an email-delivery system:

    Admin-initiated password reset.

    One-time reset token shown or securely delivered by the operator.

    Forced password change on next login.

Add self-service “forgot password” only when SMTP/provider configuration is ready. Do not create a fake recovery UI that cannot securely deliver tokens.
4.5 Bootstrap flow

Retain the repository’s setup-token concept:

    If there are no users, require a setup token.

    Create the first local user.

    Assign the immutable built-in super-admin role.

    Invalidate the setup token.

    Prevent setup endpoints once initialization is complete.

5. Phase 3 — session identity middleware
5.1 Unified principal

Introduce a small immutable principal:

type Principal struct {
    UserID       string
    Email        string
    DisplayName  string
    AuthMethod   string
    ProviderID   *string
    SessionID    string
    IsLocalAdmin bool // transitional only
}

Store only small identity values or a small principal pointer in BifrostContext; do not store complete memberships, permissions, or growing policy data there.

Populate the existing user context keys so downstream code can reuse them:

    BifrostContextKeyUserID.

    BifrostContextKeyUserName.

    BifrostContextKeyUserEmail.

The core schema already reserves these keys for Enterprise authentication middleware.
5.2 Authentication middleware

The middleware should:

    Read the opaque session cookie or bearer session.

    Hash the supplied token.

    Load the session.

    Check expiry and revocation.

    Load the user.

    Reject suspended/disabled users.

    Set the canonical principal/context values.

    Update last_seen_at asynchronously with throttling.

    Continue into RBAC middleware.

5.3 Session lifecycle

Implement:

    Sliding activity timestamp without silently extending the hard expiry.

    Absolute maximum lifetime.

    Rotation following login and privilege changes.

    Global logout.

    Per-device/session revocation.

    Cleanup job for expired/revoked sessions.

    WebSocket ticket binding to the authenticated user/session.

The existing WebSocket ticket endpoint already expects authentication middleware to put the session token on the request context.
6. Phase 4 — OIDC foundation

Implement generic OIDC first. Provider-specific integrations should mostly be presets and claim adapters over this common engine.
6.1 OIDC provider model

Add:

identity_providers
├── id
├── name
├── type
├── enabled
├── issuer_url
├── client_id
├── encrypted client_secret reference
├── scopes
├── discovery_url
├── authorization_endpoint
├── token_endpoint
├── userinfo_endpoint
├── jwks_uri
├── allowed_domains
├── claim_mappings
├── provisioning settings
└── timestamps

Secrets must go through existing secret/config encryption abstractions and must never be returned by read APIs.
6.2 OIDC endpoints

GET  /api/auth/providers
GET  /api/auth/oidc/{provider}/login
GET  /api/auth/oidc/{provider}/callback
POST /api/auth/oidc/logout
POST /api/auth/providers/{id}/verify
GET  /api/auth/providers/{id}/claims-preview

Flow:

    Generate cryptographically random state.

    Generate nonce.

    Generate PKCE verifier/challenge.

    Store a short-lived authorization transaction server-side.

    Redirect to the IdP.

    Validate exact state on callback.

    Exchange code with PKCE.

    Validate signature, issuer, audience, expiration, nonce, and authorized-party claims.

    Resolve (issuer, subject).

    Link or provision the canonical user under configured policy.

    Create the same Bifrost session used by local login.

    Redirect only to an allow-listed local return path.

6.3 Login UI

Render:

    Email/password form when local login is enabled.

    One button per enabled OIDC provider.

    “Use another method” affordance when both modes are enabled.

    Provider-specific icon and label.

    Clear but non-sensitive error states.

    Restart/configuration warning where required.

The frontend already anticipates auth_type values of "sso", "password", or "none".
Extend that response to expose multiple allowed methods instead of forcing one exclusive value:

{
  "is_auth_enabled": true,
  "has_valid_token": false,
  "auth_methods": ["password", "oidc"],
  "providers": [
    {"id": "entra-main", "name": "Sign in with Microsoft"}
  ]
}

7. Phase 5 — provider integrations from item 1.4
7.1 Generic OIDC

Make generic OIDC the base implementation:

    Discovery through /.well-known/openid-configuration.

    Configurable scopes.

    Configurable username/email/name/group claims.

    Configurable allowed audiences.

    Optional userinfo call.

    Optional allowed-email-domain rules.

    Configurable role/team/business-unit/access-profile mappings.

7.2 Okta

Add presets and extensions for:

    Org and custom authorization servers.

    Okta group claims.

    Group-to-role mapping.

    Optional Okta API token for directory synchronization.

    Paginated user/group import.

    Deactivation reconciliation.

7.3 Microsoft Entra ID

Add:

    Tenant-specific issuers.

    v1 and v2 token shapes.

    App roles.

    Group claims.

    Group overage handling through Microsoft Graph.

    GCC High and DoD endpoints.

    Client-secret or workload-identity-compatible directory access.

    Microsoft Graph pagination and throttling support.

7.4 Keycloak

Add:

    Realm discovery.

    Realm roles.

    Client roles.

    Group paths.

    Admin REST API synchronization.

    Service-account credentials.

    Self-hosted TLS/issuer validation controls without unsafe global TLS bypasses.

7.5 Zitadel

Add:

    Project-scoped roles.

    Organization/project identifiers.

    Audience handling.

    Service-account-based provisioning.

    Zitadel-specific role-claim normalization.

7.6 Google Workspace

Add:

    Google OIDC login.

    Hosted-domain validation.

    Directory API synchronization.

    Service accounts and domain-wide delegation.

    Application Default Credentials where available.

    Group membership retrieval.

    Workspace user suspension/deactivation handling.

7.7 Auth0

Add:

    Auth0 tenant/domain discovery.

    Namespaced custom claims.

    Organization support.

    Role/permission/group claim adapters.

    Optional Management API sync.

7.8 Shared provider test contract

Every adapter must pass the same conformance suite:

    Discovery.

    Login redirect.

    Callback validation.

    Invalid state.

    Invalid nonce.

    Wrong issuer/audience.

    Expired token.

    Missing email.

    Unverified email.

    Existing identity login.

    Safe account linking.

    JIT provisioning.

    Disabled user.

    Group/role mapping.

    Logout.

    Refresh/session-expiry behavior.

The documented target behavior includes SSO, automatic role assignment, teams, business units, access profiles, background reconciliation, and inbound lifecycle changes.
8. Phase 6 — RBAC

RBAC should land before exposing general multi-user administration.
8.1 Data model

roles
├── id
├── name
├── description
├── is_system
├── immutable
├── default_dac_scope
└── timestamps

permissions
├── id
├── resource
└── operation

role_permissions
├── role_id
└── permission_id

user_roles
├── user_id
├── role_id
├── source             manual | oidc | scim
├── source_provider_id
└── timestamps

8.2 Resources and operations

Start with:

Resources:
Users, Roles, Teams, Customers, BusinessUnits,
VirtualKeys, APIKeys, AccessProfiles, Projects,
Providers, RoutingRules, ModelLimits,
Logs, MCPLogs, AuditLogs,
MCPGateway, VirtualMCPs,
PromptRepository, GuardrailsConfig, SystemConfig

Operations:
View, Create, Update, Delete, Download, Execute, Assign

Keep resource and operation names centralized so the API, UI, migrations, docs, and tests do not drift.
8.3 Built-in roles

Suggested defaults:

    super_admin.

    admin.

    security_admin.

    governance_admin.

    operator.

    auditor.

    viewer.

    user.

System roles should be seeded and versioned. super_admin must not be deletable, and the system must always retain at least one active super-admin user.
8.4 Enforcement

Add route metadata or typed middleware:

RequirePermission(ResourceUsers, OperationView)
RequirePermission(ResourceUsers, OperationCreate)

Do not scatter string comparisons throughout handlers.

Enforce authorization on the backend even when the UI hides controls. The UI should consume a current-user permission endpoint only for presentation.
8.5 RBAC endpoints

GET    /api/governance/roles
POST   /api/governance/roles
GET    /api/governance/roles/{id}
PUT    /api/governance/roles/{id}
DELETE /api/governance/roles/{id}

GET    /api/governance/roles/{id}/permissions
PUT    /api/governance/roles/{id}/permissions

GET    /api/governance/rbac/resources
GET    /api/governance/rbac/operations
GET    /api/governance/rbac/permissions
GET    /api/session/me/permissions

9. Phase 7 — Data Access Control

RBAC answers “may view users?” DAC answers “which users may be viewed?”
9.1 DAC model

Support:

    own-data.

    team-data.

    all-data.

Also support per-resource overrides:

{
  "dac": "own-data",
  "entity_dac": {
    "Logs": "team-data",
    "Projects": "all-data"
  }
}

The target behavior is documented as row-level own/team/all visibility.
9.2 Query-scoping service

Create one service responsible for producing typed scopes:

type DataScope struct {
    Level           DACLevel
    UserID          string
    TeamIDs         []string
    BusinessUnitIDs []string
    CustomerIDs     []string
}

Handlers must not manually reconstruct membership rules. Each config-store list/get/update/delete method that handles a protected entity must accept or apply a DataScope.
9.3 Fail-closed rules

    Unknown scope: deny.

    Missing user identity: deny protected data.

    Team-data with no team memberships: behave like own-data, not all-data.

    A user must not update or delete a row they cannot view.

    Counts, aggregations, exports, autocomplete results, and CSV downloads must apply the same scope.

    IDs supplied directly in URLs must be scoped; list filtering alone is insufficient.

9.4 Coverage tests

For every protected resource, test:

    List.

    Get by ID.

    Create attribution.

    Update.

    Delete.

    Count.

    Search.

    Export.

    Nested child collection.

    Analytics aggregation.

10. Phase 8 — users, teams, business units, and customers
10.1 User administration

Implement:

    List/search/filter users.

    Invite/create local users.

    Create SSO-only users.

    Suspend/activate users.

    Assign roles.

    Assign multiple teams.

    Assign business units.

    Assign access profiles.

    Assign virtual keys.

    View resolved access and effective limits.

    Revoke sessions.

    Inspect identity sources.

10.2 Team memberships

Add many-to-many membership unless product requirements require one primary team:

user_teams
├── user_id
├── team_id
├── source
├── provider_id
└── timestamps

Preserve provenance so a directory sync removes only its own assignments and does not erase manual assignments.
10.3 Business units

Add:

business_units
├── id
├── name
├── description
├── customer_id nullable
├── created_by
└── timestamps

user_business_units
team_business_units
business_unit_customers

The current OSS schema-sync checks explicitly recognize business units and team-to-business-unit association as Enterprise-only gaps.
10.4 Hierarchy rules

Choose and enforce one clearly documented ownership structure. Recommended:

Customer
  └── Business units
       └── Teams
            └── Users

But allow many-to-many user/team membership. If teams can belong to several business units or customers, document how budgets are charged to avoid accidental duplicate accounting.
10.5 Identity-sync ownership

Every assignment should carry a source:

    manual.

    local.

    oidc_claim.

    directory_sync.

    Later: scim.

A sync must reconcile only assignments owned by its source/provider. It must not delete manual administrator choices.
11. Phase 9 — access profiles
11.1 Model

access_profiles
├── id
├── name
├── description
├── enabled
├── allow_all_providers
├── created_by
└── timestamps

access_profile_providers
access_profile_models
access_profile_key_grants
access_profile_budgets
access_profile_rate_limits
access_profile_mcp_configs
access_profile_virtual_mcps
user_access_profiles
role_access_profiles

The documented goal is reusable provider, model, budget, rate-limit, and MCP policy with automatic virtual-key allocation.
11.2 Effective-policy resolver

Build an immutable per-request result:

type EffectiveAccess struct {
    AllowedProviders ...
    AllowedModels ...
    AllowedKeyIDs ...
    AllowedMCPTools ...
    ApplicableBudgets ...
    ApplicableRateLimits ...
    AccountingTargets ...
    ResolutionTrace ...
}

ResolutionTrace is important for the UI’s “Why does this user have/lose access?” view, but it should be stored in a bounded manager or returned on demand—not accumulated in request context.
11.3 Virtual-key strategy

The current Enterprise description says profiles can automatically allocate virtual keys. There are two approaches:

    Physically clone/materialize a managed virtual key per user/profile.

    Treat the access profile as a native permit holder.

For a clean OSS implementation, I recommend native permit holders, while generating a virtual key only when an external client explicitly needs one. This avoids profile updates requiring mass rewrites of thousands of cloned keys.

The current governance package already contains abstractions and tests referring to permit holders beyond virtual keys, which should be extended rather than bypassed.
11.4 Access-profile endpoints

GET/POST          /api/governance/access-profiles
GET/PUT/DELETE    /api/governance/access-profiles/{id}
GET/POST/DELETE   /api/governance/access-profiles/{id}/users
GET               /api/governance/users/{id}/access-profiles
GET               /api/governance/users/{id}/effective-access

12. Phase 10 — projects

Projects are the most complicated governance component and should follow users, RBAC, DAC, and access profiles.
12.1 Model

projects
├── id
├── name
├── description
├── enabled
├── expires_at
├── access_rule          restrict | extend
├── membership_mode      explicit | open
├── accounting_mode      both | project_only | user_only
├── split_policy         none | equal
├── calendar_aligned
├── allow_all_providers
├── created_by
└── timestamps

project_members
project_providers
project_models
project_budgets
project_rate_limits
project_member_limits
project_mcp_configs
project_virtual_mcps

12.2 Request selection

Accept exactly one of:

    x-bf-project-id.

    x-bf-project-name.

Resolution must:

    Authenticate the caller.

    Load the project.

    Check enabled/expiry.

    Check open or explicit membership.

    Apply DAC where an administrative request reads the project.

    Compose project access with the caller’s normal access.

    Configure the accounting targets.

    Add project ID/name to logs, traces, metrics, and exports.

The documented project concept is a request-selected access, budget, and reporting scope.
12.3 Atomic accounting

Project and user/team/customer budget updates must be atomic from the point of view of request admission.

Recommended strategy:

    Resolve all applicable counters.

    Lock/update them in deterministic ID order.

    Reject if any limit would be exceeded.

    Commit all reservations.

    Reconcile final token/cost usage after the response.

    Ensure retries/fallbacks do not double-charge final usage.

    Maintain idempotency by request/attempt ID.

12.4 Project analytics

Add project dimensions to:

    Request logs.

    MCP logs.

    Cost analytics.

    Token analytics.

    Latency analytics.

    Prometheus labels.

    OpenTelemetry spans.

    Warehouse exports.

13. Phase 11 — virtual-key assignments and access auditing
13.1 User/key relationship

Add:

user_virtual_keys
├── user_id
├── virtual_key_id
├── source
├── assigned_by
├── created_at
└── revoked_at

Support:

    Attach key to user.

    Detach key from user.

    List users on a key.

    List keys for a user.

    Resolve keys by verified email.

    Mint an additional user key.

    Rotate without losing ownership.

    Disable user access without deleting the key.

13.2 Access audit events

Record:

    Assignment.

    Revocation.

    Key minting.

    Rotation.

    Reveal/copy if the system can reliably observe it.

    Failed access attempt.

    Administrator and target user IDs.

    Before/after relationship.

    Timestamp and request ID.

The OSS hook is currently an explicit no-op because virtual-key access auditing is Enterprise-only.
13.3 Credential presentation

Prefer showing a virtual-key secret once. Store only a secure verification form afterwards wherever feasible. If provider compatibility requires retrieval, encrypt at rest and protect reveal with a separate permission and audit event.
14. Phase 12 — user analytics and rankings
14.1 Attribution

Every authenticated inference request should carry:

    User ID/name.

    Team IDs/names.

    Business-unit IDs/names.

    Customer IDs/names.

    Access-profile IDs.

    Project ID/name.

    Virtual-key ID/name.

Do not put unbounded slices or complete objects into context. Resolve compact IDs and send finalized dimensions to the logging/telemetry managers.
14.2 Queries

Add:

    Spend by user.

    Requests by user.

    Tokens by user.

    Error rate by user.

    Latency by user.

    Provider/model distribution by user.

    User ranking over a time range.

    Filters by team, business unit, customer, access profile, and project.

14.3 DAC enforcement

Rankings must be DAC-aware:

    Own-data users see only themselves.

    Team-data users see eligible teammates.

    All-data users see everyone.

    “Other” or aggregate values must not leak information about hidden users.

The current OSS UI explicitly gates user rankings behind the Enterprise license.
15. Phase 13 — UI implementation
15.1 Replace Enterprise fallbacks progressively

Implement OSS-native views for:

    Login.

    Users.

    Teams/memberships.

    Business units.

    Roles and permissions.

    Data-access scopes.

    Access profiles.

    Projects.

    User details.

    Virtual-key user assignments.

    Effective-access explanation.

    User rankings.

    OIDC provider setup.

The current login route resolves its implementation through the Enterprise alias.
Move the shared implementation into ordinary OSS UI code and use registries only for genuinely optional extensions.
15.2 Preserve load-bearing test IDs

Every new interactive element should receive stable data-testid attributes. Do not rename existing test IDs without updating Playwright references.

Suggested convention:

login-email-input
login-password-input
login-submit-button
login-oidc-provider-<id>

user-create-button
user-role-selector
user-team-selector
user-access-profile-selector

role-permission-<resource>-<operation>
project-create-button
project-member-add-button

15.3 Effective-access UX

For each user, provide an explanation panel:

Provider: OpenAI
  Allowed by: Access Profile "Developer"
  Restricted by: Team "Sandbox"
  Final result: allowed

Model: gpt-4.1
  Allowed by: Project "Evaluation"
  Denied by: Access Profile "Low Cost"
  Final result: denied

Budget:
  User monthly: $47 / $100
  Team monthly: $900 / $1,000
  Project monthly: $120 / $500
  Effective blocker: Team monthly

Without this, support and debugging of layered governance will be difficult.
16. Phase 14 — configuration schema and declarative reconciliation

transports/config.schema.json is the source of truth, so schema changes should precede handler/documentation changes.

Add or stabilize:

auth_config.local_login
auth_config.oidc_providers
governance.users
governance.roles
governance.business_units
governance.access_profiles
governance.projects
governance.user_assignments

For each declarative entity define:

    Stable reconciliation key, preferably name or explicit ID.

    Whether dashboard changes survive config reload.

    Whether omission deletes an existing entity.

    What source_of_truth means.

    How secrets are referenced.

    Whether memberships may be declared.

    How manually assigned and IdP-assigned relationships interact.

Never silently delete manually managed relationships during config reconciliation.
17. Phase 15 — auditability

Even if the full Enterprise audit-log product is not part of the requested section, security-sensitive identity/governance changes require a basic audit trail.

Record:

    Login success/failure.

    Logout.

    Password change/reset.

    Session revocation.

    User creation, suspension, activation, deletion.

    External identity linking.

    Role and permission changes.

    Team/business-unit/customer membership changes.

    Access-profile assignment.

    Project creation/membership/policy changes.

    Virtual-key assignment/revocation.

    DAC changes.

    OIDC provider configuration changes.

Never log:

    Passwords.

    Password hashes.

    Raw session tokens.

    Authorization codes.

    Refresh tokens.

    Client secrets.

    Full ID tokens.

18. Test strategy
18.1 Unit tests

Test independently:

    Email normalization.

    Password hash/verify/upgrade.

    Session token hashing.

    Session expiration and revocation.

    OIDC state, nonce, PKCE, and claim validation.

    External identity linking.

    Claim-to-role/team/BU/profile mapping.

    RBAC permission union.

    DAC scope resolution.

    Access-profile intersection.

    Project restrict/extend semantics.

    Budget composition.

    Membership source reconciliation.

18.2 Integration tests

Use mock OIDC servers—never live IdPs in the standard suite.

Test:

    Local login to protected endpoint.

    OIDC redirect and callback.

    Mixed password/SSO mode.

    Disabled user rejection.

    Session revocation.

    Role update effective on next request.

    DAC applied to get/list/count/export.

    User access profile changes inference permissions.

    Project header modifies access and accounting.

    Virtual-key user ownership.

    Identity sync does not erase manual assignments.

18.3 Security tests

Include:

    Session fixation.

    CSRF.

    Open redirects.

    OIDC state replay.

    OIDC nonce replay.

    Wrong issuer/audience.

    Algorithm confusion and unsigned JWT.

    Duplicate-email linking attacks.

    Timing-safe password failure.

    Brute-force throttling.

    IDOR against user/team/project endpoints.

    DAC bypass through counts and nested routes.

    Privilege escalation through role editing.

    Last-super-admin removal.

    Disabled-user session reuse.

    Stale permission cache after revocation.

18.4 Race and cluster behavior

Even if clustering remains separate, test concurrent:

    Membership changes during inference.

    Password reset during active requests.

    Session revocation.

    Access-profile replacement.

    Project member addition/removal.

    Budget reservation/update.

    Cache invalidation.

Use go test -race for the affected modules.
19. Recommended delivery sequence
Milestone A — local multi-user foundation

Deliver:

    Canonical users.

    Local credentials.

    Secure sessions.

    Bootstrap admin.

    Local email/password login.

    User CRUD.

    Minimal super-admin/admin/viewer roles.

Exit criterion: Two local users can log in independently and receive different permissions.
Milestone B — complete RBAC and DAC

Deliver:

    Custom roles.

    Permission matrix.

    Resource middleware.

    Own/team/all DAC.

    UI permission gating.

    Scoped queries and exports.

Exit criterion: Cross-user and cross-team access tests demonstrate fail-closed isolation.
Milestone C — organization model

Deliver:

    Team memberships.

    Business units.

    Customer relationships.

    User assignment UI.

    Hierarchical governance resolution.

Exit criterion: A user’s organization memberships produce deterministic effective access and accounting targets.
Milestone D — generic OIDC

Deliver:

    Generic discovery.

    Authorization-code flow with PKCE.

    Account linking.

    JIT provisioning.

    Claim mapping.

    Mixed local/SSO login.

Exit criterion: A mock standards-compliant IdP passes the full authentication conformance suite.
Milestone E — named IdP adapters

Deliver in this order:

    Okta.

    Microsoft Entra.

    Keycloak.

    Google Workspace.

    Auth0.

    Zitadel.

Exit criterion: Each adapter passes the common contract and provider-specific claim tests.
Milestone F — access profiles

Deliver:

    CRUD.

    Provider/model/key/MCP policy.

    Budgets/rate limits.

    User and role assignment.

    Effective-access explanation.

Exit criterion: Profile changes take effect without recreating users or manually cloning policy.
Milestone G — projects

Deliver:

    CRUD and membership.

    Header selection.

    Restrict/extend semantics.

    Accounting modes and splitting.

    Log/metric attribution.

Exit criterion: Project-scoped requests enforce access and update the correct ledgers exactly once.
Milestone H — virtual-key/user relationships and analytics

Deliver:

    Key assignment.

    Key access audit.

    User usage dimensions.

    User rankings.

    DAC-aware analytics.

Exit criterion: Usage can be traced from request → user → key → organizational entities → project.
Milestone I — hardening and compatibility

Deliver:

    Legacy admin migration.

    Declarative configuration.

    Performance benchmarks.

    Race tests.

    API documentation.

    End-to-end Playwright coverage.

    Upgrade/rollback migration tests.

20. Rough effort estimate

For one experienced backend engineer plus one frontend engineer:
Workstream	Estimated effort
User, credential, session foundation	2–3 weeks
Local login and bootstrap UX	1–2 weeks
RBAC	2–3 weeks
DAC and scoped-query coverage	3–5 weeks
Teams/business units/hierarchy	2–4 weeks
Generic OIDC	2–3 weeks
Named IdP adapters and sync	5–8 weeks
Access profiles	3–5 weeks
Projects and accounting	5–8 weeks
Virtual-key relationships/auditing	2–3 weeks
User analytics/rankings	2–4 weeks
E2E/security/migration hardening	4–6 weeks

A realistic complete implementation is approximately:

    20–30 engineer-weeks for a functional first version.

    30–45 engineer-weeks for production-grade security, migrations, provider quirks, complete DAC coverage, and polished UI.

With two backend engineers, one frontend engineer, and shared QA/security support, I would plan for approximately 4–6 calendar months. A smaller MVP—local login, generic OIDC, users, basic RBAC, teams, and simple access profiles—could be delivered in approximately 8–12 weeks.
21. Main risks

    DAC omissions: One forgotten count/export/detail endpoint can leak data.

    Account linking: Email-only linking can lead to account takeover.

    IdP inconsistencies: Groups and roles differ substantially across providers.

    Governance precedence: Ambiguous union/intersection rules will create security bugs.

    Budget atomicity: Multiple simultaneous ledgers can double-charge or overspend.

    Cache invalidation: Revoked roles, sessions, or memberships must take effect promptly.

    Legacy migration: Existing single-admin deployments must not become inaccessible.

    SQLite concurrency: Some governance/accounting behavior may need different transactional handling than PostgreSQL.

    Context growth: Membership and policy objects must not be stored as request-sized context values.

    Scope expansion: Full SCIM provisioning is adjacent to SSO but substantially larger; I would keep SCIM out of the first implementation unless you explicitly want it included.
