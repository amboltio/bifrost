# Identity and governance contracts

This document fixes the public contracts used by the local-authentication, OIDC,
RBAC, organization, access-profile and project work. A configuration field in
`transports/config.schema.json` is not evidence that its management page or
runtime behavior is available. The dashboard reads
`GET /api/session/is-auth-enabled` and only shows a new section when its
`identity_capabilities` value is true.

## Authentication configuration

### Password management and virtual-key secrecy

- `POST /api/session/change-password` accepts `current_password` and
  `new_password` for the authenticated canonical account. It requires an active
  local credential and local login to be enabled. A wrong current password is
  a `400`; successful replacement revokes all of the user's sessions and clears
  the session cookie, so the user signs in again.
- `POST /api/governance/users/{id}/password` accepts `new_password` and
  `confirm_password`. It requires `users.reset_password`; delegated managers
  cannot reset super-admins. Super-admins may reset other super-admins.
  Replacement, auth-version change, session/recovery-token revocation, audit and
  outbox commit together. A disabled account stays disabled. Accounts without
  an active local credential return `409`; no local login is created for an
  OIDC-only account. The existing `/reset-password` endpoint still issues a
  recovery token and retains its prior contract.
- `GET /api/session/current-user` includes `has_local_password`,
  `is_super_admin` and `can_reset_password` for account controls. These controls
  do not depend on access to the privileged `/api/config` endpoint.
- Management virtual-key DTOs now return an empty `value` and a separate
  `value_prefix` of at most ten characters. A short secret is never disclosed in
  full. This applies to nested entities, configuration exports and credential
  headers in log previews. Exports contain settings, not reusable credentials.
- Creation and single rotation return `issued_secret` once; bulk rotation
  returns `issued_secrets` entries with `id`, `name` and `secret`. Issuance
  responses use `Cache-Control: no-store`. Clients must save the secret at that
  moment; subsequent reads and updates cannot retrieve it. The dashboard keeps
  these values only in a transient, initially hidden dialog and immediately
  clears mutation results from RTK Query state.
- Manual rotation keeps the same logical key, grants, settings and usage while
  immediately invalidating the retired credential, regardless of the scheduled
  rotation grace setting. Persistence uses a credential-only compare-and-swap;
  installation rejects older database snapshots. Vault-backed rotations use
  separate paths per issuance so a rollback cannot overwrite the live secret.
  Failed-issuance and retired-owned-reference cleanup is best effort, bounded to
  five seconds and logged on failure. External Vault references are not removed.
- Playground selectors use key IDs for filtering. Requests require a key the
  caller explicitly supplies; generated MCP snippets use a placeholder. The
  server does not exchange a selected key ID for a secret on the caller's behalf.

Release/promotional cards and product-news fetching are removed from the
dashboard. Operational warnings, setup/restart messages and job progress remain.

### Configuration format

`governance.auth_config` is the canonical configuration location. The historic
top-level `auth_config` alias remains accepted while existing deployments move;
when both are present they must be equivalent after defaults are applied.

```json
{
  "governance": {
    "auth_config": {
      "is_enabled": true,
      "local_login": {
        "is_enabled": true,
        "session_ttl_seconds": 43200,
        "idle_timeout_seconds": 1800,
        "allow_registration": false
      },
      "oidc_providers": [
        {
          "id": "entra",
          "display_name": "Microsoft Entra ID",
          "type": "entra",
          "issuer_url": "https://login.microsoftonline.com/<tenant>/v2.0",
          "client_id": "env.BIFROST_ENTRA_CLIENT_ID",
          "client_secret": "env.BIFROST_ENTRA_CLIENT_SECRET",
          "allowed_audiences": ["api://bifrost"],
          "claim_mappings": {
            "email": "email",
            "email_verified": "email_verified",
            "name": "name",
            "groups": "groups",
            "roles": "roles"
          }
        }
      ]
    }
  }
}
```

The usable modes are local only, OIDC only, or both. `allow_registration` is
always `false`; administrators provision users. A configured OIDC provider has
a stable `id`, an HTTPS issuer, display name, client ID and client secret.
Client secrets are redacted from management responses. OIDC configuration is
file-owned until the encrypted provider store is delivered; it must not be
persisted through the legacy three-row admin-auth store.

The local-session defaults are a 12-hour absolute lifetime and a 30-minute idle
timeout. A configured idle timeout may not exceed the absolute lifetime.

`oidc_providers[].type` accepts `generic`, `okta`, `entra`, `keycloak`,
`zitadel`, `google_workspace`, and `auth0`. These named presets use the same
discovery, PKCE, issuer, signature, nonce, expiration, and audience validation
engine. The client ID is always an accepted audience; `allowed_audiences` adds
resource audiences used by providers that issue tokens for more than one API.

The runtime uses standard `email`, `email_verified`, and `name` claims by
default. `claim_mappings` accepts dot-notated paths for providers that nest
identity claims (for example `profile.email`). `groups` and `roles` are
returned in claims-preview metadata for future authorization mapping; they do
not grant permissions by themselves.

## Existing schema inventory

`scim_config` remains an existing declarative directory-client contract. It is
not an authorization signal and does not enable an inbound SCIM server in this
release. Its provider-specific validation remains in the schema tests; directory
reconciliation is introduced only with the sourced-membership implementation.

The existing `governance.roles`, `governance.access_profiles` and
`governance.projects` schema blocks keep their published wire names and ID
types. Access-profile CRUD plus direct user and role assignments are available
through the OSS governance API. The current profile runtime supports additive
provider/model/MCP-tool grants and provider-specific model allowlists,
model-denylists and exact provider key IDs. An empty provider key-ID list
denies every key for that provider. Legacy profiles without `provider_configs`
keep the prior all-keys behavior for listed providers. Schema-defined profile
budgets, rate limits, model budget groups, virtual-MCP associations and
mandatory caps are not applied by this partial runtime and must not be treated
as active policy.

## Credential matrix

| Credential | Authenticates | Grants management access | Grants inference access | Attribution |
| --- | --- | --- | --- | --- |
| Browser session | A canonical user | Yes, through the user’s roles | Only with a resolved user/key grant | Canonical user and session |
| Local password | A canonical user during login | No by itself | No by itself | Login event only |
| OIDC identity | A canonical user during login | No by itself | No by itself | Validated issuer and subject |
| Provider API key | An upstream provider request | No | No without a Bifrost credential | Provider key only |
| Bifrost API key | A configured service principal | Only when explicitly mapped to a principal | As granted | Service/key identity |
| Virtual key | A virtual-key principal | No | As granted | Virtual key; never an inferred user |
| MCP-issued credential | Its explicit holder | No | Only through its explicit grant | Credential holder |

Caller-controlled identity headers never establish a user. A shared key assigned
to several people retains key attribution unless another verified credential
identifies the person.

## Permission and ownership contract

Permissions have `(resource, operation, scope)` shape. Grants union only for
the same resource and operation. Mandatory organization or platform
restrictions intersect after additive grants are combined.

| Resource | Operations | Own-data rule |
| --- | --- | --- |
| Users | Read, Create, Update, Disable, Assign | The user’s own profile |
| Roles and assignments | Read, Create, Update, Assign | No implicit own-data scope |
| Teams, customers and business units | Read, Create, Update, Assign | Membership and explicitly visible hierarchy rows |
| Access profiles | Read, Create, Update, Assign | Profiles assigned to the caller |
| Virtual keys | Read, Create, Update, Reveal, Assign | Key owner or explicit assignment |
| Projects | Read, Create, Update, Assign, Execute | Membership, owner and project-scoped request access |
| Inference logs and analytics | Read, Export | Attributed user and visible dimensions |
| Audit events | Read | No own-data expansion without explicit audit permission |

Only `super_admin` is a permanent authorization bypass. The request boundary
installs an authorization scope before SQL filtering, counts, aggregates,
exports and lookup lists; an authenticated request with no scope fails closed.

## Configuration ownership

Configuration loaded from `config.json` is declarative and may be synchronized
on startup. Management APIs own mutable assignments, user credentials, sessions,
audit records and accounting state. A file-declared object does not overwrite
those operational records. Source-owned directory assignments can only be
removed by a complete successful source snapshot.

Project wire values remain stable:

| Field | Values |
| --- | --- |
| `access_rule` | `intersect`, `union` |
| `accounting_mode` | `both`, `project_only`, `principal_only` |
| `is_active` | boolean |

When both `x-bf-project-id` and a project name are supplied, the presence of
the ID wins even if it is empty. An empty or invalid selected ID fails the
request; it does not fall back to a name or unscoped execution.

## Endpoint contracts

The following endpoint shapes are fixed before the corresponding handlers are
implemented. They are protected by the permissions above and return no password
hashes, reset tokens, raw sessions or OIDC tokens.

### Login capability discovery

`GET /api/session/is-auth-enabled`

```json
{
  "is_auth_enabled": true,
  "has_valid_token": false,
  "auth_type": "password",
  "identity_capabilities": {
    "local_users": false,
    "oidc_login": false,
    "organizations": false,
    "roles": false,
    "access_profiles": false,
    "projects": false,
    "user_analytics": false
  }
}
```

`POST /api/session/login` retains the legacy `{ "username", "password" }`
body until canonical-user login is delivered. A wrong credential returns `401`
with the same generic message for unknown users and wrong passwords.

### Access-profile provider rules

`POST /api/governance/access-profiles` and
`PUT /api/governance/access-profiles/{id}` accept `provider_configs` rows with
`provider_name`, `all_models_allowed`, `allowed_models`,
`blacklisted_models` and `key_ids`. Provider names are stored lower-case;
duplicate provider rows are rejected. The UI submits key IDs exactly as shown
in provider configuration. Unsupported fields such as profile budgets and rate
limits, provider weights and model budget groups are rejected instead of being
silently discarded.

### Future canonical-user operations

`POST /api/users` accepts a display name, email and role assignments. It returns
`201` with a user profile and a single-use enrollment token only in the immediate
authorized response. Duplicate normalized email returns `409`; a role outside
the actor’s delegable authority returns `403`.

`POST /api/oidc/:provider-id/login` starts a PKCE transaction and returns a
redirect target. Unknown or disabled providers return `404`. Callback failures
return a generic login error and create an audit event without returning token
or claim contents.

`GET /api/projects` and `GET /api/analytics/users` always apply the caller’s
data scope before pagination and aggregation. A missing authenticated scope
returns `403`, and an unknown project mode returns `400`.
