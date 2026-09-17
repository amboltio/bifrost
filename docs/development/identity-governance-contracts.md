# Identity and governance contracts

This document fixes the public contracts used by the local-authentication, OIDC,
RBAC, organization, access-profile and project work. A configuration field in
`transports/config.schema.json` is not evidence that its management page or
runtime behavior is available. The dashboard reads
`GET /api/session/is-auth-enabled` and only shows a new section when its
`identity_capabilities` value is true.

## Authentication configuration

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
          "issuer_url": "https://login.microsoftonline.com/<tenant>/v2.0",
          "client_id": "env.BIFROST_ENTRA_CLIENT_ID",
          "client_secret": "env.BIFROST_ENTRA_CLIENT_SECRET"
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

## Existing schema inventory

`scim_config` remains an existing declarative directory-client contract. It is
not an authorization signal and does not enable an inbound SCIM server in this
release. Its provider-specific validation remains in the schema tests; directory
reconciliation is introduced only with the sourced-membership implementation.

The existing `governance.roles`, `governance.access_profiles` and
`governance.projects` schema blocks keep their published wire names and ID
types. They are not made available through an OSS management API merely because
they appear in the schema. The later persistence work maps them to canonical
users and protected grants instead of importing Enterprise-only behavior.

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
