# Password management, virtual-key secrecy and quiet UI

## Intent

Implement the four requested features on `codex/account-passwords-key-security`, based on the verified upstream merge `2e64d07f8`. Commit the implemented features on this branch. This feature branch depends on the upstream update in PR #5.

## Passwords

The user explicitly selected an authenticated profile flow requiring the current password. Add a Change password action in the signed-in account menu, with current password, new password and confirmation. Reuse `POST /api/session/change-password` and the existing local authentication service. Wrong current passwords fail, password policy is enforced, all existing sessions are revoked atomically, browser authentication state is cleared and the user signs in again. Ordinary users may only change their own password. OIDC-only accounts manage their upstream password at their identity provider; this feature must not silently create a local login for them.

Add an administrator Reset password action on Users. The proposed UI allows an administrator to enter and confirm a replacement password without the target's current password. The backend enforces `users.reset_password`, the existing canonical actor and target authorization, request-origin checks and the password policy; password replacement, session invalidation, audit and outbox changes must commit atomically. Neither hashes nor passwords are returned or logged. Super-admins may reset every local account, including other super-admins. Delegated user managers retain the existing protection against taking over super-admin accounts. Disabled accounts remain disabled after a reset; the reset does not reactivate them. Forgotten-password email delivery is outside this request.

The existing reset endpoint issues recovery tokens rather than setting a password. Preserve existing recovery callers and introduce an explicit password-setting endpoint or an unambiguous request variant rather than silently changing that contract.

## Virtual keys

The full secret is returned only by explicit creation and rotation operations, once per issuance. A newly rotated key counts as a newly issued key. List, detail, update, quota, nested management responses, config exports and management errors must never disclose a complete virtual key or its raw secret reference. Audit/log responses must not become an alternative retrieval path. Inspect every reachable serialization surface rather than hiding text only in React.

Subsequent UI-facing responses carry a separate display prefix of at most the first 10 characters; a short secret must not be returned in full. Do not use the prefix as an authenticatable key. Copy response DTOs without mutating shared store/governance objects. Never alter internal inference credentials while redacting a response.

Keys are visually hidden by default. Revealing an existing key shows only its prefix; there is no full-key reveal or copy action. Creation and rotation use a transient, initially hidden one-time secret dialog with explicit reveal/copy. Clear its secret when closed and avoid storing it in persistent browser storage or normal entity-query caches. Existing picker and edit flows must work with redacted keys and must not submit a prefix or mask as a replacement credential.

Existing prompt/playground selectors and MCP usage snippets currently consume full stored keys. Replace generated snippet secrets with placeholders. For running a request that needs a virtual-key secret, require a credential explicitly supplied by the caller rather than retrieving the stored secret into the browser. Never silently send a prefix as an x-bf-vk credential, and do not introduce a server-side key-ID impersonation bypass as part of this feature.

Use the existing rotation manager and endpoint. Rotation invalidates the previous value and issues a fresh value while retaining the logical key ID, settings, ownership, provider/model/MCP/agent/relay grants, budgets, rate limits and accumulated usage. Add the Rotate action wherever the user manages a key, under the existing mutation permission. Protect concurrent rotations and partial database/reload failures; do not claim revocation succeeded if the old key is still accepted. Do not implement rotation by deleting/recreating governance settings.

## Quiet UI

Remove release announcements and promotional/help-sales cards such as the new-release sidebar card and production-setup promotion, including fetches and persistence used only for those promotions. Remove upstream product-news presentation that would recreate these announcements. Preserve actionable restart/setup/security messages, background-job progress, operational warnings and normal action success/error feedback. Do not hide failures by removing the notification center wholesale.

## Verification and implementation boundaries

Use existing Go/React/RTK Query/Zod components, existing test files and the canonical Users administration surface. No new dependency is needed. Cover permission boundaries, current-password checks, session revocation, prefix-only serialization on all management surfaces, one-time issuance, rotation preserving settings and invalidating old secrets, and promotional UI removal. Add meaningful browser E2E coverage with data-testid attributes and provider-harness regression cases for wire-visible changes. Run local Go tests, targeted UI tests, TypeScript and the production UI build. Do not run paid live provider APIs or deploy.

Measure any newly changed request-path behavior with existing-file benchmarks and `-benchmem`; ordinary inference requests must not acquire new allocation or redaction work. Name retained memory bounds: issued secrets exist only in a short-lived response/dialog; no new server-side credential cache is proposed.

## Proposed implementation decisions for review

1. Administrator reset means entering a new local password directly, rather than handing out a raw recovery token.
2. Rotation may disclose the newly issued value once; no later endpoint may retrieve it.
3. Preserve super-admin protection against delegated user managers and preserve actionable operational notices.
4. No self-service email recovery or OIDC password management.
