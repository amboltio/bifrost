# Account and credential security implementation plan

**Goal:** Implement the approved password, virtual-key secrecy/rotation and quiet UI features.
**Spec:** ../specs/2026-10-30-account-passwords-key-security-design.md
**Architecture:** Reuse canonical identity stores and rotation managers; redact HTTP management responses without changing inference credentials; expose newly issued keys only in transient dialogs.
**Tech stack:** Go 1.27.3, React, RTK Query, Zod, Vitest, Playwright.

## Constraints and review focus

- Preserve target-user authorization and atomic password/session/audit writes.
- Never disclose old or current stored keys via nested responses, raw secret references, config exports or snippets.
- Rotation revokes immediately, retains all settings/usage, and must not report success after reload failure.
- Never mutate shared keys while constructing redacted responses.
- Clear one-time secrets when dialogs close; don't put them into ordinary entity caches.
- New behavior stays off the inference request path; benchmark response redaction with benchmem.

## Tasks

1. Passwords: extend existing store/handler tests for admin reset and rejected targets; add explicit password-setting handler and transactional store method; add Users reset and account change dialogs with existing session endpoint; verify focused Go tests and UI typecheck.
2. Virtual keys: extend existing serialization and rotation tests first; implement prefix-only serialization with explicit one-time issuance responses; verify nested/export responses and immediate old-key invalidation. Update UI table/detail, one-time issuance dialogs, caches, snippets and prompt selectors. Run focused Go/UI tests, benchmarks and E2E regression checks.
3. Quiet UI: remove release/promotional cards and RSS presentation/fetches while preserving operational notices; verify relevant UI behavior and build.
4. Integrate: run complete focused Go package suites, UI tests/typecheck/build; add provider-harness and browser regression coverage without paid API calls. Fresh independent review, resolve material findings, commit feature branch and create PR via ambolt-gh.

## Execution ledger

- Base: a03f417ce; worktree already isolated and clean. User approved full design and requested implementation + PR.
- Ruling: use parallel-agents for independent password and quiet-UI domains; root owns virtual keys and integration. Disjoint files except surgical governance API changes. This avoids serial context cost while keeping one integrated review.
- Password domain: delegated to password_features. Quiet UI: delegated to quiet_ui.
- Root completed/integrated all partial agent work after workspace-credit interruptions; no external systems were deployed or merged.
- Passwords complete: explicit admin password endpoint with transactional authorization/audit/session and recovery revocation; current-password self-service dialog; canonical profile capabilities independent of privileged config access.
- Virtual keys complete: byte-level management response boundary (including nested/config/log previews), prefix-only DTOs, explicit no-store one-time issuance, transient dialogs/reset mutation caches, caller-supplied playground credentials and placeholder snippets.
- Final review found a Vault side effect before SQL CAS and stale reload installation. Fixed with immutable per-issuance Vault paths plus bounded best-effort cleanup, a fixed 256-stripe rotation coordinator (2 KiB), and version-checked serialized configuration installs. Tests reproduce the stale reload failure and cover Vault rollback/success/reload-failure paths.
- Quiet UI complete: promotions/release fetching and RSS/news UI removed; operational notices/jobs/setup warnings retained. Replaced obsolete News-tab browser coverage with quiet-tray coverage in credential-security.spec.ts.
- Verification: full governance/configstore/identity/HTTP handlers/lib/server Go suites passed; 19 focused UI tests passed; TypeScript and production build passed. Three real Chrome browser regressions passed against an isolated local gateway: issuance/rotation/revocation, admin and self password flows/permissions, and operational notifications without news fetches. No paid provider APIs called.
- Provider harness: six opt-in management regression requests inserted surgically and validated with augment/filter scripts; no live harness run. Requires an administrator session cookie when deliberately invoked.
- Linux Docker microbenchmarks, median of three: SendJSON common path before 611.9 ns/op, 4 allocs/op; after 623.5 ns/op, 4 allocs/op. Prefix gate alone 10.68 ns/op, zero allocations. One-key management redaction 6433 ns/op, 34 allocs/op (about 2.1 KiB/op). These are focused serialization measurements, not a production end-to-end latency claim.
- Retention: response objects are request-scoped; issued browser secrets live only until their dialog closes; rotation coordination uses a fixed 2 KiB and a per-store config-install mutex. Vault normally retains only current/grace credentials; failures of bounded best-effort cleanup are logged and can leave orphaned Vault entries for operator cleanup.
- PR is stacked on upstream PR #5 because dev has not incorporated that update. No direct writes to dev/main and no PR merge/deployment.
