# CLI superadmin implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace web admin bootstrap and setup-token access with local terminal superadmin provisioning.
**Architecture:** Persist canonical users through a trusted local store transaction. Add a subcommand to the deployed gateway binary, retain a closed management gate until provisioning, and replace the login setup UI with operator instructions.
**Tech Stack:** Go workspace, GORM SQLite/PostgreSQL, Argon2id, React/TypeScript, Playwright, Node runner scripts.
**Spec:** `docs/superpowers/specs/2026-11-01-cli-superadmin-design.md`.

## Global constraints

- No token-based bootstrap, alternate management bypass, plaintext password arguments or automatic mutation of an existing email.
- Preserve canonical policy, OIDC providers and existing data. Use the same application directory, store configuration and encryption key as the gateway.
- No new dependencies unless existing dependencies cannot supply hidden terminal input. No paid provider requests or live deployment.

## Review focus

- Concurrent duplicate creation and failures must roll back identity, role and policy changes together.
- CLI must not silently write a default SQLite database when PostgreSQL was configured or credentials could not resolve.
- Running gateway must remain fail-closed and accept the CLI-created administrator after provisioning.
- Interactive input must hide passwords, validate confirmation and handle EOF; stdin mode must reject oversized/missing secrets.
- Setup removal must not accidentally disable inference authentication or expose canonical management routes.

## Tasks

### 1. Local CLI and persistence
- [x] Add failing transaction and command tests in existing topical test files.
- [x] Implement `CreateLocalSuperAdmin` and the `createsuperadmin` subcommand, including store/encryption loading without server startup and production entrypoint forwarding.
- [x] Verify creation, repeat/duplicate behavior, local policy enablement, SQLite and noninteractive input. Document backend limits.

### 2. Backend removal and closed management gate
- [x] Add failing tests for removed setup routes/header/cookie access and CLI-first provisioning.
- [x] Remove setup token/cookie/initial-admin routes and configuration; install a fail-closed administrator provisioning gate and public status field.
- [x] Update affected Go tests, interfaces, runtime schema and auth benchmarks; verify canonical and legacy-upgrade behavior.

### 3. UI and maintained test/documentation migration
- [x] Replace browser token/admin setup with CLI instructions and ordinary sign-in; remove request-header and configuration plumbing.
- [x] Update frontend regressions and browser coverage.
- [x] Migrate maintained docs/OpenAPI, fixtures, runner scripts and provider-harness collection from setup tokens to canonical session authentication and CLI provisioning.

### 4. Integration and PR
- [x] Run focused and affected complete Go suites, UI production build/typecheck and focused frontend tests; run isolated real gateway smoke/browser verification.
- [x] Review the complete diff and search for obsolete setup-token references; resolve findings.
- [ ] Record auth-gate benchmark results and exact terminal instructions. Commit, push the new branch, open PR against `dev` and verify remote head.

## Execution ledger

- Base: `8f3311385d` (`dev`, PR #6 squash-merged). Clean existing isolated worktree reused.
- Design defaults selected from the requested Django-like CLI and prior lost-admin scenario; duplicate identities are rejected and recovery creates a separate administrator.
- Verified full Go packages: configstore/tables/identity and the HTTP main/handlers/lib/server packages. Final transport rerun passed after all source fixes; gateway binary built successfully.
- CLI/store review verified real hidden-input PTY behavior, mismatch/EOF/oversized-input rejection, case-insensitive concurrent duplicates, SQLite transaction rollback on audit/outbox/policy errors, and PostgreSQL 17 functional creation/encryption/SecretVar resolution without SQLite fallback. PostgreSQL rollback/concurrency were not fault-injected.
- Final isolated HTTP smoke passed: file credentials do not provision; initial API remains closed; CLI first/additional administrators can sign in without restarting; duplicate is rejected; removed setup endpoints reject requests; existing sessions survive additional creation; logout invalidates access. Full gateway router returns 405 for removed POST routes due to its generic routing; direct session-router regressions return 404.
- UI validation: production build/typecheck, seven focused loader tests, six login/security Chrome regressions and three marketplace Chrome regressions passed. The broad Vitest run had one unchanged Danish-Windows locale-sensitive failure in `components/warp/warpStream.utils.test.ts` (expects `12,345`, runtime formats `12.345`); other cases passed. No product workaround was added for this unrelated test.
- Offline tooling: 118 collection tests, five login-helper tests, five callback-routing tests, four clean-server tests, 23 proxy tests and two gateway lifecycle tests passed. Harness generation/filtering and JS/JSON/shell/Makefile syntax were checked. No paid provider harness was run.
- Reviews closed two security defects: file credentials could still provision after web removal, and concurrent cold policy refresh could overwrite a newly saved policy. Both received red/green regressions. Initialized canonical policy and persisted legacy-upgrade credentials remain authoritative.
- Auth gate benchmark medians, three Linux amd64 runs: canonical initialized 19.31 -> 1.548 ns/op; health 18.43 -> 12.68 ns/op; legacy initialized 6.277 -> 2.495 ns/op. All before/after samples: zero bytes and zero allocations per operation. These are gate microbenchmarks, not end-to-end latency measurements.
- Retained memory added: one fixed-size `sync.Mutex` per middleware, used only for cold policy loading and config publication; initialized requests and inference do not acquire it. CLI hashing/config mutations execute off the inference request path.
- Explicit relative SQLite paths preserve the server's existing current-working-directory semantics. Container terminal commands share the gateway's working directory; Makefile-owned provisioning now runs from the same directory as its server.
- Explicitly disabled config stores retain their pre-existing stateless behavior; this change does not alter that operator-selected mode. CLI provisioning requires a persistent supported store.
