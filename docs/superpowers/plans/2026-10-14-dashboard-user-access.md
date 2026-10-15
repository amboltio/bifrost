# Dashboard User Access Implementation Plan

> **For agentic workers:** Brug `superpowers:executing-plans` til sekventiel udførelse. Subagents kræver eksplicit valg af brugeren. Opgaverne nedenfor har fælles auth-kontrakter og skal udføres i rækkefølge.

**Goal:** Gør Users til eneste brugeradministration, og udfas dashboardets fælles adminlogin til fordel for individuelle brugersessioner og RBAC.

**Architecture:** En durable initialiseringsmarkør adskiller første opsætning fra normal drift. AuthConfig bliver fælles loginpolitik, mens canonical users/credentials/sessions ejer identitet. Security Settings bruger en afgrænset policy-API og skriver aldrig brugercredentials.

**Tech Stack:** Go 1.27.1, fasthttp, GORM/SQLite/PostgreSQL, React/Vite, TanStack Router, RTK Query, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-14-dashboard-user-access-design.md`.

## Global Constraints

- Go 1.27.1 som i users-checkoutens go.work; kontroller version ved udførelse.
- Ingen nye afhængigheder uden konkret nødvendighed.
- Go-filer har ingen underscore undtagen `_test.go`.
- Schema ændres før handlers og docs.
- Ingen streamindhold i BifrostContext.
- Inference-auth er særskilt og ændres ikke implicit ved setup/policy-save.
- Alle produkttekster følger eksisterende engelske UI-tekster. Nye interaktive elementer får `data-testid`.
- Arbejd på proposal-branch baseret på users; denne worktree mangler implementationsgrundlaget.
- Brug `ambolt-gh whoami` før GitHub-arbejde. Kun `ambolt-agent` eller dedikeret `<user>-ai`; ingen merge/approve/deploy eller credential setup.

## Evidens fra analysen

| Sted på users | Observation | Konsekvens |
|---|---|---|
| `handlers/session.go` | Login foretrækker canonical credentials | Security-formens adminpassword er ikke brugerpassword |
| `handlers/middlewares.go` | Legacy Bearer-fallback og auth-off markerer lokal admin | Nye brugerregler kan omgås via kompatibilitetsveje |
| `handlers/config.go` | GET returnerer tre adminfelter; PUT skriver dem | Skjul ikke bare kortet; stop også credential-writes |
| `configstore/rdb.go` | AuthConfig læses/skrives som tre gamle rækker | Loginpolitik/SSO skal have fuld persistence |
| `configstore/identityconfig.go` | LocalLogin/OIDC findes som typer | Genbrug kontrakten, undgå endnu en auth-model |
| `configstore/sessionidentity.go` | Idempotent legacy-import findes | Bevar importen, fjern loginfallback efter import |
| `configstore/identity.go` | CreateInitialSuperAdmin og sidste-admin-lås findes | Udvid transaktionerne frem for at kopiere funktionerne |
| `ui/.../user-groups/usersView.tsx` | Users er allerede implementeret i fallback UI | Brug eksisterende route, ingen ny brugeradministrationsside |

Filstier nedenfor er repository-relative og refererer til users-grundlaget. Ved
execution skal branchens aktuelle HEAD og eventuelle lokale ændringer dokumenteres.

## Review Focus

1. To replicas opretter første administrator samtidigt: kun én lykkes (Task 2).
2. En gammel config-save udleverer legacy fields efter migration: writes afvises uden delvis mutation (Task 3).
3. Sidste loginmetode og sidste admin ændres samtidigt: den samlede policy forbliver brugbar (Task 1/3).
4. En bruger deaktiveres med åben browser/WebSocket: ingen gammel session eller legacy fallback fortsætter (Task 2/5).
5. SSO-only uden globale adminfelter efter restart: startup, auth-status og login bruger den samme vedvarende policy (Task 1/5).

## Task 0: Bekræft execution-grundlag og mål baseline

**Files:** Read `AGENTS.md`, `go.work`, `ui/vite.config.mts`, eksisterende identity-tests og spec; ingen produktændringer.

- [ ] Bekræft users-ref, ren/ændret checkout og enterprise-alias. Bevar lokale ændringer. Flyt ikke denne worktree automatisk til en anden revision.
- [ ] Opret/rebrug en isoleret proposal-checkout baseret på users ved execution; medtag plan og spec.
- [ ] Kør følgende i proposal-checkouten, ikke den nuværende detached base:

```powershell
git status --short
git log -1 --format='%h %s'
go version
go test ./framework/identity/... -count=1
go test ./framework/configstore/... -run 'Test.*(Identity|Legacy|Session|AuthConfig)' -count=1
go test ./transports/bifrost-http/handlers/... -run 'Test.*(Session|Authorization|Users|AuthConfig)' -count=1
```

- [ ] Registrer eksisterende fejl og nødvendig serviceopsætning; en manglende toolchain er ikke et testpass. Brug `tests/docker-compose.yml` hvis de valgte tests kræver backing services.
- [ ] Tilføj benchmarks i eksisterende `middlewares_test.go` for canonical session, denied legacy Bearer og upåvirket inference. Kør dem på baseline og slutresultat med samme fixtures:

```powershell
go test ./transports/bifrost-http/handlers/... -run '^$' -bench 'BenchmarkDashboardAccess' -benchmem -count=5
```

**Acceptance:** Execution-checkout og baseline er identificeret; ingen netværkscredential eller branchhistorik ændret i planning.

## Task 1: Gem fuld loginpolitik og durable initialisering

**Files:** Modify `transports/config.schema.json`, `framework/configstore/identityconfig.go`, `framework/configstore/rdb.go`, `framework/configstore/migrations.go`, `framework/configstore/tables/config.go`, `transports/bifrost-http/lib/config.go`. Create `framework/configstore/authpolicy.go`, `framework/configstore/authpolicy_test.go`. Extend `identityconfig_test.go`, `sessionidentity_test.go`, `lib/config_test.go`.

**Interfaces:** Bevar `GetAuthConfig(context.Context) (*AuthConfig, error)` og `UpdateAuthConfig(context.Context, *AuthConfig) error`; de skal nu roundtrippe fuld policy. Introducer et smalt lifecycle-interface til setup og middleware:

```go
type DashboardIdentityState struct {
    Initialized bool `json:"initialized"`
}
type DashboardIdentityStateStore interface {
    GetDashboardIdentityState(context.Context) (DashboardIdentityState, error)
}
```

- [ ] Find de eksisterende TableGovernanceConfig keys/migrationsregistreringer. Tilføj versioneret policy-row og canonical initialiseringsmarkør i deres etablerede katalog; markør er aldrig public.
- [ ] Skriv roundtrip-tests med local_login, sessionsværdier, OIDC provider og secret references. Test restart/read-from-DB uden configfil, ikke kun in-memory typen.
- [ ] Test legacy tre-row-import, konflikter mellem top-level alias og governance-blok, nil adminfelter i SSO-only og malformed policy. Fejl skal returneres; ingen fallback til auth-off.
- [ ] Implementer atomisk full-policy save, normalisering og secret-redaction med eksisterende helpermønstre. Hash ikke en canonical brugers password under policy-save. Bevar secret references; redacted values på GET er aldrig nye credentials på PUT.
- [ ] Beslut og dokumenter samme authorityregel for startup/reload: filændringer anvendes efter eksisterende reconciliationregler; DB bruges når ingen filpolicy er deklareret. Sammenligning omfatter hele normalized policy.
- [ ] Efter canonical initialisering: afvis `is_enabled=false`; gamle fil-adminfelter er migrationshistorik og må ikke ændre canonical credentials.
- [ ] Genbrug sidste-admin role-lock ved mutationskontrol. Lås policy og admin/role-state i samme faste rækkefølge ved policyændring, admin-disable og relevante rolle-/identity-mutationer. UI-kontrol alene er utilstrækkelig.
- [ ] Kør målrettede configstore/lib tests rødt før ændringen og grønt efter. Commit kun Task 1-filer med `feat: persist canonical dashboard authentication policy`.

**Acceptance:** Fuld policy overlever restart; canonical state kan ikke blive uninitialized gennem config-save, databasefejl eller brugerdisable. Retained memory: én immutable policy per reload-generation, bound af konfigurerede providers; ingen cache per request.

## Task 2: Engangssetup og fjern legacy management-login

**Files:** Modify `framework/identity/bootstrap.go`, `framework/configstore/identity.go`, `framework/configstore/sessionidentity.go`, `transports/bifrost-http/handlers/session.go`, `handlers/middlewares.go`, `handlers/authorization.go`, `server/server.go`; extend deres eksisterende tests. Create `handlers/setupadmin.go`, `handlers/setupadmin_test.go`.

**Interfaces:** Ny `POST /api/session/setup-admin` accepterer `{email, display_name, password}` gennem eksisterende setup-token/session proof. Svaret er `201 {"status":"created"}`; ingen adminsession udstedes. Efterfølgende login bruger eksisterende `/api/session/login`.

- [ ] Skriv tests for fresh setup: manglende/ugyldigt proof `403`, valid proof `201`, anden oprettelse `409`, og to samtidige requests giver én admin.
- [ ] Udvid `CreateInitialSuperAdmin` til at oprette user, Argon2id credential, super_admin assignment, initial local-login policy og initialized-markør i samme transaktion. Kontroller markøren og alle eksisterende users, ikke kun aktive users.
- [ ] Sæt samme initialized-markør under legacy-importtransaktionen. Bevar importens idempotens og fail-closed ved tvetydigt ejerskab. Importer eksisterende admin også hvis legacy auth var deaktiveret, men start aldrig canonical drift anonymt.
- [ ] Begræns setup-session til public setup-status og setup-admin. Den må ikke længere åbne hele `/api`; efter initialisering afvises både setup-token og gammel setup-cookie.
- [ ] Når initialized: kræv canonical session på management, afvis Basic/shared-credential Bearer-fallback og ownerless sessions. Passwordlogin kan stadig genkende migreret adminidentifier via canonical lookup.
- [ ] Bevar dokumenteret noncanonical custom-store kompatibilitet særskilt. Hver branch afgøres af store/lifecycle-kontrakt, ikke blot at et credentialfelt er til stede.
- [ ] Skriv auth-matrix regressioner: gammel configpassword, base64 Bearer, Basic, ownerless session, setup-token, revoked canonical session, disabled user og valid viewer/super_admin. Cover både HTTP og WebSocket-ticket/upgrade.
- [ ] Test at normal ændring/reset af brugerpassword aldrig genaktiverer gamle globalcredentials. Beskriv særskilt om inference Basic skal udfases; implementer ingen implicit ændring af inference-auth i dette task.
- [ ] Kør focused bootstrap/session/middleware/authorization tests og benchmarks. Commit `fix: require canonical identity for initialized dashboard access`.

**Acceptance:** Kun autentificerede canonical principals når RBAC i initialized user mode. Setup kan aldrig genåbnes ved at deaktivere brugere eller loginmetoder. Ingen runtime writes til global adminpassword efter import.

## Task 3: Afgrænset API til loginpolitik

**Files:** Create `handlers/authsettings.go`, `handlers/authsettings_test.go`. Modify `handlers/config.go`, `handlers/config_test.go`, `handlers/authorization.go`, `server/server.go`, `framework/configstore/authpolicy.go`, `identityconfig.go`, `roles.go`, `identity.go`, relevante tests og `transports/config.schema.json`.

**Interfaces:** `GET /api/auth/settings` returnerer redacted AuthConfig og et revisionsnummer. `PUT /api/auth/settings` modtager `{revision, auth_config}`. Kun authenticated canonical super_admin; write kræver frisk session. Konflikt `409`, ugyldig policy `400`, manglende session `401`, utilstrækkelig adgang/friskhed `403`.

```json
{
  "revision": 3,
  "auth_config": {
    "is_enabled": true,
    "local_login": {
      "is_enabled": true,
      "session_ttl_seconds": 43200,
      "idle_timeout_seconds": 1800,
      "allow_registration": false
    },
    "oidc_providers": []
  }
}
```

- [ ] Test direkte handlerkald og routed middlewarekæde: actor skal have valid active/current-auth-version canonical session samt super_admin; lokal adminmarker alene er utilstrækkelig.
- [ ] Implementer transaction revision-check og policy-save. Stale samtidige edits `409` uden delvis mutation. Benyt origin-checks, audit/outbox og eksisterende secret-preservation helpers.
- [ ] Test og afvis sidste-metode removal, OIDC-only uden verificeret enabled provider og OIDC-only uden aktiv admin med tilknyttet enabled provideridentitet. Sidste-admin guard skal også omfatte role removal og identity unlink.
- [ ] `local_login.is_enabled=false` skal være autoritativ i canonical mode; legacy adminfelter må ikke tænde lokal loginmetode igen.
- [ ] Opdater `Server.UpdateAuthConfig`: canonical policy kræver brugbar loginmetode, ikke global username/password. Public auth-status læser samme policy og marker som middleware.
- [ ] På generisk `PUT /api/config`: accepter uændret legacy snapshot som no-op for overgangsklienter; afvis ændringer til adminfelter eller auth-policy i canonical mode før nogen andre fields gemmes. Nye policy-writes går gennem `/api/auth/settings`.
- [ ] GET `/api/config` skal ikke udlevere de historiske admincredentials i canonical mode. Public auth-status beholder legacy responsefelter for læsende klienter og får `identity_initialized` til setupvalget.
- [ ] Sessionspolitik strammes via eksisterende SessionService-regler. Ved ændret loginpolitik tilbagekaldes dashboard-sessioner, og klienten logges ind igen; method-save fejler, hvis audit/revocation-transaktion fejler.
- [ ] Kør focused config/authsettings/authorization tests. Commit `feat: manage dashboard login policy through protected API`.

**Acceptance:** Passwordreset og policy-save har separate API'er og persistence. Stale legacy-formular kan ikke slå auth fra eller overskrive SSO. Alle ændringer har identificeret actor i audit.

## Task 4: Fjern dobbelt UI og brug eksisterende Users

**Files:** Modify `ui/app/workspace/config/views/securityView.tsx`, `ui/lib/types/config.ts`, `ui/lib/types/schemas.ts`, `ui/lib/store/apis/sessionApi.ts`, `ui/lib/store/index.ts`, `ui/components/topbar.tsx`, `ui/app/login/page.tsx`, login layout/views, `ui/app/_fallbacks/enterprise/components/user-groups/usersView.tsx`. Create `ui/lib/store/apis/authSettingsApi.ts`, `ui/app/workspace/config/views/loginAccessSettings.tsx`, `ui/components/accountSecurity.tsx`. Extend `tests/e2e/features/config/config-security.spec.ts` og config page object.

**Interfaces:** RTK Query hooks `useGetAuthSettingsQuery`, `useUpdateAuthSettingsMutation`. Managementformen skriver kun Task 3 DTO. `identity_initialized` afgør setup kontra normal login; `identity_capabilities` afgør featuretilgængelighed. API-`403` skal håndteres uden logout-loop.

- [ ] Tilføj browser assertions for initialized local/mixed/SSO-only: gammelt `#auth-enabled`, global username/password og BETA-card findes ikke. Loading/error må ikke vise en tom legacy-form som fallback.
- [ ] Erstat kortet med "Login and user access". Vis local-login toggle, eksisterende OIDC providerstruktur og sessionstimeouts. CRUD-formular til users er aldrig indlejret her.
- [ ] Link "Manage users" peger på `/workspace/governance/users`; vis kun link ved `users.read`. Mutationer i Security Settings begrænses til canonical super_admin og afspejler serverens rejection.
- [ ] Fjern legacy refs, credential-change checks og setup proof dialogs fra SecurityView i canonical mode. Almindeligt security-save ændrer ikke loginpolitik, og auth-policy-save ændrer ikke inference-auth.
- [ ] Brug eksisterende OIDC konfigurationskontrakt/verify flow; providerhemmeligheder må ikke vises. Ved sidste metode/SSO-only fejl vises inline årsag, ikke succes-toast.
- [ ] Genbrug Users API til reset-password/revoke-sessions på Users-siden, hvis UI-handlingerne mangler. Reset-token vises kun ved udstedelse til autoriseret actor og gemmes ikke i localStorage, cache eller logs.
- [ ] Min konto bruger eksisterende change-password/list-sessions/logout-all/revoke-session endpoints; ingen ny route til brugeradministration. Passwordfelter vises kun når kontoen har lokal credential; SSO brugere henvises til IdP.
- [ ] Loginens setup-view opretter første admin via Task 2, hvorefter setup-cookie ryddes og browseren navigerer til login. Superadmin oprettes ikke gennem Security Settings.
- [ ] Kontroller faktisk `@enterprise` alias. Opdater konkret enterprise-komponent hvis denne build bruger den; fallback-test beviser ikke enterpriseadfærd. Genbrug serverpermissions frem for dummy `useRbac` på de berørte controls.
- [ ] Nye testids: `login-access-settings`, `manage-users-link`, `local-login-enabled`, `session-ttl-seconds`, `session-idle-seconds`, `auth-settings-save`, `setup-admin-submit`, `account-security`.
- [ ] Kør UI format/typecheck/build samt config browsertests. Commit `refactor: separate user administration from login settings`.

**Acceptance:** Users er eneste CRUD-overflade. Security Settings har ingen global account eller dashboard-off toggle i initialized mode. Min konto kan kun ændre eget password/sessioner.

## Task 5: End-to-end kvalificering og migrationsvejledning

**Files:** Create `tests/e2e/features/config/dashboard-user-access.spec.ts`, `docs/development/dashboard-user-access-migration.md`. Modify `tests/e2e/core/auth.setup.ts`, `tests/e2e/features/config/pages/config-settings.page.ts`, `tests/e2e/api/collections/provider-harness.json`, `docs/development/identity-governance-contracts.md`, eksisterende dashboard-auth docs fundet med rg.

- [ ] Brug isolerede, disposable gateway/databaser til destructive auth scenarios. Test fresh setup og legacy-databaseimport separat; ingen credentials ændres på fælles gateway.
- [ ] Kør en browser med super_admin og en anden med almindelig bruger. Opret brugeren på Users, log ind, bevis `403` ved direkte auth-policy-write og ved usermanagement uden permissions.
- [ ] Reset password/revoke sessions/disable fra Users, og bevis at anden browser, API-bearer og WebSocket ikke fortsætter. Lokal passwordændring gør gammel credential ugyldig.
- [ ] Test SSO-only med lokal mock-OIDC fixture, inklusive browser callback, logout og restart. Ingen afhængighed af produktions-IdP eller eksterne secrets.
- [ ] Test gammel setup-cookie og gammel shared Bearer på migrated installation. Begge afvises. Test concurrent policy-save og sidste-admin-mutation mod SQLite og PostgreSQL.
- [ ] Tilføj surgisk management-auth case i provider harness efter AGENTS.md-reglen. Benyt object literals og undgå hel-fil JSON-reserialize. Auth-matrix collection dækker også inference-regressioner.
- [ ] Migrationsdoc beskriver backup, engangsimport, marker/state, erstatning af scripts der brugte shared Basic/Bearer, og operatørstyret restore hvis migration fejler. Ingen runtime legacy-bypass som rollback. Rollback kræver sammenhørende DB-backup og binær; gamle releases må ikke køre blandet med initialized canonical deployment.
- [ ] Opdater contracts-doc, så afsluttede canonical endpoints ikke fortsat beskrives som fremtidige. Beskriv præcis hvad public auth-status og Security Settings betyder.

**Verification commands** (kør i execution-checkout; nødvendige services/mock-IdP oppe først):

```powershell
go test ./framework/identity/... -count=1
go test ./framework/configstore/... -run 'Test.*(Identity|Legacy|Session|Auth|Role)' -count=1
go test ./transports/bifrost-http/handlers/... -run 'Test.*(Session|Authorization|Users|Auth|Setup|Config)' -count=1
go test ./transports/bifrost-http/lib/... -run 'Test.*(Auth|Config)' -count=1
go test ./transports/bifrost-http/handlers/... -run '^$' -bench 'BenchmarkDashboardAccess' -benchmem -count=5
make run-e2e FLOW=config
git diff --check
```

Kør `npm run format`, `npm run typecheck` og `npm run build` fra `ui`.
Hvis buildens Unix copy-step er utilgængeligt på Windows, kør Vite-build og
typecheck særskilt og rapporter copy-step som ikke verificeret. Skift ikke til
en anden shell for destruktive file operations uden verificeret target.

- [ ] Registrer ns/op og allocs/op før/efter samt eventuelle retained managers.
- [ ] Foretag samlet diff-/security-review mod spec og auth-matrix. Ingen release-readiness på baggrund af typecheck alene.
- [ ] Commit `test: qualify canonical dashboard access and migration`.

**Acceptance:** Alle spec-krav har en observeret test; blokeringer er dokumenteret med output. Lokalt pass er ikke deployment-pass. Efter execution kan en proposal-PR oprettes via ambolt-gh og vedhæftes chatten; merge/deploy udføres ikke.

## Leveringsrækkefølge og færdigkriterier

Task 0 → 1 → 2 → 3 → 4 → 5. Hold ændringen samlet til release; fjern ikke kortet
alene, mens backend fortsat accepterer shared management credentials. Task-commits
er reviewpunkter, ikke invitation til at deploye mellemtilstande.

- [ ] Ingen global dashboard-account i initialized user mode.
- [ ] Ingen shared credential, ownerless session eller setup-token management-bypass.
- [ ] Users er eneste brugeradministrationsside.
- [ ] Fuld policy persistence og SSO-only uden global account.
- [ ] Sidste administrator/loginmetode beskyttet under samtidighed.
- [ ] Separate inference-auth regressioner passerer.
- [ ] Benchmark, migration og browser/API-tests er dokumenteret.

## Planens egen verifikation

Plan og spec er baseret på statisk læsning. Ingen produktkode er implementeret,
og ingen runtime-, migrations-, browser- eller performance-resultater hævdes her.
Ved planlevering kontrolleres filernes eksistens, diff-format og dækning af spec.
