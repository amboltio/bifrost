# Dashboard access through canonical users

## Aftalt mål

`/workspace/governance/users` er det eneste sted til brugeradministration. Kortet
"Password protect the dashboard" må ikke fungere som et parallelt fælles login,
når users-frameworket er aktivt. Security Settings administrerer loginmetoder og
sessionspolitik; Min konto administrerer brugerens eget password og sessioner.

Dette er en arkitekturændring af eksisterende adgangsveje. Brugeren har bedt om en
implementeringsplan; dokumenterne beskriver implementeringen, men udfører den ikke.

## Kilde og checkout

Analysen er baseret på lokal `users`-ref `0b0dd5473` og læsning af de tilsvarende
filer i `D:/Files/Documents/GitHub/bifrost`. Den aktuelle worktree er detached på
`8b4f782f5` og mangler users-frameworket. Planen gemmes her, men skal udføres på
en proposal-branch baseret på den aktuelle users-kode. Genbekræft filindhold og
lokale ændringer før udførelse; en læsning af den anden checkout beviser ikke,
at den er identisk med den committede branch.

## Valgt løsning

1. Bevar den eksisterende Users-side og dens backend. Udbyg kun manglende
   handlinger såsom passwordreset/sessionstilbagekaldelse på denne side.
2. Fjern de fælles adminfelter og auth-off-knappen i canonical user mode.
3. Security Settings får "Login og brugeradgang" med lokal loginmetode,
   SSO/OIDC og sessionstimeouts samt et adgangsstyret link til Users.
4. Dashboard og management-API kræver individuel canonical session og RBAC.
   Super-adminrollen er en autorisationsbeslutning efter autentificering.
5. Importer gamle admincredentials én gang; de er derefter ikke en loginvej.
6. Første administrator oprettes direkte som canonical user i en afgrænset
   engangsopsætning. Setup-tokenet giver ikke almindelig management-adgang.

At omdøbe den eksisterende formular løser ikke backendkonflikten. At flytte
brugeradministration til Security Settings skaber dublering. Begge fravælges.

## Tilstande og kontrakter

| Tilstand | Dashboard/management | Setup | Legacy credentials |
|---|---|---|---|
| Fresh, ikke initialiseret | Afvist bortset fra public auth-status og setup/login-assets | Tokenbeskyttet oprettelse af første admin | Ingen |
| Legacy før migration | Eksisterende adfærd på gammel installation | Eksisterende procedure | Input til engangsmigration |
| Canonical, initialiseret | Individuel session + permissions | Afvist, også med gammelt setup-token/cookie | Afvist |
| Canonical uden fungerende login | Afvist; tydelig operatorfejl | Ikke automatisk genåbnet | Afvist |

En durable initialiseringsmarkør afgør setupstatus. `is_enabled=false`, nul aktive
brugere, en databasefejl eller en deaktiveret loginmetode må ikke genåbne setup.
Manglende markør sammen med eksisterende brugere skal afvises ved startup frem
for at gætte ejerskab. Den nuværende legacy-importmarkør bruges fortsat til
idempotent migration; en særskilt canonical initialiseringsmarkør dækker både
direkte første opsætning og legacy-import.

`governance.auth_config` er fælles loginpolitik, ikke kontolagring. Historiske
adminfelter accepteres alene som migrationsinput på endnu ikke migrerede
installationer. Efter initialisering afvises ændringer til dem; historiske
uændrede felter i filen ignoreres med en deprecation-besked uden hemmeligheder.
En aktiveret user-installation kan ikke skifte til anonym management-adgang.

`local_login.is_enabled=false` slår kun passwordlogin fra. SSO-only må fungere
uden globale admincredentials. Ændringer skal afvises, hvis de efterlader ingen
aktiv loginmetode eller ingen aktiv administrator med en brugbar identitet.
OIDC discovery-verifikation er nødvendig ved overgang til SSO-only, men lover
ikke IdP-oppetid. Ingen ny anonym recovery-/break-glass-adgang indføres.

## Adgang og UI

- Users beholder create, disable, roles, reset-password og revoke-sessions.
- Min konto bruger eksisterende self-service-sessionendpoints. Ingen bruger-CRUD.
- Loginpolitik læses/ændres af en canonical `super_admin`; ikke af en delegeret
  user manager alene. Writes kræver frisk canonical session efter projektets
  eksisterende fem-minuttersregel og samme origin-kontrol som sessionændringer.
- Public auth-status indeholder kun loginmuligheder, setupstatus og capabilities.
  Den udleverer ikke policyhemmeligheder, brugerlister eller markørværdier.
- UI afgør adgang via serverens aktuelle bruger/permissions. Dummy-`useRbac`,
  enterprise-flag og den historiske `auth_type === "sso"` er ikke bevis for adgang.
- Alle produkttekster følger eksisterende engelske UI-tekster. Nye interaktive
  elementer får `data-testid`.

## Constraints og afgrænsning

- Go 1.27.1 som i users-checkoutens go.work; kontroller version ved udførelse.
- Ingen nye afhængigheder uden konkret nødvendighed.
- Go-filer har ingen underscore undtagen `_test.go`.
- Schema ændres før handlers og docs.
- Ingen streamindhold i BifrostContext.
- Inference-auth er særskilt og ændres ikke implicit ved setup/policy-save.
- Ikke-user custom stores kan beholde deres eksisterende kompatibilitet, men
  må ikke annonceres som canonical user mode eller arve canonical bypasses.
- Ingen redesign af hele governance, directory sync eller access-profile accounting.
- Request-path-ændringer benchmarkes før/efter med `-benchmem`; retained state
  beskrives med key, bound og invalidation. Config-only arbejde markeres som sådan.
- GitHub via `ambolt-gh`, tilladt agentidentitet og proposal-PR. Ingen merge/deploy.

## Definition of done

Den gamle formular og dens payloads er væk i user mode. Legacy credentials,
ownerless sessions og setup-token kan ikke give management-adgang efter
initialisering. Users er den eneste brugeradministration. Policy gemmes fuldt
og fungerer efter restart, også SSO-only uden globale credentials. Sidste
administrator/loginmetode kan ikke fjernes gennem samtidige writes. Passwordreset,
disable og sessionrevocation slår igennem i alle berørte browser/API-sessioner.
En frisk og en migreret database består de samme adgangstests. Lokale tests,
browsertests og eventuel live-verifikation rapporteres særskilt.
