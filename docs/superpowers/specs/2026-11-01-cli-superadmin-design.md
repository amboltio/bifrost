# Local CLI superadmin provisioning

The operator wants to remove the setup-token mechanism and browser-based creation of the first administrator. Operators with access to the deployed gateway's terminal must be able to establish superadmin access without an existing dashboard login.

## Contract

- Start from current `dev` on `codex/cli-superadmin-no-web-setup`; open a new PR against `dev`.
- The gateway binary supports `createsuperadmin --app-dir PATH`, including inside its production container (`/app/main createsuperadmin --app-dir /app/data`). It opens the same SQLite or PostgreSQL config store, honors the configured encryption key, and does not start the HTTP server or provider integrations.
- Interactive mode prompts for email, display name and a hidden password with confirmation. Explicit `--email` and `--display-name` are supported. Automation uses `--password-stdin`; passwords are never command-line arguments or printed.
- Creation validates a normal email and the existing password policy, stores an Argon2id verifier and atomically creates an active canonical user, password credential, super_admin grant, audit/outbox records and durable login policy/initialization state.
- It works on both empty and initialized databases. Duplicate email addresses fail without modifying the existing user. Recover access by creating a distinct superadmin; there is no implicit password replacement, reactivation or promotion of an existing identity.
- Ensure local sign-in is enabled for the new administrator while preserving other authentication policy settings and OIDC providers. Existing users, roles, sessions, virtual keys and encryption are retained.
- No web endpoint creates the initial admin. Remove the setup header, environment/config field, bootstrap token, setup cookie/session/ticket authorization, setup routes, browser form and schema/API/client contracts. The historical legacy credential migration may remain solely to preserve upgrades of existing installations; it is not a new setup path.
- A fresh installation remains closed to dashboard management. The login status reports `admin_provisioning_required`; the login page tells the operator to run the terminal command. Health/status and explicitly public authentication endpoints remain reachable. Inference authorization remains separately governed by its existing policy.
- CLI creation against a running empty gateway must allow normal login without reopening an unauthenticated management interval. Persisted policy is authoritative; the no-admin gate can refresh it while locked.
- Remove token plumbing from maintained docs, fixtures, SDK helpers, test runners and workflow scripts. Management test tooling must use canonical authenticated sessions and CLI-created test administrators, rather than a new bootstrap bypass.

## Verification and operational scope

Use red/green store/CLI and middleware/session regressions; test fresh creation, additional admins, duplicates, policy preservation, failure rollback, hidden/password-stdin input, invalid input, forbidden browser provisioning and ordinary login. Test SQLite locally; identify PostgreSQL validation limits honestly. Add UI/E2E coverage and management provider-harness cases, but do not run paid provider harness requests. Benchmark the existing management auth gate with `-benchmem`; CLI hashing and store mutation are off the inference request path.

No production credential mutation, deployment, merge or approval is authorized by this development request. Document exact container commands and any necessary restart behavior. The existing Coolify-only workflow remains intact.
