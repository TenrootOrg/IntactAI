# Multi-user accounts, roles and one login for every tool

Status: Phase 1 live on dev (2026-11-25). Replaces the 2026-11-10 plan, which
kept per-tool logins out of scope, let an Admin set other users' passwords
(OWASP ASVS 5.0 6.4.6 forbids it) and kept 7-day sessions.

The research behind it (sources for every claim below) is kept off the repo
in `~/intact-work/reports/Intact multi user roles and SSO.md`.

## 1. Roles

Four roles on one ladder. An Operator is an Admin without the Settings page
and without user management (decided 2026-11-25), so Operators also write
blueprints and run any artifact; every hunt is audited under their name. One
rule covers all user management: a user may
create, edit, disable or reset only users strictly **below** their own rank,
and may grant only roles below their own. Nobody edits their own role.

| Area | Super-admin (1) | Admin | Operator | Read-only |
|---|---|---|---|---|
| View cases, workflows, reports | yes | yes | yes | yes |
| Create/change cases, run blueprints, collect, upload, chat | yes | yes | yes | no |
| Download raw evidence | yes | yes | yes | no (reports yes) |
| Create or edit blueprints, collector configs, custom rules | yes | yes | yes | no |
| Delete a case | yes | yes | yes | no |
| Case export, import, relevance scoring (progress is in Settings) | yes | yes | no | no |
| The Settings page (LLM keys, cloud credentials, tools, network) | yes | yes | no | no |
| Host-level: upgrade, restore, data move, purge, Docker, Portainer | yes | no | no | no |
| Manage users | everyone below | Operators, Read-only | no | no |
| Bundled tools (Velociraptor, Timesketch, Kibana, VolWeb) | yes | yes | yes | no |
| IRIS (until it is removed) | yes | yes | yes | no |
| Portainer | yes | no | no | no |

Host-level power is Super-admin only because it is root-equivalent: the
backend drives the Docker socket, and Portainer is Docker. An Admin with it
could rewrite the user table, so "Admins cannot touch the Super-admin" would
not hold. Roles cannot constrain people who have a shell on the host.

Code: `modules/backend/services/users.py` (table, ranks),
`services/access_policy.py` (every route's lowest role, and each tool's),
`services/auth_service.py:gate_decision` (enforces both on every request),
`routes/user_routes.py` (management API).

## 2. Accounts and passwords

- Users are **disabled, never deleted**, and names are never reused: a new
  "anna" must not inherit an old one's audit trail or tool grants.
- A new user, and a reset, gets a **one-time password** shown once to the
  Admin. It works for 24 hours and only to choose the user's own password, so
  the Admin never knows the final one.
- Password rule (NIST SP 800-63B-4): 15+ characters, any characters, no
  composition rules, checked against known and trivial values. Passwords set
  under the old 12-character rule keep working until the next change.
- Sessions: 1 hour idle, 12 hours in all. Disabling a user, changing their
  role or their password ends their sessions on the next request.
- User management needs the password typed in the last 15 minutes (step-up).
- Super-admin transfer: from the Super-admin's own session, with the password,
  to an enabled Admin, in one transaction; the old Super-admin becomes an Admin.
- Recovery: `sudo scripts/reset-login.sh` on the host resets the Super-admin
  only. A forgotten Admin/Operator password is reset by someone above them.
- Upgrade: the existing single login becomes the Super-admin (same name and
  password); everyone signs in once more. The old credential rows stay in sync
  with the Super-admin, so a rollback still signs the Super-admin in.

## 3. Security

- CSRF: state-changing API requests from another **origin** are refused
  (`Sec-Fetch-Site`, then `Origin`). SameSite=Lax was not enough: the tools on
  other ports are "same-site" with the dashboard (RFC 6265 §8.5).
- No CORS: the dashboard calls its own origin only.
- nginx strips the dashboard cookie before requests reach any tool, logs the
  user name for every tool request, and asks the backend per tool
  (`/api/auth/verify?tool=`), so a role that may not open a tool gets 403.
- Audit log: every login event and every state-changing request, under the
  user's name, hash-chained so an edited or removed line is detectable
  (`auth_service.verify_audit_chain`). An off-box copy is a later phase.

## 4. Case chat

One shared chat per case for now; every message shows who wrote it.
Read-only users read it and cannot write. Private per-user threads are later.

## 5. One login for every tool (Phases 2 and 3)

The dashboard stays the only login. nginx asks it on every tool request, then
passes that user's identity on. No free edition supports one SSO standard, so
each tool gets its own way in:

| Tool | Way in | Generated password? |
|---|---|---|
| Timesketch | trusted user header set by nginx (`SSO_ENABLED`) | no |
| Kibana / Elasticsearch (Basic licence) | per-user native user, nginx injects `Authorization: Basic` | yes |
| Velociraptor | per-user user via VQL `user_create`/`user_grant`, injected Basic; OIDC fallback | yes |
| VolWeb | per-user Django user, token handed to the browser on VolWeb's origin | yes |
| Portainer | Super-admin only, keeps its own login (CE ends Aug 2027) | — |

Read-only users get no tool accounts: Kibana's and Velociraptor's read roles
see every case, VolWeb and Portainer have no read-only role.

Generated passwords: encrypted (AES-GCM) in their own table, key in a root-only
file under `data/state/backend/`, never shown or logged, rotated freely. One
reconciler keeps every tool account in its desired state (boot, user change,
nightly) and reverts drift. No human gets Elasticsearch `superuser`, Velociraptor
`administrator` (except the Super-admin) or VolWeb's `/admin/`.

## 6. Phases

0. Lab tests: Velociraptor with an injected Basic header; Kibana when the
   injected user changes in one browser; Timesketch's API client with
   `SSO_ENABLED`; VolWeb's token hand-over.
1. **Dashboard users, roles, gate, CSRF/CORS, cookie strip, audit chain,
   screens.** Tools keep their shared logins.
2. Timesketch header login, Kibana per-user accounts, the password vault and
   reconciler, backend service accounts separate from human ones.
3. Velociraptor and VolWeb per-user accounts; MFA (TOTP, then WebAuthn) for
   Admins and up, with recovery codes.
4. Restricted cases, per-user API tokens, off-box audit, Portainer replacement,
   IRIS removal.
