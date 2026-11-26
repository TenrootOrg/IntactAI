# Multi-user accounts, roles and one login for every tool

Status: Phases 0-3 live on dev (2026-11-25): dashboard users and roles, and
per-user accounts with automatic sign-in in Kibana, Velociraptor, Timesketch
and VolWeb. Next: MFA, then Phase 4. Replaces the 2026-11-10 plan, which
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
  (`auth_service.verify_audit_chain`). An off-box copy goes to the customer's
  syslog server (Settings -> Security, `services/audit_forward.py`, RFC 5424 over
  UDP or TCP), and security alerts are raised from the same entries
  (`services/security_alerts.py`; dashboard banner for Admins and up).

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
| VolWeb | per-user Django user, nginx replaces the Bearer token per request | yes |
| Portainer | Super-admin only, keeps its own login (CE ends Aug 2027) | — |

Read-only users get no tool accounts: Kibana's and Velociraptor's read roles
see every case, VolWeb and Portainer have no read-only role.

Generated passwords: encrypted (AES-GCM) in their own table, key in a root-only
file under `data/state/backend/`, never shown or logged, rotated freely. One
reconciler keeps every tool account in its desired state (boot, user change,
nightly) and reverts drift. No human gets Elasticsearch `superuser`, Velociraptor
`administrator` (except the Super-admin) or VolWeb's `/admin/`.

## 6. Phase 0 results (2026-11-25, on the dev box, nothing reconfigured)

Each tool was tried with throwaway users that were deleted afterwards, or by
reading the code installed on the box.

- **Velociraptor 0.77.4**: a user made at runtime with VQL `user_create`
  works at once (no restart). A request carrying `Authorization: Basic` for
  that user gets the GUI and API as that user with no login prompt; POSTs need
  no CSRF token; a wrong password is 401. Basic is stateless, so switching
  users in one browser just follows the header. **Way in: confirmed.**
- **Kibana 9.5.6 (Basic)**: an injected `Authorization: Basic` for a native
  user is accepted and creates no Kibana session (`sid`). The header wins
  even over another user's own form-login `sid`, so a user switch in one
  browser is safe. **Way in: confirmed.**
- **Timesketch 20261014**: the local username/password POST is handled before
  the SSO branch, so the backend's API client keeps logging in with
  `SSO_ENABLED`. Header SSO runs only on `/login/` and then Timesketch keeps
  its own session (`timesketch_session`, `remember_token` for 7 days): the
  dashboard's login and logout must expire both (cookies are not isolated by
  port, so the dashboard can). Header name: `SSO_USER_ENV_VARIABLE =
  'HTTP_X_INTACT_USER'`. **Way in: confirmed, with the cookie reset.**
- **VolWeb 3.16.0**: the SPA keeps `access_token`, `refresh_token` and
  `username` in localStorage and sends `Authorization: Bearer` on every API
  call (access 10 min, refresh 1 day, rotation + blacklist on). nginx can
  replace that header with a fresh token for the signed-in user, exactly like
  Kibana, so whatever an earlier user left in localStorage is never used; a
  bootstrap page on port 8002 only has to put placeholder values there.
  VolWeb's WebSockets (`/ws/...`) check no user at all: only the nginx gate
  protects them. **Way in: header replacement (better than the token
  hand-over planned).**

## 7. Release notes to carry

- **Admins and the Super-admin: set up two-step login straight after the
  upgrade.** Until they do, whoever holds the password first can enrol their
  own authenticator. The dashboard holds them on the setup screen.
- **Lost authenticator:** an Admin resets it for the users below them (Users,
  Reset 2-step). The Super-admin: `sudo scripts/reset-login.sh` on the
  appliance, then the setup page; this also clears two-step login.
- **Air-gapped boxes:** codes depend on the appliance's clock. The code
  screens warn when the browser and appliance clocks differ by more than a
  minute; point the box at the site's own time server if it has one.
- **Rollback** turns two-step login off until the next upgrade
  (docs/UPGRADE_CONTRACT.md, "Dashboard users and rollback").
- **Portainer** stays the Super-admin's, on its own default login (decided
  2026-11-26): it controls Docker, i.e. the whole host.
- **Restricted cases** need a Velociraptor org of their own: restricting a case
  whose org another case shares is refused, and a case cannot be moved into a
  restricted case's org. Kibana and VolWeb cannot be restricted per case;
  Timesketch Admins still see a restricted sketch's name (not its events).
- **API tokens** (user menu): read or write, at most the user's own role, never
  for Super-admin-only or password-again actions; they stop working when the
  user's role, password or two-step login changes.
- **Windows.EventLogs.CondensedAccountUsage** now returns one row per logon
  shape (account, source, logon type, logon process) with Count, EventTime
  (first) and LastSeen, and leaves logoff and lock/unlock events out. A
  collection is hundreds of times smaller; set Aggregate=N (and EventIDRegex)
  on a manual collection for the old one-row-per-event output.

## 8. Phases

0. Done 2026-11-25 (section 6): every tool has a confirmed way in.
1. **Dashboard users, roles, gate, CSRF/CORS, cookie strip, audit chain,
   screens.** Tools keep their shared logins.
2. Done: Timesketch header login, Kibana per-user accounts, the password
   vault and reconciler (services/tool_accounts).
3. Done: Velociraptor and VolWeb per-user accounts, then two-step login (TOTP,
   air-gapped, required for Admins and up, 10 recovery codes).
4. Done 2026-11-26: restricted cases, Operator case export/import, Read-only
   report pictures, per-user API tokens, off-box audit (syslog) and security
   alerts. Portainer stays the Super-admin's default login (no replacement).
   Still open: WebAuthn (needs a hostname, browsers refuse it on an IP), IRIS
   removal, private per-user chat threads.
