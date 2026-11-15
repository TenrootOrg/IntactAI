# Plan: multi-user accounts

Status: **planned for a future release, not started.** Written 2026-11-10 from
the first round of decisions. The case chat (section 5) still needs a design
discussion before any code.

## 1. Goal

Several people can work on one appliance, each with their own login. Keep it
simple and secure:

- one Admin, created at install;
- the Admin creates the other users;
- two other roles: read/write and read only.

## 2. Roles

| | Admin | Analyst (read/write) | Viewer (read only) |
|---|---|---|---|
| How many | exactly one, created at install | any | any |
| Created by | the installer | the Admin | the Admin |
| Read cases, results, reports, dashboards | yes | yes | yes |
| Create/edit cases, run collections, workflows, uploads | yes | yes | no |
| Use the case chat (spends the LLM keys) | yes | yes | no, can only read it |
| Settings (network/ports, upgrades, LLM keys, data move, users) | yes | no | no |
| Manage users (create, delete, change role, set password, unlock) | yes | no | no |

- The Admin can't create a second Admin, and the Admin account can't be
  deleted or downgraded.
- "Settings" means every Settings page and its API, not only what the UI hides.
  The backend checks the role on every write route. Hiding a button is not
  security.

## 3. Login, lockout and recovery

- **Login stays one simple page.** It takes a username and password, and the
  same session cookie as today.
- **Lockout is per user.** Too many failed logins lock that one account, and the
  other users keep working.
  - Today's counter (`services/auth_service.py`) is global, and on purpose it
    is a *timed* lock with backoff (10 failures → 15 min, doubling, cap 24 h).
    That stops someone on the network from locking the operator out for good.
  - Keep the timed backoff per user, and add an Admin action to unlock early.
- **The Admin unlocks users.** In user management the Admin can:
  - unlock a locked user;
  - set a new password for any user. That also unlocks them and ends their
    sessions.
- **A locked Admin recovers through config.yaml.**
  - The login message for a locked Admin says: "Reset the admin password in
    config.yaml and restart."
  - Today's recovery path is `first_login: true` in config.yaml, which reopens
    the setup page. Access to the host IS the authentication.
  - With users, that path must reset **only the Admin** (password, lock,
    sessions). Every other user, password and session stays as it was. This
    needs its own test.
- **Sessions are per user.** Changing a password or deleting a user ends that
  user's sessions.
- **nginx gate:** `/api/auth/verify` keeps gating the dashboard and every tool
  port. It has to accept any valid user session.
  - Any role may pass the gate to the bundled tools (see section 6).
  - Portainer is the one to reconsider: anyone with its login controls Docker.

## 4. Every page works for several users

- **Shared data is shared.** A case and everything in it (runs, results,
  findings, reports, notes) belongs to the case, not to a user. When one user
  changes something, everyone sees it.
- **Not real time, but fast.** Open pages refresh shared data about every
  **5 seconds**, using the polling pattern pages already use.
  - Refresh only what the page shows, and only while the tab is visible.
- **Per-user data stays per user.** That covers UI preferences, the private
  case chat (section 5) and the user's own sessions.
- **Show who did it.** Every run, change and chat message records its user, and
  the Settings → Actions log shows it.
- **Conflicts.** Two users editing the same field: last write wins, but the
  page shows "changed by <user> just now" on refresh, so nobody overwrites
  silently. Long-running actions (one collection per client, one upgrade at a
  time) keep their existing locks.
- **Audit.** The existing auth audit log records the username for every login,
  failure, lock, unlock, password change and user change.
- An audit of every page and route for single-user assumptions is still to do;
  see section 7, open question 1.

## 5. Case chat (to discuss)

Today the case has one chat (`/api/cases/<case_id>/chat` in
`routes/case_routes.py`), shared by whoever is logged in.

Wanted:

- **A private chat per user, per case.** Each Analyst or Admin talks to the AI
  in their own thread. Others don't see it.
- **One shared chat** where users can talk to each other.
- **Share from private to shared.** A user can push a message, or an AI answer,
  from their private chat into the shared chat.

Options to decide on:

- **A. Shared chat per case** (recommended to start). Each case gets a "Team"
  thread next to every user's private thread. Sharing copies the message, with
  "shared by <user> from their chat", into that case's Team thread. It's simple
  and keeps talk about a case inside the case.
- **B. One global chat for the whole appliance.** Plus per-user private chats in
  each case, and sharing into the global chat with a link back to the case. It's
  better for cross-case talk, but a busy box gets noisy.
- **C. Both.** A Team thread per case plus one global chat. It's the most
  flexible and the most UI and code.

Points to settle:

- Is the shared chat human-only, or can the AI be asked there too? Whose
  context does the AI use?
- Does a shared AI answer keep its sources and evidence links?
- Do Viewers read the shared chat only, as decided in section 2?
- Existing chats on upgrade go to the Admin's private thread (section 6).

## 6. Bundled tools, upgrades, and where it touches the code

- **Bundled tools** (Kibana, IRIS, Timesketch, Portainer, VolWeb) keep their own
  credentials. Our gate decides who reaches them, and their own login decides
  what each person can do there. Per-user accounts inside those tools are not
  part of this feature.
- **Upgrading an existing box.** The current single login becomes the Admin
  (same username and password), existing chats become the Admin's private
  chats, and no data moves.
  - This runs in the new backend on first start (a migration like
    `services/auth_migrate.py`).
  - The upgrade engine's backward-compatibility surface is untouched; see
    `docs/UPGRADE_CONTRACT.md`.
- **Code it touches** (first look, not a full audit):
  - `services/auth_service.py`: one credential and one global lock today. It
    becomes a users table in the DB, with a per-user lock and sessions.
  - `routes/auth_routes.py`: setup, login, logout, change-password, verify.
    Add the user-management routes (Admin only).
  - A role check (decorator) on every write route, and Admin-only on
    `system_routes`, upgrade, settings, data move and LLM keys.
  - The case chat routes and storage, for per-user and shared threads.
  - Frontend: a Users card in Settings; hide what the role can't do; a user
    menu (name, role, change own password, log out).

## 7. Decisions so far, and open questions

Decided (2026-11-10):

| Question | Decision |
|---|---|
| Roles | Admin, Analyst (read/write), Viewer (read only) |
| Number of Admins | exactly one |
| Locked Admin | reset via config.yaml; resets the Admin only, never other users |
| Settings | Admin only; Analysts use the chats (and so the LLM keys) |
| Viewer chat | read only, no chatting |
| Bundled tools | keep their own credentials; gated there |
| Sync | open pages refresh shared data about every 5 s |
| Existing boxes | the current login becomes the Admin on upgrade |
| When | a future release |

Open:

1. A full audit of pages and routes for single-user assumptions, to size the
   work.
2. Chat option A, B or C (section 5), and whether the AI answers in the
   shared chat.
3. Should Viewers reach Portainer at all? It hands out Docker control to
   anyone with its login.
4. Password rules for new users: minimum length, and whether to force a change
   at first login.
5. Deleting a user: keep their name on past runs and messages (recommended),
   and decide what happens to their private chats.
