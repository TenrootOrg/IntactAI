# risx-mssp → Intact.AI — operator runbook

Move a customer off risx-mssp and onto Intact.AI **while keeping their deployed
Velociraptor fleet connected**. No endpoint is reinstalled, re-enrolled or
touched; every client keeps its existing `client_id`.

This is the step-by-step version. The design notes and the lab evidence behind
it are in [RISX_MIGRATION.md](RISX_MIGRATION.md).

---

## Read this first — the one thing that will break the migration

A deployed Velociraptor client dials **`Client.server_urls` verbatim**, normally
`https://<old-host>:8000/`. It has no discovery, no fallback and no way of being
told about a new address.

**The Intact box must answer at the address the clients already dial, on port
8000.** Either it takes over the old machine's IP/DNS name, or you repoint DNS
to it. Nothing in any config file changes this, and the migration script refuses
to run by default if the address does not resolve to the machine you are on.

Decide this before you start, because it drives the next choice.

## Which path?

| | **New machine** (recommended) | **Same machine** |
|---|---|---|
| Risk | Old box stays intact and bootable — a true rollback | No rollback once wiped |
| Downtime | Only the IP/DNS cutover | The whole install |
| Address | Requires an IP/DNS handover | Address stays put, nothing to move |
| Use when | You can get a second machine, or the old host is an old OS | Hardware is fixed, or the box is a VM you cannot duplicate |

Both are supported. **Take the new machine if you can** — a migration you can
walk away from is worth more than the hardware.

---

## Step 1 — Back up the Velociraptor files

**Do this before anything else.** risx's own `cleanup.sh` runs
`docker volume rm $(docker volume ls -q)` and `rm -rf <workdir>/*`; if you run it
first, the files below are gone and the fleet cannot be recovered.

### Where they live

Everything is in one directory on the risx box:

```
/home/<user>/setup_platform/workdir/velociraptor/velociraptor/
├── server.config.yaml      ← THE ONLY FILE YOU ACTUALLY NEED
├── client.config.yaml         derived; Intact regenerates it on every boot
├── clients/{linux,mac,windows}/   repacked installers — not needed
└── <the datastore and filestore, in the same directory>
```

Find it without guessing the username:

```bash
ls -d /home/*/setup_platform/workdir/velociraptor/velociraptor/
```

There is **no `api.config.yaml`** on a risx box — it creates an `api` *user*
instead — and nothing needs migrating there. Intact mints its own.

### Take the backup

```bash
# On the RISX box.
VELO=$(ls -d /home/*/setup_platform/workdir/velociraptor/velociraptor)
STAMP=$(date +%Y%m%d-%H%M%S)

# The config — this is the migration. Keep it safe.
sudo install -m 600 "$VELO/server.config.yaml" "$HOME/velo-server.config.$STAMP.yaml"

# Belt and braces: the whole directory, in case you later want history.
sudo tar -czf "$HOME/velociraptor-full-$STAMP.tar.gz" -C "$(dirname "$VELO")" velociraptor
sudo chown "$USER" "$HOME"/velo-server.config.$STAMP.yaml "$HOME"/velociraptor-full-$STAMP.tar.gz

ls -lh "$HOME"/velo-*"$STAMP"*
```

Then copy both **off the machine** — `scp`, a USB stick, anything — and verify
the copy opens before you touch the old box:

```bash
# From your laptop
scp <user>@<risx-host>:'~/velo-*' ./
python3 -c "import yaml,sys; d=yaml.safe_load(open('velo-server.config.<stamp>.yaml')); \
print('CA present:', bool(d['CA']['private_key']), '| clients dial:', d['Client']['server_urls'])"
```

> **`server.config.yaml` is a credential.** It contains the Velociraptor CA
> private key and the client nonce — anyone holding it can impersonate the
> server to the whole fleet. Keep it at mode `600`, do not put it in a ticket or
> a chat, and delete your working copies once the migration is verified.

### What you do *not* need

The repacked installers under `clients/`, the ELK/IRIS/MISP data, the risx
front-end and back-end. Clients re-enrol from the config alone.

---

## Step 2 — Decommission risx-mssp

### Path A — New machine (recommended)

Do **nothing** to the old box yet. Leave it running until the new appliance is
up and clients are checking in (Step 5). Then:

1. Stop risx so the two cannot both answer on 8000:
   ```bash
   cd /home/<user>/setup_platform/scripts && bash cleanup.sh    # or simply: sudo poweroff
   ```
2. Move the address over — give the Intact box the old machine's IP, or repoint
   the DNS name the clients use.
3. Keep the old machine powered off but **not wiped** for a week. It is your
   rollback.

### Path B — Same machine

The address never moves, which is the one thing this path makes easy. Everything
else is harder, so confirm before you start:

```bash
ls -lh "$HOME"/velo-*        # the backup exists HERE
# ...and has been copied OFF this machine. Check on the other end, not this one.
```

Then remove risx:

```bash
cd /home/<user>/setup_platform/scripts

# The supported teardown: stops every app in .env, removes its volumes and dirs.
bash cleanup.sh

# If that leaves anything behind (a half-installed app, a stale network):
bash cleanup.sh --force
```

> `cleanup.sh --force` stops and removes **every container, network and volume
> on the host**, and deletes the whole workdir. It does not distinguish risx's
> containers from anything else running on that machine. On a dedicated box that
> is exactly right; on a shared one it is a catastrophe. Check `docker ps -a`
> first.

Confirm the machine is clean:

```bash
docker ps -a          # expect: nothing, or nothing risx
docker volume ls      # expect: nothing risx
ls /home/*/setup_platform/workdir 2>/dev/null   # expect: empty or absent
```

Reboot before installing Intact. It costs a minute and clears the docker network
state that `cleanup.sh` restarts the daemon to fix.

---

## Step 3 — Install Intact.AI

Requirements: Ubuntu, **16 GB RAM** (32 recommended), 4+ cores, 100 GB+ disk, a
static IP.

```bash
# 1. Clone
git clone https://github.com/TenrootOrg/IntactAI.git intact
cd intact

# 2. Configure
nano config.yaml
```

**Set `domain` to the address the clients already dial** — the host part of
`Client.server_urls` from the config you backed up. Getting this right now saves
re-running things later. Set the module passwords while you are in there.

```bash
# 3. Install
sudo bash install.sh
```

Air-gapped instead? Use `sudo bash install.sh --package <package.tar>` — see the
README's *Air-gapped installation* section.

When it finishes, log in to `https://<domain>/` and complete the first-login
setup. Do not migrate before the appliance is healthy on its own.

---

## Step 4 — Adopt the Velociraptor identity

Copy the backed-up config onto the Intact box, then, **from the install root**:

```bash
cd /path/to/intact

# ALWAYS dry-run first. Needs no root, changes nothing.
sudo ./scripts/adopt_velociraptor_identity.sh \
     --from ~/velo-server.config.<stamp>.yaml --dry-run
```

Read the output. It prints the incoming CA fingerprint, the CA currently on the
box, the address the clients dial, and whether that address resolves here. If it
says the address diverges, **stop and fix the address** — proceeding gets you a
healthy server that no client ever reaches.

```bash
# For real.
sudo ./scripts/adopt_velociraptor_identity.sh --from ~/velo-server.config.<stamp>.yaml
```

Options:

| flag | when |
|---|---|
| `--dry-run` | always, first |
| `--domain X` | override the address from `config.yaml` |
| `--datastore <dir>` | also bring the old datastore (historical hunts/flows). Skip it if you only need clients reconnecting — they will, without it |
| `-y` | skip the prompts. Also the override for a diverging address, when you are cutting DNS separately |
| `-h` | the full help |

What it does: transforms the config to Intact's layout, stops Velociraptor, backs
the current config up to `data/tmp/velo-before-adopt-<timestamp>/`, writes the
adopted `server.config.yaml` at `0600`, deletes `client.config.yaml` and
`api.config.yaml` so the entrypoint re-derives them from the adopted CA, restarts
with `--no-build --pull never`, verifies, and **rolls back to the backup on any
failure**.

---

## Step 5 — Verify the fleet

```bash
docker exec intact_velociraptor ./velociraptor \
  --config /velociraptor/server.config.yaml \
  query "SELECT client_id, os_info.hostname AS host, last_seen_at FROM clients()"
```

Clients return on their own polling interval, so a large fleet **trickles in over
minutes to hours** rather than arriving at once. "Nothing yet" ten minutes in is
not a failure.

Also check the dashboard's Velociraptor tab, and that a collection dispatches to
one returning client before you call it done.

### If clients do not come back

1. **Address.** From an endpoint: `curl -vk https://<the-address-in-server_urls>:8000/`
   — it must reach the Intact box. This is the cause the overwhelming majority of
   the time.
2. **Port.** `ss -ltnp | grep 8000` on the appliance; `8000` must be open to the
   endpoints through any firewall in between.
3. **Identity.** Compare fingerprints — the adopted CA must match the backup:
   ```bash
   sudo python3 -c "import hashlib,yaml; d=yaml.safe_load(open('data/velociraptor/server.config.yaml')); \
   print(hashlib.sha256(d['CA']['private_key'].encode()).hexdigest()[:16])"
   ```
4. **Roll back the adoption** — the previous config is in
   `data/tmp/velo-before-adopt-<timestamp>/`; copy `server.config.yaml` back,
   delete `client.config.yaml` and `api.config.yaml`, and
   `docker compose -f modules/velociraptor/docker-compose.yaml up -d --no-build --pull never`.

---

## Afterwards

- Delete every working copy of `server.config.yaml` that is not the appliance's
  own (your laptop, the backup dir, any transfer medium).
- Keep the full `velociraptor-full-<stamp>.tar.gz` archive somewhere safe until
  the customer is satisfied — it is the only copy of the old datastore.
- Leave the old machine powered off but not wiped for a week.

## Scope

The adoption script rewrites Velociraptor's own config and restarts that one
container. It does not touch any other module, the database, or anything else the
installer manages. Everything from risx other than Velociraptor — Timesketch,
IRIS, ELK, MISP — is not migrated and starts fresh in Intact.
