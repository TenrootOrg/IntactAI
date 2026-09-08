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
<risx home>/setup_platform/workdir/velociraptor/velociraptor/
├── server.config.yaml      ← THE ONLY FILE YOU ACTUALLY NEED
├── client.config.yaml         derived; Intact regenerates it on every boot
├── clients/{linux,mac,windows}/   repacked installers — not needed
└── <the datastore and filestore, in the same directory>
```

Find it without guessing the username:

```
ls -d /home/*/setup_platform/workdir/velociraptor/velociraptor/
```

### "Don't we need the certificate?"

Yes — and you already have it. **There are no separate certificate files.**
Everything is embedded as PEM text inside `server.config.yaml`:

| field | what it is |
|---|---|
| `CA.private_key` | the CA that signs everything — *this* is the fleet's identity |
| `Client.ca_certificate` | the CA cert each client pins. Velociraptor's own docs say of it: **"Do not change this!"** |
| `Client.nonce` | a shared secret; the server refuses clients presenting the wrong one |
| `Client.server_urls` | the address clients dial, used verbatim |
| `Frontend.certificate` / `Frontend.private_key` | the TLS cert clients validate against the CA |
| `GUI.gw_certificate` / `GUI.gw_private_key` | the GUI gateway pair |

Confirm it for yourself on the risx box — no `.pem`, `.crt` or `.key` files
exist in that directory:

```
ls -la "$VELO" | grep -iE '\.pem|\.crt|\.key' || echo "none — it is all inside server.config.yaml"
```

That is why one file is the whole migration, and why it has to be handled like a
credential: anyone holding it can impersonate the server to every endpoint.

All eight fields above are carried through **byte-for-byte** by the migration —
asserted by `tests/test_transform_config.py`, and proven end-to-end by running a
real Velociraptor 0.74.1 client against a 0.77.2 server on the transformed
config: it enrolled and completed its interrogation. See
[RISX_MIGRATION.md](RISX_MIGRATION.md) for that evidence.

There is **no `api.config.yaml`** on a risx box — it creates an `api` *user*
instead — and nothing needs migrating there. Intact mints its own.

### Take the backup

Run this **on the risx box**, as the normal login user (not root — `sudo` is
used only where it is needed).

#### 1. Make the backup folder

```
mkdir -p ~/velociraptor_backup
chmod 700 ~/velociraptor_backup          # only you can read it — it will hold a private key
cd ~/velociraptor_backup
pwd                                      # expect: ~/velociraptor_backup
```

#### 2. Copy the files into it

```
# Locate the risx Velociraptor directory (no need to know the username).
VELO=$(ls -d /home/*/setup_platform/workdir/velociraptor/velociraptor)
echo "Found: $VELO"

STAMP=$(date +%Y%m%d-%H%M%S)

# (a) THE FILE THE MIGRATION NEEDS.
sudo install -m 600 -o "$USER" -g "$USER" \
     "$VELO/server.config.yaml" \
     ~/velociraptor_backup/server.config.yaml

# (b) The derived client config — not needed to migrate, useful to compare against later.
sudo install -m 600 -o "$USER" -g "$USER" \
     "$VELO/client.config.yaml" \
     ~/velociraptor_backup/client.config.yaml 2>/dev/null || \
     echo "no client.config.yaml — fine, Intact regenerates it"

# (c) Everything, including the datastore, in case history is wanted later.
sudo tar -czf ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz \
     -C "$(dirname "$VELO")" velociraptor
sudo chown "$USER":"$USER" ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz
chmod 600 ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz
```

#### 3. Check what you got

```
ls -lh ~/velociraptor_backup/
```

Expect something like:

```
-rw------- 1 user user  13K  server.config.yaml
-rw------- 1 user user 2.7K  client.config.yaml
-rw------- 1 user user 1.2G  velociraptor-full-20260908-101500.tar.gz
```

Now prove the important file is intact and says what you expect — **before** you
touch anything else. This prints the CA fingerprint and the address your clients
dial; write both down, you will compare them after the migration:

```
python3 -c "
import hashlib, yaml
d = yaml.safe_load(open('$HOME/velociraptor_backup/server.config.yaml'))
print('CA fingerprint :', hashlib.sha256(d['CA']['private_key'].encode()).hexdigest()[:16])
print('clients dial   :', d['Client']['server_urls'])
print('nonce present  :', bool(d['Client'].get('nonce')))
"
```

All three must be present. An empty `CA fingerprint` or a missing `nonce` means
you have copied the wrong file — stop and find the right one.

#### 4. Get it off the machine

A backup that only exists on the box you are about to wipe is not a backup.

```
# From your laptop (not the risx box):
scp -r RISX_BOX:~/velociraptor_backup ./          # RISX_BOX = your ssh target, e.g. ops@10.0.0.5
ls -lh velociraptor_backup/
```

Then verify the copy on your laptop opens and shows the **same** CA fingerprint
as above:

```
python3 -c "
import hashlib, yaml
d = yaml.safe_load(open('velociraptor_backup/server.config.yaml'))
print('CA fingerprint :', hashlib.sha256(d['CA']['private_key'].encode()).hexdigest()[:16])
"
```

Only once those fingerprints match are you allowed to move on to Step 2.

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
   ```
   cd "$(ls -d /home/*/setup_platform)/scripts" && bash cleanup.sh   # or simply: sudo poweroff
   ```
2. Move the address over — give the Intact box the old machine's IP, or repoint
   the DNS name the clients use.
3. Keep the old machine powered off but **not wiped** for a week. It is your
   rollback.

### Path B — Same machine

The address never moves, which is the one thing this path makes easy. Everything
else is harder, so confirm before you start:

```
ls -lh ~/velociraptor_backup/   # the backup exists HERE
# ...and has been copied OFF this machine. Check on the other end, not this one.
```

Then remove risx:

```
cd "$(ls -d /home/*/setup_platform)/scripts"

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

```
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

> **Budget for the download.** The installer fetches and extracts the complete
> module set **regardless of which modules you enable in `config.yaml`** — the
> enabled flags decide what gets loaded and deployed, not what gets downloaded.
> Expect roughly **6 GB pulled**, ~13 GB extracted and up to **22 GB of scratch
> space** in use partway through, even on a trimmed-down install. On a metered
> or slow link, plan for it.

```
# 1. Clone the LATEST RELEASE (resolved from GitHub, so this never goes stale)
LATEST=$(curl -fsSL https://api.github.com/repos/TenrootOrg/IntactAI/releases/latest \
         | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
echo "Installing $LATEST"
git clone --branch "$LATEST" https://github.com/TenrootOrg/IntactAI.git intact
cd intact

# 2. Configure
nano config.yaml
```

**Set `domain` to the address the clients already dial** — the host part of
`Client.server_urls` from the config you backed up. Getting this right now saves
re-running things later. Set the module passwords while you are in there.

```
# 3. Install
sudo bash install.sh
```

Air-gapped instead? Use `sudo bash install.sh --package <package.tar>` — see the
README's *Air-gapped installation* section.

When it finishes, log in to `https://<domain>/` and complete the first-login
setup. Do not migrate before the appliance is healthy on its own.

---

## Step 4 — Adopt the Velociraptor identity

Copy the backup folder onto the Intact box first:

```
# From your laptop, onto the NEW appliance:
scp -r velociraptor_backup INTACT_BOX:~/          # INTACT_BOX = your ssh target for the new appliance
```

Then, on the Intact box, **from the install root**:

```
cd /path/to/intact

# ALWAYS dry-run first. Needs no root, changes nothing.
sudo ./scripts/adopt_velociraptor_identity.sh \
     --from ~/velociraptor_backup/server.config.yaml --dry-run
```

Read the output. It prints the incoming CA fingerprint, the CA currently on the
box, the address the clients dial, and whether that address resolves here. If it
says the address diverges, **stop and fix the address** — proceeding gets you a
healthy server that no client ever reaches.

```
# For real.
sudo ./scripts/adopt_velociraptor_identity.sh \
     --from ~/velociraptor_backup/server.config.yaml
```

Options:

| flag | when |
|---|---|
| `--dry-run` | always, first |
| `--from <dir>` | the folder works too — `--from ~/velociraptor_backup` finds `server.config.yaml` inside it |
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

```
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

0. **Give it a minute — this is the usual answer.** The Velociraptor container
   repacks the Linux, Mac and Windows client installers *before* it starts
   serving (measured at 8-63 seconds, longer on a small box). Until that
   finishes, nothing is listening on 8000 even though `docker ps` says `Up` and
   the migration script has printed success. Watch for the moment it is ready:

   ```
   docker logs -f intact_velociraptor | grep -m1 'Frontend is ready'
   ```

   The script now waits for this itself, so you should not see it — but if you
   ever adopt with an older copy, that is what is happening. **Do not restart
   the container to hurry it**: a restart starts the repack over.

   If you have already waited and the dashboard still looks stale, these are
   safe and clear any connection the browser was holding to the old container:

   ```
   sudo docker restart intact_velociraptor    # only if the frontend is truly stuck
   sudo docker restart intact_nginx           # drops stale proxied connections
   ```

1. **Address.** From an endpoint: `curl -vk https://<the-address-in-server_urls>:8000/`
   — it must reach the Intact box. This is the cause the overwhelming majority of
   the time.
2. **Port.** `ss -ltnp | grep 8000` on the appliance; `8000` must be open to the
   endpoints through any firewall in between.
3. **Identity.** Compare fingerprints — the adopted CA must match the backup:
   ```
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
  own — your laptop, `~/velociraptor_backup/server.config.yaml` on the Intact
  box, and any USB stick used to carry it:
  ```
  shred -u ~/velociraptor_backup/server.config.yaml   # on the Intact box
  ```
- **Keep** `~/velociraptor_backup/velociraptor-full-<stamp>.tar.gz` somewhere
  safe until the customer is satisfied — it is the only copy of the old
  datastore, and it also still contains the CA, so store it like a credential.
- Leave the old machine powered off but not wiped for a week.

## Scope

The adoption script rewrites Velociraptor's own config and restarts that one
container. It does not touch any other module, the database, or anything else the
installer manages. Everything from risx other than Velociraptor — Timesketch,
IRIS, ELK, MISP — is not migrated and starts fresh in Intact.

---

## Appendix — the backup, in one paste

Everything in Step 1, as a single block that stops for a **y/N** before each
step that costs anything, and shows you what it is about to act on first.

> **Paste this into a terminal. Do not pipe it into `bash`** — the prompts read
> from standard input, so piping would feed the script to itself and answer its
> own questions.

Run it **on the risx box**, as the normal login user.

```
# ---------------------------------------------------------------------------
# risx-mssp -> Intact.AI : back up the Velociraptor identity
# Stops before every step that writes or reads a credential. Nothing is
# deleted by this block, ever.
# ---------------------------------------------------------------------------
confirm() {
    printf '\n%s [y/N] ' "$1"
    read -r ans || ans=""
    case "$ans" in
        [Yy]*) return 0 ;;
        *) printf '  stopped — nothing further was done.\n'; return 1 ;;
    esac
}

# --- 1. find the risx Velociraptor directory -------------------------------
VELO=$(ls -d /home/*/setup_platform/workdir/velociraptor/velociraptor 2>/dev/null | head -1)
if [ -z "$VELO" ]; then
    echo "No risx install found under /home/*/setup_platform — is this the right box?"
else
    echo "Found: $VELO"
    echo
    ls -la "$VELO" | head -20

    confirm "Is that the Velociraptor directory you want to back up?" && {

    # --- 2. make the backup folder ------------------------------------------
    mkdir -p ~/velociraptor_backup && chmod 700 ~/velociraptor_backup
    echo "  created ~/velociraptor_backup (mode 700)"

    # --- 3. copy the config (this is the migration) -------------------------
    sudo install -m 600 -o "$USER" -g "$USER" \
         "$VELO/server.config.yaml" ~/velociraptor_backup/server.config.yaml
    sudo install -m 600 -o "$USER" -g "$USER" \
         "$VELO/client.config.yaml" ~/velociraptor_backup/client.config.yaml 2>/dev/null \
         || echo "  no client.config.yaml — fine, Intact regenerates it"
    echo "  copied:"
    ls -lh ~/velociraptor_backup/

    # --- 4. prove the file is the right one ---------------------------------
    echo
    echo "  This is the identity your whole fleet is pinned to:"
    python3 -c "
import hashlib, yaml, os
d = yaml.safe_load(open(os.path.expanduser('~/velociraptor_backup/server.config.yaml')))
print('   CA fingerprint :', hashlib.sha256(d['CA']['private_key'].encode()).hexdigest()[:16])
print('   clients dial   :', d['Client']['server_urls'])
print('   nonce present  :', bool(d['Client'].get('nonce')))
"
    echo
    echo "  Write the CA fingerprint down — you will compare it after the migration."

    confirm "Do all three look right (fingerprint, address, nonce=True)?" && {

    # --- 5. full archive, including the datastore ---------------------------
    STAMP=$(date +%Y%m%d-%H%M%S)
    echo "  archiving the whole directory (this can take a few minutes)…"
    sudo tar -czf ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz \
         -C "$(dirname "$VELO")" velociraptor
    sudo chown "$USER":"$USER" ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz
    chmod 600 ~/velociraptor_backup/velociraptor-full-$STAMP.tar.gz
    echo
    ls -lh ~/velociraptor_backup/
    echo
    echo "  DONE. Now copy this folder OFF the machine before you touch anything:"
    echo "     scp -r RISX_BOX:~/velociraptor_backup ./"
    echo
    echo "  Then verify the copy on the other end shows the SAME fingerprint."
    echo "  Only then start Step 2."
    }
    }
fi
```

After it finishes, continue from **Step 2** above. The teardown, the Intact
install and the adoption stay as separate deliberate steps on purpose — one
mistyped answer in a paste-and-go block should never be able to wipe a
customer's box.
