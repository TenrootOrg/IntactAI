# Design: signing the upgrade package

> **Status: design only.** Nothing here is implemented. It exists so the
> trade-offs — particularly the ones that touch the frozen bootstrap contract —
> are settled before any code is written.

## The gap

Everything the upgrade verifies today proves **integrity**, not **authenticity**.
A package that was corrupted in transit is caught; a package that was *replaced*
is not.

| Layer | Where | Catches |
|---|---|---|
| gzip CRC | `upkg_verify_archive` (`lib/upgrade/package.sh`) | bit-rot in the outer archive |
| per-asset sha256 | release `*.index.json`, and `--expect-sha256` | a corrupted or truncated asset |
| per-file sha256 map | `contents.sha256`, ~1123 entries, verified by `upkg_verify_file_checksums` | a file swapped or missing inside an otherwise valid archive |
| image layer digests | `docker load` | corrupt image layers |

The hole is structural, not a bug: **the manifest cannot hash itself**
(`scripts/ci/packager/package.py` explicitly excludes `manifest.json` from the
map — "the manifest can't contain its own hash"). So an attacker who can write
to whatever the box downloads from can rewrite a file *and* rewrite the entry
describing it. Every check still passes.

The `.index.json` sha256 values are a partial anchor, but they ship from the same
place, over the same channel, with the same trust properties. Nothing on the box
holds a secret that a forger does not.

## What makes this different from ordinary supply-chain signing

The obvious answer is cosign keyless (Fulcio + Rekor). **It does not work here.**
Verification requires reaching Fulcio/Rekor at verify time, and the case that
matters most — a hand-carried package applied on an air-gapped appliance — has no
network at all. Any design that needs to phone out to verify is a design that
fails exactly where it is needed.

So the requirements are:

1. **Verifiable offline.** No network, no OCSP, no transparency-log lookup.
2. **Trust anchored in something already hand-carried.** The box cannot fetch the
   public key over the same channel as the package — that is circular.
3. **Backwards compatible.** Boxes running today's bootstrap must not break, and
   unsigned older releases must remain installable during the transition.
4. **Cheap to verify.** No new runtime dependency on an air-gapped appliance.

## Proposed shape

### Trust anchor: the frozen bootstrap

`scripts/bootstrap_upgrade.sh` is already the right place, and it is the *only*
right place:

- it is **hand-carried** to the box out of band, which is precisely the separate
  channel a trust anchor needs;
- it is **frozen** (6 commits, "DO NOT ADD FEATURES") and it is already the
  security boundary: it is what verifies the engine's sha256 before exec'ing it;
- it runs **before** any packaged code does, so a compromised package cannot
  disable its own verification.

Embedding a public key in it makes the existing hand-carry step carry trust as
well as code, at no extra operational cost.

### Artifacts

Add to every release:

```
<tag>.manifest.json          (unchanged)
<tag>.manifest.json.sig      detached signature over the manifest bytes
<tag>.index.json.sig         detached signature over the index bytes
```

Signing the **manifest** is what matters: it already contains the sha256 of every
file, so a valid signature over it transitively authenticates the entire package.
The index is signed too so the per-asset hashes used *before* extraction are
covered — otherwise an attacker could still swap a whole asset and only be caught
after it was unpacked.

### Algorithm

**Ed25519**, raw detached signatures.

- Verifiable with `python3` + `cryptography`, which the appliance already has;
  no new dependency, and notably **no GPG** — no keyring state, no trust-db, no
  agent, nothing to go wrong offline.
- Small keys, small signatures, no parameter choices to get wrong.
- Falls back to `openssl pkeyutl -verify` if `cryptography` is ever absent.

### Verification points

| Stage | Checks | On failure |
|---|---|---|
| bootstrap, after fetching the engine | `<tag>-engine.tar.gz.sha256` **and** its signature | refuse to exec |
| engine, in `upkg_acquire` before extraction | `index.json.sig` → then per-asset sha256 | refuse the package |
| engine, after reading the manifest | `manifest.json.sig` → then the existing per-file map | refuse the package |

The existing checks all stay. Signing does not replace them; it makes the values
they compare against trustworthy.

## Key management (the part that actually decides feasibility)

This is the real cost, and it should be decided before any code is written.

- **Signing key: offline.** An Ed25519 private key that never exists on a CI
  runner. CI produces the artifacts; signing is a deliberate, separate step on a
  machine that holds the key. This keeps a compromised CI token from being able
  to sign a release — which is most of the value.
  - Convenient middle ground if that is too heavy: a GitHub Actions environment
    secret gated on manual approval. Weaker (the key touches a runner), still far
    better than nothing.
- **Rotation.** Embed a **list** of accepted public keys in the bootstrap, not
  one. A new key ships in a bootstrap release before it is first used to sign, so
  boxes accept both old and new during the overlap. Without this, rotation
  strands every box that has not upgraded its bootstrap.
- **Compromise.** There is no revocation channel on an air-gapped box. The
  recovery path is: rotate the key, publish a new bootstrap, and hand-carry it —
  the same channel the bootstrap already uses. This should be written down before
  it is needed, not during.
- **Key identity in the artifact.** Signatures carry a short key id so a
  verification failure can say *"signed by an unknown key K"* rather than just
  "bad signature".

## Rollout

Signing cannot be mandatory on day one — existing releases are unsigned and boxes
in the field must still upgrade.

1. **Sign, don't enforce.** CI starts producing `.sig` files. The engine verifies
   *if present*, logs the key id, ignores absence. Zero behaviour change.
2. **Warn on absent.** Once every supported release is signed, an unsigned
   package logs a loud warning.
3. **Enforce.** A missing or bad signature refuses the package. Gate it behind an
   `INTACT_ALLOW_UNSIGNED=1` escape hatch for genuine recovery scenarios, with
   the same "this is deliberate" framing the downgrade refusal already uses.

Step 3 is the only breaking change, and by then it is a flag flip.

## The frozen-contract problem

Adding verification to `bootstrap_upgrade.sh` **changes the frozen contract**,
which is the one thing that file exists not to do. The tension is real and worth
stating plainly:

- The bootstrap is frozen so that *old boxes can always upgrade* — changing it
  risks stranding them.
- But the trust anchor has to live somewhere the package cannot rewrite, and the
  bootstrap is the only such place.

The resolution: the bootstrap gains **exactly one capability** — "verify a
detached Ed25519 signature against an embedded key list" — and nothing else. That
capability is additive and version-independent: it never needs to change again
when a release changes, only when a *key* changes, which is the rotation case
already designed for above. An old bootstrap that predates signing keeps working
because verification is opt-in until step 3.

This is still a contract change and should be reviewed as one, not slipped in.

## What this does not solve

- **A compromised build.** If the source or CI is compromised, the result is a
  correctly-signed malicious package. Signing proves origin, not good intent.
  Reproducible builds are the answer to that, and are a different project.
- **The operator's own key handling.** If the private key lives next to the CI
  token, this buys very little.
- **Trust on first use.** The very first bootstrap a customer receives is trusted
  because of how it was delivered. Signing does not change that; it only means
  every *subsequent* package inherits that one act of trust.

## Effort

Roughly: half a day for signing + verification code, plus the rollout flag work.
The genuinely expensive part is **key management policy** — where the key lives,
who can sign, and what happens when it leaks. That decision should come first;
the code is the easy half.
