# Software Bill of Materials — Intact.AI

Generated: 2026-05-03

This SBOM lists every direct and transitive dependency the platform pulls in
— first-party Python packages, vendored frontend libraries, third-party
Docker images, external binaries downloaded by the installer, host-side tools
shipped under `data/tools/` — together with their declared licenses.

> **Project license:** the Intact.AI repo itself does not ship a `LICENSE`
> or `COPYING` file at the root. Add one before any public distribution; the
> redistribution status of several included third-party tools (Sysinternals,
> THOR Lite, FTK Imager, PingCastle) is constrained by their EULAs even if
> our code is permissively licensed.

---

## 1. License-type summary

| Type | Where it appears | Compliance notes |
|---|---|---|
| **MIT** | Most Python deps, JS vendored libs, several KAPE tools | Permissive; attribution required on redistribution |
| **Apache-2.0** | TimeSketch, OpenSearch, Plaso, gRPC, requests, OpenAI/Anthropic SDKs, EvtxHussar, WinPMEM, all Velociraptor VQL artifacts | Permissive; NOTICE file required on redistribution |
| **BSD-2/3-Clause** | Flask, Werkzeug, Jinja2, NumPy, pandas, nginx, YARA, Eric Zimmerman tools | Permissive; attribution required |
| **PSF-2.0** | aiohappyeyeballs, typing_extensions, parts of greenlet | Permissive; Python license family |
| **MPL-2.0** | certifi, parts of tqdm | File-level copyleft |
| **ISC** | requests-oauthlib | Permissive |
| **LGPL-2.1 / LGPL-3.0** | pySigma, IRIS web app | Library copyleft — shipping unmodified containers is fine; modifying source triggers source-distribution obligations |
| **GPL-2.0** | pyvelociraptor, Chainsaw, Volatility | Strong copyleft — distributing modified versions requires source release |
| **GPL-3.0** | Hayabusa, Takajo, Zircolite, LOKI | Strong copyleft (with v3-specific patent clauses) |
| **AGPL-3.0** | Velociraptor server + binaries | Network copyleft — running over a network = "distribution" |
| **Elastic License v2 (dual with SSPL)** | Elasticsearch, Logstash, Kibana | Source-available; **cannot be offered as a managed service** without an Elastic agreement |
| **CC-BY-4.0** | SwiftOnSecurity Sysmon config | Attribution required |
| **DRL 1.1** | SIGMA detection rules | Permissive with detection-specific clauses |
| **Proprietary / EULA (free use, restricted redistribution)** | Sysinternals (`autoruns64.exe`, `procexp64.exe`, `Sysmon64.exe`, `sigcheck64.exe`, `strings64.exe`, `disk2vhd64.exe`), FTK Imager, THOR Lite, PingCastle, NirSoft viewers | **Cannot be redistributed in this repo without explicit permission.** Strongly recommend pulling these at install time from the vendor instead of vendoring them. |

---

## 2. Project metadata

| Field | Value |
|---|---|
| Project | Intact.AI |
| Backend version | 1.0.0 |
| Backend runtime | Python 3.11.15 in `python:3.11-slim` |
| Custom-built images | `intact-backend:1.0.0`, `velociraptor-server:0.76.3` |

---

## 3. First-party Python — backend (`modules/backend`)

### 3.1 Direct dependencies (declared in `requirements*.txt`)

| Package | Pin | License | Source file | Purpose |
|---|---|---|---|---|
| Flask | `==3.1.2` | BSD-3-Clause | `requirements.txt` | Web framework |
| flask-cors | `==6.0.2` | MIT | `requirements.txt` | CORS |
| Werkzeug | `==3.1.6` | BSD-3-Clause | `requirements.txt` | WSGI lib |
| requests | `==2.32.5` | Apache-2.0 | `requirements.txt` | HTTP client |
| PyYAML | `==6.0.3` | MIT | `requirements.txt` | YAML |
| APScheduler | `==3.11.2` | MIT | `requirements.txt` | Scheduler |
| SQLAlchemy | `==2.0.46` | MIT | `requirements.txt` | ORM |
| elasticsearch | `>=8,<9` | Apache-2.0 | `requirements-elk.txt` | ES client |
| grpcio | `==1.78.0` | Apache-2.0 | `requirements-velociraptor.txt` | gRPC runtime |
| grpcio-tools | `==1.78.0` | Apache-2.0 | `requirements-velociraptor.txt` | gRPC code-gen |
| protobuf | `==6.33.5` | BSD-3-Clause | `requirements-velociraptor.txt` | Protobuf |
| pyvelociraptor | `==0.1.9` | **GPL** | `requirements-velociraptor.txt` | Velociraptor client |
| pysigma | `>=0.10.0` | **LGPL-2.1** | `requirements-azure.txt` | SIGMA conversion |
| azure-identity | `>=1.15.0` | MIT | `requirements-azure.txt` | Azure AD auth |
| msgraph-sdk | `>=1.0.0` | MIT | `requirements-azure.txt` | Microsoft Graph |
| anthropic | `==0.79.0` | MIT | `requirements-agentic.txt` | Claude API |
| openai | `==2.21.0` | Apache-2.0 | `requirements-agentic.txt` | OpenAI API |
| timesketch-api-client | `==20260209` | Apache-2.0 | `requirements-timesketch.txt` | TS REST client |
| timesketch-import-client | `==20260108` | Apache-2.0 | `requirements-timesketch.txt` | TS uploader |

> **Copyleft fl ag:** `pyvelociraptor` (GPL) and `pySigma` (LGPL-2.1) are
> the only non-permissive direct deps. They're imported as libraries so
> link-time obligations apply; if you modify their source, source-release
> obligations kick in.

### 3.2 Full pip freeze of `intact_backend` (105 packages)

| Package | Version | License |
|---|---|---|
| aiohappyeyeballs | 2.6.1 | PSF-2.0 |
| aiohttp | 3.13.5 | Apache-2.0 AND MIT |
| aiosignal | 1.4.0 | Apache-2.0 |
| altair | 6.1.0 | BSD-3-Clause |
| annotated-types | 0.7.0 | MIT |
| anthropic | 0.79.0 | MIT |
| anyio | 4.13.0 | MIT |
| APScheduler | 3.11.2 | MIT |
| attrs | 26.1.0 | MIT |
| azure-core | 1.39.0 | MIT |
| azure-identity | 1.25.3 | MIT |
| beautifulsoup4 | 4.14.3 | MIT |
| blinker | 1.9.0 | MIT |
| certifi | 2026.4.22 | MPL-2.0 |
| cffi | 2.0.0 | MIT |
| charset-normalizer | 3.4.7 | MIT |
| click | 8.3.3 | BSD-3-Clause |
| cryptography | 47.0.0 | Apache-2.0 OR BSD-3-Clause |
| diskcache | 5.6.3 | Apache-2.0 |
| diskcache-stubs | 5.6.3.6.20240818 | Apache-2.0 |
| distro | 1.9.0 | Apache-2.0 |
| docstring_parser | 0.18.0 | MIT |
| elastic-transport | 8.17.1 | Apache-2.0 |
| elasticsearch | 8.19.3 | Apache-2.0 |
| Flask | 3.1.2 | BSD-3-Clause |
| flask-cors | 6.0.2 | MIT |
| frozenlist | 1.8.0 | Apache-2.0 |
| google-auth | 2.49.2 | Apache-2.0 |
| google-auth-oauthlib | 1.3.1 | Apache-2.0 |
| greenlet | 3.5.0 | MIT AND PSF-2.0 |
| grpcio | 1.78.0 | Apache-2.0 |
| grpcio-tools | 1.78.0 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| h2 | 4.3.0 | MIT |
| hpack | 4.1.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| hyperframe | 6.1.0 | MIT |
| idna | 3.13 | BSD-3-Clause |
| importlib_metadata | 8.7.1 | Apache-2.0 |
| itsdangerous | 2.2.0 | BSD-3-Clause |
| Jinja2 | 3.1.6 | BSD-3-Clause |
| jiter | 0.14.0 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| microsoft-kiota-abstractions | 1.10.1 | MIT |
| microsoft-kiota-authentication-azure | 1.10.1 | MIT |
| microsoft-kiota-http | 1.10.1 | MIT |
| microsoft-kiota-serialization-form | 1.10.1 | MIT |
| microsoft-kiota-serialization-json | 1.10.1 | MIT |
| microsoft-kiota-serialization-multipart | 1.10.1 | MIT |
| microsoft-kiota-serialization-text | 1.10.1 | MIT |
| msal | 1.36.0 | MIT |
| msal-extensions | 1.3.1 | MIT |
| msgraph-core | 1.3.8 | MIT |
| msgraph-sdk | 1.56.0 | MIT |
| multidict | 6.7.1 | Apache-2.0 |
| narwhals | 2.20.0 | MIT |
| networkx | 3.6.1 | BSD-3-Clause |
| numpy | 2.4.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| oauthlib | 3.3.1 | BSD-3-Clause |
| openai | 2.21.0 | Apache-2.0 |
| opentelemetry-api | 1.41.1 | Apache-2.0 |
| opentelemetry-sdk | 1.41.1 | Apache-2.0 |
| opentelemetry-semantic-conventions | 0.62b1 | Apache-2.0 |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause |
| pandas | 3.0.2 | BSD-3-Clause |
| pip | 26.1 | MIT |
| propcache | 0.4.1 | Apache-2.0 |
| protobuf | 6.33.5 | BSD-3-Clause |
| pyasn1 | 0.6.3 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.3 | MIT |
| pydantic_core | 2.46.3 | MIT |
| PyJWT | 2.12.1 | MIT |
| pyparsing | 3.3.2 | MIT |
| **pySigma** | **1.3.3** | **LGPL-2.1-only** |
| python-dateutil | 2.9.0.post0 | Apache-2.0 OR BSD-3-Clause |
| **pyvelociraptor** | **0.1.9** | **GPL** |
| PyYAML | 6.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| requests | 2.32.5 | Apache-2.0 |
| requests-oauthlib | 2.0.0 | ISC |
| rpds-py | 0.30.0 | MIT |
| setuptools | 79.0.1 | MIT (unspecified in metadata; upstream is MIT) |
| six | 1.17.0 | MIT |
| sniffio | 1.3.1 | MIT OR Apache-2.0 |
| soupsieve | 2.8.3 | MIT |
| SQLAlchemy | 2.0.46 | MIT |
| std-uritemplate | 2.0.8 | Apache-2.0 |
| timesketch-api-client | 20260209 | Apache-2.0 |
| timesketch-import-client | 20260108 | Apache-2.0 |
| tqdm | 4.67.3 | MPL-2.0 AND MIT |
| types-PyYAML | 6.0.12.20260408 | Apache-2.0 |
| typing-inspection | 0.4.2 | MIT |
| typing_extensions | 4.15.0 | PSF-2.0 |
| tzlocal | 5.3.1 | MIT |
| urllib3 | 2.6.3 | MIT |
| Werkzeug | 3.1.6 | BSD-3-Clause |
| wheel | 0.47.0 | MIT |
| xlrd | 2.0.2 | BSD |
| yarl | 1.23.0 | Apache-2.0 |
| zipp | 3.23.1 | MIT |

---

## 4. Frontend (vendored under `modules/nginx/html/`)

| Library | Version | License | Path |
|---|---|---|---|
| Tailwind CSS (browser build) | latest at vendor time | MIT | `js/tailwind.js` |
| Alpine.js | unspecified | MIT | `js/alpine.min.js` |
| flatpickr | 4.6.13 | MIT | `vendor/flatpickr/flatpickr.min.js` |
| tus-js-client | unspecified | MIT | `vendor/tus/tus.min.js` |

### Remote (CDN-loaded at runtime)

| Resource | License | Endpoint |
|---|---|---|
| Google Fonts (JetBrains Mono, Orbitron) | SIL OFL 1.1 (both) | `fonts.googleapis.com/css2?...` |

> All first-party JS in `js/*.js` is project code (no declared license — see
> top-level note about adding a project `LICENSE` file).

---

## 5. Docker images (third-party)

| Image | Tag | License | Provenance |
|---|---|---|---|
| `python` | `3.11-slim` | PSF-2.0 (Python) + Debian (base layers) | Docker Hub Official |
| `ubuntu` | `22.04` | Multiple (Ubuntu base; mostly GPL/MIT/BSD) | Docker Hub Official |
| `tusproject/tusd` | `latest` | MIT | tus.io / GitHub |
| `docker.elastic.co/elasticsearch/elasticsearch` | `9.3.3` | **Elastic License v2 OR SSPL v1** | Elastic |
| `docker.elastic.co/logstash/logstash` | `9.3.3` | **Elastic License v2 OR SSPL v1** | Elastic |
| `docker.elastic.co/kibana/kibana` | `9.3.3` | **Elastic License v2 OR SSPL v1** | Elastic |
| `ghcr.io/dfir-iris/iriswebapp_app` | `v2.4.27` | **LGPL-3.0** | DFIR-IRIS |
| `ghcr.io/dfir-iris/iriswebapp_db` | `v2.4.27` | LGPL-3.0 (app) + PostgreSQL License (DB) | DFIR-IRIS |
| `ghcr.io/dfir-iris/iriswebapp_nginx` | `v2.4.27` | LGPL-3.0 (config) + BSD-2-Clause (nginx) | DFIR-IRIS |
| `rabbitmq` | `3-management-alpine` | MPL-2.0 | Docker Hub Official |
| `nginx` | `alpine` | BSD-2-Clause | Docker Hub Official |
| `postgres` | `15` | PostgreSQL License (BSD/MIT-like) | Docker Hub Official |
| `redis` | `7-alpine` | BSD-3-Clause (7.4 still BSD; 7.6+ moves to RSALv2/SSPL dual) | Docker Hub Official |
| `opensearchproject/opensearch` | `2.11.0` | Apache-2.0 | OpenSearch project |
| `us-docker.pkg.dev/osdfir-registry/timesketch/timesketch` | `20260326` | Apache-2.0 | Google OSDFIR |
| `log2timeline/plaso` | `20260119` | Apache-2.0 | Plaso project |
| `portainer/portainer-ce` | `2.39.1` | zlib | Portainer |
| `portainer/agent` | `2.33.6` | zlib | Portainer |
| `alpine` | `latest` | MIT (Alpine base) | Docker Hub Official |

> **Elastic stack flag:** Elastic License v2 prohibits offering ES/Logstash/Kibana
> as a managed/hosted service to third parties. Internal use is fine.
> SSPL is similarly restrictive for SaaS. If you ship this product to customers
> who run it themselves, you're OK. If you sell it as a hosted service,
> you need an Elastic commercial agreement.

---

## 6. Custom-built images

### `intact-backend:1.0.0` — `modules/backend/Dockerfile`
- Base: `python:3.11-slim` (PSF-2.0 + Debian)
- apt: `docker.io` (Apache-2.0), `curl` (curl license — MIT-like), `ca-certificates` (MPL-2.0)
- Docker Compose plugin v2.27.0 — Apache-2.0
- Project code: **no declared license** (see top-level note)

### `velociraptor-server:0.76.3` — `modules/velociraptor/Dockerfile`
- Base: `ubuntu:22.04`
- apt: `rsync` (GPL-3.0), `curl`, `ca-certificates`
- Bundled Velociraptor v0.76.3 binaries (Linux, macOS, Windows): **AGPL-3.0**

---

## 7. External binaries downloaded by `install.sh` / `lib/docker.sh`

| Source | Version | License | Purpose |
|---|---|---|---|
| Velocidex/velociraptor | v0.74.1 | **AGPL-3.0** | Offline Collector binaries |
| Velocidex/velociraptor | v0.75 | AGPL-3.0 | `velociraptor-collector` template |
| SigmaHQ/sigma | HEAD of `main` | **DRL 1.1** (Detection Rule License) | SIGMA rules for Azure detection |

---

## 8. Tools shipped under `data/tools/` (68 files)

| Tool / file | License | Notes |
|---|---|---|
| **Eric Zimmerman tools** (`AmcacheParser`, `AppCompatCacheParser`, `bstrings`, `EvtxECmd`, `JLECmd`, `LECmd`, `MFTECmd`, `PECmd`, `RBCmd`, `RECmd`, `RecentFileCacheParser`, `SBECmd`, `SrumECmd`, `SumECmd`, `iisGeolocate`, `rla`, `hasher`) | MIT | All from github.com/EricZimmerman |
| **Sysinternals** (`autorunsc64.exe`, `disk2vhd64.exe`, `procexp64.exe`, `sigcheck64.exe`, `strings64.exe`, `Sysmon64.exe`) | **Microsoft Sysinternals EULA** | Free use; **redistribution restricted** — re-vendoring in our repo is technically a EULA violation |
| `sysmonconfig-export.xml` | **CC-BY-4.0** | SwiftOnSecurity sysmon-config; attribution required |
| `chainsaw_all_platforms+rules+examples.zip` | GPL-2.0 | WithSecure Labs |
| `EvtxHussar1.8_windows_amd64.zip` | Apache-2.0 | github.com/yarox24/EvtxHussar |
| `hayabusa-3.8.1-*` | GPL-3.0 | Yamato Security |
| `takajo-2.15.1-win-x64.zip` | GPL-3.0 | Yamato Security |
| `zircolite_win_x64_2.40.0.7z` | GPL-3.0 | wagga40 / Zircolite |
| `yara-4.5.5-2368-win{32,64}.zip` | BSD-3-Clause | VirusTotal |
| `yara-forge-rules-{core,extended,full}.zip` | Mixed (per-rule; mostly GPL/Apache/MIT) | YARAforge aggregator |
| `yara-rules-full.yar`, `full_linux_file.yar.gz`, `full_windows_file.yar.gz` | Mixed (per-rule) | Aggregated rule sets |
| `Velociraptor-Artifacts-main.zip`, `Velociraptor.Sigma.Artifacts.zip`, `Velociraptor_Triage_v0.1.zip`, `Windows.Registry.Hunter.zip`, `artifact_exchange_v2.zip` | Apache-2.0 | Velociraptor project artifacts |
| `DetectRaptorVQL.zip` | Apache-2.0 | github.com/det-lab/DetectRaptor |
| `Rapid7LabsVQL.zip` | BSD-3-Clause | Rapid7 Labs VQL artifacts |
| `velociraptor-v0.76.1-{linux,darwin,windows}-*` | **AGPL-3.0** | Velociraptor binaries |
| `velociraptor-collector` | AGPL-3.0 | Velociraptor offline collector |
| `winpmem_mini_x64_rc2.exe` | Apache-2.0 | Velocidex / WinPMEM |
| `volatility-master.zip` | **VSL** (Volatility Software License — GPL-2.0-like) | Volatility Foundation |
| `FTKImager-commandline.zip` | **AccessData EULA (proprietary)** | Free for use; redistribution forbidden — re-vendoring is a EULA violation |
| `loki-linux-x86_64-v2.10.0.tar.gz` | GPL-3.0 | Nextron Systems / LOKI |
| `thor-lite-windows_10.7.30.zip` | **Nextron THOR EULA (proprietary)** | Free for personal/evaluation use; redistribution forbidden |
| `Windows-KB890830-x64-MRT.exe` | **Microsoft EULA** | Microsoft Malicious Software Removal Tool — redistribution restricted |
| `windows_hardening-master.zip` | MIT | github.com/0x6d69636b/windows_hardening |
| `PingCastle_3.3.0.1.zip` | **Non-commercial license** | Free for internal use only; **commercial deployment requires a paid license** |
| `lolrmm.csv` | MIT | github.com/magicsword-io/LOLRMM |
| `false_positives.csv` | (as part of YARA / Hayabusa configs) | matches host project license |
| `linforce.sh` | (script, no embedded license) | Treat as project-internal |
| `PersistenceSniper.zip` | MIT | github.com/last-byte/PersistenceSniper |
| `lastactivityview.zip`, `browsinghistoryview-x64.zip` | **NirSoft freeware EULA** | Free use; **redistribution forbidden in commercial product** |
| `SQLiteHunter.zip` | unspecified | github project; check upstream LICENSE before redistributing |
| `takajo-2.15.1-win-x64.zip` | GPL-3.0 | Yamato Security |

> **Action required for any commercial distribution of Intact.AI:**
> remove or replace the proprietary-EULA tools above (Sysinternals, FTK
> Imager, THOR Lite, NirSoft viewers, Windows MRT, PingCastle), or
> arrange the appropriate commercial licenses with each vendor.
> Pulling them from the vendor at install time on the customer's
> machine is usually a clean workaround — the customer accepts each
> EULA themselves.

---

## 9. Build & runtime versions (observed)

| Component | Version | License |
|---|---|---|
| Backend Python | 3.11.15 | PSF-2.0 |
| TimeSketch worker Python | 3.12.3 | PSF-2.0 |
| TimeSketch postgres | 15.17 | PostgreSQL License |
| TimeSketch redis | 7.4.8 | BSD-3-Clause |
| TimeSketch nginx | 1.29.8 | BSD-2-Clause |
| Project nginx | 1.29.8 | BSD-2-Clause |
| IRIS postgres | 12.22 | PostgreSQL License |
| IRIS RabbitMQ | 3.13.7 | MPL-2.0 |
| Plaso (log2timeline) | 20260119 | Apache-2.0 |

---

## 10. Compliance summary — what to actually worry about

1. **No project `LICENSE` file.** Add one (Apache-2.0 or MIT recommended)
   before any external distribution.
2. **Elastic stack** (`elasticsearch`/`logstash`/`kibana` 9.3.3) under
   Elastic License v2 — fine for self-hosted use; not OK for SaaS resale
   without an Elastic commercial agreement.
3. **AGPL-3.0** on Velociraptor server + collector binaries — running
   over a network is "distribution" under AGPL; you must offer source
   to network users on request. Velociraptor source is public, so this
   is satisfied by linking to the upstream repo in the UI.
4. **GPL-3.0 / GPL-2.0** in tools (Hayabusa, Takajo, Zircolite, LOKI,
   Volatility, Chainsaw, rsync) — you can ship them; you cannot
   statically link them into your own code without that code becoming
   GPL.
5. **LGPL-3.0** in IRIS web app — fine to use the published image.
   Modifications to IRIS source code itself trigger source-distribution.
6. **Proprietary EULAs** (Sysinternals, FTK, THOR Lite, NirSoft viewers,
   Windows MRT, PingCastle) — **legally cannot be redistributed in this
   repo as bundled binaries.** Highest-priority compliance item: pull
   from each vendor at install time instead of vendoring.