# Deployment: local development vs the shared server

This document distinguishes two environments that are **not** interchangeable.

| | Local development | Shared company server |
|---|---|---|
| Purpose | Instructor building and verifying the lab | Serving a lab session on a host shared with ~9 other labs |
| Host | Windows workstation, Docker Desktop | Ubuntu 26.04 LTS, Docker Engine, many labs per host |
| Compose project | `bcssl-siem-lab07` | `bcssl-siem-lab07` |
| Discovery | Interactive, single user | Remote, scripted, must be reproducible |
| Secrets | Generated locally by `scripts/setup.ps1` | Generated **on the server** |

---

## 1. Local development

Unchanged from before. Docker Desktop, loopback only, nothing reachable from
another machine.

```powershell
.\scripts\setup.ps1        # once
.\scripts\start_lab.ps1    # each session
```

Both scripts are **Windows PowerShell** and hardcode a Windows virtual
environment (`.\.venv\Scripts\python.exe`). They do not run under `pwsh` on
Ubuntu; on the server the equivalent steps are written out longhand in
section 4.

---

## 2. What changed for server deployment

Five mechanical changes were made so this lab can coexist with other labs on one
Docker host. None of them changes what the lab does.

### 2.1 Every Docker name is explicit

Compose normally derives the project name from the containing directory. In this
deployment that directory is a person's (`/opt/bcssl-teqm/dhamini`), which is
both generic and capable of colliding with a sibling lab. Container names are
worse: `container_name` is unique across the **entire Docker host**, not per
project, so the previous generic `es` and `kibana` would make `docker compose up`
fail outright the moment any other lab used the same word.

| Resource | Name |
|---|---|
| Compose project | `bcssl-siem-lab07` |
| Containers | `bcssl-siem07-es`, `bcssl-siem07-kibana` |
| Network | `bcssl-siem07-net` |
| Volumes | `bcssl-siem07-es-data`, `bcssl-siem07-kibana-config` |

> **Consequence to be aware of.** The explicit volume names differ from the
> auto-generated ones an earlier revision used. The previous volumes still exist
> and still hold their data — nothing is deleted — but the stack now resolves to
> the new names and will therefore start against an **empty** volume until data
> is loaded. This has not been done on this workstation, deliberately: it is a
> data operation and belongs in the deployment phase, not in a hardening change.
> See section 4.3.

### 2.2 The declared network is now actually used

`docker-compose.yml` declared a `siem-lab-net` network that no service ever
referenced, so Compose silently used its auto-generated default and the
declared name did nothing. Both services now attach to it explicitly, verified
by inspecting the rendered configuration rather than by reading the YAML.

### 2.3 Resource limits

| Service | CPU | Memory | Why |
|---|---|---|---|
| Elasticsearch | 2 | 2g | Memory is unchanged and deliberate (see below). CPU is capped so an uncapped reindex or wide aggregation cannot starve the other labs on a 16-core host. |
| Kibana | 1 | 1g | Kibana is a Node.js process; 768m left almost no headroom for importing saved objects or aggregating the full dataset. |

Total for this lab: **3 CPU, 3 GB of the host's 16 cores and 30 GB.** Measured
steady-state use is far below that — around 0.4–0.8 CPU and 232 MB of the
Elasticsearch heap — so these are burst ceilings, not a reservation.

**The Elasticsearch heap stays at 512 MB on purpose.** It is not a rounded
figure. A 512 MB heap plus roughly 1 GB of off-heap buffers fits inside 2 GB; if
the heap is raised without raising the container limit proportionally, the JVM
and its direct buffers cross the cgroup limit, the OOM killer sends SIGKILL
(exit 137), and Elasticsearch restarts in a loop that presents to a student as a
blank dashboard.

### 2.4 Bounded container logging

Docker's default `json-file` driver does not rotate and does not cap. On a host
whose root filesystem is shared with nine other labs, that is a way to fill the
disk. Both services now log with `max-size: 10m`, `max-file: 3` — roughly 60 MB
of container logs for this lab in total. The Docker daemon's global
configuration is untouched; this is per-service.

### 2.5 The training platform no longer picks its own port

`scripts/serve_training.py` previously walked forward from the requested port
through `port+19` and started on the first free one, printing a single line. On
a shared host that is wrong: it can land on another lab's port or a firewalled
one, and it leaves the process listening somewhere its reverse proxy, systemd
unit and documentation do not expect. It now **uses the requested port or exits
non-zero**, naming the port and how to resolve it. Local development is
unaffected whenever the port is free, which is the normal case.

---

## 3. Ports and what must stay private

| Port | Service | Binding | Status |
|---|---|---|---|
| 9200 | Elasticsearch | `127.0.0.1` | **Must stay private.** `xpack.security.enabled=false`, so anything that reaches this port has unauthenticated cluster administration, including deleting the shared dataset. |
| 5601 | Kibana | `127.0.0.1` | Private. **How students reach Kibana is an open decision — see section 5.** |
| 8080 | Training platform | assign explicitly | The intended student entry point. Assign a port explicitly with `--port`; it no longer self-selects. |

Elasticsearch and Kibana must remain on `127.0.0.1`. Do not widen these
bindings. That is not a style preference: it is currently the only control
preventing a student on the network from deleting the dataset the class is
investigating.

---

## 4. Deploying to the server

Not yet performed. This is the intended sequence; steps marked **(needs server
admin)** require privileges this project does not assume it has.

### 4.1 Prerequisites

- **(needs server admin)** `vm.max_map_count` must be at least `262144`.
  Elasticsearch refuses to start otherwise. This is a kernel sysctl, so it
  needs elevated privileges; it cannot be set from inside a container. It is
  also a whole-host setting, so it must be agreed rather than assumed.
- **(needs server admin)** Confirm the deployment directory is writable by the
  account that will run the platform, and confirm `docker` group membership.
- **(needs server admin)** Confirm a free host port for the training platform
  and inventory ports across all labs.

### 4.2 Copy the project

Copy the repository **without** `.venv`, `.git`, `__pycache__`,
`.pytest_cache`, `logs/app.log*`, or `docs/report-assets/`. The Windows
virtual environment is unusable on Linux and the `.git` directory carries
answer-key history that should not travel.

Two things are git-ignored and therefore must be transferred deliberately:
`data/answer-key.json` (required for grading) and `logs/generated/enterprise-14d_*`
(required to rebuild the dataset). Move them by a secure channel.

### 4.3 Secrets, then the stack

Generate the three Kibana keys **on the server**:

```bash
docker compose run --rm kibana bin/kibana-encryption-keys
```

Write them into a `.env` next to the compose file. Do not copy the workstation
`.env`: the two hosts would then hold the same keys over different saved-object
stores, and either could decrypt the other's Kibana sessions.

```bash
docker compose up -d
docker compose ps          # both services must reach "healthy"
```

Expect an empty cluster: the volume names are new (section 2.1). Load the
canonical dataset, ingesting **by file** rather than by directory so the
mixed-dataset guard cannot be triggered:

```bash
python -m src.main init-templates
python -m src.main ingest --file logs/generated/enterprise-14d_auth.log
python -m src.main ingest --file logs/generated/enterprise-14d_windows.jsonl
python -m src.main ingest --file logs/generated/enterprise-14d_firewall.log
python scripts/correlate_range.py --since 2026-09-16T00:00:00Z \
                                   --until 2026-09-30T00:00:00Z --expect-alerts 4
```

Verify before going further: **9,584 events, 4 alerts, 20 of 20 evidence event
IDs resolving.**

### 4.4 Dashboard and training platform

```bash
python -m src.main import-dashboard
python scripts/validate_scenarios.py
python scripts/create_admin.py          # interactive; needs a terminal (ssh -t)
```

Then run the platform on an explicitly chosen port:

```bash
python scripts/serve_training.py --port <assigned-port>
```

How that process is kept running (a service manager, restart-on-failure, log
handling) has **not** been decided or implemented. It is listed in section 5.

### 4.5 Rollback

- `docker compose down` — **never `down -v`**, which destroys the data volume.
- If the volume is lost, rebuild it from `logs/generated/enterprise-14d_*` using
  the commands in 4.3. This is why those files must be on the server.
- If `data/training.db` is lost, `data/answer-key.json` is intact, so accounts
  are recreated; **student progress history is the only unrecoverable data.**

---

## 5. Explicitly not done

Stating these plainly, because the gap between "documented" and "implemented" is
where deployment projects go wrong.

- **No classroom access architecture.** How students reach Kibana — per-student
  accounts, a read-only proxy, or something else — is an undecided question.
  `docs/DEPLOYMENT_MODES.md` sets out the options and the trade-offs. None is
  built. Until it is, the platform is reachable but the Discover half of the
  investigation loop is not.
- **No TLS and no xpack authentication.** Elasticsearch and Kibana run exactly as
  they do locally, with security disabled and loopback-bound. This is why the
  loopback binding matters and must not be widened. The Python client has no TLS
  or credential support, so enabling security would disconnect the engine rather
  than protect it; that work is not started.
- **No reverse proxy.** No nginx or other proxy is configured or shipped.
- **No service manager unit** for the training platform.
- **No automated backup** of `data/` or the volumes.
- **Volume migration for the renamed volumes** has not been done (section 2.1).
- **The repository must be private.** `docs/INSTRUCTOR_GUIDE.md` is tracked with
  answers in prose and answer-key material is reachable from earlier history.

None of the above is a defect in the lab. It is an accurate statement of how far
the deployment work has gone.
