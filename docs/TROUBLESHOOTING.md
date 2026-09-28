# Troubleshooting — Lab #07

## Docker / Elasticsearch / Kibana

**`docker` is not recognized**
Docker Desktop is not installed or not on `PATH`. Install Docker Desktop, then open a new
PowerShell window. `.\scripts\setup.ps1 -SkipDocker` lets you continue without Docker (unit
tests and `--dry-run` ingestion still work).

**Elasticsearch container exits immediately**
Single-node Elasticsearch needs a pinned heap and enough container memory for off-heap buffers:
with `ES_JAVA_OPTS=-Xms512m -Xmx512m` give the container at least **2 GB** (Kibana 768 MB+).
Anything smaller gets OOM-killed with exit code 137 — see the dashboard-blank-panels entry below,
which is usually the symptom you notice first.

```powershell
docker compose logs elasticsearch | Select-Object -Last 40
```

Look for `bootstrap checks failed` (raise the Docker Desktop memory limit) or
`OutOfMemoryError` (raise `mem_limit`). To confirm the heap is pinned:

```powershell
docker exec es ps -o args= -C java | Select-String "Xm"
docker stats es --no-stream --format "{{.MemUsage}} ({{.MemPerc}})"
```

**`curl http://localhost:9200` fails but the container is "Up"**
Elasticsearch needs 30–90 s on first boot. `setup.ps1` already waits and retries. Check:

```powershell
docker compose ps
Invoke-RestMethod http://localhost:9200/_cluster/health
```

`status: red` means no primary shard is allocated — usually still starting or a data-volume
permission problem. `yellow` is expected and acceptable for a single-node lab (replicas cannot
be allocated with one node).

**Kibana is slow or shows "Kibana server is not ready yet"**
Kibana waits for Elasticsearch and then optimizes/reindexes on first start; 2–5 minutes is
normal.

```powershell
docker compose logs kibana | Select-Object -Last 40
Invoke-RestMethod http://localhost:5601/api/status
```

**Dashboard shows "Could not find the data view: -" (or panels with no data)**
The saved objects are missing Kibana's data-view pointer. Kibana stores a visualization's data
view **twice**: as a `references` entry *and* as an `indexRefName` pointer inside
`kibanaSavedObjectMeta.searchSourceJSON`. On load it only resolves the data view from the
`indexRefName` (see `@kbn/data-plugin/common/search/search_source/inject_references.js`), so a
file that has the reference but no `indexRefName` loads with an empty data view — which renders
as the literal `-`.

Inspect it:

```powershell
curl.exe -s -H "kbn-xsrf: x" "http://localhost:5601/api/saved_objects/visualization/siem-vis-alerts-by-severity"
# searchSourceJSON must contain: "indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"
# and must NOT contain a literal "index"
```

Fix: never hand-edit `dashboards/soc-triage-board.ndjson`. Regenerate and validate it:

```powershell
python scripts/build_dashboard.py          # regenerate
python scripts/build_dashboard.py --check  # validate references
python -m src.main import-dashboard        # re-import (idempotent)
```

The generator's validator fails if any visualization/dashboard is missing `indexRefName`, points
at the wrong data view, or carries a dangling reference. `tests/test_dashboard_ndjson.py` guards
the same invariant. Both data views must exist first: `security-alerts-*` (time field
`timestamp`) and `normalized-events-*` (time field `@timestamp`).

**Dashboard panels are blank, empty, or stuck on "loading" (most common lab failure)**
The panels are almost always fine — **Elasticsearch is being OOM-killed**. When ES dies,
Kibana reports `savedObjects service is now unavailable` and the dashboard cannot resolve its
panels or their data, so the panels spin forever. The dashboards load normally again a minute
later, which makes the problem look intermittent and easy to miss.

Confirm it:

```powershell
docker compose logs elasticsearch | Select-String "exit code 137"   # 137 = SIGKILL = OOM
docker inspect es --format "{{.RestartCount}} {{.State.OOMKilled}}"  # restarts > 0 = it died
docker stats es --no-stream --format "{{.MemUsage}} ({{.MemPerc}})"  # pinned at 100% = too tight
Invoke-RestMethod http://localhost:5601/api/status | Select-Object -ExpandProperty status
```

Fix: Elasticsearch needs a pinned heap plus room for off-heap memory. With
`ES_JAVA_OPTS=-Xms512m -Xmx512m` the container must have **at least 2 GB** — a 512 MB or 1 GB
limit gets OOM-killed because the JVM plus direct/native buffers exceed it. If ES is
auto-sizing its heap to a few hundred MB, it is running without `ES_JAVA_OPTS`. Kibana needs
768 MB+. Always confirm with `docker stats` that neither container is pinned near 100%.

**Port 9200 or 5601 already in use**
Another Elasticsearch/Kibana (often a native install) is bound to the port. Stop it, or change
the host-side mapping in `docker-compose.yml` (`"9201:9200"`) and set `ES_PORT=9201` for the
application.

**Elasticsearch data persists stale mappings after a mapping change**
Field mappings cannot be changed in place. For a lab reset:

```powershell
docker compose down
docker volume ls | Select-String siem
docker volume rm <project>_es-data
docker compose up -d
```

## Python application

**`ModuleNotFoundError: No module named 'src'`**
Run commands from the repository root (where `src/` lives), or use `python -m src.main ...`
instead of `python src/main.py ...`.

**`ModuleNotFoundError: No module named 'elasticsearch'` (or `yaml`, `apscheduler`)**
Activate the venv and install dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**`SchemaError` raised during ingestion**
See "Events are rejected as invalid" below.

**`CorrelationEngine` finds no events**
The cycle queries only the last `lookback_window_minutes` (120) minutes. Sample logs are
anchored a few minutes in the past, so regenerate and ingest immediately before correlating:

```powershell
python -m src.main generate-samples --scenario brute_force
python -m src.main ingest --log-dir .\logs\generated
python -m src.main correlate --run-once
```

**No alerts even though events exist**
Check, in order: (1) `python -m src.main stats` shows `normalized-events-*` documents;
(2) the rule is `enabled` in `config/app-config.yaml`; (3) `min_failures` is actually reached
(count events per `src_ip` in Kibana Discover); (4) a previous cycle already alerted —
delete `data\dedup-cache.json` to replay.

**Alerts are duplicated**
Should not happen: both event and alert document IDs are deterministic, and dedup suppresses
repeats within 30 minutes. If you see duplicates, the engine is writing to a different index
pattern (check `security-alerts-*` for multiple date indices) or the dedup cache path is not
writable. `data\dedup-cache.json` must be creatable in the working directory.

**`APScheduler is not installed`**
`pip install apscheduler`, or use `python -m src.main correlate --run-once` for a single cycle.

## Ingestion and parsing

**"Unable to detect source type"**
The filename and first line are not recognized. Pass the type explicitly:

```powershell
python -m src.main ingest --file .\logs\custom.log --source-type linux_auth
```

**Many lines are skipped**
Skipped lines are normal for unrelated syslog traffic (cron, sshd session open, kernel). Set
`--log-level DEBUG` to see each unparsed line:

```powershell
python -m src.main ingest --log-dir .\logs\generated --log-level DEBUG
```

**Events are rejected as invalid (`@timestamp cannot be in the future`)**
The source clock is ahead of the ingestion host, or syslog timestamps lack a year and were
parsed as this year. Fix NTP on the source host; `normalize_to_utc` already rolls classic syslog
timestamps back a year when they are more than a minute ahead of now.

**Windows events are all skipped**
The input must be one JSON object per line. A raw `.evtx` binary file cannot be parsed directly
— export it first:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 500 |
    Select-Object TimeCreated, Id, ComputerName, EventData |
    ConvertTo-Json -Depth 5 | Set-Content .\logs\samples\windows-export.json
```

**Re-running ingest duplicates events**
It should not: IDs are SHA-256 of `host|timestamp|event_type|src_ip|raw_event`. If duplicates
appear, the raw text differs between runs (e.g. timestamps regenerated) — ingest the same file
without regenerating it.

## Kibana

**Dashboard import fails**
`Kibana → Stack Management → Saved Objects → Import → dashboards\soc-triage-board.ndjson`.
A partial import can leave duplicate IDs; delete the objects named `siem-*` and re-import.
The NDJSON targets Kibana 8.13 — do not import into a much older version.

**Panels show "No data"**
(1) The time picker is outside the alert window (set it to `Last 24 hours`);
(2) `security-alerts-*` has no documents yet — run `correlate --run-once`;
(3) the data view was not created: `Stack Management → Data Views` should list
`security-alerts-*` and `normalized-events-*` after import.

**`src_ip` is not aggregatable**
It is mapped as an Elasticsearch `ip` field. Documents indexed before the template existed may
have it as text — reindex after applying `config/elasticsearch-template.json`.

## Tests

**`pytest` collects nothing**
Run `python -m pytest tests -q` from the repository root.

**Tests fail with `FileNotFoundError` for `tests/data/*.json`**
Run pytest from the repository root; the data-driven rule tests resolve paths relative to it.

**Coverage below target**
```powershell
python -m pytest tests --cov=src --cov-report=term-missing
```
Focus on the untested branches listed in the report; the parsers and rules are the graded areas.

## Getting help

When reporting a problem include: the exact command, the command output, the relevant
`logs\app.log` lines, `python -m src.main stats` output, and whether Docker was running.
