# Troubleshooting — Lab #07

## Docker / Elasticsearch / Kibana

**`max virtual memory areas vm.max_map_count [65530] is too low`**

Elasticsearch 8 refuses to start unless the host allows enough memory-map areas for the Lucene
index. This is the most common Elasticsearch-on-Docker failure, and it presents as a container
that exits immediately or restarts in a loop:

```powershell
docker compose logs elasticsearch | Select-String "max_map_count"
```

**Linux / Ubuntu / WSL2** — raise the limit persistently:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
```

**Docker Desktop on Windows** — no host change is normally needed, because Elasticsearch runs
inside a Linux VM whose limit is already high. If you still hit it, raise the WSL2 limit in
`%UserProfile%\.wslconfig`:

```ini
[wsl2]
kernelCommandLine = "sysctl.vm.max_map_count=262144"
```

then run `wsl --shutdown` and restart Docker Desktop. Verify the limit the container actually
sees:

```powershell
docker exec es sysctl vm.max_map_count
```

The shipped stack avoids this by design: a pinned 512 MB heap inside a 2 GB container stays well
inside the default limit. You will only meet it on a bare Ubuntu server or a constrained host.

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

**Data view says "This dashboard has no data" / a data view is not found**

Kibana data views are field-capable objects: they only enumerate a field once an index matching
their pattern has actually been written. Consequences, all common on a first run:

- **The pattern must match a real index.** `security-alerts-*` shows an empty field list until
  at least one `security-alerts-YYYY-MM-DD` index exists. Generate and correlate first, then
  open Discover: `python -m src.main generate-samples --scenario all`, `ingest`,
  `correlate --run-once`.
- **A time field is mandatory.** A data view with no time field cannot be used by Discover or by
  any time-based panel. This lab sets `timestamp` for `security-alerts-*` and `@timestamp` for
  `normalized-events-*`. Verify:
  ```powershell
  curl.exe -s -H "kbn-xsrf: x" "http://localhost:5601/api/data_views/data_view/siem-security-alerts"
  # .data_view.timeFieldName must be "timestamp"
  ```
  If it is empty, delete the data view in *Stack Management → Data views*, re-run
  `python -m src.main import-dashboard`, and recreate it against the live index.
- **The dashboard time range must cover the data.** The SOC Triage Board defaults to `now-7d`.
  If you replay a lab with timestamps older than that, or the clock is wrong, every panel is
  empty even though documents exist. Widen the range to `now-30d` while debugging.
- **Fields appear only after a refresh.** Add a field by re-opening the data view, or hit
  *Refresh fields* in the field list popup.

**Events are rejected as "in the future", or correlation windows look empty (timezone drift)**

Every timestamp in the lab is normalised to UTC, and the schema enforces
`@timestamp <= ingest_timestamp`. A source host whose clock is ahead therefore produces events
that are rejected or shifted, which looks like a correlation rule silently missing an attack.

```powershell
# what the parser produced vs. when it was ingested
curl.exe -s "http://localhost:9200/normalized-events-*/_search?size=3&sort=@timestamp:desc" |
  Select-String "@timestamp","ingest_timestamp"

# host clock vs. the container's idea of now
Get-Date -Format o
docker exec es date -u +%Y-%m-%dT%H:%M:%SZ
```

- Fix NTP on the log source host first; that is the root cause.
- Confirm the container runs in UTC: `docker-compose.yml` sets no `TZ`, so the JVM uses UTC.
  Aware that year-less syslog lines (`Sep 25 11:14:54 …`) have **no year**, so
  `src/utils/time_utils.py` infers the current UTC year. Replaying a log file captured in a
  previous December will therefore land in the wrong year. Use the sample generator, or pass
  ISO-8601 timestamps, for anything you intend to replay.
- Kibana displays times in the **browser's** timezone, not the stored one. If a student reports
  an hour that disagrees with the alert, check their profile timezone before suspecting the data.

## Filebeat (optional live ingestion)

The lab does not require Filebeat: `logs/generated` plus `ingest` is the documented local path,
and nothing in `docker-compose.yml` runs Filebeat. This section only applies if you choose the
optional live path from `docs/TRAINING_PLATFORM.md`.

**Filebeat re-ships the same log lines and the alert counts inflate**

Filebeat persists its read position in a **registry** file, and re-reads from there on restart. If
the registry is deleted, reset, or pointed at a different data directory, Filebeat re-reads the
whole file from the beginning. Because ingestion is idempotent (deterministic document IDs), that
alone is harmless — but if the log file has also been rotated or re-generated with new timestamps,
the same attack appears twice with different document IDs, and the event count drifts away from
the canonical 50.

```powershell
# where is the registry, and what has it recorded?
Get-Content .\.filebeat\registry.json -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "registry.json" -Path C:\ProgramData\Filebeat, .\logs\live -ErrorAction SilentlyContinue

# do we have duplicates?
python -m src.main stats
```

- Fix A — resume from the recorded offset (normal restart): start Filebeat with the **same**
  `-path.data` and `-registry` directories it used before. Changing either one forces a re-read.
- Fix B — deliberately re-read from the start after fixing a config: stop Filebeat, delete only
  `registry.json` (never the log files), then start it again.
- Fix C — you changed the log source's timestamps rather than its content, and now hold two
  copies of the same incident. Reset the lab dataset and replay once:
  `python scripts\reset_lab_data.py --yes`, then `generate-samples`, `ingest`, `correlate`.
- Always ship each file to exactly one place. Feeding both a file tail and a Filebeat copy of the
  same events is the usual cause of a doubled alert count.

**Filebeat cannot write to Elasticsearch, or the index has the wrong mapping**

Confirm the output target and that the raw template exists:

```powershell
curl.exe -s "http://localhost:9200/_index_template" | Select-String "raw-events"
```

`raw-events` is installed alongside the other two templates by
`python -m src.main init-templates`. If it is missing, re-run that command. Live lines are stored
raw on purpose: the Python engine performs normalization, so the parsers and correlation rules
behave identically for sample and live data.

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
