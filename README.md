# SIEM Log Correlation Engine — Lab #07

**BlueCloud Softech Solutions — Cybersecurity Training Lab Series**

A working Security Information and Event Management (SIEM) engine. It ingests Windows
Security / Sysmon, Linux `auth.log`, and firewall syslog events, normalizes them into a
single validated event schema, correlates them with three detection rules, writes
deduplicated alerts to Elasticsearch, and surfaces them on a Kibana SOC Triage Board — with a
branded student training platform and five hands-on investigation scenarios layered on top.

Everything runs locally: two Docker containers and a Python virtual environment. No cloud
accounts, no API keys, no Kubernetes, no authentication system.

---

## Contents

- [Objective](#objective)
- [Key features](#key-features)
- [Architecture and data flow](#architecture-and-data-flow)
- [Technologies used](#technologies-used)
- [Quick start](#quick-start)
- [The three correlation rules](#the-three-correlation-rules)
- [The five investigation scenarios](#the-five-investigation-scenarios)
- [Training platform and Kibana usage](#training-platform-and-kibana-usage)
- [Example results](#example-results)
- [Testing and validation](#testing-and-validation)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Deployment notes](#deployment-notes)
- [Security notes](#security-notes)
- [Documentation](#documentation)

---

## Objective

Build a functional SIEM correlation engine that demonstrates the core detection-engineering
workflow used in production SOC tooling:

1. **Ingest** heterogeneous log sources (Windows Event Log, Linux `auth.log`, firewall syslog).
2. **Normalize** them into one schema so rules can be written once and run over any source.
3. **Correlate** individual events into higher-value security alerts using time-windowed rules.
4. **Deduplicate** alerts so an ongoing attack does not flood the analyst.
5. **Visualize** alerts on a Kibana dashboard and let an analyst drill from an alert straight
   back to the exact raw events that produced it.
6. **Teach** the workflow to students through five practical scenarios that are solvable only
   from data that actually exists in the cluster.

The lab deliberately includes two conditions that must **not** alert, so students learn to
challenge a detection rather than trust it.

---

## Key features

| Capability | Detail |
|---|---|
| **Multi-source parsing** | Windows Security/Sysmon (4624, 4625, 4672, 4688, 4689), Linux `auth.log` (sshd, sudo, PAM, cron), firewall syslog (Cisco ASA, UFW/kernel, Fortinet, Palo Alto) |
| **One normalized schema** | 13 fields, strict validation, UTC timestamps, deterministic SHA-256 document IDs for idempotent re-ingestion |
| **Three correlation rules** | Configurable thresholds, severities, and human-readable reasoning on every alert |
| **Deduplication** | 30-minute suppression window with evidence-growth re-alerting, persisted to a JSON cache and self-seeded from Elasticsearch |
| **Evidence drill-down** | Every alert stores `evidence_event_ids`; each ID resolves to the exact normalized event, including its original `raw_event` |
| **SOC Triage Board** | Generated (not hand-edited) Kibana saved objects with a `--check` validator that prevents the "Could not find the data view" regression |
| **Training platform** | Static HTML/CSS/JS + Python stdlib server. No backend, no database, no build step, no network calls at runtime |
| **Student answer checking** | Graded **server-side**; the instructor key never reaches the browser. Per-question verdict, targeted hints, unlimited retry, and a completion gate |
| **Five scenarios** | Each one is bound to real data and verified against the live cluster by an automated validator |
| **Reproducible sessions** | A reset step guarantees every session starts from the same canonical dataset (50 events / 4 alerts) |
| **Isolated test suite** | Runs entirely against an in-memory fake Elasticsearch — no Docker required |

---

## Architecture and data flow

```
  raw log lines                the generator writes five scenarios
  (auth.log, Windows EVTX,     to logs/generated/, or Filebeat ships
   firewall syslog)            live lines to raw-events-*
        │
        ▼
  ┌──────────────────┐
  │   src/           │   windows_sysmon.py  → event_type, user, host, process, command_line
  │  normalization/  │   linux_auth.py      → logon_failure / logon_success / privilege_escalation
  │  parsers +       │   firewall_syslog.py → network_connection, src_ip → dst_ip, ports
  │  schema          │   schema.py          → validation, document IDs, serialization
  └────────┬─────────┘
           │  schema-validated, UTC, deterministic _id
           ▼
   normalized-events-YYYY-MM-DD         (Elasticsearch index template)
           │
           ▼
  ┌──────────────────┐
  │  src/correlation │   rules.py          → 3 time-windowed detection rules
  │  engine          │   deduplication.py  → 30-min suppression + evidence growth
  │                  │   engine.py         → cycle orchestration, scheduler
  └────────┬─────────┘
           │  alert documents: rule_name, severity, reasoning, evidence_event_ids
           ▼
    security-alerts-YYYY-MM-DD          (Elasticsearch index template)
           │
           ├──────────────────────────────► Kibana "SOC Triage Board"
           │                                  (4 panels, security-alerts-*)
           │                                  drill-down to normalized-events-*
           ▼
  training/  (static platform, :8080)  ──►  5 investigation scenarios
                                                 │
                                                 └─ read-only access to the same
                                                    Elasticsearch and Kibana the
                                                    student is investigating
```

**Data view of the live stack:**

| Component | Port | Role |
|---|---|---|
| Elasticsearch 8.13.0 | 9200 | stores `normalized-events-*` and `security-alerts-*` |
| Kibana 8.13.0 | 5601 | SOC Triage Board, Discover, data views |
| Training platform | 8080 | student-facing scenarios, instructions, progress |
| Python engine | — | parsers, rules, dedup, CLI, scheduler |

---

## Technologies used

| Technology | Version | Why |
|---|---|---|
| Python | 3.10+ (developed on 3.12) | normalization, correlation, CLI, scheduler |
| Elasticsearch | 8.13.0 (pinned) | index storage, search, aggregations |
| Kibana | 8.13.0 | dashboards and data views |
| Docker Compose | — | runs the SIEM stack locally |
| `elasticsearch-py` | 8.13.0 | ES client |
| PyYAML | 6.0.1 | rule configuration |
| APScheduler | 3.10.4 | optional scheduled correlation cycle |
| `requests` | 2.31.0 | Kibana saved-objects API |
| pytest / pytest-cov | 8.2.0 / 5.0.0 | 396-test suite, no Docker needed |
| HTML / CSS / vanilla JS | — | training platform, no framework, no build step |
| Python stdlib `http.server` | — | serves the training platform |

The client library version is pinned to match the cluster. Elasticsearch clients send a
`compatible-with` header, and a 9.x client talking to an 8.13 server is rejected — so
`elasticsearch==8.13.0` must not be floated upward without upgrading the stack.

---

## Quick start

### One-time setup

```powershell
.\scripts\setup.ps1
```

Creates the virtual environment, installs `requirements.txt`, starts the Docker stack, waits
for it to become healthy, and installs the index templates.

### Every session after that

```powershell
.\scripts\start_lab.ps1
```

This brings the lab up in a known-good state: containers → health wait → index templates →
**clear the previous session's data** → generate samples → ingest → correlate → import the
dashboard → validate the scenarios → serve the training platform.

| Purpose | URL |
|---|---|
| **Training platform** (student entry point) | <http://localhost:8080> |
| **SOC Triage Board** | <http://localhost:5601/app/dashboards#/view/siem-soc-triage-board> |
| Kibana Discover (event drill-down) | <http://localhost:5601/app/discover> |
| Elasticsearch | <http://localhost:9200> |

Stop with `Ctrl+C` for the training platform and `docker compose stop` for the stack — the
Docker volumes keep the data.

### Manual equivalent

```powershell
# 1. Generate synthetic logs for all five scenarios (writes to .\logs\generated)
python -m src.main generate-samples --scenario all

# 2. Parse, validate and index into normalized-events-YYYY-MM-DD
#    Refused if .\logs\generated also holds enterprise-14d_* - one dataset per
#    directory. See docs/DATASET.md section 2.1.
python -m src.main ingest --log-dir .\logs\generated

# 3. Correlate once
python -m src.main correlate --run-once

# 4. Or run the scheduler (default: every 60s, Ctrl+C to stop)
python -m src.main correlate

# 5. Counts by type, severity, and rule
python -m src.main stats

# 6. Import the SOC Triage Board into Kibana (idempotent, overwrite=true)
python -m src.main import-dashboard
```

Useful flags: `--source-type linux_auth|windows_sysmon|firewall_syslog` (override detection),
`--file <path>` (single file), `--dry-run` (parse and validate without indexing),
`--log-level DEBUG`, `--kibana-url <url>` (env `KIBANA_URL`).

### Why each session needs a reset

The lab is written against one canonical dataset: **50 normalized events and 4 alerts**.
Re-ingesting without a reset does *not* reproduce it — the Windows sample records carry
millisecond timestamps taken from the clock at generation time, so their deterministic document
IDs change on every run and roughly six duplicate events accumulate per session (measured:
50 → 56 → 62). Alerts stay at 4 only because deduplication hides them, so the drift is easy to
miss, but `scripts/validate_scenarios.py` will fail.

```powershell
python scripts\reset_lab_data.py          # shows exactly which indices it would delete
python scripts\reset_lab_data.py --yes    # performs the reset
```

`start_lab.ps1` does this automatically when it finds data from an earlier session; pass
`-KeepLabData` to opt out. The reset only ever deletes the two regenerable lab indices and the
dedup cache — never the Elasticsearch or Kibana volumes, index templates, data views,
dashboards, or correlation configuration. It resolves the index patterns to concrete names
first, because Elasticsearch 8 refuses wildcard deletes by default, and it verifies the indices
are actually gone before reporting success.

---

## The three correlation rules

Thresholds live in [`config/app-config.yaml`](config/app-config.yaml) and are overridable by
environment variable. Full logic: [`docs/RULE_LOGIC.md`](docs/RULE_LOGIC.md).

### Rule 1 — Brute force suspected → `high`

Five or more failed logins from the same `src_ip` within the configured window, with **no**
successful login for that source in the window.

| Setting | Value |
|---|---|
| `min_failures` | `5` |
| `time_window_minutes` | `5` |
| `severity` | `high` |
| Evidence | every failed logon in the burst |

The rule deliberately suppresses itself when a success appears for the same source, handing the
incident to Rule 2 so a single attack is not reported twice.

### Rule 2 — Successful brute force → `critical`

A failed-login burst followed by a **successful** login from the same source IP, within the
configured window after the burst. This is an escalation of Rule 1, not a separate detector.

| Setting | Value |
|---|---|
| `success_window_minutes` | `10` |
| `severity` | `critical` |
| Evidence | the failures **and** the success event |

### Rule 3 — Post-logon suspicious execution → `high`

A successful login followed by a suspicious process execution on the **same host** within the
configured window. Configuration also lists benign `expected_processes`, so a service restart
does not look like an intrusion.

| Setting | Value |
|---|---|
| `time_after_login_minutes` | `2` |
| `severity` | `high` |
| `suspicious_processes` | `cmd.exe`, `powershell.exe`, `bash`, `/bin/bash`, `/bin/bash -i`, `nc` |
| `expected_processes` | `explorer.exe`, `svchost.exe`, `spoolsv.exe`, `cron`, `systemd-logind`, `sshd` |
| Evidence | the logon event and the process event |

### Deduplication

Alerts are keyed by a `dedup_key` derived from the rule and its scope. A repeat within
`alert_dedup_window_minutes` (`30`) is suppressed unless the alert has accumulated at least
`min_new_evidence_for_realert` (`2`) new evidence IDs, so a *growing* attack still surfaces.
The cache is stored in `data/dedup-cache.json` and is self-seeded from the alerts already in
Elasticsearch, so deleting the cache does not cause duplicates.

---

## The five investigation scenarios

All five run on the same SIEM and are solvable only from data that is actually in
Elasticsearch. The answer key is deliberately kept **outside** the served directory, in
[`docs/INSTRUCTOR_GUIDE.md`](docs/INSTRUCTOR_GUIDE.md).

| # | Scenario | Page | Detected by | Severity | Level |
|---|---|---|---|---|---|
| 1 | Brute Force Investigation | `training/scenarios/scenario-1-brute-force.html` | `brute_force` | high | Easy |
| 2 | Successful Login After Brute Force | `training/scenarios/scenario-2-successful-brute-force.html` | `successful_brute_force` | critical | Medium |
| 3 | Suspicious Post-Login Process Execution | `training/scenarios/scenario-3-post-login-execution.html` | `suspicious_process_post_login` | high | Medium |
| 4 | Linux Privilege Escalation and Reverse Shell | `training/scenarios/scenario-4-linux-privilege-escalation.html` | `suspicious_process_post_login` | high | Hard |
| 5 | Multi-Event SOC Investigation | `training/scenarios/scenario-5-multi-event-soc-investigation.html` | all three rules | capstone | Hard |

Each scenario asks nine identifications (source IP, user, host, exact timestamps, elapsed time,
rule and threshold, evidence events, and a written finding) and ends with a "mark complete"
control. Progress, notes, and opened hints are stored in the browser via `localStorage` — there
is no server-side state and no account.

**The two teaching traps.** The dataset contains two conditions that must *not* alert, and
Scenario 5 requires students to explain why:

- `svc_backup` from `10.0.0.30` fails **4** logons before succeeding — below `min_failures: 5`.
- `app-02` runs `powershell.exe` **30 minutes** after login — outside `time_after_login_minutes: 2`.

Students also learn the distinction between the alert's normalized `user` and the raw event's
own user field (`jdoe` vs `CORP\jdoe`), and that an alert's existence does not mean two alerts
are the same incident.

---

## Training platform and Kibana usage

### Training platform

```powershell
python scripts\serve_training.py          # http://localhost:8080
python scripts\validate_scenarios.py      # verify all 5 scenarios against live data
```

A lightweight static site served by the Python standard library. No backend, no database, no
authentication, and nothing is fetched from the internet at runtime.

| Page | Purpose |
|---|---|
| `training/index.html` | Branded landing page: objective, learning outcomes, scenario index, live ES status |
| `training/instructions.html` | Schema and rule reference, the investigation workflow, required identifications, sample queries |
| `training/scenarios/scenario-1..5.html` | The five scenarios: incident, objective, steps, evidence notes, hints ladder |
| `training/assets/` | `bluecloud.css` (blue primary / orange accent), `lab.js`, logo |

The intended student workflow:

1. Read the incident and objective on the scenario page.
2. Open the **SOC Triage Board**: the Alert Queue for the current alerts, the
   activity panels for the surrounding baseline.
3. Follow an alert's evidence into **Discover**, using the ids from the alert
   document there.
4. Pull the supporting events in **Discover**.
5. Record the nine identifications in the answer boxes.
6. Write the finding, then mark the scenario complete.

### Kibana dashboard

```powershell
python -m src.main import-dashboard     # or: --kibana-url http://localhost:5601
```

Uploads `dashboards/soc-triage-board.ndjson` through Kibana's saved-objects API
(`overwrite=true`, so re-running is safe): 2 data views, 8 visualizations, and the dashboard.
The manual route is *Kibana → Stack Management → Saved Objects → Import*.

The NDJSON is **generated, not hand-maintained**:

```powershell
python scripts/build_dashboard.py          # regenerate dashboards/soc-triage-board.ndjson
python scripts/build_dashboard.py --check  # validate data-view and panel references
```

`--check` fails if a visualization lacks the `indexRefName` pointer Kibana needs to resolve its
data view (the cause of the "Could not find the data view: -" error), if a reference dangles,
if a data view or its time field is wrong, if a panel aggregates on a field its index does not
map, or if two panels overlap on the grid. Run it after any dashboard change.

#### What the board shows

The board reads **two indices on purpose**, and the split is the point:

| Panel | Reads | Answers |
|---|---|---|
| Alert Queue | `security-alerts-*` | What needs attention? One row per correlated alert. |
| Alerts by Severity | `security-alerts-*` | How serious, and in what proportion? |
| Alert Timeline | `security-alerts-*` | When was activity detected across the fortnight? |
| Authentication Activity | `normalized-events-*` | Is the failure rate normal? |
| Top Source IPs by Event Volume | `normalized-events-*` | Which addresses are active, and how much? |
| Event Type Mix | `normalized-events-*` | What kinds of telemetry exist? |
| Event Volume by Host | `normalized-events-*` | Which hosts are busy? |
| Alerts by Host | `security-alerts-*` | Which hosts drew attention? |

Alert panels describe the four correlated alerts. Activity panels describe the 9,584
events they were found in, which is what turns "three high alerts" into something an
analyst can reason about. Volume is not a verdict: the busiest source address is usually
the busiest, not the most interesting, and the board does not label any address or host.

The board opens on an **absolute** range — `2026-09-15T00:00:00.000Z` to
`2026-09-30T23:59:59.999Z` — which contains the whole lab dataset with a day of slack
at each end. It was `now-7d`, then `now-15d`; both were relative, and a relative window
against a fixed dataset ages until it hides evidence. That is exactly what happened:
`now-15d` stopped containing the 2026-09-17 brute-force alert and the board quietly
showed 3 of the 4 canonical alerts. An absolute window cannot.

Reproducibility is worth more here than freshness. The dataset is generated from one
fixed seed and one fixed base timestamp so every cohort investigates the same alerts and
gets the same graded answers; re-anchoring it to chase the calendar would trade that
away for nothing, since the window can simply be stated absolutely. The training pages'
Discover links use the same two values, so following a link and opening the board show
the same data; `tests/test_dashboard_ndjson.py` and `tests/test_ui_render_contracts.py`
assert the two have not drifted apart and that the window still contains the dataset.

The board also saves `timeRestore: true`, which reads backwards but is not.
Measured on Kibana 8.13: with `false` the board ignores its own saved range and
falls back to "Last 15 minutes" — zero alerts, no error, not even a "No results"
message. With `true` it applies the saved range and shows all four canonical
alerts. So the flag that sounds like "don't let the browser override the lab's
range" is in fact the one that makes the lab's range apply at all.

If the dataset is ever deliberately re-anchored, the window changes deliberately in the
same change, in `scripts/build_dashboard.py` and `training/assets/js/lab.js`. Nothing
recomputes it at run time. See `docs/DATASET.md` section 4.

The Alert Queue deliberately does **not** show the alert's `reasoning` field. That text
states the findings outright, which would answer the scenario questions before the student
looks at any evidence. It is still available in **Discover** for an instructor.

Pulling alert evidence directly:

```powershell
python -c "from src.utils.evidence_linker import fetch_evidence; from src.elasticsearch_client import get_es_client; import json; print(json.dumps(fetch_evidence(get_es_client(), ['<event_id>']), indent=2))"
```

---

## Example results

### Ingestion and correlation

```
Ingestion result: lines_read=50 | parsed=50 | skipped=0 | indexed=50 (normalized-events-2026-09-28=50)
  Indexed 50 event(s) into normalized-events-2026-09-28

Correlation cycle complete: events=47 alerts_created=4 suppressed=0
  [brute_force:1, successful_brute_force:1, suspicious_process_post_login:2] in 0.58s
  brute_force: 1 alert(s) written
  successful_brute_force: 1 alert(s) written
  suspicious_process_post_login: 2 alert(s) written
```

### Distribution

```
$ python -m src.main stats
normalized-events-* documents: 50
security-alerts-* documents:  4
  logon_failure: 25
  logon_success: 11
  network_connection: 7
  process_create: 4
  privilege_escalation: 3
  severity high: 3
  severity critical: 1
  rule suspicious_process_post_login: 2
  rule brute_force: 1
  rule successful_brute_force: 1
```

Hosts: `web-01` (37 events, Linux), `fw-01` (7, firewall), `app-01` (4, Windows),
`app-02` (2, Windows — the non-alerting trap).

### The four alerts

| # | Rule | Severity | Source IP | User | Host | Evidence | Elapsed |
|---|---|---|---|---|---|---|---|
| A | `brute_force` | high | `203.0.113.45` | `root` (also `admin` ×5) | `web-01` | 10 events | 132 s |
| B | `successful_brute_force` | **critical** | `203.0.113.66` | `alice` | `web-01` | 6 events (5 failures + success) | 129 s |
| C | `suspicious_process_post_login` | high | `198.51.100.25` | `jdoe` | `app-01` | 2 events (`cmd.exe /c whoami && net user administrator /active:yes`) | 20 s |
| D | `suspicious_process_post_login` | high | `198.51.100.77` | `deploy` | `web-01` | 2 events (`sudo … COMMAND=/bin/bash -i`) | 45 s |

Counts, severities, and elapsed times are fixed by the generator.

**Absolute UTC timestamps no longer shift with every session.** The older 50-event sample set
was generated relative to "now" so the alerts always fell inside the dashboard window and the
engine's lookback. The Phase 4A dataset is instead a *fixed* 14-day window anchored at
`2026-09-16T00:00:00Z`, so the same four alerts always land on the same dates and the same
document ids. That makes the lab reproducible, and it also means the alerts age: any fixed
relative window in Kibana or in the training pages' Discover links will eventually need
widening. `docs/DATASET.md` tracks this.

A representative alert document:

```json
{
  "rule_name": "brute_force",
  "severity": "high",
  "src_ip": "203.0.113.45",
  "host": "web-01",
  "user": "root",
  "event_type": "brute_force",
  "first_seen": "…", "last_seen": "…",
  "evidence_event_ids": ["…", "…"],
  "reasoning": "10 failed logon attempts from 203.0.113.45 to web-01 within 5 minutes …",
  "dedup_key": "…", "dedup_window_minutes": 30
}
```

---

## Testing and validation

```powershell
# from the project virtual environment, which is where pytest-cov is installed
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m pytest tests --cov=src --cov-report=term-missing
```

On Linux/macOS use `./.venv/bin/python` instead. Plain `python -m pytest tests -q` works with
any interpreter that has `pytest`; only the `--cov` form needs `pytest-cov`, which is declared in
`requirements.txt` and installed by `scripts\setup.ps1` into `.venv`.

```
396 passed, 1 skipped
```

The suite runs entirely against an **in-memory fake Elasticsearch** — no Docker required, so it
is safe to run anywhere. Coverage includes every parser (positive and negative), the schema and
document IDs, config loading, the ES client, all three correlation rules against
`tests/data/positive_cases.json` and `negative_cases.json`, deduplication, the engine, a full
generate → ingest → correlate pipeline, the Kibana saved objects, the training platform
(pages, navigation, scenario wiring, answer-key leakage), and the student answer checker
(grading, normalisation, refusal handling, the HTTP surface, and the guarantee that no answer
reaches a student-facing asset).

The scenarios are verified against **live** data by a separate command, which is what guarantees
a scenario can never reference evidence that does not exist:

```powershell
python scripts\validate_scenarios.py
```

```
RESULT: all 124 checks passed - every scenario is backed by real data
```

It re-derives every answer-key value from the cluster: the source IPs, users, hosts, failure
counts, elapsed times, rule names, severities, evidence IDs, and the two deliberate
non-alerting conditions. If the data and the documentation ever disagree, this fails.

---

## Configuration

All tunables live in [`config/app-config.yaml`](config/app-config.yaml) and can be overridden by
environment variables (`ES_HOST`, `ES_PORT`, `KIBANA_URL`, `RULE_MIN_FAILURES`,
`RULE_TIME_WINDOW_MINUTES`, `LOG_LEVEL`).

| Group | Keys |
|---|---|
| `app` | `name`, `log_level`, `time_zone` |
| `correlation` | `engine_frequency_seconds` (60), `alert_dedup_window_minutes` (30), `lookback_window_minutes` (120), `min_new_evidence_for_realert` (2), `dedup_cache_path` |
| `rules.*` | `enabled`, thresholds, `severity`, `suspicious_processes`, `expected_processes` |

See [`docs/CONFIGURATION_REFERENCE.md`](docs/CONFIGURATION_REFERENCE.md) for every parameter and
[`docs/FALSE_POSITIVE_TUNING.md`](docs/FALSE_POSITIVE_TUNING.md) for the tuning methodology.

### Index templates and optional live ingestion

`python -m src.main init-templates` installs all three index templates:

| Template | Indices | Used by |
|---|---|---|
| `normalized-events` | `normalized-events-*` | the sample and live pipelines |
| `security-alerts` | `security-alerts-*` | the correlation engine and the dashboard |
| `raw-events` | `raw-events-*` | the **optional** Filebeat path only |

The `raw-events` template is installed even though nothing in `docker-compose.yml` runs Filebeat.
It is inert until a document is actually shipped, so it has no effect on the local sample-data
workflow. It exists because the configs in `config/filebeat/` target `raw-events-*`, and
`init-templates` is the initialization path that has to create it. Live lines are stored raw for
evidence; normalization stays in the Python engine, so the same parsers and correlation rules run
for sample and live data. See [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for Filebeat
registry and offset problems.

---

## Project structure

```
config/
  app-config.yaml                 rule thresholds, windows, process lists
  elasticsearch-template.json     normalized-events-* mappings
  elasticsearch-alert-template.json
  elasticsearch-raw-template.json
  filebeat/                       Windows / Linux / firewall shipper configs (optional live ingest)
src/
  main.py                         CLI: init-templates, generate-samples, ingest, correlate,
                                  stats, import-dashboard
  config.py                       YAML + env overrides with validation
  elasticsearch_client.py         connection, indexing, search, aggregations
  normalization/
    schema.py                     common event schema, Alert, validation, document IDs
    parsers.py                    LogParser base class, syslog/IP helpers
    windows_sysmon.py             Event IDs 4624, 4625, 4672, 4688, 4689
    linux_auth.py                 sshd accepted/failed/invalid, sudo, PAM, cron
    firewall_syslog.py            Cisco ASA, UFW/kernel, Palo Alto, Fortinet
    sample_generator.py           five deterministic scenarios
    ingestion.py                  detect → parse → validate → index
  correlation/
    engine.py                     cycle orchestration, scheduler, status
    rules.py                      the three Lab #07 rules
    deduplication.py              30-minute suppression with evidence growth
    alert_schema.py               alert doc IDs, severity ranking
  utils/                          logging, time, evidence linking
training/                         BlueCloud training platform (static, no build step)
  index.html                      landing page
  instructions.html               student guide: schema, rules, workflow, queries
  scenarios/                      the five investigation scenarios
  assets/css/bluecloud.css        blue primary / orange accent theme
  assets/js/lab.js                nav, hints, local progress and notes
  assets/js/lab-check.js          student answer-checking workflow (holds no answers)
  assets/img/bluecloud-logo.png   brand mark
tests/                            unit + integration suites, rule case data, platform tests
dashboards/
  soc-triage-board.ndjson         Kibana saved objects (generated)
logs/samples/                     hand-inspectable reference fixture per log format
docs/
  TRAINING_PLATFORM.md            how the student platform is run and deployed
  INSTRUCTOR_GUIDE.md             instructor-only answer key and rubric
  answer-key.json                 NOT tracked - lives at data/answer-key.json (git-ignored)
  LOG_PARSER_REFERENCE.md         regex patterns, assumptions, example matches
  RULE_LOGIC.md                   rule pseudocode, flowcharts, evidence semantics
  CONFIGURATION_REFERENCE.md      every tunable parameter
  FALSE_POSITIVE_TUNING.md        threshold tuning methodology
  TROUBLESHOOTING.md              common issues and fixes
  PHASE_CHECKLIST.md              go/no-go criteria + deployment readiness
scripts/
  setup.ps1                       one-time bootstrap (venv, deps, Docker, templates)
  start_lab.ps1                   per-session starter
  reset_lab_data.py               clears regenerable lab data so a session is reproducible
  serve_training.py               stdlib static server + the answer-check API
  answer_grader.py                server-side grading (imported by serve_training.py)
  build_dashboard.py              generates + validates the Kibana saved objects
  validate_scenarios.py           proves every scenario is backed by real data
```

---

## Deployment notes

There are two environments and they are not interchangeable. For the shared
company server — isolation names, resource limits, secret handling, and the
deployment sequence — see **[docs/SERVER_DEPLOYMENT.md](docs/SERVER_DEPLOYMENT.md)**.

The lab is built for a Linux host as well as Windows. Verified locally on
Windows; the Linux baseline is Ubuntu 22.04 LTS or newer, including Ubuntu 26.04.

```bash
git clone <your-repo-url> siem-log-correlation-engine
cd siem-log-correlation-engine

# Elasticsearch will not start below this. It is a kernel sysctl, so it needs
# elevated privileges and must be set by whoever administers the host - it
# cannot be set from inside the container. Check with: sysctl vm.max_map_count
sudo sysctl -w vm.max_map_count=262144

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -c constraints.txt

docker compose up -d
python -m src.main init-templates

# Each session (the reset is what keeps the dataset reproducible)
python scripts/reset_lab_data.py --yes
python -m src.main generate-samples --scenario all
python -m src.main ingest --log-dir ./logs/generated   # one dataset per directory
python -m src.main correlate --run-once
python -m src.main import-dashboard
python scripts/validate_scenarios.py
```

The `ingest` line above indexes the per-scenario demonstration fixtures and
nothing else, which is why it succeeds on a clean checkout. It is **refused** if
`./logs/generated` also holds `enterprise-14d_*`: `ingest --log-dir` will not
index two datasets in one directory, prints the conflicting filenames, indexes
nothing — not even the enterprise half — and exits non-zero. To rebuild the
approved enterprise dataset instead, follow `docs/DATASET.md` section 2, which
generates with `--clean` and correlates the full fourteen days with
`scripts/correlate_range.py`.

Serve the training platform behind a reverse proxy (nginx is the simplest option).
The platform is the component that enforces authentication, answer grading and
progress, so the proxy must forward to it — it must **not** serve `training/` as
static files:

```bash
# behind the proxy, bound to loopback. The port is explicit: the server no
# longer picks a different one if this is busy, it exits and says so.
python3 scripts/serve_training.py --host 127.0.0.1 --port 8080
```

```nginx
server {
    listen 80;
    server_name siem-lab.example.com;

    # Proxy to the platform. Do NOT replace this with `root .../training`.
    # Serving the directory statically would bypass the platform's own access
    # control - every scenario page would be readable without signing in - and
    # would break /api/check, /api/reveal, /api/auth/* and /api/es-status,
    # because none of those exist as files. See docs/SERVER_DEPLOYMENT.md.
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Notes:

- Bind Kibana and Elasticsearch to `localhost` or a private network. They are not hardened.
- Elasticsearch is capped at 2 GB and Kibana at 1 GB in this configuration; the JVM heap is
  pinned to 512 MB so the container cannot over-commit. Lower the heap and Elasticsearch will be
  OOM-killed, which looks like a blank dashboard. Raise the heap without raising the container
  limit and you get the same failure, because the off-heap buffers cross the limit too.
- The `es-data` and `kibana` volumes hold all state. **Never** run `docker compose down -v` or
  delete those volumes — you will lose the imported data views and dashboard.
- **Do not apply `docker-compose.prod.yml`.** It is not usable: its port list is concatenated
  onto the base file's rather than replacing it, so it binds 9200 and 5601 twice and cannot
  start; its certificate paths do not exist; and the Python client has no TLS or credential
  support, so enabling xpack security would disconnect the engine rather than protect it.
  Enabling xpack authentication is a later, separate piece of work.

---

## Security notes

This is a training lab running on `localhost`. It is **not** hardened.

- `xpack.security.enabled=false` in `docker-compose.yml`, for lab convenience only. Elasticsearch
  and Kibana are unauthenticated — which is why both ports are published to `127.0.0.1` only:

  ```yaml
  ports:
    - "127.0.0.1:9200:9200"   # was "9200:9200"
    - "127.0.0.1:5601:5601"   # was "5601:5601"
  ```

  Unauthenticated cluster access means anyone who can reach port 9200 can read *and delete* the
  shared dataset, so the default binds to the loopback interface. The documented single-machine
  workflow is unchanged. **Before using this lab on a classroom network, read
  `docs/DEPLOYMENT_MODES.md`** — there is no safe classroom mode configured yet, and the
  available options are a real decision, not a port number.
- Kibana's three `XPACK_*_ENCRYPTIONKEY` settings are **required** and have no fallback value:

  ```yaml
  XPACK_SECURITY_ENCRYPTIONKEY: ${SIEM_ENCRYPTION_KEY:?SIEM_ENCRYPTION_KEY is required ...}
  ```

  They used to fall back to fixed strings that were published in this repository, which meant
  they protected nothing: anyone who could read the file could decrypt Kibana's sessions and
  encrypted saved objects. `scripts/ensure_lab_env.ps1` — called by both `setup.ps1` and
  `start_lab.ps1` — now generates three random keys into a git-ignored `.env` on first run, so a
  fresh clone still starts with no manual step and Compose fails fast with a clear message if a
  key is missing. To supply your own, use `bin/kibana-encryption-keys`; real values belong in
  `.env` and nowhere else. Rotating the keys invalidates existing encrypted saved objects, so
  re-import the dashboard with `python -m src.main import-dashboard`. See `.env.example`.
- `POST /api/reveal` requires a signed-in student who has already submitted a check for that
  scenario, and is rate limited per user. It used to be anonymous and unthrottled, which handed
  the entire answer key to any caller in about half a second. `POST /api/check` remains
  stateless and unauthenticated.
- `.env` is git-ignored and only `.env.example` (placeholders) is committed. Certificates,
  keys, and `config/certs/` are ignored.
- To harden, apply `docker-compose.prod.yml`, which enables X-Pack security and TLS for both
  services and expects `ES_PASSWORD` / `KIBANA_SYSTEM_USERNAME` / `KIBANA_SYSTEM_PASSWORD` plus
  certificates mounted from `./certs`:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  ```

- The training platform has **no authentication and no access control** by design. Anything it
  serves is public to whoever can reach port 8080. The instructor answer key is kept outside the
  served directory (`docs/INSTRUCTOR_GUIDE.md`) and must never be copied into `training/`.
- All data is synthetic. Source IPs come from the RFC 5737 documentation ranges
  (`203.0.113.0/24`, `198.51.100.0/24`) and hosts and users are fictional.
- Student answers and progress live in the browser's `localStorage` and never leave the machine.
  Clearing site data resets a student's progress.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/TRAINING_PLATFORM.md`](docs/TRAINING_PLATFORM.md) | running and deploying the student platform, Ubuntu/nginx, troubleshooting |
| [`docs/INSTRUCTOR_GUIDE.md`](docs/INSTRUCTOR_GUIDE.md) | **instructor only** — answer key, evidence, investigation paths, hints, rubric |
| [`docs/RULE_LOGIC.md`](docs/RULE_LOGIC.md) | rule pseudocode, flowcharts, evidence semantics |
| [`docs/LOG_PARSER_REFERENCE.md`](docs/LOG_PARSER_REFERENCE.md) | regex patterns, assumptions, example matches |
| [`docs/CONFIGURATION_REFERENCE.md`](docs/CONFIGURATION_REFERENCE.md) | every tunable parameter |
| [`docs/FALSE_POSITIVE_TUNING.md`](docs/FALSE_POSITIVE_TUNING.md) | threshold tuning methodology and rationale |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | common issues and fixes |
| [`docs/PHASE_CHECKLIST.md`](docs/PHASE_CHECKLIST.md) | go/no-go criteria per phase and deployment readiness |

---

## License

Course material for BlueCloud Softech Solutions' cybersecurity training lab series. Provided for
educational use.
