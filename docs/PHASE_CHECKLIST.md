# Phase Checklist & Deployment Readiness — Lab #07

Go/no-go criteria per phase with the exact PowerShell commands. Each phase is complete only
when every check passes.

---

## Phase 1 — Docker stack, templates, config, ES client

| # | Check | Command | Expected |
|---|---|---|---|
| 1.1 | Containers healthy | `docker compose ps` | `es` and `kibana` Up/healthy |
| 1.2 | Elasticsearch responds | `Invoke-RestMethod http://localhost:9200/_cluster/health` | `status: yellow` or `green` |
| 1.3 | Kibana responds | `Invoke-RestMethod http://localhost:5601/api/status` | `overall.level: available` |
| 1.4 | Event index template | `Invoke-RestMethod http://localhost:9200/_index_template/normalized-events` | Template body returned |
| 1.5 | Alert index template | `Invoke-RestMethod http://localhost:9200/_index_template/security-alerts` | Template body returned |
| 1.6 | Config loads | `python -m pytest tests/test_config.py -q` | All pass |
| 1.7 | ES wrapper works | `python -m pytest tests/test_elasticsearch_client.py -q` | All pass |
| 1.8 | No ES errors | `docker compose logs elasticsearch \| Select-String "ERROR"` | No matches |

## Phase 2 — Normalization & sample ingestion

| # | Check | Command | Expected |
|---|---|---|---|
| 2.1 | Samples generated | `python -m src.main generate-samples --scenario all` | 5 scenarios × 3 files |
| 2.2 | Parsers validated | `python -m pytest tests/normalization -q` | All pass |
| 2.3 | Schema validation | `python -m pytest tests/normalization/test_schema.py -q` | All pass |
| 2.4 | Events indexed | `python -m src.main ingest --log-dir .\logs\generated` | `indexed=50` (or more), no errors |
| 2.5 | Schema in ES | `Invoke-RestMethod "http://localhost:9200/normalized-events-*/_search?size=1&pretty"` | `@timestamp`, `host`, `user`, `src_ip`, `event_type`, `raw_event` present |
| 2.6 | Daily rolling index | `Invoke-RestMethod http://localhost:9200/_cat/indices/normalized-events-*` | One index named `normalized-events-YYYY-MM-DD` |
| 2.7 | Idempotent re-ingest | Re-run 2.4, then `python -m src.main stats` | Event count unchanged |
| 2.8 | Visible in Kibana | Discover → data view `normalized-events-*` | Sample events listed |

## Phase 3 — Correlation & alerting

| # | Check | Command | Expected |
|---|---|---|---|
| 3.1 | Rule tests | `python -m pytest tests/correlation -q` | All pass (positive + negative + dedup) |
| 3.2 | Rule 1 fires | `python -m src.main correlate --run-once` | `brute_force=1`, severity `high` |
| 3.3 | Rule 2 escalates | same command | `successful_brute_force=1`, severity `critical` |
| 3.4 | Rule 3 fires | same command | `suspicious_process_post_login=2`, severity `high` |
| 3.5 | Alerts in ES | `python -m src.main stats` | 4 alert docs, severity/rule breakdown printed |
| 3.6 | Evidence persisted | Inspect any alert document | `evidence_event_ids` resolves to real events |
| 3.7 | Dedup works | Re-run `correlate --run-once` | `alerts_created=0 suppressed=4` |
| 3.8 | Scheduler runs | `python -m src.main correlate`, wait 90s, Ctrl+C | Two `Correlation cycle complete` lines in the console/log |
| 3.9 | Full regression | `python -m pytest tests -q` | 166 tests pass |

Re-alert behaviour check (optional): after 3.7, add two more failed logins for the brute-force
IP within the window, re-run, and confirm one new alert (evidence grew by ≥ 2 events).

## Phase 4 — Live ingestion (Filebeat)

| # | Check | Command | Expected |
|---|---|---|---|
| 4.1 | Config valid | `filebeat.exe test config -c config\filebeat\filebeat.yml` | Config OK |
| 4.2 | Ships raw logs | Start Filebeat, wait 60s | `raw-events-*` document count grows |
| 4.3 | Raw evidence retained | `Invoke-RestMethod "http://localhost:9200/raw-events-*/_search?size=1"` | Original log line/message present |
| 4.4 | Normalized path still works | `python -m src.main ingest --file <exported>.jsonl --source-type windows_sysmon` | Events indexed, 0 errors |
| 4.5 | Correlation unaffected | `python -m src.main correlate --run-once` | Cycle completes without error |

Live hosts are optional in the lab; the sample path exercises the identical parsers and rules.

## Phase 5 — Kibana visualization

| # | Check | Command / action | Expected |
|---|---|---|---|
| 5.1 | Saved objects import | Stack Management → Saved Objects → Import `dashboards\soc-triage-board.ndjson` | 7 objects imported, no errors |
| 5.2 | Data views exist | Stack Management → Data Views | `security-alerts-*`, `normalized-events-*` |
| 5.3 | Dashboard renders | Open **SOC Triage Board**, time picker `Last 24 hours` | 4 panels populated |
| 5.4 | Severity filter | Add filter `severity is critical` | Counts and tables update |
| 5.5 | Rule filter | Add filter `rule_name is brute_force` | Only Rule 1 alerts shown |
| 5.6 | Source IP filter | Add filter `src_ip is 203.0.113.45` | Only that source shown |
| 5.7 | Drill-down | Click an alert → `evidence_event_ids` → Discover | The triggering events are listed |

---

## Deployment readiness checklist (post-Phase 5)

- [ ] `python -m pytest tests -q` passes on the deployment target (Python 3.10+)
- [ ] `pip install -r requirements.txt` executed inside the virtualenv on the server
- [ ] `config/app-config.yaml` reviewed: thresholds tuned for real traffic, not lab samples
- [ ] `xpack.security.enabled=true` and TLS enabled (`docker-compose.prod.yml`)
- [ ] `ES_USERNAME` / `ES_PASSWORD` / `KIBANA_SYSTEM_USERNAME` / `KIBANA_SYSTEM_PASSWORD` set as
      environment variables (never committed; `.env` is gitignored)
- [ ] Default Elasticsearch password changed
- [ ] Ports 9200/5601 not exposed publicly — reverse proxy with TLS in front
- [ ] Filebeat shippers configured with the correct CA and least-privilege credentials
- [ ] Retention policy defined for `normalized-events-*` and `security-alerts-*`
      (alerts must outlive their evidence)
- [ ] NTP synchronized on every log source (correlation depends on accurate timestamps)
- [ ] Correlation engine runs under a supervisor (`systemd` unit or Docker restart policy)
- [ ] `data/dedup-cache.json` on persistent storage, or suppression resets on restart
- [ ] Log rotation configured for `logs/app.log` (already rotated at 10 MB × 5 files)
- [ ] Backup/restore of the `es-data` volume verified
- [ ] `docs/FALSE_POSITIVE_TUNING.md` reviewed and thresholds baselined against real traffic
- [ ] Application code unchanged from the lab (Lab #07 requirement: zero code changes for
      Windows → Ubuntu migration; only config and compose overrides differ)
