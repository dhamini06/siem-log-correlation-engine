# Configuration Reference — Lab #07

Configuration file: `config/app-config.yaml`. Loaded by `src/config.py`, validated on every
load (invalid values raise `ValueError` before any work starts). Environment variables override
file values, which makes container and CI overrides trivial.

## Environment variable overrides

| Variable | Overrides | Example |
|---|---|---|
| `ES_HOST` | `app.es_host` | `localhost` |
| `ES_PORT` | `app.es_port` (int) | `9200` |
| `RULE_MIN_FAILURES` | `rules.brute_force.min_failures` (int) | `8` |
| `RULE_TIME_WINDOW_MINUTES` | `rules.brute_force.time_window_minutes` (int) | `3` |
| `LOG_LEVEL` | `app.log_level` | `DEBUG` |

```powershell
$env:ES_HOST = "localhost"
$env:RULE_MIN_FAILURES = "8"
python -m src.main correlate --run-once
```

---

## `app`

| Key | Default | Meaning |
|---|---|---|
| `name` | `siem-lab` | Logical application name (logging/identification only) |
| `log_level` | `INFO` | Root log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `time_zone` | `UTC` | All timestamps are normalized to UTC; do not change |

## `correlation`

| Key | Default | Meaning / effect |
|---|---|---|
| `engine_frequency_seconds` | `60` | How often the scheduled engine runs a cycle. Lower = faster alerting, more ES load. Must be a positive integer. |
| `alert_dedup_window_minutes` | `30` | Suppression window per `dedup_key` (rule + src_ip + user). Also controls how far back existing alerts are re-read to seed the dedup cache on startup. |
| `lookback_window_minutes` | `120` | How far back each cycle queries `normalized-events-*`. Must exceed the largest rule window (10 min) with headroom for downtime. |
| `min_new_evidence_for_realert` | `2` | New evidence IDs required to re-alert inside the dedup window. Raise to reduce repeat alerts. |
| `dedup_cache_path` | `data/dedup-cache.json` | Where dedup state is persisted. Delete the file to force a clean re-alert of the current window. |

## `rules.brute_force` (Rule 1)

| Key | Default | Meaning / effect |
|---|---|---|
| `enabled` | `true` | Set `false` to disable Rule 1 without editing code |
| `min_failures` | `5` | Failures required to alert. Lower = more sensitive/noisy; must be a positive integer |
| `time_window_minutes` | `5` | Sliding window for the failure burst. Wider catches slow attacks, raises noise |
| `severity` | `high` | Alert severity written to `security-alerts-*` |

## `rules.successful_brute_force` (Rule 2)

| Key | Default | Meaning / effect |
|---|---|---|
| `enabled` | `true` | Disable to stop escalations |
| `success_window_minutes` | `10` | How long after the burst start a success still counts as part of the attack |
| `severity` | `critical` | Escalation severity |

Rule 2 also depends on `rules.brute_force.min_failures` / `time_window_minutes`: the burst must
satisfy Rule 1's condition for the escalation to fire.

## `rules.suspicious_exec` (Rule 3)

| Key | Default | Meaning / effect |
|---|---|---|
| `enabled` | `true` | Disable Rule 3 |
| `time_after_login_minutes` | `2` | Window between login and suspicious execution. Shorten to reduce noise from normal admin work |
| `severity` | `high` | Alert severity |
| `suspicious_processes` | `cmd.exe`, `powershell.exe`, `bash`, `/bin/bash`, `/bin/bash -i`, `nc` | Process names/paths/command lines that trigger the rule. Multi-word entries match the command line only |
| `expected_processes` | `explorer.exe`, `svchost.exe`, `spoolsv.exe`, `cron`, `systemd-logind`, `sshd` | Allowlist; a match suppresses the process. Take precedence over the suspicious list |

Process matching is case-insensitive and considers `process.name`, `process.path`, and
`process.command_line`.

---

## Index templates

| File | Patterns | Purpose |
|---|---|---|
| `config/elasticsearch-template.json` | `normalized-events-*` | `@timestamp`/`ingest_timestamp` dates, `src_ip`/`dst_ip` as `ip`, keywords for filtering, `process` object, `raw_event` text |
| `config/elasticsearch-alert-template.json` | `security-alerts-*` | `rule_name`, `severity`, `timestamp`/`first_seen`/`last_seen`, `src_ip` as `ip`, `evidence_event_ids` keyword array, `reasoning` text, `dedup_key`, `false_positive_feedback` |
| `config/elasticsearch-raw-template.json` | `raw-events-*` | Filebeat raw log retention (not applied by `init-templates`; apply manually if you enable Phase 4) |

All templates use 1 shard and 0 replicas (single-node lab) with a 5s refresh interval. Indices
roll daily: `normalized-events-YYYY-MM-DD` and `security-alerts-YYYY-MM-DD`.

## Index lifecycle

The lab relies on daily index rolling for retention. For a longer-lived deployment, add an ILM
policy that deletes `normalized-events-*` after N days and archives `security-alerts-*`
(never delete alerts before their evidence, or the drill-down breaks):

```json
PUT _ilm/policy/siem-retention
{
  "policy": {
    "phases": {
      "hot": { "actions": { "rollover": { "max_primary_shard_size": "30gb", "max_age": "1d" } } },
      "delete": { "min_age": "90d", "actions": { "delete": {} } }
    }
  }
}
```

## Filebeat configuration

`config/filebeat/filebeat.yml` (Windows Security + Sysmon),
`config/filebeat/filebeat-linux.yml` (`auth.log` + auditd),
`config/filebeat/filebeat-firewall.yml` (firewall logs / syslog receiver). All ship raw lines
to `raw-events-*` with `siem.source_type` tagging. TLS/credentials for production are present
as commented placeholders only.

## Security-related configuration

The local stack deliberately runs with `xpack.security.enabled=false`. `docker-compose.prod.yml`
contains the hardened overrides (security enabled, TLS for Elasticsearch and Kibana, larger heap)
and is **not** used by default. Before deploying: set `ES_USERNAME`/`ES_PASSWORD`, mount
certificates under `./certs`, and terminate TLS in front of port 9200/5601.
