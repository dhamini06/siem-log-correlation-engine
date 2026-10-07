# False Positive Tuning — Lab #07

## Method

1. **Measure the baseline.** Ingest a representative window (the `normal_day` and
   `false_positive_mix` scenarios exist for this) and count alerts per rule per day:
   ```powershell
   python -m src.main ingest --log-dir .\logs\generated
   python -m src.main correlate --run-once
   python -m src.main stats
   ```
   The `ingest` line needs `.\logs\generated` to hold one dataset. If it also
   holds `enterprise-14d_*` it is refused — see `docs/DATASET.md` §2.1.
2. **Classify each alert** as true positive or false positive. Record the reason in the
   `false_positive_feedback` field of the alert document (`unreviewed` / `true_positive` /
   `false_positive`). In Kibana, filter on that field to review only the questionable ones.
3. **Change one parameter at a time** in `config/app-config.yaml`, then replay the same data.
   Because ingestion is idempotent (deterministic document IDs), re-running `ingest` +
   `correlate --run-once` is safe and gives a like-for-like comparison.
4. **Re-check both directions.** Raising a threshold must not silence the positive scenarios:
   ```powershell
   python -m pytest tests/correlation -q
   ```
   The data-driven cases in `tests/data/positive_cases.json` and `negative_cases.json` are the
   regression net for tuning changes.
5. **Record the decision.** Note the parameter, old value, new value, and the measured effect
   in the pull request or lab report.

## Tuning levers, in order of preference

| Order | Lever | Use when |
|---|---|---|
| 1 | `rules.<rule>.enabled` | A rule does not apply to your environment at all |
| 2 | `rules.suspicious_exec.expected_processes` (allowlist) | A known-good binary appears in Rule 3 alerts (e.g. a management agent, a backup tool) |
| 3 | Raise `min_failures` | Rule 1 fires on ordinary user typos or flaky clients |
| 4 | Shorten `time_window_minutes` | Failures are spread out because users retry slowly — bursts are genuinely not attacks |
| 5 | Raise `alert_dedup_window_minutes` | The same ongoing incident re-alerts repeatedly while evidence grows slowly |
| 6 | Filter by `host`/`user` upstream | A single noisy system dominates the alert volume (for example a scanner or kiosk) |

Prefer allowlists and higher thresholds over exclusions coded into the parsers: parser changes
affect every downstream rule and require re-indexing.

## Rationale for the shipped defaults

| Parameter | Value | Rationale |
|---|---|---|
| `min_failures` | 5 | Lab #07 mandates 5. In production, 8–10 is common for internet-facing SSH once VPN/bastion noise is removed; 3 is too low (a mistyped password plus a retry loop reaches it) |
| `time_window_minutes` | 5 | Lab #07 mandate. Password-spraying tools fire hundreds of attempts in seconds, so a wider window mostly adds slow user-error traffic |
| `success_window_minutes` | 10 | Long enough to cover a human retyping a password and retrying, short enough to avoid flagging a legitimate login hours later |
| `time_after_login_minutes` | 2 | Interactive shells start immediately after logon. 2 minutes keeps normal post-login activity (opening Office, file sync) out of scope; interactive shells after 2 minutes are rare |
| `suspicious_processes` | shells + netcat + PowerShell | The canonical post-exploitation toolset for this lab. Note `powershell.exe` is a large false-positive source in real environments — narrow it with `expected_processes` or by excluding service accounts upstream |
| `expected_processes` | shells/services/scheduler | `explorer.exe` (interactive desktop), `svchost.exe`/`spoolsv.exe` (Windows services), `cron`/`systemd-logind`/`sshd` (Linux session and task infrastructure) |
| `alert_dedup_window_minutes` | 30 | Matches incident-review cadence: an analyst triaging the same source IP inside half an hour should see one alert, not twenty |
| `min_new_evidence_for_realert` | 2 | One extra event is usually a duplicate or a retry; two or more means the attack is still active and worth another ping |
| `lookback_window_minutes` | 120 | Four times the largest rule window, so a brief engine outage does not create a blind spot |

## Known false-positive sources and fixes

| Source | Symptom | Fix |
|---|---|---|
| Shared NAT / VPN egress | Many unrelated users appear as one `src_ip` | Raise `min_failures`; alert on `src_ip` + `user` pairs in your own wrapper; do not disable the rule |
| Password manager retries | 4–6 failures then a success for one user | Rule 1 needs 5 in 5 minutes; a success inside the window hands the case to Rule 2 (critical). Confirm with the user, then set `false_positive_feedback=false_positive` |
| Scheduled task running PowerShell | Rule 3 fires 30 minutes after an admin login | Outside the 2-minute window — no alert. If a task starts immediately, add the binary to `expected_processes` |
| Monitoring agent | Rule 3 on `svchost.exe`/`agent.exe` startup | Add the binary to `expected_processes` |
| Sysmon re-export duplicates | Duplicate failures inflate the count | Ingestion is idempotent by document ID; verify you are not feeding both a file and a live Filebeat copy of the same events |
| Clock skew across sources | Events appear "in the future" and are rejected | The schema rejects `@timestamp` more than 5 minutes ahead of ingestion; fix NTP on the source host |

## Regression checklist after any tuning change

```powershell
python -m pytest tests -q                       # unit + data-driven rule cases
python -m src.main generate-samples --scenario all
python -m src.main ingest --log-dir .\logs\generated
python -m src.main correlate --run-once         # expect 1 brute_force, 1 successful_brute_force, 2 suspicious_process_post_login
Remove-Item .\data\dedup-cache.json -ErrorAction SilentlyContinue
```

Expected after the full replay above: `brute_force=1`, `successful_brute_force=1`,
`suspicious_process_post_login=2`, and zero alerts from `normal_day` and `false_positive_mix`.

This replay assumes `.\logs\generated` holds the demonstration fixtures alone. If
it also holds `enterprise-14d_*`, the `ingest` line is refused rather than
indexing both — see `docs/DATASET.md` §2.1.
