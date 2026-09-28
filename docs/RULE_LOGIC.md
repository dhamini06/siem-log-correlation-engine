# Correlation Rule Logic — Lab #07

Entry point: `src/correlation/rules.py`. Rules are pure functions over a chronologically
sorted list of `CorrelatedEvent` objects, so they are fully unit-testable without
Elasticsearch. `apply_rules()` runs all three and returns a time-sorted list; a failing rule
is logged and skipped without aborting the cycle.

Shared input model:

```
CorrelatedEvent = event_id, timestamp, event_type, src_ip, user, host,
                  process_name, process_path, command_line
```

Every alert carries `rule_name, severity, timestamp, src_ip, user, host, evidence_event_ids,
reasoning, first_seen, last_seen, dedup_key, dedup_window_minutes`.

---

## Helper: failure burst detection

```
find_failure_bursts(events, min_failures, window_minutes):
    group logon_failure events by src_ip (skip "unknown"/empty)
    for each src_ip, failures sorted by time:
        i = 0
        while i < len(failures):
            window = [f in failures[i:] if f.time < failures[i].time + window]
            if len(window) >= min_failures:
                emit window; i += len(window)      # non-overlapping clusters
            else:
                i += 1
    return bursts sorted by first_seen
```

Because clusters are maximal and non-overlapping, a continuous stream of failures produces one
alert covering the whole stream, while two clearly separated bursts produce two alerts.

---

## Rule 1 — Brute Force

**Trigger:** `>= min_failures` (default 5) `logon_failure` events from the same `src_ip`
inside `time_window_minutes` (default 5).
**Severity:** `high`.

```
for burst in find_failure_bursts(...):
    if any logon_success from burst.src_ip in
       [burst.first_seen, burst.last_seen + window]:
        skip          # Rule 2 owns the successful case
    emit Alert(rule_name="brute_force", severity=high,
               first_seen=burst.first, last_seen=burst.last,
               evidence=burst event IDs,
               dedup_key=sha256("brute_force|src_ip|user")[:32])
```

Negative cases: 4 failures, failures spread beyond the window, failures split across source
IPs, or events with `src_ip="unknown"`.

---

## Rule 2 — Successful Brute Force (escalation)

**Trigger:** the Rule 1 condition plus a `logon_success` from the same `src_ip` within
`success_window_minutes` (default 10) of the burst start. The success user must match the
failed user; if no exact match exists, the first success from that IP is used.
**Severity:** `critical`.

```
for burst in find_failure_bursts(...):
    candidates = logon_success where src_ip == burst.src_ip
                 and burst.first_seen <= t <= burst.first_seen + success_window
    if not candidates: continue
    match = earliest(candidates matching user, else earliest candidate)
    emit Alert(rule_name="successful_brute_force", severity=critical,
               first_seen=burst.first, last_seen=match.time,
               evidence=burst IDs + [match.event_id],
               reasoning="Brute force attack succeeded ... likely gained access")
```

Evidence therefore always contains the failures **and** the success — the escalation is
self-contained for triage.

---

## Rule 3 — Suspicious Post-Login Execution

**Trigger:** a `logon_success` followed within `time_after_login_minutes` (default 2) by a
process-execution event on the **same host** whose process matches `suspicious_processes`
and not `expected_processes`. Process-execution evidence is `process_create`
(Windows 4688 / Sysmon 1) or `privilege_escalation` (Linux `sudo COMMAND=` records such as
`/bin/bash -i`).
**Severity:** `high`.

```
process_events = [e for e in events if e.event_type in
                  ("process_create", "privilege_escalation")]

for login in logon_success events (host known, not already alerted):
    deadline = login.time + time_after_login_minutes
    matches = [p for p in process_events
               if p.host == login.host
               and login.time <= p.time <= deadline
               and not matches_any(p, expected_processes)
               and matches_any(p, suspicious_processes)]
    if matches:
        emit Alert(rule_name="suspicious_process_post_login", severity=high,
                   first_seen=login.time, last_seen=earliest match,
                   evidence=[login.event_id, match.event_id])
        # one alert per login, even if several suspicious processes follow
```

Process matching compares lowercased `process.name`, `process.path`, and `process.command_line`.
Multi-word or flag-style entries (`/bin/bash -i`) only match the command line; single-token
entries match a whole path segment. Negative cases: process on a different host, process before
the login, process later than the window, or a process on the `expected_processes` allowlist
(`explorer.exe`, `svchost.exe`, `spoolsv.exe`, `cron`, `systemd-logind`, `sshd`).

---

## Deduplication (`src/correlation/deduplication.py`)

```
cache: dedup_key -> {last_alert_time, evidence_ids, alert_count}

for alert in candidates:
    entry = cache.get(alert.dedup_key)
    if entry is None:                                  -> emit, create entry
    elif alert.time - entry.last_alert_time >= 30min:  -> emit, reset entry
    elif |new evidence IDs| >= 2:                      -> emit, merge evidence
    else:                                              -> suppress (INFO log)
```

`dedup_key = sha256("rule_name|src_ip|user")[:32]`, so an analyst's re-triage of one source IP
does not suppress a different rule or a different account. The cache is persisted to
`data/dedup-cache.json` and is also re-seeded from existing `security-alerts-*` documents on
the first cycle after a restart, so suppression survives both restarts and cache loss.

## Engine cycle (`src/correlation/engine.py`)

```
run_correlation_cycle():
    seed dedup cache from alerts in the last 30 minutes (first cycle only)
    hits = ES.search_hits("normalized-events-*", range @timestamp [now-lookback, now))
    events = load_events(hits)                 # sorted by time
    alerts = apply_rules(events, config)       # Rules 1 -> 2 -> 3
    emit, suppressed = dedup.filter_alerts(alerts)
    for alert in emit:
        ES.index_alert(f"security-alerts-{alert.date}",
                       alert.to_dict(), sha256(dedup_key + first_seen))
    refresh security-alerts-*
    persist dedup cache
    log "Correlation cycle complete: events=N alerts_created=N suppressed=N [...] in Xs"
```

`lookback_window_minutes` (default 120) bounds the query so a cycle stays fast; because the
window is much larger than every rule window, alerts remain correct across engine downtime.
`python -m src.main correlate` schedules this cycle every `engine_frequency_seconds` (default 60)
with APScheduler; job exceptions are caught so the scheduler never dies.

## Tuning pointers

| Symptom | First knob | Reference |
|---|---|---|
| Rule 1 too noisy | raise `min_failures`, or add an allowlisted `src_ip` upstream | `docs/FALSE_POSITIVE_TUNING.md` |
| Rule 2 missing | raise `success_window_minutes` | `docs/CONFIGURATION_REFERENCE.md` |
| Rule 3 noisy | extend `expected_processes`, shorten `time_after_login_minutes` | `docs/FALSE_POSITIVE_TUNING.md` |
| Repeat alerts | `alert_dedup_window_minutes`, `min_new_evidence_for_realert` | `docs/CONFIGURATION_REFERENCE.md` |
