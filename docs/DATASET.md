# Lab dataset (Phase 4A)

This document describes the synthetic log dataset the training lab runs on:
what it contains, how it is produced, what it deliberately does *not* do, and
the one limitation a student or instructor should know about.

Everything here is generated locally from a fixed seed by
`src/normalization/enterprise_generator.py`. There is no external data source,
no network fetch, and no manual editing of the log files.

---

## 1. Shape

| Property | Value |
|---|---|
| Normalized events | 9,584 |
| Hosts | 31 (16 Linux, 15 Windows) |
| Distinct source addresses | 231 (232 counting `unknown`) |
| Distinct accounts | 40 |
| Event types | 5 |
| Sources | `linux_auth`, `windows_sysmon`, `firewall_syslog` |
| Time span | 14.0 days, 2026-09-16 00:01Z → 2026-09-29 23:57Z |
| Seed | `1337` |
| Base timestamp | `2026-09-16T00:00:00Z` |
| Alerts produced | exactly 4 |

Event type distribution:

| Event type | Count | Share |
|---|---|---|
| `logon_success` | 3,115 | 32.5% |
| `process_create` | 2,781 | 29.0% |
| `network_connection` | 2,087 | 21.8% |
| `privilege_escalation` | 1,017 | 10.6% |
| `logon_failure` | 584 | 6.1% |

Severity mix: `low` 4,733 (49.4%), `medium` 4,312 (45.0%), `high` 539 (5.6%).

The brief asked for `dns_query`, `web_request`, `file_access` and
`service_state` as well. `EventType` in `src/normalization/schema.py` has six
members and none of those four, and adding them is a schema change, which is
out of scope for this phase. The dataset therefore uses the types that exist
and represents the intent through them: DNS and web traffic appear as
`network_connection` records against port 53 and 80/443, file-server access as
`network_connection` against 445, and service lifecycle as `systemctl` sudo
records plus type-5 logons. If those event types are wanted later, they belong
with the schema and question redesign, not here.

`Severity` likewise has no `informational` level. `low` is the schema's
baseline tier and carries the routine traffic.

---

## 2. Reproducing it

```powershell
# Reset first: this deletes normalized-events-*, security-alerts-* and the
# dedup cache, and nothing else.
python scripts\reset_lab_data.py --yes

# Generate (writes three files, then self-audits the alert population)
python -m src.normalization.enterprise_generator --output .\logs\generated --clean

# Ingest
python -m src.main --log-level WARNING ingest --log-dir .\logs\generated

# Correlate the full 14 days and write the alerts
python scripts\correlate_range.py --since 2026-09-16T00:00:00Z --expect-alerts 4

# Re-import the board if its saved range changed
python -m src.main import-dashboard
```

`--clean` matters. `ingest --log-dir` indexes **every** log file it finds, and the older
per-scenario demonstration files live in the same directory. Without `--clean` the generator
refuses to run rather than let two datasets be indexed together: duplicate attack fixtures,
two different timestamp anchors, and an event count nobody can explain. This is not
hypothetical - it happened once during development and indexed 9,634 events instead of 9,584.

### 2.1 The ingestion guard

The generator-side refusal above protects the enterprise dataset from the
demonstration files. The **ingestion** side is now guarded too, because the
generator is not the only way a directory comes to hold both datasets.

`ingest --log-dir <dir>` refuses the run when `<dir>` contains the approved
enterprise dataset (`enterprise-14d_*`) **and** per-scenario demonstration
fixtures (`brute_force_*`, `normal_day_*`, `post_login_exec_*`,
`successful_brute_force_*`, `false_positive_mix_*`). When it refuses:

- nothing is indexed - not even the enterprise files, so there is no partial load;
- the command exits non-zero;
- both sets of conflicting filenames are printed;
- it suggests either `ingest --file <path>` for an explicitly chosen input, or
  pointing `--log-dir` at a directory holding only the dataset you mean.

The check runs before the first Elasticsearch write, before the indexing client
is even acquired, and it applies to `--dry-run` as well: a dry run that
succeeded would certify a directory that must not be ingested. `--file` is never
blocked, because naming one file is already an unambiguous choice.

What the guard does **not** do: it does not choose a directory for you, and it
does not move anything. Keeping the two datasets apart is still the operator's
job, and the recovery procedure in section 2 is the supported way to rebuild the
enterprise dataset.

Both halves of the decision come from `foreign_log_files()` and
`dataset_paths()` in `enterprise_generator`, so the ingestion guard and the
generator cannot drift apart about which files belong to the dataset.

`correlate --run-once` will *not* work against this dataset. The engine scans
`[now - 120min, now]`, which is correct for a live engine watching a moving
window but sees about one hour of a fourteen-day dataset.
`scripts/correlate_range.py` reuses the same `apply_rules`, the same
`AlertDeduplicator`, the same `index_alert` call and the same
`alert_document_id`, and only widens the range. It is a backfill, which is
what a real SIEM calls that operation too. It refuses to run when a range holds
more than 10,000 events rather than silently correlating a prefix of the data.

Verified idempotent: re-ingesting the same files leaves the event count at 9,584 (document ids
are a content hash, so writes overwrite), and a second backfill writes 0 alerts and suppresses
all 4 as duplicates.

### Determinism

Two runs with the same seed produce byte-identical files. There is no
`datetime.now()` in the generation path, no unseeded randomness, and no UUIDs.

One element is clock-derived, and it is the parsers' doing rather than the
generator's. `parse_syslog_header` matches a classic syslog header with no year
field, and `normalize_to_utc` fills the year in from the current clock. A
parser change is out of scope here, so `resolve_base_time()` mirrors that same
inference and applies it to the Windows JSON timestamps as well, which keeps
both sources on the same dates. Month, day, time of day, ordering, counts,
process ids and every other field are fully fixed; only the calendar year
tracks the clock, exactly as it already does for the current lab data.

Re-ingesting the same files is safe. Document ids are a SHA-256 of
`host | timestamp | event_type | src_ip | raw_event`, and the dataset is
constructed so no two events share all five, so a second ingest overwrites the
same documents rather than duplicating them.

---

## 3. What is in it

### Enterprise topology

31 hosts across three tiers: application servers `app-01..06`, workstations
`wks-101..108`, and a server tier holding `web-01..04`, `db-01..03`, both
domain controllers, the firewall, proxy, file server, jump host, build agent,
mail, VPN and backup hosts.

All addresses are RFC 1918 private or RFC 5737 documentation-reserved
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). No address in the
dataset could belong to a real system on the internet. Account names are
generic and invented; none is a real identity.

Attack source addresses also appear in ordinary traffic, so an attacker is not
identifiable merely by having an address that only ever shows up during an
attack. The alerts are reachable from the rules, not from eyeballing which
addresses look unusual.

### Baseline activity

Interactive logons in business hours, service and scheduled-task logons at
night, password typos, routine process creation, administrative sudo,
east-west traffic, and blocked internet background scanning at the edge.
Weekends run a reduced shift.

### False-positive families

All six documented families are present and none of them alerts.

| Family | Instance | Why it stays silent |
|---|---|---|
| Below threshold | 4 failures from `10.0.0.30`, then a success | fewer than `min_failures` |
| Spread beyond window | 6 failures from `10.0.0.32`, 5 min apart | never 5 inside `time_window_minutes` |
| Split across source IPs | 3 + 3 from `10.0.0.41` / `10.0.0.42` | no single address reaches the threshold |
| Late success | 4 failures, success 20 min later | under threshold, and outside `success_window_minutes` |
| Scheduled task | `powershell.exe` on `app-02` 30 min after a logon | outside `time_after_login_minutes` |
| Expected service | `svchost.exe` on `app-03` 30 s after a logon | matches `expected_processes` |

The "below threshold" family is not emitted a second time. Its canonical
instance is the `svc_backup` sequence in
`sample_generator.generate_false_positive_mix`, and the Scenario 01 answer key
pins that one by address. A second instance on the same host with the same
account and count would leave a student with two equally correct answers.
`tests/data/negative_cases.json` remains authoritative for the *semantics*; the
address it uses there is a fixture value, not a contract.

### Canonical attack fixtures

The four alert-producing sequences are produced by calling the existing
`sample_generator` functions with the documented seed, so the evidence is
byte-for-byte the evidence students have always been able to read. Their
internal spacing - which is what the answer key's durations are measured
against - cannot drift: the 132-second Scenario 01 window is a property of
`random.Random(1337)` reaching `randint(5, 20)` nine times.

They sit 36, 148, 260 and 292 hours from the dataset anchor, interleaved with
baseline activity rather than next to one another.

---

## 4. Time ranges: absolute, because the dataset is

Making the dataset reproducible changed something that used to hide itself: the
absolute timestamps stopped moving. The old 50-event sample set was generated
relative to "now", so every alert was always fresh and any sensible Kibana range
showed it. This dataset is anchored at a constant, so the alerts have a fixed
age that grows every day.

That fixed age is the whole point of it. Every cohort has to investigate the same
alerts, read the same evidence documents, and get the same graded answers, so the
dataset cannot be re-anchored to chase the calendar. Once the data is fixed, a
window expressed relative to "now" is simply the wrong shape: it is guaranteed to
stop covering the data, and it does so silently.

So the investigation window is **absolute**:

| | |
|---|---|
| `INVESTIGATION_FROM` | `2026-09-15T00:00:00.000Z` |
| `INVESTIGATION_TO` | `2026-09-30T23:59:59.999Z` |
| Dataset | 2026-09-16 00:01:07Z .. 2026-09-29 23:57:07Z |

A day of slack at each end means containment does not depend on the exact first
and last event. The values live in two files, `training/assets/js/lab.js` and
`scripts/build_dashboard.py`, and two tests assert they agree - they are
different files in different languages, so the agreement cannot come from sharing
a constant.

### 4.1 The SOC Triage Board

`timeFrom` was `now-7d`, then `now-15d`. Both were relative, so both aged. The
board now saves the absolute window above, generated by
`scripts/build_dashboard.py`; the NDJSON is regenerated with that script rather
than hand-edited.

`timeRestore` is `true`, and that is worth stating plainly because it reads the
other way round. Measured on Kibana 8.13 against this board, reading the rendered
time picker in a browser:

| `timeFrom` | `timeRestore` | Result |
|---|---|---|
| absolute ISO | `false` | **0 alerts**, picker "Last 15 minutes" |
| absolute ISO | `true` | **4 alerts**, picker shows the dates |
| `now-15d` | `false` | **0 alerts**, picker "Last 15 minutes" |
| `now-15d` | `true` | 3 alerts, picker "Last 15 days" |

So `false` does **not** mean "pin the lab's range"; it means "ignore the lab's
range", and Kibana falls back to its own 15-minute default without reporting an
error. That is worse than the ageing problem this window exists to solve, and it
is invisible - no error, and not even a "No results" message. An earlier revision
of this lab set the flag to `false` on the reasonable-sounding assumption that it
would stop a student's browser-local choice overriding the board; the browser
experiment above is what disproved that.

Two `date_histogram` aggregations (Alert Timeline, Authentication Activity) carry
their own `timeRange`, which overrides the global range for those panels. They are
built from the same two constants, so they follow the board automatically.

### 4.2 The Discover deep-links

Each training page used to build its own Discover URL in an inline script at the
foot of the page:

```js
return KIBANA + "/app/discover#/?_g=(time:(from:now-24h,to:now))" + ...
```

Eight pages did this, and the eight copies were the problem as much as the
value was. A student who clicked **Investigate in Discover** landed on **511 of
9,584 events (5.3%) and 0 of 4 alerts** - all four attacks outside the window -
while the board looked perfectly correct. Nothing failed, because each page was
internally consistent.

The block is now defined once, in `training/assets/js/lab.js`, as
`initKibanaLinks()`, and the eight inline copies are gone. The pages keep their
`data-kibana-dash` / `data-kibana-link` / `data-kibana-alerts` / `data-es-link`
attributes; the shared script fills in the URLs on `DOMContentLoaded`.

| Window | Events visible | Alerts visible |
|---|---|---|
| `now-24h` (before) | 488 of 9,584 | **0 of 4** |
| `now-15d` (before, once aged) | 9,584 of 9,584 | **3 of 4** |
| absolute (now) | **9,584 of 9,584** | **4 of 4** |

**The absolute values have to be quoted in the URL.** Kibana's Rison time syntax
discards an unquoted absolute ISO:

```
_g=(time:(from:2026-09-15T00:00:00.000Z,to:2026-09-30T23:59:59.999Z))   -> 0 rows, picker says "Last 15 minutes"
_g=(time:(from:'2026-09-15T00:00:00.000Z',to:'2026-09-30T23:59:59.999Z')) -> 4 alerts
```

Measured against Kibana 8.13, and both wrong forms fail *silently* into a
zero-result range - the same failure class as the original `now-24h` defect. So
the two constants stay plain unquoted ISO, because that is what Kibana stores in
a saved object's `timeFrom` and because the cross-file tests compare them byte
for byte; `discoverUrl()` applies the quoting where the URL is serialised.

`tests/test_ui_render_contracts.py` guards all of this: no page may carry its own
`discover()`, its own time range, or its own Kibana base URL; `now-24h` may not
appear anywhere under `training/`; the initializer must be registered on
`DOMContentLoaded`; the window must be absolute and must contain the dataset at
both ends with bounded slack; and `discoverUrl()` must quote it. Each was checked
by reintroducing the defect and confirming the tests fail.

### 4.3 If the dataset is ever re-anchored

The window is not derived from anything at run time - there is no mechanism that
recomputes it, and none should be added. Re-anchoring the dataset is a deliberate
release, and the window changes deliberately and in the same change, in both
files. The containment tests in `tests/test_ui_render_contracts.py` and
`tests/test_dashboard_ndjson.py` are what will fail if that is forgotten, because
they compare the window against `DATASET_FIRST_DAY` / `DATASET_LAST_DAY` rather
than against a remembered literal.

That is also why those two tests assert containment rather than equality with a
literal. The original assertion was `window == "now-15d"`, which checked the
implementation instead of the property it was named for: it rejected any correct
absolute window, and it went on passing long after `now-15d` had stopped covering
the data.

---

## 5. Known limitation: Rule 3 has no notion of a scheduled job

**This is a limitation of the current correlation model, not a property of a
realistic enterprise, and it is not fixed here.**

`rule_suspicious_process_post_login` treats the following names as suspicious
whenever they appear within `time_after_login_minutes` (2) of a successful
logon on the same host:

```
cmd.exe, powershell.exe, bash, /bin/bash, /bin/bash -i, nc
```

That is the whole test. The rule has no concept of a routine shell, no concept
of a scheduled task, and no allowlist for administrative tooling. Measured
against the earlier demonstration dataset it fired on 604 of 3,600 baseline
events, which is why the demonstration set had to be tiny.

Phase 4A does not change `suspicious_processes`, does not change the rule, and
does not add an allowlist. Instead the **baseline is built to respect the rule
as written**: those process names are kept out of ordinary logon-then-process
sequences, and where they appear at all they are placed where no logon can pair
with them. Routine shell work is represented with `explorer.exe`,
`svchost.exe`, `spoolsv.exe`, `sshd`, `systemctl`, `apt-get` and similar.

The consequence is honest but worth stating plainly: a real enterprise runs
`cmd.exe` after logons constantly, and this rule would fire on all of it. The
dataset does not model that, because modelling it would mean modelling four
hundred false positives, and widening the alert population is explicitly out
of scope for this phase.

Scheduled PowerShell and `cmd.exe` runs *do* appear in the dataset, on hosts
carrying no interactive logon near them. They are the visible shape of the
problem: to this rule they are indistinguishable from the start of an attack,
and the only reason they stay quiet is their distance from a logon.

Fixing this properly means changing rule semantics - an allowlist keyed on
parent process and schedule context, or splitting the rule by account - and
that is deferred to the rule and question redesign phase. When it happens, the
baseline here becomes the natural noise floor to validate the new rule against.

---

## 6. Tests

`tests/test_enterprise_dataset.py` covers determinism, dataset shape, schema
validity, document-id uniqueness, the six false-positive families, the Rule 3
constraint, and - the group that matters most - the answer-key integrity
checks that assert each pinned value a student is expected to discover is still
present and still unambiguous:

- Scenario 01: ten failures from `203.0.113.45` on `web-01`, spanning 132
  seconds, across `root` and `admin`, no success from that address, plus three
  blocked connections to `10.0.0.10:22`.
- Scenario 01 non-alerting account: `svc_backup`, exactly four failures, only
  from `10.0.0.30`.
- Scenario 02: five failures and one success for `alice` on `web-01`, the
  success inside the ten-minute window. The earlier suggestion of ten failures
  is explicitly not adopted; the answer key is authoritative.
- Scenario 03: one logon and one `cmd.exe` on `app-01`, twenty seconds apart.
  Asserted as *exactly one* each, because a second `cmd.exe` on that host would
  make "what was created" ambiguous.
- Scenario 04: one logon and one `sudo /bin/bash -i` on `web-01`, forty-five
  seconds apart, with benign sudo records present for comparison.
- Alert queue: four alerts, three high, one critical, two from the post-login
  rule, four distinct source addresses.
- No answer-pinned account (`alice`, `admin`, `root`, `deploy`, `jdoe`,
  `svc_backup`) mistypes a password in the background, which would change the
  expected counts.
- No generated line names a scenario, a verdict, or a grading outcome.

---

## 7. Deferred

Not in this phase, and not started:

- widening the alert population beyond the four canonical alerts
- changing Rule 3, or `suspicious_processes`
- adding a routine-process allowlist
- rewriting the Scenario 05 queue-count questions
- per-question checking (the current design is deferred until this phase and
  the per-question design are both final)
- new event types or a new severity tier
- Kibana dashboard work beyond the one measured range fix
