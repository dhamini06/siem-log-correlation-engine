# Instructor Guide & Answer Key — BlueCloud Softech Solutions SIEM Lab

**Lab #07 — SIEM Log Correlation Engine**
**Classification: INSTRUCTOR USE ONLY — do not distribute to students before the exercise.**

All answers below are derived from the live Elasticsearch data and are verified automatically by
`python scripts/validate_scenarios.py`. Every value in this document exists in the cluster right
now, so you can re-verify at any time.

---

## 0. Student answer checking (instructor notes)

The platform checks student answers automatically. This guide remains the authoritative
source of truth. Its machine-readable form, `data/answer-key.json`, is what the platform
actually grades against, and is deliberately not in version control because the repository
is public. Keep the two in step when you edit either one.

| Aspect | Behaviour |
|---|---|
| Where grading runs | Server-side, in \scripts/answer_grader.py\. The key is never sent to the browser. |
| What a student sees | Per question: Correct, Partially correct, or Needs work. For anything unmatched: the name of the part and a hint. Never the answer. |
| Show solution | Available per question. Returns the model answer and marks the scenario **assisted**. Mention it when collecting work. |
| Completion | Unlocks only when every machine-checked question is correct. |
| Self-reviewed questions | Interpretation and finding questions carry a checkbox and a review prompt; they are not machine-graded. |
| Not graded | Absolute UTC timestamps and PIDs, because the sample generator re-bases them every session. |

**Marking guidance.** A scenario reported as complete means every *checkable* fact was right. The
written answers are still yours to assess — that is what the self-review checkboxes and the
per-scenario notes below are for.

## 1. Lab at a glance

| Item | Value |
|---|---|
| Normalized events | 50 |
| Security alerts | 4 (3 high, 1 critical) |
| Correlation rules | 3 |
| Affected hosts | `web-01` (Linux), `app-01` (Windows), `app-02` (Windows, non-alerting), `fw-01` (firewall) |
| Scenario pages | 5 |
| Estimated time | 60–90 minutes total |

### The four alerts

| # | Rule | Severity | src_ip | User | Host | Window (UTC) | Evidence |
|---|---|---|---|---|---|---|---|
| A | `brute_force` | high | 203.0.113.45 | root | web-01 | 07:25:55 → 07:28:07 | 10 events |
| B | `successful_brute_force` | **critical** | 203.0.113.66 | alice | web-01 | 07:25:55 → 07:28:04 | 6 events |
| C | `suspicious_process_post_login` | high | 198.51.100.25 | jdoe | app-01 | 07:25:55 → 07:26:15 | 2 events |
| D | `suspicious_process_post_login` | high | 198.51.100.77 | deploy | web-01 | 07:26:55 → 07:27:40 | 2 events |

### Reference timeline (all UTC)

```
05:30:55  web-01  logon_success   alice       10.0.0.21   baseline
05:30:55  fw-01   network_conn    10.0.1.40   UFW BLOCK dport 445
05:31:15  web-01  logon_failure   alice       10.0.0.21   baseline (1 of 1)
   ...    carol/bob repeat this pattern on 10.0.0.22 / 10.0.0.23 ...
05:40:55  web-01  priv_esc        carol       sudo /usr/bin/systemctl restart nginx   benign
05:55:55  web-01  priv_esc        carol       sudo /usr/bin/apt-get update            benign
06:55:55  web-01  logon_success   CORP\administrator 10.0.0.5  app-02 login
06:55:55  web-01  logon_failure   svc_backup  10.0.0.30   (1)
06:56:25  web-01  logon_failure   svc_backup  10.0.0.30   (2)
06:56:55  web-01  logon_failure   svc_backup  10.0.0.30   (3)
06:57:25  web-01  logon_failure   svc_backup  10.0.0.30   (4)
06:58:55  web-01  logon_success   svc_backup  10.0.0.30   NO ALERT (4 < 5)
07:25:55  web-01  logon_failure   root        203.0.113.45  attack A starts
07:25:55  web-01  logon_failure   alice       203.0.113.66  attack B starts
07:25:55  app-01  logon_success   CORP\jdoe   198.51.100.25
07:25:55  app-02  process_create  CORP\administrator  powershell -File Inventory.ps1  NO ALERT (30 min after login)
07:26:11  web-01  logon_failure   admin       203.0.113.45  "Invalid user admin"
07:26:15  app-01  process_create  CORP\jdoe   cmd.exe /c whoami && net user administrator /active:yes
07:26:55  web-01  logon_success   deploy      198.51.100.77
07:27:40  web-01  priv_esc        deploy      sudo USER=root COMMAND=/bin/bash -i
07:28:04  web-01  logon_success   alice       203.0.113.66  ← COMPROMISE
07:28:15  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
07:28:18  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
07:28:21  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
```

---

## 2. Scenario 1 — Brute Force Investigation

**Rule:** `brute_force` · **Severity:** high · **Time:** ~15 minutes

### Answers

| Q | Answer |
|---|---|
| 1 | Source IP **203.0.113.45**, target host **web-01** |
| 2 | **root** × 5, **admin** × 5 (the admin attempts are logged as `Invalid user admin`) |
| 3 | **10 failed logons**, **07:25:55Z → 07:28:07Z** (132 seconds / 2 min 12 s) |
| 4 | Rule **`brute_force`**; thresholds **`min_failures: 5`** and **`time_window_minutes: 5`** |
| 5 | **No.** No `logon_success` event exists with `src_ip: 203.0.113.45`. Also note rule 1 explicitly *suppresses* itself when a success is seen, handing the case to rule 2. |
| 6 | Three `network_connection` events on `fw-01`, `src_ip: 203.0.113.45` → `dst_ip: 10.0.0.10`, **port 22**, at **07:28:15, 07:28:18, 07:28:21Z** — seconds after the SSH burst |
| 7 | **`svc_backup` from 10.0.0.30** — **4** failures (06:55:55–06:57:25Z) then a success at 06:58:55Z. **4 < `min_failures` (5)**, so no alert. A human retyping a password looks exactly like this. |
| 8 | `Invalid user admin` means the account **does not exist** on the host, so sshd rejected it before a password check. Combined with `Failed password for root`, the attacker was **cycling through a username list** — credential stuffing, not one targeted account. |
| 9 | **Finding:** An external host (203.0.113.45) ran an automated credential attack against the SSH service of `web-01`, attempting 10 authentications across two accounts (`root`, `admin`) inside 2 minutes 12 seconds. The web server rejected every attempt and the perimeter firewall blocked the follow-on connections, so **no account was compromised**. Impact is attempted unauthorised access; the exposure is a password-guessable or internet-reachable SSH service on a web server. |

### Expected investigation path
1. SOC Triage Board → `SIEM Alerts by Severity` → the `brute_force` alert.
2. Read `reasoning`: it states source IP, host, count and window.
3. Discover, `normalized-events-*`: `event_type: "logon_failure" AND src_ip: "203.0.113.45"`, sort by `@timestamp` asc → confirm 10 events and the window.
4. Break down by `user` → root 5, admin 5.
5. Confirm no success: `event_type: "logon_success" AND src_ip: "203.0.113.45"` → 0 hits.
6. `host: "fw-01"` → the three `network_connection` blocks to port 22.
7. `user: "svc_backup"` → 4 failures + 1 success, no alert.

### Common student mistakes
- Reading the count as 5 (the threshold) instead of 10 (the actual count).
- Reporting the alert's `first_seen` as the attack start and missing that failures continue after it.
- Concluding "compromised" because the word "brute force" appears in the reasoning.

### Hints ladder
1. Locate the alert on the board. 2. Filter Discover by the attacker IP. 3. The two thresholds are in `config/app-config.yaml`. 4. Firewall events are `event_type: "network_connection"` on `fw-01`. 5. Search other failure bursts on `web-01`. 6. A strong finding names activity, target, origin, volume, window, outcome and impact.

---

## 3. Scenario 2 — Successful Login After Brute Force

**Rule:** `successful_brute_force` · **Severity:** critical · **Time:** ~15 minutes

### Answers

| Q | Answer |
|---|---|
| 1 | Rule **`successful_brute_force`**, `src_ip` **203.0.113.66**, host **web-01**, account **alice** |
| 2 | **07:25:55, 07:26:16, 07:26:31, 07:26:51, 07:27:13** (all UTC) |
| 3 | Success at **07:28:04Z**; **129 seconds** (2 min 9 s) after the first failure |
| 4 | **6 events** = **5 failed logons + 1 successful logon** |
| 5 | Rule 2 is an **escalation**: it fires only when the rule-1 burst condition is met *and* a success follows within `success_window_minutes: 10`. A success changes the meaning from "attempted" to "achieved", so severity goes high → **critical**. |
| 6 | Scenario 1: 203.0.113.45, accounts root/admin, **10 failures, no success**, high. Scenario 2: 203.0.113.66, single account **alice**, **5 failures then a success**, **critical**. |
| 7 | The success event's `process.name` is **`sshd`** and its `raw_event` reads `Accepted password for alice ... ssh2`. The failures carry **no process** because no session was ever established. This proves an authenticated SSH session existed. |
| 8 | Impact: an **unauthenticated external party now holds a valid interactive session** as `alice` — confidentiality and integrity of everything that account can reach. First three actions: (1) block 203.0.113.66 at the firewall, (2) disable/rotate `alice`'s credential and revoke active sessions, (3) preserve the host for forensics (memory, auth logs, shell history) before rebuilding. |
| 9 | **Finding:** The account `alice` on `web-01` was **successfully compromised**. Five consecutive failed SSH authentications from 203.0.113.66 between 07:25:55Z and 07:27:13Z were followed 51 seconds later by an accepted password authentication at 07:28:04Z, establishing an interactive SSH session (`Accepted password for alice ... ssh2`). The 2 min 9 s gap falls inside the 10-minute success window, so the SIEM escalated to **critical**: this is a confirmed, not attempted, intrusion. |

### Expected investigation path
1. `SIEM Alerts by Severity` → the only `critical` alert.
2. `Top Source IPs by Alert Count` → separate this attacker IP from Scenario 1's.
3. Read `reasoning` → it states 5 failures then a success.
4. Discover, filter `src_ip: "203.0.113.66"` → 6 events, sort ascending.
5. Count `evidence_event_ids` → 6.
6. Open one evidence event → compare `process` presence on failures vs the success.

### Common student mistakes
- Confusing the two attacker IPs (there are two brute force episodes in the lab).
- Answering 5 for the evidence count instead of 6.
- Saying "the rule detected 5 failures" and missing the escalation logic.

### Hints ladder
1. Two episodes, two IPs. 2. The reasoning sentence says "succeeded". 3. Count `evidence_event_ids` and load them. 4. Compare `process` on failures vs success. 5. Cut off the source, invalidate the credential, preserve evidence.

---

## 4. Scenario 3 — Suspicious Post-Login Process Execution

**Rule:** `suspicious_process_post_login` · **Severity:** high · **Time:** ~15 minutes

### Answers

| Q | Answer |
|---|---|
| 1 | Host **app-01**, user **`jdoe`** (the alert field) / **`CORP\jdoe`** (the event field), source IP **198.51.100.25** |
| 2 | Logon **07:25:55.101Z**; process creation **07:26:15.101Z** |
| 3 | **20 seconds** apart. The rule window is `time_after_login_minutes: 2` (120 s) |
| 4 | Process **cmd.exe**, path `C:\Windows\System32\cmd.exe`, command line **`cmd.exe /c whoami && net user administrator /active:yes`** |
| 5 | `cmd.exe /c whoami` → launch a command shell and print the **current identity and privilege level**. `net user administrator /active:yes` → **enable (or re-enable) the built-in `administrator` account** so the actor has a known, powerful credential to authenticate with later. The `&&` chains them: identify, then prepare persistence. |
| 6 | Parent is **`winlogon.exe`** (PID 812) — the component that creates the session at interactive logon, so this is a **hands-on-keyboard** shell spawned straight from the login session, not a service or scheduled task. |
| 7 | Rule **`suspicious_process_post_login`**. It requires (a) a `logon_success` on a host and (b) within `time_after_login_minutes` a process on the **same host** whose name is in `suspicious_processes` and not in `expected_processes`. `cmd.exe` is on the suspicious list and is not on the allowlist. |
| 8 | **No — separate incident.** Different host (`app-01` vs `web-01`), different user (`jdoe` vs `root`/`alice`), different source IP, and no shared identity or infrastructure. Report it as a distinct finding; do not merge the two. |
| 9 | **Finding:** Immediately after authenticating to `app-01` from 198.51.100.25 at 07:25:55Z, the account `CORP\jdoe` spawned `cmd.exe` at 07:26:15Z — 20 seconds later — running `whoami` to establish its privilege level and `net user administrator /active:yes` to enable the built-in administrator account. A legitimate interactive session rarely re-enables a dormant admin account seconds after login; this is the reconnaissance-and-persistence pattern of an attacker operating an already-valid credential. Response: isolate the host, disable the account, and determine how the credential was obtained. |

> **Note on the username (accept either form).** The **alert** stores the domain-stripped
> `jdoe`, because the correlation rule normalises the account for grouping. The underlying
> **event** stores the full Windows form `CORP\jdoe`. Both are correct; mark either as right and
> use the difference as a teaching point about how the SIEM normalises identity across sources.
> This is a common source of confusion and worth calling out in the debrief.

### Expected investigation path
1. Find the post-login alert on a **Windows** host (`app-01`), not `web-01` — that is Scenario 4.
2. Read `first_seen` (logon) and `last_seen` (process) → 20 s delta.
3. Load the 2 evidence events.
4. Expand `process` on the 4688 event → `command_line`, `parent_name`, `parent_pid`.
5. Compare with the benign `svchost.exe` / `agent.exe` events on the same host.

### Common student mistakes
- Picking Scenario 4's alert (also `suspicious_process_post_login`).
- Reporting 2 minutes (the window) instead of 20 seconds (the actual gap).
- Describing `whoami` as "malicious" without explaining it is reconnaissance.

### Hints ladder
1. Windows host vs Linux host. 2. Subtract `first_seen` from `last_seen`. 3. Expand the `process` object; read `raw_event` too. 4. Consider each command separately. 5. `parent_name` = `winlogon.exe`. 6. Compare hosts/users/IPs before deciding they are related.

---

## 5. Scenario 4 — Linux Privilege Escalation and Reverse Shell

**Rule:** `suspicious_process_post_login` · **Severity:** high · **Time:** ~20 minutes (hardest judgement call)

### Answers

| Q | Answer |
|---|---|
| 1 | Host **web-01**, user **deploy**, source IP **198.51.100.77** |
| 2 | SSH logon **07:26:55Z**; sudo command **07:27:40Z** |
| 3 | **45 seconds** |
| 4 | `sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -i` |
| 5 | **`deploy` → `root`**, i.e. full administrative privilege on `web-01` |
| 6 | `-i` makes the shell **interactive**, so it presents a prompt and reads commands from the attacker. Over an already-established SSH session that is the standard way to retain interactive control and survive a dropped connection — it is the classic reverse-shell pattern. A service restart or package update never needs an interactive shell. |
| 7 | Benign sudo runs are by **`carol`** on `web-01`: **`/usr/bin/systemctl restart nginx`** and **`/usr/bin/apt-get update`**. Both are recorded as `privilege_escalation` with severity **medium**. |
| 8 | **`process.command_line`** (interactive shell vs administrative command), **`severity`** (high vs medium), and **`raw_event`** (the `TTY=pts/0` / `COMMAND=` content). Secondary: the `user` performing the escalation. |
| 9 | **Finding:** The deployment account `deploy` escalated to **root** on the production web server `web-01` at 07:27:40Z — 45 seconds after authenticating from 198.51.100.77 — and requested an **interactive** shell (`COMMAND=/bin/bash -i`). Unlike the routine `systemctl` and `apt-get` sudo activity performed by `carol` on the same host, an interactive root shell grants complete control of the host and enables persistence. Containment: isolate `web-01` from the network, terminate the `deploy` session, preserve auth and sudo logs for forensics, and audit everything the account and root touched during the session window. |

### Expected investigation path
1. `Top Source IPs by Alert Count` → pick the post-login alert from `web-01` (not `app-01`).
2. Read the `reasoning` — it quotes `/bin/bash -i` verbatim.
3. Discover: `event_type: "privilege_escalation" AND host: "web-01"` → 3 events.
4. Compare `process.command_line` and `severity` across the three.
5. `raw_event` gives the full sudo invocation including TTY, PWD and target user.

### Common student mistakes
- Treating **all** `privilege_escalation` events as malicious and flagging `carol`.
- Missing the `USER=root` token and answering "escalated to sudo" instead of "to root".
- Not reading the `-i` flag significance.

### Grading note
This scenario is where you check judgement. A student who flags `carol`'s sudo without noticing the
interactive shell has the wrong answer. A student who correctly separates them and justifies it
with `command_line` + `severity` has understood triage.

### Hints ladder
1. Different source IP and a Linux host. 2. The sudo line structure. 3. What `-i` changes. 4. Filter `event_type: "privilege_escalation" AND host: "web-01"`. 5. Name the single discriminating field, then the impact.

---

## 6. Scenario 5 — Multi-Event SOC Investigation (capstone)

**All rules** · **Time:** ~25 minutes

### Answers

| Q | Answer |
|---|---|
| 1 | **4 alerts**: **3 high** (`brute_force` ×1, `suspicious_process_post_login` ×2) and **1 critical** (`successful_brute_force` ×1) |
| 2 | See the alert table at the top of this guide (A–D) |
| 3 | **4 distinct source IPs** generated alerts: 203.0.113.45 → web-01, 203.0.113.66 → web-01, 198.51.100.25 → app-01, 198.51.100.77 → web-01. Two are brute force, two are post-login execution. |
| 4 | First attacker event **07:25:55Z**; last **07:28:21Z** (the final firewall block). Total span ≈ **2 minutes 26 seconds**. |
| 5 | **Separate.** `web-01` carries two alerts from different source IPs (203.0.113.45 → root, 203.0.113.66 → alice), different rules and different accounts. A single attacker could plausibly run both, but nothing in the data links them: no shared credential, no shared tooling, and the two episodes run in parallel. Report them as concurrent activity on the same host, and treat 203.0.113.66 as the confirmed compromise. |
| 6 | **`successful_brute_force` (critical, 203.0.113.66).** It is the only alert representing **achieved** access — a valid SSH session for `alice` on `web-01` at 07:28:04Z. The `brute_force` alert is an *attempt* that failed; the two post-login alerts are post-authentication behaviour whose origin is not established by the SIEM alone. |
| 7 | The firewall (`fw-01`) shows the attack from the **perimeter**, not just from a single host: three `UFW BLOCK` records from 203.0.113.45 to 10.0.0.10 port 22 confirm hostile external traffic. No host log proves the attack was external — the SSH source address alone could be spoofed or proxied. |
| 8 | **(a) `svc_backup`** on `web-01`: 4 failed logons then a success from 10.0.0.30 — below `min_failures: 5`, so no alert; a legitimate user retyping a password. **(b) `CORP\administrator`** on `app-02`: `powershell.exe -File C:\Scripts\Inventory.ps1` at 07:25:55Z, **30 minutes** after the 06:55:55Z logon — outside `time_after_login_minutes: 2`, so no alert; a scheduled inventory task. |
| 9 | The baseline is routine internal SSH from **10.0.0.21–10.0.0.23** (alice, bob, carol) on `web-01`, each account showing exactly **one** success and **one** failure spread across hours, plus carol's two benign sudo commands. It is normal because the failures never cluster (1 per user, never ≥5 in a window), the source IPs are internal, the cadence is hours apart rather than seconds apart, and the sudo commands are administrative — no interactive shell. |
| 10 | *Handover example:* Between 07:25:55Z and 07:28:21Z a coordinated burst of hostile activity hit the estate. Two external addresses (203.0.113.45 and 203.0.113.66) brute-forced SSH on `web-01`; 203.0.113.66 **succeeded**, obtaining an interactive session as `alice` at 07:28:04Z — confirmed compromise, critical. Simultaneously, two accounts showed post-login hands-on-keyboard activity: `CORP\jdoe` on `app-01` re-enabling the built-in administrator account via `cmd.exe`, and `deploy` on `web-01` obtaining an interactive root shell via `sudo /bin/bash -i`. The perimeter firewall blocked follow-on connections from 203.0.113.45. Benign activity (`svc_backup` retype, scheduled PowerShell inventory) correctly produced no alerts. *Next actions:* (1) disable `alice` and `deploy`, revoke sessions, block both external IPs; (2) preserve and image `web-01` and `app-01` for forensics; (3) audit all activity by `alice`, `deploy` and `CORP\jdoe` since 07:20Z and force a credential reset programme for all four accounts. |

### Expected investigation path
1. Board → record all 4 alerts (severity, rule, IP, user, host, time).
2. Discover → set a range covering the incident, sort `@timestamp` asc, read down the list.
3. Group by `src_ip` then `host`; identify 4 clusters.
4. Identify the baseline (10.0.0.21–23) and rule it out.
5. Search for the two non-alerting near-misses.
6. Rank by severity and by *achieved* vs *attempted*.
7. Write the handover.

### Common student mistakes
- Merging all `web-01` activity into one attack.
- Missing one of the two non-alerting near-misses (Q8) — this is the highest-value question.
- Ranking the `brute_force` alert above the `successful_brute_force` alert because it has more events.
- Omitting the firewall records from the timeline.

### Hints ladder
1. Export the master alert table first. 2. Sort the whole incident by time. 3. Group by `src_ip`, then host. 4. Search failure bursts and `powershell.exe` separately. 5. Severity is a triage order; look for *confirmed* compromise. 6. A handover answers impact, assets, achievement, next step, and three actions.

---

## 7. Facilitator notes

### Running the session
- **Setup (10 min):** start the stack, generate samples, ingest, correlate, import the dashboard, then start the training platform. Confirm the SOC Triage Board is populated before students arrive.
- **Do not** re-run `correlate` mid-session — deduplication will suppress the alerts and students will see an empty board. If you must re-run, delete `data\dedup-cache.json` first.
- **Data ages.** Sample events are generated relative to "now" and the dashboard defaults to a 7-day window. If the lab is rebuilt on a later day, regenerate the samples rather than editing timestamps.

### Regenerating a clean lab
```powershell
docker compose up -d
python -m src.main init-templates
python scripts\reset_lab_data.py --yes     # clear the previous session first
python -m src.main generate-samples --scenario all
python -m src.main ingest --log-dir .\logs\generated
python -m src.main correlate --run-once
python -m src.main import-dashboard
python -m src.main stats
```
Expected: 50 events, 4 alerts (`brute_force` 1, `successful_brute_force` 1, `suspicious_process_post_login` 2).

**Always reset first.** Re-ingesting without a reset appends ~6 duplicate events per session
(Windows sample timestamps carry milliseconds, so their document IDs change each run), which
breaks the counts this guide and the scenarios depend on. `start_lab.ps1` does this automatically.

### Verifying before class
```powershell
python scripts/validate_scenarios.py
```
Every check must pass. This asserts each scenario's exact values against the live cluster, so it
also confirms the answer key above is still correct.

### Common questions from students
| Question | Answer |
|---|---|
| "Why is `src_ip` empty on some events?" | Not all events have a source address. Process creation and sudo records have no network origin, so the field is `null`. The schema uses `null`, not `"unknown"`, because Elasticsearch `ip` fields reject non-addresses. |
| "Why is `web-01` in some alerts and `app-01` in others?" | Different operating systems. `web-01` is Linux (`auth.log` / sudo), `app-01` and `app-02` are Windows (4624/4688). |
| "Is 198.51.100.25 the same attacker as 203.0.113.45?" | No. Different addresses, different hosts, different accounts. Do not merge them. |
| "How do I know `svc_backup` is not an attack?" | 4 failures is below the 5-failure threshold, the source is internal, the failures are 30 s apart rather than seconds apart, and the account then logs in successfully — the signature of a user retyping a password. |
| "The reasoning field already gives me the answer. Is that cheating?" | No. Real SIEMs write a reasoning string too. Your job is to **verify** each number against the underlying events, which is what catches a misfiring or mistuned rule. |

### Assessment rubric

| Level | Descriptor |
|---|---|
| **Exceeds** | Correct values, each tied to a named record; explains rule thresholds; correctly separates malicious from benign activity; identifies the two non-alerting near-misses. |
| **Meets** | Correct values for most questions with evidence for the main ones; identifies the malicious sudo as distinct from the benign sudo. |
| **Developing** | Finds the right alerts but counts or timestamps are approximate, or the finding is asserted without evidence. |
| **Below** | Answers from the scenario title, or confuses the two attacker IPs, or treats all sudo/privilege-escalation events as malicious. |
