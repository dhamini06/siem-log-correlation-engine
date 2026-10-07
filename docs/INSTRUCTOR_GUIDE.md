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

Students work through an investigation queue: they answer **one objective at a time**, press
**Check answer** on that question, get an immediate verdict, and move on. There is no
"submit everything" button. A scenario ends with a **final analyst finding** which is
required in its own right.

Question ids are `s<N>e<M>` for evidence objectives and `s<N>f` for the finding — Scenario 1
has `s1e1`…`s1e8` then `s1f`. These are the ids in the tables below and in
`data/answer-key.json`.

| Aspect | Behaviour |
|---|---|
| Where grading runs | Server-side, in `scripts/answer_grader.py`. The key is never sent to the browser. |
| What a student sees | Per question: **Correct**, **Partly right**, or **Not yet**. For anything unmatched: the name of the part and a hint. Never the answer. |
| Checking | One question per request. The response carries a verdict for that question only, so checking one objective never disturbs another. |
| Show a hint | Available after a check that did not pass. Gives a pointer, never the answer. |
| Show solution | Available after a check. Returns the model answer and marks that question **assisted**. Assistance is sticky: answering it correctly afterwards does not clear the mark. Mention it when collecting work. |
| The final finding | Required. Graded against a four-part rubric (Evidence, Assessment, Impact, Recommended response for Scenarios 1–4; Timeline, Confirmed compromise, Parallel and quiet activity, Recommended next actions for Scenario 5). Every rubric element must be present. |
| Completion | Unlocks only when **every evidence question and the final finding** are correct. Evidence alone cannot complete a scenario. |
| Not graded | Absolute UTC timestamps and PIDs, because the sample generator re-bases them every session. Durations and counts *are* graded, since those are stable. |

**Marking guidance.** A scenario reported as complete means every evidence objective was right
*and* the finding covered its rubric. That is a machine judgement on required concepts, not a
judgement of writing quality — read the findings yourself before crediting them. Questions a
student saw the solution for are recorded as **assisted**, and the counts are shown in the
progress summary.

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

Times below are the values in the current 9,584-event dataset (base
`2026-09-16T00:00:00Z`, 14 days). The generator re-bases absolute times on every
lab session, so **only the durations are graded** — a student's answer is the
interval, never the clock time.

| # | Rule | Severity | src_ip | User | Host | Window (UTC) | Elapsed | Evidence |
|---|---|---|---|---|---|---|---|---|
| A | `brute_force` | high | 203.0.113.45 | root | web-01 | 09-17 12:00:00 → 12:02:12 | **132 s** | 10 events |
| B | `successful_brute_force` | **critical** | 203.0.113.66 | alice | web-01 | 09-22 04:00:00 → 04:02:09 | **129 s** | 6 events |
| C | `suspicious_process_post_login` | high | 198.51.100.25 | jdoe | app-01 | 09-26 20:00:00 → 20:00:20 | **20 s** | 2 events |
| D | `suspicious_process_post_login` | high | 198.51.100.77 | deploy | web-01 | 09-26 20:01:00 → 20:01:45 | **45 s** | 2 events |

Alerts A and B share the host `web-01` and nothing else: different source address,
different account. Treat them as separate activity.

### Reference timeline (all UTC, current dataset)

```
-- Alert A: brute force against web-01 over SSH --------------------------
09-17 12:00:00  web-01  logon_failure   root         203.0.113.45  (1 of 10)
09-17 12:00:16  web-01  logon_failure   admin        203.0.113.45  Invalid user admin
09-17 12:00:26  web-01  logon_failure   root         203.0.113.45  (3 of 10)
09-17 12:00:41  web-01  logon_failure   admin        203.0.113.45  Invalid user admin
09-17 12:00:58  web-01  logon_failure   root         203.0.113.45  (5 of 10)
09-17 12:01:14  web-01  logon_failure   admin        203.0.113.45  Invalid user admin
09-17 12:01:28  web-01  logon_failure   root         203.0.113.45  (7 of 10)
09-17 12:01:45  web-01  logon_failure   admin        203.0.113.45  Invalid user admin
09-17 12:01:56  web-01  logon_failure   root         203.0.113.45  (9 of 10)
09-17 12:02:12  web-01  logon_failure   admin        203.0.113.45  (10 of 10)  <- ALERT A
                        10 failures, 2 accounts, 132 s. No success follows.
09-17 12:02:20  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
09-17 12:02:23  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
09-17 12:02:26  fw-01   network_conn    203.0.113.45  UFW BLOCK dport 22
                        3 blocks, 8-14 s after the last failure.

-- Alert B: the same shape, but a success follows ------------------------
09-22 04:00:00  web-01  logon_failure   alice        203.0.113.66  (1 of 5)
09-22 04:00:21  web-01  logon_failure   alice        203.0.113.66  (2 of 5)
09-22 04:00:36  web-01  logon_failure   alice        203.0.113.66  (3 of 5)
09-22 04:00:56  web-01  logon_failure   alice        203.0.113.66  (4 of 5)
09-22 04:01:18  web-01  logon_failure   alice        203.0.113.66  (5 of 5)
09-22 04:02:09  web-01  logon_success   alice        203.0.113.66  <- ALERT B
                        Accepted password. 129 s from first failure, inside
                        success_window_minutes, so severity escalated.

-- Alerts C and D: post-login process execution, minutes apart ----------
09-26 20:00:00  app-01  logon_success   CORP\jdoe    198.51.100.25
09-26 20:00:20  app-01  process_create  CORP\jdoe                 <- ALERT C
                        cmd.exe /c whoami && net user administrator /active:yes
09-26 20:01:00  web-01  logon_success   deploy       198.51.100.77
09-26 20:01:45  web-01  priv_esc        deploy                    <- ALERT D
                        sudo USER=root COMMAND=/bin/bash -i

-- Routine activity on web-01, for contrast with alert D ---------------
09-26 19:00:04  web-01  priv_esc        deploy       medium  /usr/bin/journalctl --vacuum-time=7d
09-26 13:43:45  web-01  priv_esc        admin        medium  /usr/bin/ntpdate -s 10.20.0.5
09-26 09:58:51  web-01  priv_esc        root         medium  /usr/bin/docker ps --format table
09-26 06:45:22  web-01  priv_esc        svc_deploy   medium  /usr/bin/docker ps --format table
                        severity medium, expected processes -> no alert.

-- The non-alerting near-misses ----------------------------------------
09-28 04:00:00  web-01  logon_success   svc_backup   10.0.0.30
09-28 04:00:30  web-01  logon_failure   svc_backup   10.0.0.30
09-28 04:01:00  web-01  logon_failure   svc_backup   10.0.0.30
09-28 04:01:30  web-01  logon_failure   svc_backup   10.0.0.30
09-28 04:03:00  web-01  logon_success   svc_backup   10.0.0.30
                        4 failures < min_failures (5) -> NO ALERT. A retyped password.

09-19 04:00:00  web-02  logon_failure   svc_sql      10.0.0.32   (1 of 6)
09-19 04:25:00  web-02  logon_failure   svc_sql      10.0.0.32   (6 of 6)
                        6 failures, 5 min apart: at most 2 inside any 5-minute window.

09-19 04:00:00  web-03  logon_failure   mchen        10.0.0.41   (1 of 3)
09-19 04:00:00  web-03  logon_failure   mchen        10.0.0.42   (1 of 3)
                        6 failures, but split across two source addresses: 3 each.

09-19 04:00:00  web-04  logon_failure   tnguyen      10.0.0.50   (1 of 4)
09-19 04:21:00  web-04  logon_success   tnguyen      10.0.0.50
                        burst then a success 21 min later: outside success_window_minutes.

09-28 04:00:00  app-02  logon_success   CORP\administrator
09-28 04:30:00  app-02  process_create  CORP\administrator
                        powershell.exe -File C:\Scripts\Inventory.ps1
                        severity high, but 30 min after the logon: outside the window.
```

The last two entries are the answer to `s5e7`: suspicious-looking activity that
raised no alert, and the specific rule condition that stayed unsatisfied.

---

## 2. Scenario 1 — Brute Force Investigation

**Rule:** `brute_force` · **Severity:** high · **Time:** ~15 minutes

### Answers

| Id | Asks | Accepted | Where it comes from |
|----|-------|----------|--------------------|
| `s1e1` | Identify the source address the engine alerted on for this brute force. | source address: `203.0.113.45` | SOC Triage Board > Alert Queue |
| `s1e2` | Identify the host that was being targeted. | target host: `web-01` | SOC Triage Board > Alert Queue |
| `s1e3` | Determine how many failed authentications this alert covers. | number of failed logons: `10`, or equivalent wording | Kibana Discover, security-alerts-* > evidence_event_ids |
| `s1e4` | Determine how long the burst of failures lasted. | elapsed seconds from first to last failure: `132`, or equivalent wording | Kibana Discover, normalized-events-* sorted by @timestamp |
| `s1e5` | Determine whether the activity targeted one account or several. | number of distinct accounts named in the failures: `2`, or equivalent wording | Kibana Discover, raw_event on the logon_failure events |
| `s1e6` | Identify which service port the blocked connections were aimed at. | destination port of the blocked connections: `22`, or equivalent wording | Kibana Discover, event_type network_connection |
| `s1e7` | Determine how many connections the perimeter firewall refused. | number of blocked connections from the attacker: `3`, or equivalent wording | Kibana Discover, event_type network_connection |
| `s1e8` | Explain why comparable-looking activity elsewhere in the lab produced no alert. | which rule condition was not met: `below`, `condition never held`, `did not alert`, `did not meet`, `did not reach`, `did not trigger`, `fell short`, `fewer`, `less`, `min_failures`, `min_failures: 5`, `min_failures=5`, `never fired`, `never held`, `never reached`, `never triggered`, `no alert was raised`, `not high enough`, `reach`, `short of`, `threshold`, `under`, or equivalent wording | Kibana Discover + the rule's configured count threshold |
| **`s1f`** | State the complete assessment: origin, target, volume, timing, perimeter corroboration, outcome and impact. | Graded against the rubric below: evidence: origin, target, volume and timing; assessment: what the activity was; impact: was anything obtained; response: what you would do next | SOC Triage Board > Alert Queue, plus the network_connection events for the perimeter blocks |

**Model answer for `s1f`** — An external host ran an automated credential attack against SSH on web-01, making repeated failed authentications across more than one account name inside a short burst, and the perimeter firewall refused the follow-on connections to the same service. No successful authentication followed, so no account was taken over: this is a contained attempt rather than a compromise. Block the source address, confirm the perimeter rule held, and review whether the configured failure threshold is appropriate for this service.

**Rubric for `s1f`.** A complete finding states all four. EVIDENCE: the source address, the target host, the failed-authentication count, the burst duration, the number of accounts tried, and the blocked perimeter connections. ASSESSMENT: an automated credential attack against one service from outside the network, spreading effort across more than one account name. IMPACT: no account was taken over - no successful authentication followed - so this is an attempted attack that was contained at the perimeter, not a compromise. RECOMMENDED RESPONSE: block the source address, confirm the perimeter rule that refused the connections, and review whether the count threshold is right for this service.

### Expected investigation path
1. SOC Triage Board → `Alerts by Severity` → the `brute_force` alert.
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

| Id | Asks | Accepted | Where it comes from |
|----|-------|----------|--------------------|
| `s2e1` | Identify the account this alert concerns. | account: `alice` | SOC Triage Board > Alert Queue |
| `s2e2` | Identify the source address this alert concerns. | source address: `203.0.113.66` | SOC Triage Board > Alert Queue |
| `s2e3` | Determine how many failed authentications preceded the successful one. | number of failed authentications: `5`, or equivalent wording | Kibana Discover, evidence set filtered to logon_failure |
| `s2e4` | Determine how long the attacker had before the successful authentication. | elapsed seconds from first failure to the success: `129`, or equivalent wording | Kibana Discover, normalized-events-* sorted by @timestamp |
| `s2e5` | Determine whether the success fell inside the window the escalating rule allows. | yes, the success fell inside the configured window: `yes`, `inside`, `within`, `fall inside`, or equivalent wording; and the severity therefore escalated: `escalat`, `critical`, `escalate`, or equivalent wording | Compare the interval you just calculated with the window the escalating rule is configured with |
| `s2e6` | Identify the evidence in the raw log line that separates success from failure. | what distinguishes the success event: `accepted`, `accepted password`, `authentication was accepted`, `raw log line`, or equivalent wording | Kibana Discover, raw_event on the success event |
| `s2e7` | Determine whether this activity and the failed-only burst came from the same source. | no, different source addresses: `no`, `different`, `separate`, `distinct`, `not the same`, or equivalent wording; and they are therefore separate activity: `separate`, `different`, `distinct`, `no`, `not linked`, `unrelated`, or equivalent wording | SOC Triage Board > Alert Queue, comparing the two brute-force alerts |
| **`s2f`** | State whether access was achieved and justify it from the evidence. | Graded against the rubric below: evidence: account, origin, failures and acceptance; assessment: achieved access, not an attempt; impact: who and what is exposed; response: contain and preserve | SOC Triage Board > Alert Queue, plus the alert's evidence set including the accepted authentication |

**Model answer for `s2f`** — An external source made repeated failed SSH authentications against one account on one host, and an accepted-password line in the raw log records that the authentication then succeeded, establishing a valid session. The elapsed interval fell inside the escalating rule's configured window, which is why the severity rose to critical. An external party now holds authenticated access as that account: block the source, rotate the credential and revoke sessions, and preserve the host for forensics.

**Rubric for `s2f`.** A complete finding states all four. EVIDENCE: the account, the source address, the number of failed authentications, the interval to the accepted authentication, and the raw log line that records acceptance. ASSESSMENT: this is achieved access, not an attempt - a valid session was established, which is why the severity escalated. IMPACT: an external party holds an authenticated session on that account on that host. RECOMMENDED RESPONSE: block the source address, disable or rotate the account credential and revoke its sessions, and preserve the host before rebuilding.

### Expected investigation path
1. `Alerts by Severity` → the only `critical` alert.
2. `Top Source IPs by Event Volume` → separate this attacker IP from Scenario 1's.
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

| Id | Asks | Accepted | Where it comes from |
|----|-------|----------|--------------------|
| `s3e1` | Identify the host this alert concerns. | host: `app-01` | SOC Triage Board > Alert Queue |
| `s3e2` | Identify the account that authenticated and then ran the process. | account: `jdoe`, `corp\jdoe`, `corp/jdoe` | SOC Triage Board > Alert Queue, then the logon event |
| `s3e3` | Identify the process that was created after the logon. | process name: `cmd.exe`, `cmd` | Kibana Discover, event_type process_create for that host |
| `s3e4` | Determine the order in which the operations in the command line ran. | first operation, then second operation: `print the current identity -> re-enable a disabled built-in account` | Kibana Discover, process.command_line |
| `s3e5` | Determine how soon after the logon the process was created. | elapsed seconds between logon and process creation: `20`, or equivalent wording | Kibana Discover, the alert's two evidence events |
| `s3e6` | Identify the parent process and what it indicates about the session. | the parent process: `winlogon.exe`, `winlogon`; and what that indicates about the session: `interactive`, `hands-on-keyboard`, `keyboard`, `hands on`, `console`, `desktop`, `logged on`, `logon session`, or equivalent wording | Kibana Discover, process.parent_name on the process_create event |
| `s3e7` | Determine whether the evidence supports a link to the authentication activity. | no, the evidence does not support a link: `no`, `different`, `separate`, `distinct`, `unrelated`, or equivalent wording; and state which field decides it: `host`, `user`, `src_ip`, `source address`, `different host`, `different user`, `different source`, or equivalent wording | SOC Triage Board > Alert Queue, comparing host, user and source address |
| **`s3f`** | State the assessment: who, where, from where, when, what they ran, why it is suspicious, and the response. | Graded against the rubric below: evidence: who, where, from where and when; evidence: the command activity, in order; assessment: why it is suspicious; response: immediate containment | SOC Triage Board > Alert Queue, plus the alert's two evidence events (logon and process_create) |

**Model answer for `s3f`** — Immediately after authenticating to one application-server host from an external address, that account spawned a command shell twenty seconds later and ran two chained operations: printing its current identity, then re-enabling a disabled built-in account. An interactive logon parent shows a person drove this from a logged-on desktop, and disabling a built-in account that only an administrator can re-enable is preparation for keeping privileged access. Isolate the host, disable both accounts, and preserve the process records before rebuilding.

**Rubric for `s3f`.** A complete finding states all four. EVIDENCE: the account, the host, the source address, the short interval after authentication, the process, and both operations in its command line in order. ASSESSMENT: the operations are reconnaissance followed by preparation - establishing the current identity and re-enabling a disabled built-in account - which is the standard preparation for maintaining access, and the interactive parent process shows a person was at the keyboard. IMPACT: an interactive shell on the application server with the means to obtain a privileged account. RECOMMENDED RESPONSE: isolate the host, disable the account and any built-in account it re-enabled, and preserve the host and its process records before rebuilding.

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

| Id | Asks | Accepted | Where it comes from |
|----|-------|----------|--------------------|
| `s4e1` | Identify the host this alert concerns. | host: `web-01` | SOC Triage Board > Alert Queue |
| `s4e2` | Identify the account that authenticated and then requested elevation. | account: `deploy` | SOC Triage Board > Alert Queue, then the logon event |
| `s4e3` | Identify the account the elevated command assumed. | account assumed by the elevated command: `root` | Kibana Discover, raw_event on the elevation event |
| `s4e4` | Determine what kind of command was requested and why it matters. | what the requested command does: `interactive shell`, `shell`, `interactive`, or equivalent wording | Kibana Discover, COMMAND= in the raw_event of the elevation event |
| `s4e5` | Determine how soon after authenticating the elevation was requested. | elapsed seconds between logon and the elevated command: `45`, or equivalent wording | Kibana Discover, the alert's two evidence events |
| `s4e6` | Identify the recorded fields that tell the two apart. | the distinguishing fields: `severity -> the full command text -> the original log line`, `severity -> the full command text -> the original log line`, `severity, the full command text, the original log line` | Kibana Discover, comparing the two elevation events |
| `s4e7` | Determine what comparable activity on the same host did NOT do, and why it stayed quiet. | what the routine elevation did instead: `restart`, `service`, `nginx`, `apt-get`, `package`, `update`, `routine`, `administrative`, `maintenance`, or equivalent wording; and why that kept it out of the alert queue: `not in the suspicious`, `suspicious_processes`, `expected`, `expected_processes`, `allow`, `allowlist`, `not on the`, `does not contain`, `no suspicious`, or equivalent wording | Kibana Discover, event_type privilege_escalation on that host |
| **`s4f`** | State the escalation, the contrast with routine use, the evidence, and the containment recommendation. | Graded against the rubric below: evidence: the escalation; evidence: what was requested, and what separates it; assessment: how it differs from routine administrative use; impact and response | SOC Triage Board > Alert Queue, plus the elevation event and the routine elevation records on the same host |

**Model answer for `s4f`** — A deployment account on the production web server authenticated from an external address and requested elevation forty-five seconds later, assuming root and asking for an interactive shell rather than any of the routine administrative commands recorded on the same host. Severity, the full command text and the preserved raw line are the fields that separate the two, and only this one is on the rule's suspicious-process list. Root on a production web server is unrestricted access: isolate the host, revoke the account's privilege, preserve the host and its logs, and audit what changed during the session.

**Rubric for `s4f`.** A complete finding states all four. EVIDENCE: the initiating account, the account it assumed, the host, the interval after authenticating, the interactive command that was requested, and the recorded fields that separate it from the routine use on the same host. ASSESSMENT: this is escalation to full administrative privilege followed by a request for an interactive shell - the standard way to retain interactive control of a host - which is materially different from the routine administrative commands recorded on the same host. IMPACT: whoever requested it holds unrestricted root access to a production web server and can read or alter anything on it. RECOMMENDED RESPONSE: isolate the host, revoke the initiating account's privilege, preserve the host and its raw logs for forensics, and audit what was changed during the session.

### Expected investigation path
1. `Alert Queue` → pick the post-login alert for `web-01` (not `app-01`).
2. Follow the alert's evidence ids to the logon and the elevation event.
3. Discover: `event_type: "privilege_escalation" AND host: "web-01"` → many events over
   the fortnight, but **exactly one** at severity `high`.
4. Compare `process.command_line` and `severity` across them.
5. `raw_event` gives the full sudo invocation including TTY, PWD and target user.

### Common student mistakes
- Treating **all** `privilege_escalation` events on the host as malicious. Over 14 days
  `web-01` records 78: 77 routine administrative commands at severity `medium` and one
  interactive shell at `high`.
- Missing the `USER=root` token and answering "escalated to sudo" instead of "to root".
- Not reading the `-i` flag significance.
- Assuming the attacker account is the only one that uses sudo. `deploy` runs routine
  commands on that host too, so the account name does **not** separate the two cases —
  the severity and the requested command do.

### Grading note
This scenario is where you check judgement. A student who flags every sudo on the host as
malicious has the wrong answer, and so has one who separates them but cannot say *which
recorded field* did the separating. A student who names `severity`, the full command text
and the preserved raw line, and explains that the routine commands fall on the rule's
expected-process list, has understood triage.

### Hints ladder
1. Different source IP and a Linux host. 2. The sudo line structure. 3. What `-i` changes. 4. Filter `event_type: "privilege_escalation" AND host: "web-01"`. 5. Name the single discriminating field, then the impact.

---

## 6. Scenario 5 — Multi-Event SOC Investigation (capstone)

**All rules** · **Time:** ~25 minutes

### Answers

| Id | Asks | Accepted | Where it comes from |
|----|-------|----------|--------------------|
| `s5e1` | Order the four alerts from earliest to latest. | the four alerts in time order: `the failed-only authentication burst -> the authentication burst that succeeded -> the first post-authentication process -> the second post-authentication process` | SOC Triage Board > Alert Queue, timestamp column |
| `s5e2` | Determine how many separate source addresses the engine alerted on. | number of distinct alerting source addresses: `4`, or equivalent wording | SOC Triage Board > Alert Queue, src_ip column |
| `s5e3` | Determine which two of the alerts landed on the same host. | the two alerts sharing a host: `the failed-only authentication burst -> the authentication burst that succeeded` | SOC Triage Board > Alert Queue, host column |
| `s5e4` | Determine whether the alerts on the shared host came from the same source. | no, different source addresses: `no`, `different`, `separate`, `distinct`, or equivalent wording; so they must be tracked as separate activity: `separate`, `different`, `distinct`, `no`, `not linked`, `unrelated`, or equivalent wording | SOC Triage Board > Alert Queue, comparing src_ip and user on those two rows |
| `s5e5` | Determine which alert records that the attacker actually got in. | which alert represents achieved access: `the authentication burst that succeeded` | SOC Triage Board > Alert Queue, severity column |
| `s5e6` | Determine which alert represents the most serious outcome and justify it. | which alert is the most serious: `the authentication burst that succeeded`, `succeeded`, or equivalent wording; and why it outranks the others: `successful`, `success`, `session`, `accepted`, `authenticated`, `got in`, `critical`, `achieved`, `compromise`, `valid session`, or equivalent wording | SOC Triage Board > Alert Queue, severity plus the evidence sets |
| `s5e7` | Explain how activity that looked suspicious produced no alert. | an example of quiet suspicious activity: `powershell`, `app-02`, `administrator`, `scheduled`, `task`, `inventory`, `script`, `30 minutes`, `30 min`, `outside`, `window`, `late`, or equivalent wording; and which rule condition kept it quiet: `window`, `time_after_login_minutes`, `time window`, `too long`, `outside`, `2 minutes`, `expected`, `expected_processes`, `threshold`, `not in the suspicious`, `did not reach`, or equivalent wording | Kibana Discover, normalized-events-* |
| **`s5f`** | Write the handover: timeline, confirmed compromise, parallel activity, quiet-but-suspicious behaviour, and next actions. | Graded against the rubric below: timeline: the alerts in order; confirmed compromise: what proves access was achieved; parallel and quiet activity; recommended next actions | SOC Triage Board > Alert Queue for the timeline and severity, plus normalized-events-* for the quiet activity |

**Model answer for `s5f`** — Four alerts across three hosts over several days, in order: a failed-only authentication burst, an authentication burst that succeeded, then two post-authentication process alerts. The confirmed compromise is the burst that succeeded - an accepted authentication gave an external party a valid session on one account on the web server - and that host and account need containing now. The two alerts sharing the web server came from different source addresses, so they are separate activity and must not be merged into one attacker, and separate suspicious activity on another host produced no alert because it ran outside the rule's post-authentication window, which is a detection gap worth reviewing. Next actions: block the confirmed source address at the perimeter, disable the accessed account and revoke its sessions while preserving the host, and review whether the rule's window is too narrow to catch the quiet activity.

**Rubric for `s5f`.** A complete handover covers all four. TIMELINE: put the four alerts in order and say what each represents, spanning the days they occur rather than hours. CONFIRMED COMPROMISE: name the one alert that proves access was achieved and the account and host it affects. PARALLEL AND QUIET ACTIVITY: state that the two alerts sharing a host came from different sources and must be tracked separately, and explain the suspicious activity that produced no alert. RECOMMENDED NEXT ACTIONS: give three concrete actions - block the confirmed source address, contain the account and host that were actually accessed, and review the detection gaps the quiet activity exposed. Keep it to a short paragraph plus three actions.

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
- Missing the non-alerting near-misses (`s5e7`) — this is the highest-value question, because the activity really was suspicious and the rule's window is why nothing fired.
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

The `ingest` line above requires `.\logs\generated` to hold the demonstration
fixtures **only**. If `enterprise-14d_*` is also present, that line is refused:
nothing is indexed, the conflicting filenames are printed, and the exit code is
non-zero. Either work in a directory holding only the fixtures, ingest a single
named file with `--file`, or rebuild the enterprise dataset as documented in
`docs/DATASET.md` §2.

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
