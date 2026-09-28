# Log Parser Reference — Lab #07

All parsers implement `LogParser.parse(raw_line) -> NormalizedEvent | None`, return `None`
for unparseable lines (never raise), and set `parsed_count` / `skipped_count` for metrics.
Every event is validated against the common schema before indexing.

## Common utilities (`src/normalization/parsers.py`)

| Helper | Behaviour |
|---|---|
| `parse_syslog_header(line)` | Splits `Sep 25 17:20:01 web-01 sshd[1]: message` into `(datetime, host, message)`. Host is lowercased by callers; a missing host yields `unknown`. |
| `clean_ip(value)` | Extracts and range-checks an IPv4 address, strips `/32` and brackets, returns `unknown` for anything unusable. |
| `LogParser.parse_file(path)` | Parses a whole file, skipping blank/unparseable lines. |

### Timestamp normalization (`src/utils/time_utils.py`)

| Input | Interpretation |
|---|---|
| `2024-01-15T14:32:45.123Z` | ISO8601 UTC |
| `2024-01-15T14:32:45+05:30` | Converted to UTC |
| `2024-01-15 14:32:45` | Assumed UTC |
| `Sep 25 17:20:01` | Classic syslog; year inferred as the current UTC year. If the result is more than 1 minute in the future, the previous year is used (syslog carries no year). |
| `Sep 25 2024 17:20:01` | Syslog with explicit year |
| `1713212445` / `1713212445000` | Unix epoch seconds / milliseconds |

All normalized events store `@timestamp` as ISO8601 UTC with millisecond precision. The schema
rejects events more than 5 minutes in the future and allows at most 300 seconds of clock skew
between `@timestamp` and `ingest_timestamp`.

---

## 1. Linux auth.log — `src/normalization/linux_auth.py`

### SSH accepted login → `logon_success` (severity `low`)

```
Regex: sshd(?:\[(?P<pid>\d+)\])?:\s*Accepted\s+(?P<method>\S+)\s+for\s+
       (?P<user>[^\s]+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)

Example: Sep 25 17:21:01 web-01 sshd[12345]: Accepted password for alice from 10.0.0.5 port 51240 ssh2
Result:  event_type=logon_success, user=alice, src_ip=10.0.0.5, port=51240, protocol=ssh,
         severity=low
```

### SSH failure / invalid user → `logon_failure` (severity `medium`)

```
Regex A: sshd...:\s*(?:Failed\s+(?:password|publickey|gssapi-with-mic|keyboard-interactive)
                   |Connection closed by (?:authenticating|invalid) user)\s+
                   (?:for\s+)?(?:invalid user\s+)?(?P<user>\S+)(?:\s+from\s+(?P<ip>...))?
Regex B: sshd...:\s*Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>...)

Example: Sep 25 17:20:01 web-01 sshd[12345]: Failed password for alice from 10.0.0.5 port 51234 ssh2
Example: Sep 25 17:20:02 web-01 sshd[12345]: Invalid user admin from 203.0.113.45 port 51235
Result:  event_type=logon_failure, src_ip set when present, severity=medium
```

### sudo → `privilege_escalation` (severity `high` for an interactive root shell, else `medium`)

```
Regex: sudo(?:\[pid\])?:\s*(?P<user>[^\s:]+)\s*:\s*TTY=(?P<tty>[^;]*);\s*PWD=(?P<pwd>[^;]*);\s*
       USER=(?P<target>[^;\s]+)\s*;\s*COMMAND=(?P<command>.+)$

Example: Sep 25 17:22:00 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -i
Result:  event_type=privilege_escalation, user=deploy, severity=high,
         process.name=/bin/bash, process.command_line=/bin/bash -i
```

`/bin/bash -i`, `/bin/sh -i`, and `/usr/bin/bash -i` are treated as interactive shells (high).

### PAM failure → `logon_failure` (severity `medium`)

```
Regex: (?P<service>su|login|sshd)\S*:\s*pam_unix\([^)]*\):\s*authentication failure
       (?:.*?\buser=(?P<user>\S+))?(?:.*?\brhost=(?P<rhost>\S+))?

Example: web-01 su[999]: pam_unix(su:auth): authentication failure; ... ruser=alice user=root rhost=10.0.0.5
Result:  event_type=logon_failure, user=root, src_ip=10.0.0.5
```

**Assumptions:** syslog timestamps are UTC (set the host to UTC or add an offset upstream);
accounts may carry a PAM realm (`alice@CORP` → `alice`); local logs without an IP yield
`src_ip="unknown"`, which the correlation rules deliberately ignore.

---

## 2. Windows Security / Sysmon — `src/normalization/windows_sysmon.py`

Input is one JSON object per line (EVTX export via `ConvertTo-Json`, or Filebeat/Logstash
output). `EventData` may be an object or a Logstash-style `[{Key, Value}]` array.

| Event ID | `event_type` | Severity |
|---|---|---|
| 4624 | `logon_success` | `low` |
| 4625 | `logon_failure` | `medium` |
| 4688 (Sysmon 1) | `process_create` | `high` if suspicious process by a non-service account, else `medium` |
| 4672 | `privilege_escalation` | `medium` |
| anything else | ignored (`None`) | — |

Accepted field aliases: `TimeCreated` / `@timestamp` / `UtcTime`; `Computer` / `host`;
`TargetUserName` / `SubjectUserName` / `User`; `TargetDomainName` / `SubjectDomainName`;
`IpAddress` / `SourceAddress`; `NewProcessName` / `ProcessName` / `Image`;
`ParentProcessName` / `ParentImage`; `CommandLine` / `ProcessCommandLine`.

**User normalization:** `DOMAIN\user`; a `-`/empty domain means local (`user`); `ANONYMOUS
LOGON` is preserved. Hostnames are lowercased so Rule 3 host matching is case-insensitive.

**Suspicious process heuristic** (`is_suspicious_process`): base name in
`powershell.exe, cmd.exe, bash, nc, nc.exe, wscript.exe, cscript.exe`, or a command line
containing `-enc` / `EncodedCommand`, `bash -i` / `sh -i`, or `nc -e`. Accounts in
`INTERACTIVE_SYSTEM_USERS` (`NT AUTHORITY\SYSTEM`, `LocalService`, `NetworkService`, …) are
not escalated to `high`.

---

## 3. Firewall syslog — `src/normalization/firewall_syslog.py`

All output is `event_type=network_connection`; severity is `high` for deny/block/drop actions
and `low` for allowed traffic. `port` prefers the destination port, falling back to the
source port.

### Cisco ASA

```
Regex: %ASA-\d-\d+:\s*(?P<action>Built inbound|Built outbound|Deny)\s+(?P<proto>\w+)
       .*?src\s+(?P<src_zone>[\w-]+):(?P<src_ip>[0-9.]+)(?:/(?P<spt>\d+))?\s+
       dst\s+(?P<dst_zone>[\w-]+):(?P<dst_ip>[0-9.]+)(?:/(?P<dpt>\d+))?

Example: Sep 25 17:30:05 fw-01 %ASA-4-106023: Deny tcp src outside:203.0.113.45/51234 dst inside:10.0.0.10/22
Result:  src_ip=203.0.113.45, dst_ip=10.0.0.10, port=22, protocol=tcp, severity=high
```

### Linux UFW / kernel

```
Regex: (?P<action>\[UFW\s+(?P<ufw_action>\w+)\]).*?SRC=(?P<src_ip>[0-9.]+)\s+DST=(?P<dst_ip>[0-9.]+)
       \s+PROTO=(?P<proto>\w+)(?:\s+SPT=(?P<spt>\d+))?(?:\s+DPT=(?P<dpt>\d+))?

Example: fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.99 DST=10.0.0.10 PROTO=TCP SPT=40000 DPT=3389
Result:  port=3389, protocol=tcp, severity=high
```

### Palo Alto

```
Regex: (?P<action>deny|allow|drop|accept)\s+(?P<proto>\w+)\s+(?P<src_ip>[0-9.]+)(?:/(?P<spt>\d+))?
       \s*(?:->|to)\s*(?P<dst_ip>[0-9.]+)(?:/(?P<dpt>\d+))?

Example: fw-01 firewall: deny tcp 198.51.100.7/44444 -> 10.0.0.10/22
Result:  severity=high
```

**Assumptions:** IPv4 only (IPv6 firewall logs fall through to the generic branch and are
skipped if no IPv4 pair is present); the firewall hostname becomes `host`; the firewall has no
user context, so `user="unknown"`.

---

## 4. Source detection (`src/normalization/ingestion.py`)

1. Filename signature, in order: `windows`/`sysmon`/`evtx`/`jsonl` → `windows_sysmon`;
   `auth`/`secure` → `linux_auth`; `firewall`/`fw`/`syslog` → `firewall_syslog`.
2. Extension: `.json`, `.jsonl`, `.ndjson` → `windows_sysmon`.
3. First-line sniff: leading `{` → `windows_sysmon`; `sshd`/`sudo:`/`pam_unix` → `linux_auth`;
   `%ASA`/`UFW`/`PROTO=` → `firewall_syslog`.
4. Otherwise the ingestion run fails loudly — pass `--source-type` explicitly.

## 5. Idempotency

`compute_event_document_id()` = SHA-256 of `host | @timestamp | event_type | src_ip | raw_event`.
Re-ingesting the same file overwrites the same document, so re-runs never duplicate events.
Alerts use SHA-256 of `dedup_key | first_seen` for the same reason.

## 6. Serialization to Elasticsearch

`src_ip` and `dst_ip` are mapped as Elasticsearch `ip` fields, which **reject** the `"unknown"`
sentinel (ES raises `document_parsing_exception`). Parsers therefore keep `"unknown"` in memory
for a missing address — the correlation rules rely on that sentinel to skip unusable events —
and `to_dict()` converts it to `null` on the way to Elasticsearch (`ip_or_none()`). The same
applies to an alert's `src_ip`. Document IDs are computed from the in-memory value, so the ID
is unaffected by this conversion.
