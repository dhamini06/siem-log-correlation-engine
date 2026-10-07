"""Deterministic enterprise SOC dataset generator (Phase 4A).

Replaces the ~50-event demonstration set with a realistic small-enterprise SOC
dataset: roughly ten thousand normalized events across fourteen days, thirty-one
hosts, a full normal-activity baseline, the six documented false-positive
families, and the four canonical attack fixtures that the existing answer key
depends on.

Design constraints, and why they shape the code
------------------------------------------------

*Nothing here reveals an answer.* The dataset is log traffic. The four attack
fixtures are produced by calling the *existing* ``sample_generator`` functions
with the same seed, so the evidence a student has always been able to read is
byte-for-byte the evidence they read before. No label, name, or comment in any
generated record says what it is.

*Determinism.* One fixed seed and one fixed base timestamp. No ``datetime.now()``
in the generation path, no unseeded randomness, no UUIDs. Two runs with the same
seed produce identical files.

*The one clock dependency is the parsers', not ours.* ``parse_syslog_header``
matches a classic syslog header with no year field, and ``normalize_to_utc``
then infers the year from the current clock. A parser change is out of scope for
this phase, so :func:`resolve_base_time` mirrors that same inference and applies
it to *both* the syslog lines and the Windows JSON timestamps, keeping the two
sources on the same dates. Month, day, time of day, ordering, counts, and every
process id are fully fixed; only the calendar year tracks the clock, exactly as
it already does for the current lab data.

*Rule 3 is not changed, and the baseline is built to respect it as written.*
``suspicious_process_post_login`` treats ``cmd.exe``, ``powershell.exe``,
``bash``, ``/bin/bash``, ``/bin/bash -i`` and ``nc`` as suspicious whenever they
appear within two minutes of a successful logon on the same host. It has no
concept of a routine shell. The baseline therefore does not place those process
names in any ordinary logon-then-process sequence. This is a documented
limitation of the current correlation model, not a property of a realistic
enterprise, and it is called out in docs/DATASET.md rather than hidden.

*Alerts must not move.* The four canonical alerts are the answer key's expected
alert population. :func:`audit_alerts` runs the real, unmodified rules over the
generated events and fails loudly if the population is not exactly those four.
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from . import sample_generator as sg
from .sample_generator import (
    SSH_ACCEPTED_TEMPLATE,
    SSH_FAILED_TEMPLATE,
    SSH_INVALID_USER_TEMPLATE,
    SUDO_TEMPLATE,
    UFW_DENY_TEMPLATE,
    _syslog_ts,
    _windows_event,
)

# --------------------------------------------------------------------------
# Determinism contract
# --------------------------------------------------------------------------

DEFAULT_SEED = 1337
#: Fixed anchor for day 0 of the dataset. A constant, not "now", so two runs
#: a week apart produce the same data.
DEFAULT_BASE_TIME = "2026-09-16T00:00:00Z"
DATASET_DAYS = 14
DATASET_NAME = "enterprise-14d"

# --------------------------------------------------------------------------
# Enterprise topology
# --------------------------------------------------------------------------

LINUX_HOSTS: Tuple[str, ...] = (
    "web-01", "web-02", "web-03", "web-04",
    "db-01", "db-02", "db-03",
    "dc-01", "fw-01", "proxy-01", "files-01",
    "jump-01", "build-01", "mail-01", "vpn-01", "bak-01",
)

WINDOWS_HOSTS: Tuple[str, ...] = (
    "app-01", "app-02", "app-03", "app-04", "app-05", "app-06", "dc-02",
    "wks-101", "wks-102", "wks-103", "wks-104",
    "wks-105", "wks-106", "wks-107", "wks-108",
)

ALL_HOSTS: Tuple[str, ...] = LINUX_HOSTS + WINDOWS_HOSTS

# Interactive accounts. Generic, invented names - no real identities.
INTERACTIVE_USERS: Tuple[str, ...] = (
    "alice", "bwilson", "jdoe", "mchen", "rpatel", "tnguyen",
    "deploy", "helpdesk",
)

# Service and system accounts.
SERVICE_USERS: Tuple[str, ...] = (
    "svc_backup", "svc_web", "svc_deploy", "svc_monitor", "svc_sql",
    "svc_print", "svc_iis", "backup", "root", "system",
)

ALL_USERS: Tuple[str, ...] = INTERACTIVE_USERS + SERVICE_USERS

# Internal address plan, one /24 per tier.
_TIERS: Dict[str, Tuple[str, int]] = {
    "app": ("10.10.1.", 40),
    "wks": ("10.10.2.", 40),
    "srv": ("10.20.0.", 60),
}

# Internal hosts that never originate an authentication attempt themselves.
_TIER_OF: Dict[str, str] = {}
for _h in ("app-01", "app-02", "app-03", "app-04", "app-05", "app-06"):
    _TIER_OF[_h] = "app"
for _h in ("wks-101", "wks-102", "wks-103", "wks-104",
           "wks-105", "wks-106", "wks-107", "wks-108"):
    _TIER_OF[_h] = "wks"
# Everything else lives in the server tier, including dc-02, which is a Windows
# host but sits on the same subnet as the rest of the infrastructure.
for _h in ALL_HOSTS:
    _TIER_OF.setdefault(_h, "srv")

#: Accounts that may appear in baseline *failures*. Deliberately excludes
#: every account named by a scenario question or an answer key part - alice,
#: admin, root, deploy, jdoe and svc_backup all appear in the attack fixtures or
#: in the false-positive cases. If those accounts also mistyped a password in
#: the background, a student counting failures for them would get a different
#: number from the one the answer key expects, which is a content bug rather
#: than a difficulty setting.
TYP0_USERS: Tuple[str, ...] = (
    "bwilson", "mchen", "rpatel", "tnguyen", "helpdesk",
    "svc_web", "svc_deploy", "svc_sql", "svc_print", "svc_iis",
)

# Clients that legitimately authenticate: workstations, jump host, build agent.
_LOGIN_CLIENTS: Tuple[str, ...] = (
    "wks-101", "wks-102", "wks-103", "wks-104", "wks-105",
    "wks-106", "wks-107", "wks-108", "jump-01", "build-01", "vpn-01",
)


def host_address(host: str) -> str:
    """The host's own stable internal address.

    Derived from the name, so the same host always resolves to the same
    address on every run and in every dataset.
    """
    prefix, size = _TIERS[_TIER_OF.get(host, "srv")]
    index = (sum(ord(c) for c in host) * 7) % size + 5
    return "%s%d" % (prefix, index)


def peer_address(rng: random.Random, tier: str) -> str:
    prefix, size = _TIERS[tier]
    return "%s%d" % (prefix, rng.randrange(20, size))


# --------------------------------------------------------------------------
# Baseline process vocabularies
#
# Every entry is checked against the current rule semantics: none of these
# names or command lines match the `suspicious_processes` token list, and none
# contains the substrings windows_sysmon.is_suspicious_process() reacts to
# ("-enc", "encodedcommand", "bash -i", "nc -e"). See the module docstring.
# --------------------------------------------------------------------------

WINDOWS_ROUTINE_PROCESSES: Tuple[Tuple[str, str, str], ...] = (
    (r"C:\Windows\explorer.exe", None, r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k wsvcs",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\System32\services.exe", None, r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\System32\lsass.exe", None, r"C:\Windows\System32\wininit.exe"),
    (r"C:\Windows\System32\wininit.exe", None, r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\System32\spoolsv.exe", None, r"C:\Windows\System32\services.exe"),
    (r"C:\Windows\System32\taskhostw.exe", None, r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\inetsrv\w3wp.exe", None, r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Microsoft SQL Server\MSSQL16\MSSQL\Binn\sqlservr.exe",
     "sqlservr.exe -s CORP", r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Monitoring\agent.exe", "agent.exe --config agent.yml",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Backup\backup-agent.exe", "backup-agent.exe --run daily",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Java\jdk-17\bin\java.exe",
     "java.exe -jar C:\\apps\\billing\\billing.jar",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Python312\python.exe", "python.exe C:\\apps\\etl\\run.py",
     r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", None,
     r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", None,
     r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\conhost.exe", None, r"C:\Windows\System32\cmd.exe"),
)

# Linux administrative commands. sudo records become privilege_escalation events
# with process.name = the first token, so the first token must not match the
# suspicious list ("bash", "/bin/bash", "/bin/bash -i", "nc", "cmd.exe",
# "powershell.exe") and the whole line must not contain a standalone "bash" or
# an interactive-shell form.
LINUX_ROUTINE_SUDO: Tuple[str, ...] = (
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl reload postgresql",
    "/usr/bin/apt-get update",
    "/usr/bin/apt-get upgrade -y",
    "/usr/bin/journalctl --vacuum-time=7d",
    "/usr/sbin/ufw reload",
    "/opt/monitoring/bin/agent --config /etc/monitoring/agent.conf",
    "/usr/bin/rsync -a /srv/data /backup/srv",
    "/usr/bin/tar -czf /backup/app-01.tar.gz /srv/app",
    "/usr/local/bin/rotate-logs",
    "/usr/bin/docker ps --format table",
    "/usr/bin/certbot renew --quiet",
    "/usr/bin/useradd -m -s /bin/sh svc_onboarding",
    "/usr/bin/chown -R svc_web:svc_web /srv/www",
    "/usr/bin/df -h",
    "/usr/bin/ntpdate -s 10.20.0.5",
)

# Ports used by routine east-west traffic.
_SERVICE_PORTS: Tuple[Tuple[str, int], ...] = (
    ("tcp", 22), ("tcp", 80), ("tcp", 443), ("tcp", 445), ("tcp", 1433),
    ("tcp", 3306), ("tcp", 5432), ("tcp", 3389), ("tcp", 5985), ("tcp", 8080),
    ("tcp", 8443), ("tcp", 9090), ("tcp", 27017),
)

#: Blocked inbound attempts seen by the edge firewall. These are ordinary
#: internet background scans; they are single events spread thinly, so they
#: never form a failure burst on one source address.
_BLOCKED_TARGET_PORTS: Tuple[int, ...] = (22, 23, 80, 443, 3389, 445, 1433, 3306, 5900)


# --------------------------------------------------------------------------
# Base-time resolution
# --------------------------------------------------------------------------

def resolve_base_time(base_time: Optional[str] = None) -> datetime:
    """Return the dataset anchor with a year that is not in the future.

    ``parse_syslog_header`` matches a header with no year field, and
    ``normalize_to_utc`` fills the year in from the current clock, rolling back
    a year when the result would otherwise be in the future. This mirrors that
    rule for the whole dataset, including the Windows JSON records which *do*
    carry a full ISO timestamp, so every source lands on the same dates.

    Month, day, time and everything downstream of the RNG are unaffected.
    """
    raw = base_time or DEFAULT_BASE_TIME
    text = raw.replace("+00:00", "Z")
    base = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if base > now + timedelta(minutes=1):
        base = base.replace(year=base.year - 1)
    return base.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Baseline generation
# --------------------------------------------------------------------------

def _business_window(day_index: int, rng: random.Random) -> Tuple[int, int]:
    """Local start/end hour for a day. Weekends run a reduced shift."""
    weekday = (day_index + 2) % 7  # base date is a Wednesday
    if weekday >= 5:
        return 10, 16
    return 7 + rng.randrange(0, 2), 17 + rng.randrange(0, 2)


def _pid(rng: random.Random) -> int:
    return rng.randrange(2000, 32000)


def _port(rng: random.Random) -> int:
    return rng.randrange(33000, 65000)


class _Baseline:
    """Accumulates raw log lines per source, keyed by nothing but the list.

    Every timestamp is derived from the resolved base plus a seeded offset, so
    the whole class is a pure function of (base, seed).
    """

    def __init__(self, base: datetime, seed: int) -> None:
        self.base = base
        self.rng = random.Random(seed)
        self.auth: List[Tuple[datetime, str]] = []
        self.windows: List[Tuple[datetime, str]] = []
        self.firewall: List[Tuple[datetime, str]] = []
        #: host -> sorted timestamps of successful logons, used to keep
        #: baseline process creation clear of the Rule 3 window.
        self.logons: Dict[str, List[datetime]] = {}

    # -- helpers --
    def add_auth(self, moment: datetime, line: str) -> None:
        self.auth.append((moment, line))

    def add_win(self, moment: datetime, record: Dict) -> None:
        self.windows.append((moment, json.dumps(record)))

    def add_fw(self, moment: datetime, line: str) -> None:
        self.firewall.append((moment, line))

    def note_logon(self, host: str, moment: datetime) -> None:
        self.logons.setdefault(host, []).append(moment)

    def clear_of_rule3(self, host: str, moment: datetime) -> bool:
        """True when no successful logon on `host` falls in the 2-minute window."""
        for stamp in self.logons.get(host, ()):
            if moment - timedelta(minutes=2) <= stamp <= moment + timedelta(minutes=2):
                return False
        return True


def _interactive_logons(base_: _Baseline) -> int:
    """Business-hours interactive and service logons across the fleet."""
    count = 0
    for day_index in range(DATASET_DAYS):
        start_hour, end_hour = _business_window(day_index, base_.rng)
        day = base_.base + timedelta(days=day_index)
        for host in WINDOWS_HOSTS:
            sessions = base_.rng.randrange(3, 9)
            for _ in range(sessions):
                moment = day + timedelta(
                    hours=base_.rng.randrange(start_hour, end_hour),
                    minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60),
                )
                user = base_.rng.choice(INTERACTIVE_USERS)
                client = base_.rng.choice(_LOGIN_CLIENTS)
                base_.add_win(moment, {
                    "EventID": 4624,
                    "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "Computer": host,
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventData": {
                        "TargetUserName": user,
                        "TargetDomainName": "CORP",
                        "SubjectUserName": user,
                        "SubjectDomainName": "CORP",
                        "IpAddress": host_address(client),
                        "LogonType": 2,
                    },
                })
                base_.note_logon(host, moment)
                count += 1
        # SSH logons to the Linux tier from workstations and the jump host.
        for host in LINUX_HOSTS:
            if host in ("fw-01", "proxy-01"):
                continue
            for _ in range(base_.rng.randrange(1, 4)):
                moment = day + timedelta(
                    hours=base_.rng.randrange(start_hour, end_hour),
                    minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60),
                )
                user = base_.rng.choice(INTERACTIVE_USERS + ("deploy",))
                client = base_.rng.choice(("wks-101", "wks-102", "wks-103",
                                           "wks-104", "jump-01", "build-01"))
                base_.add_auth(moment, SSH_ACCEPTED_TEMPLATE.format(
                    ts=_syslog_ts(moment), host=host, pid=_pid(base_.rng),
                    user=user, ip=host_address(client), port=_port(base_.rng)))
                base_.note_logon(host, moment)
                count += 1
    return count


def _service_logons(base_: _Baseline) -> int:
    """Service and scheduled-task logons: same shape, different hours."""
    count = 0
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        for host in ALL_HOSTS:
            for _ in range(base_.rng.randrange(2, 6)):
                hour = base_.rng.choice((0, 1, 2, 3, 4, 5, 22, 23))
                moment = day + timedelta(
                    hours=hour, minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60))
                user = base_.rng.choice(SERVICE_USERS)
                if host in WINDOWS_HOSTS:
                    base_.add_win(moment, {
                        "EventID": 4624,
                        "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "Computer": host,
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventData": {
                            "TargetUserName": user,
                            "TargetDomainName": "CORP",
                            "SubjectUserName": user,
                            "SubjectDomainName": "CORP",
                            "IpAddress": host_address("build-01" if base_.rng.random() < 0.5
                                                      else "dc-02"),
                            "LogonType": 5,
                        },
                    })
                else:
                    base_.add_auth(moment, SSH_ACCEPTED_TEMPLATE.format(
                        ts=_syslog_ts(moment), host=host, pid=_pid(base_.rng),
                        user=user, ip=host_address("jump-01"), port=_port(base_.rng)))
                base_.note_logon(host, moment)
                count += 1
    return count


def _failed_logons(base_: _Baseline) -> int:
    """Password typos and stale credentials.

    Invariant: no source address ever reaches five failures inside a five
    minute window, so Rule 1 and Rule 2 stay silent. Each client address is
    given at most two failures per day, and the two are hours apart.
    """
    count = 0
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        for host in LINUX_HOSTS + WINDOWS_HOSTS[:6]:
            if host in ("fw-01", "proxy-01"):
                continue
            for _ in range(base_.rng.randrange(1, 4)):
                moment = day + timedelta(
                    hours=base_.rng.randrange(24), minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60))
                user = base_.rng.choice(TYP0_USERS)
                client = base_.rng.choice(_LOGIN_CLIENTS)
                if host in WINDOWS_HOSTS:
                    base_.add_win(moment, {
                        "EventID": 4625,
                        "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "Computer": host,
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventData": {
                            "TargetUserName": user,
                            "TargetDomainName": "CORP",
                            "SubjectUserName": user,
                            "SubjectDomainName": "CORP",
                            "IpAddress": host_address(client),
                            "LogonType": 2,
                            "Status": "0xC000006D",
                            "SubStatus": "0xC000006A",
                        },
                    })
                else:
                    base_.add_auth(moment, SSH_FAILED_TEMPLATE.format(
                        ts=_syslog_ts(moment), host=host, pid=_pid(base_.rng),
                        user=user, ip=host_address(client), port=_port(base_.rng)))
                count += 1
    return count


def _windows_processes(base_: _Baseline) -> None:
    """Routine process creation on the Windows fleet.

    Nothing here matches the rule's suspicious list, so these may appear at any
    time; they are still kept clear of a logon for realism rather than for
    correctness.
    """
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        start_hour, end_hour = _business_window(day_index, base_.rng)
        for host in WINDOWS_HOSTS:
            for _ in range(base_.rng.randrange(8, 20)):
                moment = day + timedelta(
                    hours=base_.rng.randrange(0, 24), minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60))
                if not base_.clear_of_rule3(host, moment):
                    continue
                path, command, parent = base_.rng.choice(WINDOWS_ROUTINE_PROCESSES)
                user = base_.rng.choice(INTERACTIVE_USERS + SERVICE_USERS)
                base_.add_win(moment, {
                    "EventID": 4688,
                    "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "Computer": host,
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventData": {
                        "TargetUserName": user,
                        "TargetDomainName": "CORP",
                        "SubjectUserName": user,
                        "SubjectDomainName": "CORP",
                        "NewProcessName": path,
                        "ProcessId": str(_pid(base_.rng)),
                        "CommandLine": command,
                        "ParentProcessName": parent,
                        "ParentProcessId": str(_pid(base_.rng)),
                    },
                })


def _linux_sudo(base_: _Baseline) -> int:
    """Administrative sudo activity. The Linux tier's process-creation record."""
    count = 0
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        for host in LINUX_HOSTS:
            if host in ("fw-01",):
                continue
            for _ in range(base_.rng.randrange(3, 8)):
                moment = day + timedelta(
                    hours=base_.rng.randrange(24), minutes=base_.rng.randrange(60),
                    seconds=base_.rng.randrange(60))
                if not base_.clear_of_rule3(host, moment):
                    continue
                user = base_.rng.choice(("deploy", "admin", "svc_deploy", "root"))
                base_.add_auth(moment, SUDO_TEMPLATE.format(
                    ts=_syslog_ts(moment), host=host, user=user,
                    command=base_.rng.choice(LINUX_ROUTINE_SUDO)))
                count += 1
    return count


def _network(base_: _Baseline) -> int:
    """Edge firewall records: permitted sessions and blocked scans.

    Both forms are iptables/UFW kernel lines, which is the only shape the
    parser accepts for *permitted* traffic: the ASA pattern in
    ``firewall_syslog`` needs explicit ``src .../dst ...`` keywords, and the
    ``%ASA-6-302013`` "Built connection" form shown in that module's own
    docstring has no such keywords, so a line written that way is silently
    skipped. ``[UFW ALLOW]`` and ``[UFW BLOCK]`` both parse, and the parser
    reads the bracketed action to decide severity, which is what gives this
    dataset a mix of permitted and denied traffic rather than blocks only.
    """
    count = 0
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        for _ in range(base_.rng.randrange(120, 190)):
            moment = day + timedelta(
                hours=base_.rng.randrange(24), minutes=base_.rng.randrange(60),
                seconds=base_.rng.randrange(60))
            tier = base_.rng.choice(("app", "wks", "srv"))
            dst = peer_address(base_.rng, tier)
            proto, port = base_.rng.choice(_SERVICE_PORTS)
            if base_.rng.random() < 0.22:
                # Ordinary internet background scanning, blocked at the edge.
                src = "198.51.100.%d" % base_.rng.randrange(2, 250)
                action, dpt = "BLOCK", base_.rng.choice(_BLOCKED_TARGET_PORTS)
            else:
                src = host_address(base_.rng.choice(_LOGIN_CLIENTS))
                action, dpt = "ALLOW", port
            base_.add_fw(moment, UFW_DENY_TEMPLATE.format(
                ts=_syslog_ts(moment), host="fw-01", src_ip=src, dst_ip=dst,
                spt=_port(base_.rng), dpt=dpt).replace("[UFW BLOCK]", "[UFW %s]" % action))
            count += 1
    return count


# --------------------------------------------------------------------------
# False-positive families
#
# The six documented negative cases. Offsets, addresses and accounts follow
# tests/data/negative_cases.json so the lab and its test fixtures describe the
# same shapes. None of these may alert.
# --------------------------------------------------------------------------

NEGATIVE_FAMILIES: Tuple[Tuple[str, str, str, str, int], ...] = (
    # (family, src_ip, user, host, failure_count)
    #
    # There is deliberately no separate "below threshold" entry here. That
    # family's canonical instance is the svc_backup sequence in
    # sample_generator.generate_false_positive_mix - four failures from
    # 10.0.0.30 then a success - and it is the instance the Scenario 01 answer
    # key pins by address. Emitting a second one on the same host with the same
    # account and the same count (the shape in tests/data/negative_cases.json,
    # which uses 10.0.0.31) would leave a student with two equally correct
    # answers to "which account failed a few times and did not alert".
    # tests/data/negative_cases.json stays authoritative for the *semantics*;
    # the address it uses is a fixture value, not a contract.
    ("spread_beyond_window", "10.0.0.32", "svc_sql", "web-02", 6),
    ("split_across_source_ips", "10.0.0.41", "mchen", "web-03", 3),
    ("split_across_source_ips", "10.0.0.42", "mchen", "web-03", 3),
    ("late_success", "10.0.0.50", "tnguyen", "web-04", 4),
)


def _negative_families(base_: _Baseline, anchor: datetime) -> int:
    """Emit the four logon-shaped negative families."""
    count = 0
    for family, src_ip, user, host, failures in NEGATIVE_FAMILIES:
        if family == "spread_beyond_window":
            # Six failures, five minutes apart: a twenty-five minute run.
            step = 300
        elif family == "split_across_source_ips":
            # Six failures, five seconds apart, interleaved over two sources.
            step = 5
        elif family == "late_success":
            step = 15
        else:
            step = 30 if family == "below_threshold" else 20

        moment = anchor
        for index in range(failures):
            base_.add_auth(moment, SSH_FAILED_TEMPLATE.format(
                ts=_syslog_ts(moment), host=host, pid=_pid(base_.rng),
                user=user, ip=src_ip, port=_port(base_.rng)))
            count += 1
            moment += timedelta(seconds=step)

        if family == "below_threshold":
            # A scheduled backup that authenticates successfully.
            base_.add_auth(moment + timedelta(minutes=1),
                           SSH_ACCEPTED_TEMPLATE.format(
                               ts=_syslog_ts(moment + timedelta(minutes=1)),
                               host=host, pid=_pid(base_.rng), user=user,
                               ip=src_ip, port=_port(base_.rng)))
            count += 1
        elif family == "late_success":
            # The same account, twenty minutes later, once the credentials are
            # refreshed. Outside Rule 2's ten-minute success window.
            base_.add_auth(moment + timedelta(minutes=20),
                           SSH_ACCEPTED_TEMPLATE.format(
                               ts=_syslog_ts(moment + timedelta(minutes=20)),
                               host=host, pid=_pid(base_.rng), user=user,
                               ip=src_ip, port=_port(base_.rng)))
            count += 1
    return count


def _negative_scheduled_task(base_: _Baseline, anchor: datetime) -> int:
    """A scheduled inventory run: PowerShell, but half an hour after logon."""
    logon = anchor
    base_.add_win(logon, {
        "EventID": 4624,
        "TimeCreated": logon.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Computer": "app-02",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": {
            "TargetUserName": "administrator", "TargetDomainName": "CORP",
            "SubjectUserName": "administrator", "SubjectDomainName": "CORP",
            "IpAddress": "10.10.1.12", "LogonType": 3,
        },
    })
    base_.note_logon("app-02", logon)
    run = logon + timedelta(minutes=30)
    base_.add_win(run, {
        "EventID": 4688,
        "TimeCreated": run.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Computer": "app-02",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": {
            "TargetUserName": "administrator", "TargetDomainName": "CORP",
            "SubjectUserName": "administrator", "SubjectDomainName": "CORP",
            "NewProcessName":
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ProcessId": str(_pid(base_.rng)),
            "CommandLine": "powershell.exe -File C:\\Scripts\\Inventory.ps1",
            "ParentProcessName": r"C:\Windows\System32\taskschd.exe",
            "ParentProcessId": str(_pid(base_.rng)),
        },
    })
    return 2


def _negative_expected_service(base_: _Baseline, anchor: datetime) -> int:
    """A user logs on, then a service host starts its usual child process.

    This family is not in the canonical four, so it is emitted here. It is not
    pinned by any answer-key part, and it does not need to be unique: svchost
    starting straight after a logon is one of the most common things on a
    Windows fleet, and that ubiquity is exactly what makes it a good teaching
    example of activity that looks structured but is expected.
    """
    logon = anchor
    base_.add_win(logon, {
        "EventID": 4624,
        "TimeCreated": logon.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Computer": "app-03",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": {
            "TargetUserName": "jdoe", "TargetDomainName": "CORP",
            "SubjectUserName": "jdoe", "SubjectDomainName": "CORP",
            "IpAddress": "10.10.1.23", "LogonType": 2,
        },
    })
    base_.note_logon("app-03", logon)
    child = logon + timedelta(seconds=30)
    base_.add_win(child, {
        "EventID": 4688,
        "TimeCreated": child.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Computer": "app-03",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": {
            "TargetUserName": "NT AUTHORITY\\SYSTEM", "TargetDomainName": "-",
            "SubjectUserName": "NT AUTHORITY\\SYSTEM", "SubjectDomainName": "-",
            "NewProcessName": r"C:\Windows\System32\svchost.exe",
            "ProcessId": str(_pid(base_.rng)),
            "CommandLine": "svchost.exe -k netsvcs",
            "ParentProcessName": r"C:\Windows\System32\services.exe",
            "ParentProcessId": str(_pid(base_.rng)),
        },
    })
    return 2


#: Hosts that may host an unattended scheduled run.
#:
#: Deliberately excludes every host a scenario question points at: web-01
#: (Scenarios 01, 02, 04), app-01 (Scenario 03), app-02 and app-03 (the
#: scheduled-task and expected-service negative cases) and web-02..web-04 (the
#: spread-window and split-source negative families). A second cmd.exe or
#: powershell.exe on one of those hosts would leave a student with two equally
#: correct answers to "what process was created, and what was its command line".
UNATTENDED_JOB_HOSTS: Tuple[str, ...] = (
    "app-04", "app-05", "app-06", "dc-02", "wks-106", "wks-107", "wks-108",
)


def _unattended_scheduled_runs(base_: _Baseline) -> int:
    """PowerShell and cmd.exe running with no interactive logon nearby.

    These are the *reason* Rule 3 has a known limitation: a scheduled report
    job looks exactly like the start of an attack to a rule that has no notion
    of a schedule. Here they sit far enough from any logon that the rule's
    two-minute window never opens, which is the documented compromise.
    """
    count = 0
    jobs = (
        (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -File C:\\Scripts\\NightlyReport.ps1",
         r"C:\Windows\System32\taskschd.exe"),
        (r"C:\Windows\System32\cmd.exe",
         "cmd.exe /c C:\\Scripts\\collect-metrics.cmd",
         r"C:\Windows\System32\taskschd.exe"),
        (r"C:\Program Files\Git\bin\bash.exe", "bash /c/scripts/verify.sh",
         r"C:\Windows\System32\taskschd.exe"),
    )
    for day_index in range(DATASET_DAYS):
        day = base_.base + timedelta(days=day_index)
        for host in UNATTENDED_JOB_HOSTS:
            moment = day + timedelta(
                hours=base_.rng.choice((2, 3, 4)), minutes=base_.rng.randrange(60),
                seconds=base_.rng.randrange(60))
            if not base_.clear_of_rule3(host, moment):
                moment += timedelta(minutes=7)
            if not base_.clear_of_rule3(host, moment):
                continue
            path, command, parent = jobs[base_.rng.randrange(len(jobs))]
            base_.add_win(moment, {
                "EventID": 4688,
                "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "Computer": host,
                "Provider": "Microsoft-Windows-Security-Auditing",
                "EventData": {
                    "TargetUserName": "svc_monitor", "TargetDomainName": "CORP",
                    "SubjectUserName": "svc_monitor", "SubjectDomainName": "CORP",
                    "NewProcessName": path, "ProcessId": str(_pid(base_.rng)),
                    "CommandLine": command, "ParentProcessName": parent,
                    "ParentProcessId": str(_pid(base_.rng)),
                },
            })
            count += 1
    return count


# --------------------------------------------------------------------------
# Canonical attack fixtures
# --------------------------------------------------------------------------

#: Deterministic offsets, in hours from the dataset anchor, for the four
#: canonical sequences. They are hours apart and interleaved with the baseline
#: rather than sitting next to one another, so the queue is not obvious from
#: the timeline alone.
ATTACK_OFFSETS: Dict[str, float] = {
    "brute_force": 36.0,
    "successful_brute_force": 148.0,
    "post_login_exec": 260.0,
    "false_positive_mix": 292.0,
}

#: The alert population the answer key expects, and the exact identity of each
#: canonical alert. Used only by the self-audit and by tests.
CANONICAL_ALERTS: Tuple[Tuple[str, str, str], ...] = (
    ("brute_force", "high", "203.0.113.45"),
    ("successful_brute_force", "critical", "203.0.113.66"),
    ("suspicious_process_post_login", "high", "198.51.100.25"),
    ("suspicious_process_post_login", "high", "198.51.100.77"),
)


def _canonical_fixtures(base_: _Baseline, base: datetime, seed: int) -> int:
    """Append the four attack fixtures, byte-identical to the current lab data.

    The existing ``sample_generator`` functions are called directly with the
    documented seed. Their internal spacing - which is what the answer key's
    durations are measured against - therefore cannot drift: the 132-second
    Scenario 01 window is a property of ``random.Random(1337)`` reaching
    ``randint(5, 20)`` nine times, and that is exactly what happens here.
    """
    count = 0
    plan = (
        ("brute_force", "brute_force"),
        ("successful_brute_force", "successful_brute_force"),
        ("post_login_exec", "post_login_exec"),
        ("false_positive_mix", "false_positive_mix"),
    )
    for scenario, key in plan:
        anchor = base + timedelta(hours=ATTACK_OFFSETS[key])
        auth, windows, firewall = sg.GENERATORS[scenario](anchor, random.Random(seed))
        for line in auth:
            # Recover the timestamp from the syslog line we just produced.
            base_.add_auth(_line_time(line, anchor), line)
            count += 1
        for record in windows:
            base_.windows.append((_record_time(record, anchor), record))
            count += 1
        for line in firewall:
            base_.add_fw(_line_time(line, anchor), line)
            count += 1
    return count


def _line_time(line: str, anchor: datetime) -> datetime:
    """Timestamp of a syslog line we generated, resolved like the parser does."""
    from ..utils.time_utils import normalize_to_utc
    stamp = line.split(" ", 3)
    if len(stamp) < 3:
        return anchor
    try:
        return normalize_to_utc("%s %s %s" % (stamp[0], stamp[1], stamp[2]))
    except ValueError:
        return anchor


def _record_time(record: str, anchor: datetime) -> datetime:
    from ..utils.time_utils import normalize_to_utc
    try:
        return normalize_to_utc(json.loads(record)["TimeCreated"])
    except (ValueError, KeyError, TypeError):
        return anchor


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def build_lines(base_time: Optional[str] = None, seed: int = DEFAULT_SEED
                ) -> Dict[str, List[str]]:
    """Generate every raw log line, grouped by source type.

    Pure function of (base_time, seed): no clock, no global state, no I/O.
    """
    base = resolve_base_time(base_time)
    b = _Baseline(base, seed)

    _interactive_logons(b)
    _service_logons(b)
    _failed_logons(b)
    _windows_processes(b)
    _linux_sudo(b)
    _network(b)

    # False positives, spread across the fortnight rather than clustered.
    #
    # The scheduled-task family is not re-emitted here: the canonical
    # svc_backup / PowerShell sequence in sample_generator.generate_false_positive_mix
    # already *is* that family - a 4624 on app-02 followed thirty minutes later
    # by powershell.exe - and the Scenario 05 answer key pins it by host, process
    # and offset. Emitting a second one would give a student two PowerShell runs
    # on app-02 and no way to choose.
    day3 = base + timedelta(days=3, hours=4)
    _negative_families(b, day3)
    _negative_expected_service(b, base + timedelta(days=9, hours=6))
    _unattended_scheduled_runs(b)

    _canonical_fixtures(b, base, seed)

    return {
        "auth": [line for _, line in sorted(b.auth, key=lambda item: item[0])],
        "windows": [record for _, record in sorted(b.windows, key=lambda item: item[0])],
        "firewall": [line for _, line in sorted(b.firewall, key=lambda item: item[0])],
    }


#: Extensions ``ingest --log-dir`` will pick up from a directory.
LOG_SUFFIXES = (".log", ".jsonl", ".ndjson")


def dataset_paths(output_dir: str) -> Dict[str, str]:
    """The three file paths this dataset writes.

    Filenames carry the source markers ingestion detects ("auth", "windows",
    "firewall"), so the existing ingest path routes them with no flags.
    """
    return {
        "auth": os.path.join(output_dir, "%s_auth.log" % DATASET_NAME),
        "windows": os.path.join(output_dir, "%s_windows.jsonl" % DATASET_NAME),
        "firewall": os.path.join(output_dir, "%s_firewall.log" % DATASET_NAME),
    }


def foreign_log_files(output_dir: str) -> List[str]:
    """Log files in `output_dir` that are not part of this dataset.

    ``ingest --log-dir`` indexes *every* log file it finds, so a directory
    holding both this dataset and the older per-scenario demonstration files
    would silently index two datasets at once: duplicate attack fixtures, two
    different timestamp anchors, and an event count nobody can explain. These
    datasets are alternatives, not layers, so the caller is told rather than
    left to discover it as a wrong alert count.
    """
    if not os.path.isdir(output_dir):
        return []
    ours = {os.path.basename(p) for p in dataset_paths(output_dir).values()}
    return sorted(
        name for name in os.listdir(output_dir)
        if name not in ours and name.lower().endswith(LOG_SUFFIXES)
    )


def generate_enterprise_logs(
    output_dir: str,
    base_time: Optional[str] = None,
    seed: int = DEFAULT_SEED,
    clean: bool = False,
) -> Dict[str, str]:
    """Write the dataset to `output_dir` and return the file paths.

    Refuses to write when `output_dir` already holds other log files, unless
    `clean` is set, in which case only files with a log extension are removed.
    Nothing else in the directory is touched.
    """
    os.makedirs(output_dir, exist_ok=True)
    stale = foreign_log_files(output_dir)
    if stale:
        if not clean:
            raise SystemExit(
                "%s already holds %d other log file(s):\n  %s\n\n"
                "ingest --log-dir would index those alongside this dataset. "
                "Re-run with --clean to remove them, or write to a different "
                "--output directory."
                % (output_dir, len(stale), "\n  ".join(stale)))
        for name in stale:
            os.remove(os.path.join(output_dir, name))
        print("removed %d stale log file(s) from %s" % (len(stale), output_dir))

    lines = build_lines(base_time=base_time, seed=seed)
    paths = dataset_paths(output_dir)
    for kind, text in (
        ("auth", lines["auth"]),
        ("windows", lines["windows"]),
        ("firewall", lines["firewall"]),
    ):
        with open(paths[kind], "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(text) + "\n")
    return paths


# --------------------------------------------------------------------------
# Self-audit
# --------------------------------------------------------------------------

def parse_lines(lines: Dict[str, List[str]]) -> List:
    """Parse generated lines with the real parsers, in memory."""
    from .firewall_syslog import FirewallSyslogParser
    from .linux_auth import LinuxAuthParser
    from .windows_sysmon import WindowsSysmonParser

    events = []
    for line in lines["auth"]:
        event = LinuxAuthParser().parse(line)
        if event is not None:
            events.append(event)
    for line in lines["windows"]:
        event = WindowsSysmonParser().parse(line)
        if event is not None:
            events.append(event)
    for line in lines["firewall"]:
        event = FirewallSyslogParser().parse(line)
        if event is not None:
            events.append(event)
    return events


def audit_alerts(events: Sequence) -> List[Tuple[str, str, str]]:
    """Run the real, unmodified rules and return (rule, severity, src_ip)."""
    from ..config import load_app_config
    from ..correlation.rules import apply_rules, load_events

    hits = []
    for event in events:
        hits.append({"_id": event.raw_event[:0] or str(id(event)),
                     "_source": event.to_dict()})
    alerts = apply_rules(load_events(hits), load_app_config())
    return sorted((a.rule_name, a.severity.value, a.src_ip or "") for a in alerts)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate the deterministic enterprise SOC dataset (Phase 4A)")
    parser.add_argument("--output", default="./logs/generated",
                        help="Output directory (default: ./logs/generated)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help="RNG seed (default: %d)" % DEFAULT_SEED)
    parser.add_argument("--base-time", default=None,
                        help="Fixed anchor, ISO-8601. Default %s" % DEFAULT_BASE_TIME)
    parser.add_argument("--clean", action="store_true",
                        help="Remove other .log/.jsonl files from the output "
                             "directory first (they would otherwise be indexed "
                             "alongside this dataset)")
    args = parser.parse_args()

    # Write first, so a directory collision is caught before any work is done.
    paths = generate_enterprise_logs(
        args.output, base_time=args.base_time, seed=args.seed, clean=args.clean)

    print("Enterprise dataset (seed=%d, base=%s)"
          % (args.seed, args.base_time or DEFAULT_BASE_TIME))
    for kind, path in sorted(paths.items()):
        count = sum(1 for line in open(path, encoding="utf-8") if line.strip())
        print("  %-9s %6d lines -> %s" % (kind, count, path))
    events = parse_lines(build_lines(base_time=args.base_time, seed=args.seed))
    print("  parsed   %6d normalized events" % len(events))
    found = audit_alerts(events)
    print("  alerts   %d" % len(found))
    for rule, severity, src_ip in found:
        print("      %-30s %-9s %s" % (rule, severity, src_ip))
    expected = sorted(CANONICAL_ALERTS)
    if found != expected:
        print("\nAUDIT FAILED: the alert population moved.")
        print("  expected: %r" % (expected,))
        print("  found   : %r" % (found,))
        return 1
    print("\nAUDIT OK: exactly the four canonical alerts, unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
