"""Deterministic sample log generator for SIEM Lab (Phase 2).

Scenarios:
  normal_day              - benign SSH logins, sudo, service process creation
  brute_force             - 10 failed SSH logins from one source IP (Rule 1)
  successful_brute_force  - 5 failures then a success from the same IP (Rule 2)
  post_login_exec         - login followed by cmd.exe / bash -i (Rule 3)
  false_positive_mix      - admin PowerShell and a scheduled task, below thresholds

Events are anchored near the current UTC time so the generated data falls
inside the correlation engine's lookback window when ingested immediately.
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

SCENARIOS = (
    "normal_day",
    "brute_force",
    "successful_brute_force",
    "post_login_exec",
    "false_positive_mix",
)

#: Fallback stream for the Windows process/parent ids in ``_windows_event``.
#: Fixed so a caller that supplies no stream still gets reproducible output.
_WINDOWS_PID_SEED = 4242

SSH_FAILED_TEMPLATE = (
    "{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
)
SSH_INVALID_USER_TEMPLATE = (
    "{ts} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}"
)
SSH_ACCEPTED_TEMPLATE = (
    "{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
)
SUDO_TEMPLATE = (
    "{ts} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
)
UFW_DENY_TEMPLATE = (
    "{ts} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src_ip} DST={dst_ip} "
    "PROTO=TCP SPT={spt} DPT={dpt}"
)


def _syslog_ts(moment: datetime) -> str:
    return moment.strftime("%b %d %H:%M:%S")


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _windows_event(
    event_id: int,
    moment: datetime,
    host: str,
    user: str,
    domain: str = "CORP",
    ip: str = "",
    process: str = "",
    command: str = "",
    parent: str = "",
    rng: random.Random = None,
) -> str:
    """Render one Windows event record.

    `rng` is used for ProcessId/ParentProcessId. It previously drew from the
    *global* random module, which made those two fields differ between runs even
    with a fixed seed, so "same seed, same output" was not true of this file.
    A caller that omits `rng` gets its own seeded stream rather than global
    state, so nothing reaches into process-wide randomness.
    """
    if rng is None:
        rng = random.Random(_WINDOWS_PID_SEED)
    data: Dict[str, object] = {
        "TargetUserName": user,
        "TargetDomainName": domain,
        "SubjectUserName": user,
        "SubjectDomainName": domain,
    }
    if ip:
        data["IpAddress"] = ip
        data["LogonType"] = 3
    if process:
        data.update(
            {
                "NewProcessName": process,
                "ProcessId": str(rng.randint(1000, 9999)),
                "CommandLine": command,
                "ParentProcessName": parent or "C:\\Windows\\explorer.exe",
                "ParentProcessId": str(rng.randint(500, 999)),
                "SubjectUserName": user,
                "SubjectDomainName": domain,
            }
        )
    return json.dumps(
        {
            "EventID": event_id,
            "TimeCreated": _iso(moment),
            "Computer": host,
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventData": data,
        }
    )


def generate_normal_day(base: datetime, rng: random.Random) -> Tuple[List[str], List[str], List[str]]:
    auth, windows, firewall = [], [], []
    users = ["alice", "bob", "carol"]
    ip_pool = ["10.0.0.21", "10.0.0.22", "10.0.0.23"]

    for index in range(6):
        moment = base + timedelta(minutes=index * 7)
        user = users[index % len(users)]
        auth.append(
            SSH_ACCEPTED_TEMPLATE.format(
                ts=_syslog_ts(moment),
                host="web-01",
                pid=2000 + index,
                user=user,
                ip=ip_pool[index % len(ip_pool)],
                port=40000 + index,
            )
        )
        # A single isolated failure per user: never reaches the 5-failure threshold.
        auth.append(
            SSH_FAILED_TEMPLATE.format(
                ts=_syslog_ts(moment + timedelta(seconds=20)),
                host="web-01",
                pid=2100 + index,
                user=user,
                ip=ip_pool[index % len(ip_pool)],
                port=41000 + index,
            )
        )

    for index, command in enumerate(["/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update"]):
        moment = base + timedelta(minutes=10 + index * 15)
        auth.append(
            SUDO_TEMPLATE.format(
                ts=_syslog_ts(moment),
                host="web-01",
                user="carol",
                command=command,
            )
        )

    for index, (process, command, parent) in enumerate(
        [
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "C:\\Windows\\System32\\services.exe"),
            ("C:\\Program Files\\Monitoring\\agent.exe", "agent.exe --config agent.yml", "C:\\Windows\\System32\\services.exe"),
        ]
    ):
        moment = base + timedelta(minutes=index * 3)
        windows.append(
            _windows_event(
                4688, moment, "app-01", "NT AUTHORITY", domain="-", process=process,
                command=command, parent=parent,
            )
        )

    for index in range(4):
        moment = base + timedelta(minutes=index * 11)
        firewall.append(
            UFW_DENY_TEMPLATE.format(
                ts=_syslog_ts(moment),
                host="fw-01",
                src_ip=f"10.0.1.{40 + index}",
                dst_ip="10.0.0.10",
                spt=50000 + index,
                dpt=rng.choice([22, 3389, 445]),
            )
        )
    return auth, windows, firewall


def generate_brute_force(base: datetime, rng: random.Random) -> Tuple[List[str], List[str], List[str]]:
    auth, windows, firewall = [], [], []
    attacker_ip = "203.0.113.45"
    moment = base
    for index in range(10):
        user = "root" if index % 2 == 0 else "admin"
        line = (
            SSH_INVALID_USER_TEMPLATE.format(
                ts=_syslog_ts(moment), host="web-01", pid=3000 + index,
                user=user, ip=attacker_ip, port=51000 + index,
            )
            if user == "admin"
            else SSH_FAILED_TEMPLATE.format(
                ts=_syslog_ts(moment), host="web-01", pid=3000 + index,
                user=user, ip=attacker_ip, port=51000 + index,
            )
        )
        auth.append(line)
        moment += timedelta(seconds=rng.randint(5, 20))

    for index in range(3):
        firewall.append(
            UFW_DENY_TEMPLATE.format(
                ts=_syslog_ts(moment + timedelta(seconds=index * 3)),
                host="fw-01", src_ip=attacker_ip, dst_ip="10.0.0.10", spt=51000 + index, dpt=22,
            )
        )
    return auth, windows, firewall


def generate_successful_brute_force(base: datetime, rng: random.Random) -> Tuple[List[str], List[str], List[str]]:
    auth, windows, firewall = [], [], []
    attacker_ip = "203.0.113.66"
    moment = base
    for index in range(5):
        auth.append(
            SSH_FAILED_TEMPLATE.format(
                ts=_syslog_ts(moment), host="web-01", pid=4000 + index,
                user="alice", ip=attacker_ip, port=52000 + index,
            )
        )
        moment += timedelta(seconds=rng.randint(10, 25))
    # Success 2 minutes after the burst starts: inside the 10-minute success window.
    auth.append(
        SSH_ACCEPTED_TEMPLATE.format(
            ts=_syslog_ts(moment + timedelta(seconds=30)), host="web-01", pid=4050,
            user="alice", ip=attacker_ip, port=52099,
        )
    )
    return auth, windows, firewall


def generate_post_login_exec(base: datetime, rng: random.Random) -> Tuple[List[str], List[str], List[str]]:
    auth, windows, firewall = [], [], []
    windows.append(
        _windows_event(
            4624, base, "app-01", "jdoe", domain="CORP", ip="198.51.100.25",
        )
    )
    windows.append(
        _windows_event(
            4688, base + timedelta(seconds=20), "app-01", "jdoe", domain="CORP",
            process="C:\\Windows\\System32\\cmd.exe",
            command="cmd.exe /c whoami && net user administrator /active:yes",
            parent="C:\\Windows\\System32\\winlogon.exe",
        )
    )
    # Second case: Linux login then interactive reverse shell via sudo.
    auth.append(
        SSH_ACCEPTED_TEMPLATE.format(
            ts=_syslog_ts(base + timedelta(minutes=1)), host="web-01", pid=5001,
            user="deploy", ip="198.51.100.77", port=53000,
        )
    )
    auth.append(
        SUDO_TEMPLATE.format(
            ts=_syslog_ts(base + timedelta(minutes=1, seconds=45)), host="web-01",
            user="deploy", command="/bin/bash -i",
        )
    )
    return auth, windows, firewall


def generate_false_positive_mix(base: datetime, rng: random.Random) -> Tuple[List[str], List[str], List[str]]:
    auth, windows, firewall = [], [], []
    moment = base
    # Four failures only: just below the Rule 1 threshold.
    for index in range(4):
        auth.append(
            SSH_FAILED_TEMPLATE.format(
                ts=_syslog_ts(moment), host="web-01", pid=6000 + index,
                user="svc_backup", ip="10.0.0.30", port=54000 + index,
            )
        )
        moment += timedelta(seconds=30)
    auth.append(
        SSH_ACCEPTED_TEMPLATE.format(
            ts=_syslog_ts(moment + timedelta(minutes=1)), host="web-01", pid=6050,
            user="svc_backup", ip="10.0.0.30", port=54099,
        )
    )
    # Scheduled task launching PowerShell, 30 minutes after login: outside Rule 3's 2 minutes.
    windows.append(
        _windows_event(4624, base, "app-02", "administrator", domain="CORP", ip="10.0.0.5")
    )
    windows.append(
        _windows_event(
            4688, base + timedelta(minutes=30), "app-02", "administrator", domain="CORP",
            process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command="powershell.exe -File C:\\Scripts\\Inventory.ps1",
            parent="C:\\Windows\\System32\\taskschd.exe",
        )
    )
    return auth, windows, firewall


GENERATORS = {
    "normal_day": generate_normal_day,
    "brute_force": generate_brute_force,
    "successful_brute_force": generate_successful_brute_force,
    "post_login_exec": generate_post_login_exec,
    "false_positive_mix": generate_false_positive_mix,
}

# How far after the anchor each scenario's last event lands. The anchor is pushed
# back by at least this much so no generated event is timestamped in the future
# (the schema rejects future @timestamp values).
SCENARIO_SPAN_MINUTES = {
    "normal_day": 120,
    "brute_force": 5,
    "successful_brute_force": 5,
    "post_login_exec": 5,
    "false_positive_mix": 35,
}


def generate_sample_logs(
    output_dir: str,
    scenario: str,
    base_time: datetime = None,
    seed: int = 1337,
    minutes_ago: int = 5,
) -> Dict[str, str]:
    """Generate one scenario's log files and return a mapping of file paths.

    Args:
        output_dir: Directory to write files into (created if missing).
        scenario: One of SCENARIOS.
        base_time: Anchor timestamp; defaults to now minus `minutes_ago`.
        seed: RNG seed for reproducible output.
        minutes_ago: How far in the past to anchor the scenario.

    Returns:
        {"auth": path, "windows": path, "firewall": path}
    """
    if scenario not in GENERATORS:
        raise ValueError(f"Unknown scenario '{scenario}'. Choose from: {', '.join(SCENARIOS)}")

    if base_time is None:
        minutes_back = max(minutes_ago, SCENARIO_SPAN_MINUTES[scenario])
        base_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_back)
    elif base_time.tzinfo is None:
        base_time = base_time.replace(tzinfo=timezone.utc)

    rng = random.Random(seed)
    auth, windows, firewall = GENERATORS[scenario](base_time, rng)

    os.makedirs(output_dir, exist_ok=True)
    paths = {
        "auth": os.path.join(output_dir, f"{scenario}_auth.log"),
        "windows": os.path.join(output_dir, f"{scenario}_windows.jsonl"),
        "firewall": os.path.join(output_dir, f"{scenario}_firewall.log"),
    }

    with open(paths["auth"], "w", encoding="utf-8") as handle:
        handle.write("\n".join(auth) + ("\n" if auth else ""))
    with open(paths["windows"], "w", encoding="utf-8") as handle:
        handle.write("\n".join(windows) + ("\n" if windows else ""))
    with open(paths["firewall"], "w", encoding="utf-8") as handle:
        handle.write("\n".join(firewall) + ("\n" if firewall else ""))

    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SIEM Lab sample logs")
    parser.add_argument(
        "--output", default="./logs/generated", help="Output directory (default: ./logs/generated)"
    )
    parser.add_argument(
        "--scenario", choices=SCENARIOS + ("all",), default="all",
        help="Scenario to generate, or 'all' (default: all)",
    )
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducible output")
    parser.add_argument(
        "--minutes-ago", type=int, default=5,
        help="Anchor the scenario this many minutes in the past",
    )
    args = parser.parse_args()

    scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
    for scenario in scenarios:
        paths = generate_sample_logs(
            args.output, scenario, seed=args.seed, minutes_ago=args.minutes_ago
        )
        print(f"[{scenario}]")
        for kind, path in paths.items():
            count = sum(1 for _ in open(path, "r", encoding="utf-8")) if os.path.getsize(path) else 0
            print(f"  {kind:<9} {count:>3} lines -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
