"""Correlation rules for the SIEM Lab (Phase 3).

Three mandatory Lab #07 rules:
  Rule 1 - brute_force                  : >= min_failures failures from one src_ip
                                          inside time_window_minutes -> high
  Rule 2 - successful_brute_force       : Rule 1 condition plus a success from the
                                          same src_ip/user inside
                                          success_window_minutes -> critical
  Rule 3 - suspicious_process_post_login: logon_success followed by a suspicious
                                          process_create on the same host inside
                                          time_after_login_minutes -> high

Rules operate on decoded Elasticsearch hits (dicts carrying an ``event_id`` key)
so they can be unit tested without a live cluster.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..normalization.schema import Alert, Severity, build_dedup_key
from ..utils.time_utils import ensure_utc, normalize_to_utc

logger = logging.getLogger(__name__)

RULE_BRUTE_FORCE = "brute_force"
RULE_SUCCESSFUL_BRUTE_FORCE = "successful_brute_force"
RULE_SUSPICIOUS_POST_LOGIN = "suspicious_process_post_login"
# Config section name for Rule 3 (distinct from the alert rule_name).
RULE_SUSPICIOUS_EXEC_RULE = "suspicious_exec"


@dataclass
class CorrelatedEvent:
    """Read-only view over a normalized event hit used by the rules."""

    event_id: str
    timestamp: datetime
    event_type: str
    src_ip: str
    user: str
    host: str
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    raw: Dict[str, Any] = None  # type: ignore[assignment]

    @classmethod
    def from_hit(cls, hit: Dict[str, Any]) -> "CorrelatedEvent":
        source = hit.get("_source", hit)
        process = source.get("process") or {}
        raw_ts = source.get("@timestamp") or source.get("timestamp")
        timestamp = normalize_to_utc(str(raw_ts)) if raw_ts else datetime.min.replace(tzinfo=None)
        return cls(
            event_id=str(hit.get("_id") or source.get("event_id") or ""),
            timestamp=ensure_utc(timestamp),
            event_type=str(source.get("event_type", "")),
            src_ip=str(source.get("src_ip") or "unknown"),
            user=str(source.get("user") or "unknown"),
            host=str(source.get("host") or "unknown"),
            process_name=process.get("name"),
            process_path=process.get("path"),
            command_line=process.get("command_line"),
            raw=source,
        )

    @property
    def display_user(self) -> str:
        """Username without the Windows domain prefix, lowercased for matching."""
        user = self.user.split("\\")[-1]
        return user.strip().lower()


def load_events(hits: Iterable[Dict[str, Any]]) -> List[CorrelatedEvent]:
    """Convert ES hits into CorrelatedEvent objects sorted by timestamp."""
    events = [CorrelatedEvent.from_hit(hit) for hit in hits]
    events.sort(key=lambda item: item.timestamp)
    return events


# -- Shared helpers --

def _valid_src_ip(event: CorrelatedEvent) -> bool:
    return bool(event.src_ip) and event.src_ip not in ("unknown", "", "-")


def _rule_config(config: Dict[str, Any], rule: str) -> Dict[str, Any]:
    return dict(config.get("rules", {}).get(rule, {}) or {})


def _rule_enabled(config: Dict[str, Any], rule: str) -> bool:
    return bool(_rule_config(config, rule).get("enabled", True))


def _severity(config: Dict[str, Any], rule: str, default: Severity) -> Severity:
    try:
        return Severity(_rule_config(config, rule).get("severity", default.value))
    except ValueError:
        return default


def _minutes(config: Dict[str, Any], rule: str, key: str, default: int) -> int:
    value = _rule_config(config, rule).get(key, default)
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def find_failure_bursts(
    events: Sequence[CorrelatedEvent],
    min_failures: int,
    window_minutes: int,
) -> List[List[CorrelatedEvent]]:
    """Group failure events into bursts meeting the brute-force condition.

    A burst is a maximal sliding window [first_failure, first_failure + window]
    containing at least ``min_failures`` failures from one src_ip. Bursts are
    returned in chronological order and do not overlap for the same source IP.
    """
    window = timedelta(minutes=window_minutes)
    by_ip: Dict[str, List[CorrelatedEvent]] = {}
    for event in events:
        if event.event_type == "logon_failure" and _valid_src_ip(event):
            by_ip.setdefault(event.src_ip, []).append(event)

    bursts: List[List[CorrelatedEvent]] = []
    for src_ip in sorted(by_ip):
        failures = sorted(by_ip[src_ip], key=lambda item: item.timestamp)
        index = 0
        while index < len(failures):
            start = failures[index].timestamp
            end = start + window
            cluster = [f for f in failures[index:] if f.timestamp < end]
            if len(cluster) >= min_failures:
                bursts.append(cluster)
                # Continue after this cluster so separate bursts can alert again.
                index += len(cluster)
            else:
                index += 1
    bursts.sort(key=lambda cluster: cluster[0].timestamp)
    return bursts


# -- Rule 1: brute force --

def rule_brute_force(
    events: Sequence[CorrelatedEvent],
    config: Dict[str, Any],
) -> List[Alert]:
    """Rule 1: >= min_failures failures from one src_ip inside time_window_minutes.

    Suppressed when a success from the same src_ip falls inside the burst window;
    Rule 2 (successful_brute_force) escalates that case instead.
    """
    if not _rule_enabled(config, RULE_BRUTE_FORCE):
        return []

    min_failures = _minutes(config, RULE_BRUTE_FORCE, "min_failures", 5)
    window_minutes = _minutes(config, RULE_BRUTE_FORCE, "time_window_minutes", 5)
    severity = _severity(config, RULE_BRUTE_FORCE, Severity.HIGH)
    dedup_window = int(config.get("correlation", {}).get("alert_dedup_window_minutes", 30))

    alerts: List[Alert] = []
    for burst in find_failure_bursts(events, min_failures, window_minutes):
        first_seen = burst[0].timestamp
        last_seen = burst[-1].timestamp
        src_ip = burst[0].src_ip

        success_in_burst = any(
            event.event_type == "logon_success"
            and event.src_ip == src_ip
            and first_seen <= event.timestamp <= last_seen + timedelta(minutes=window_minutes)
            for event in events
        )
        if success_in_burst:
            logger.debug(
                "Rule 1 suppressed for %s: success observed, Rule 2 will escalate", src_ip
            )
            continue

        alert = Alert(
            rule_name=RULE_BRUTE_FORCE,
            severity=severity,
            timestamp=last_seen,
            first_seen=first_seen,
            last_seen=last_seen,
            src_ip=src_ip,
            user=burst[0].display_user,
            host=burst[0].host,
            evidence_event_ids=[event.event_id for event in burst],
            reasoning=(
                f"{len(burst)} failed logons from {src_ip} against {burst[0].host} "
                f"within {window_minutes} minutes "
                f"({first_seen.isoformat()} to {last_seen.isoformat()}) "
                f"exceeded the threshold of {min_failures}."
            ),
            dedup_key=build_dedup_key(RULE_BRUTE_FORCE, src_ip, burst[0].display_user),
            dedup_window_minutes=dedup_window,
        )
        alerts.append(alert)
    return alerts


# -- Rule 2: successful brute force --

def rule_successful_brute_force(
    events: Sequence[CorrelatedEvent],
    config: Dict[str, Any],
) -> List[Alert]:
    """Rule 2: brute-force burst followed by a success from the same src_ip/user."""
    if not _rule_enabled(config, RULE_SUCCESSFUL_BRUTE_FORCE):
        return []

    min_failures = _minutes(config, RULE_BRUTE_FORCE, "min_failures", 5)
    window_minutes = _minutes(config, RULE_BRUTE_FORCE, "time_window_minutes", 5)
    success_window = _minutes(config, RULE_SUCCESSFUL_BRUTE_FORCE, "success_window_minutes", 10)
    severity = _severity(config, RULE_SUCCESSFUL_BRUTE_FORCE, Severity.CRITICAL)
    dedup_window = int(config.get("correlation", {}).get("alert_dedup_window_minutes", 30))

    successes = [event for event in events if event.event_type == "logon_success" and _valid_src_ip(event)]

    alerts: List[Alert] = []
    for burst in find_failure_bursts(events, min_failures, window_minutes):
        src_ip = burst[0].src_ip
        burst_start = burst[0].timestamp
        window_end = burst_start + timedelta(minutes=success_window)

        candidates = [
            event for event in successes
            if event.src_ip == src_ip
            and burst_start <= event.timestamp <= window_end
        ]
        if not candidates:
            continue

        exact = [event for event in candidates if event.display_user == burst[0].display_user]
        match = sorted(exact or candidates, key=lambda item: item.timestamp)[0]

        evidence = [event.event_id for event in burst] + [match.event_id]
        alert = Alert(
            rule_name=RULE_SUCCESSFUL_BRUTE_FORCE,
            severity=severity,
            timestamp=match.timestamp,
            first_seen=burst_start,
            last_seen=match.timestamp,
            src_ip=src_ip,
            user=match.display_user,
            host=match.host,
            evidence_event_ids=evidence,
            reasoning=(
                f"Brute force attack succeeded: {len(burst)} failed logons from {src_ip} "
                f"followed by a successful SSH login as '{match.user}' on {match.host} "
                f"within {success_window} minutes. Attacker likely gained access."
            ),
            dedup_key=build_dedup_key(RULE_SUCCESSFUL_BRUTE_FORCE, src_ip, match.display_user),
            dedup_window_minutes=dedup_window,
        )
        alerts.append(alert)
    return alerts


# -- Rule 3: suspicious post-login execution --

def _process_matches(process: CorrelatedEvent, tokens: Sequence[str]) -> bool:
    """True when a suspicious/expected token matches the process name, path, or command line."""
    haystacks = [
        (process.process_name or "").lower(),
        (process.process_path or "").lower(),
        (process.command_line or "").lower(),
    ]
    for token in tokens:
        needle = str(token).strip().lower()
        if not needle:
            continue
        for haystack in haystacks:
            if not haystack:
                continue
            if " " in needle or needle.startswith("-"):
                # Multi-word / flag tokens only match the command line.
                if needle in haystack:
                    return True
            elif haystack == needle or haystack.endswith("/" + needle) or needle in haystack.split():
                return True
    return False


def rule_suspicious_process_post_login(
    events: Sequence[CorrelatedEvent],
    config: Dict[str, Any],
) -> List[Alert]:
    """Rule 3: successful login followed by a suspicious process on the same host.

    Evidence is any process-execution record on the same host within the
    configured window: ``process_create`` (Windows 4688 / Sysmon 1) or
    ``privilege_escalation`` (Linux sudo COMMAND records, e.g. ``/bin/bash -i``).
    """
    if not _rule_enabled(config, RULE_SUSPICIOUS_EXEC_RULE,):
        return []

    after_minutes = _minutes(config, RULE_SUSPICIOUS_EXEC_RULE, "time_after_login_minutes", 2)
    severity = _severity(config, RULE_SUSPICIOUS_EXEC_RULE, Severity.HIGH)
    dedup_window = int(config.get("correlation", {}).get("alert_dedup_window_minutes", 30))
    rule_cfg = _rule_config(config, RULE_SUSPICIOUS_EXEC_RULE)
    suspicious = rule_cfg.get(
        "suspicious_processes", ["cmd.exe", "powershell.exe", "bash", "nc", "/bin/bash -i"]
    )
    expected = rule_cfg.get(
        "expected_processes", ["explorer.exe", "svchost.exe", "spoolsv.exe", "cron", "sshd"]
    )

    process_events = [
        event for event in events
        if event.event_type in ("process_create", "privilege_escalation")
    ]
    alerts: List[Alert] = []
    seen_logins = set()

    for login in events:
        if login.event_type != "logon_success":
            continue
        if login.host in ("unknown", ""):
            continue
        login_key = (login.host, login.user, login.timestamp)
        if login_key in seen_logins:
            continue

        deadline = login.timestamp + timedelta(minutes=after_minutes)
        matches = [
            process
            for process in process_events
            if process.host == login.host
            and login.timestamp <= process.timestamp <= deadline
            and _process_matches(process, expected) is False
            and _process_matches(process, suspicious)
        ]
        if not matches:
            continue

        seen_logins.add(login_key)
        first_match = min(matches, key=lambda item: item.timestamp)
        process_label = first_match.command_line or first_match.process_name or "unknown"
        alert = Alert(
            rule_name=RULE_SUSPICIOUS_POST_LOGIN,
            severity=severity,
            timestamp=first_match.timestamp,
            first_seen=login.timestamp,
            last_seen=first_match.timestamp,
            src_ip=login.src_ip,
            user=login.display_user,
            host=login.host,
            evidence_event_ids=[login.event_id, first_match.event_id],
            reasoning=(
                f"User '{login.user}' logged in to {login.host} from {login.src_ip} and "
                f"executed suspicious process '{process_label}' "
                f"{int((first_match.timestamp - login.timestamp).total_seconds())}s later."
            ),
            dedup_key=build_dedup_key(RULE_SUSPICIOUS_POST_LOGIN, login.src_ip, login.display_user),
            dedup_window_minutes=dedup_window,
        )
        alerts.append(alert)

    alerts.sort(key=lambda item: item.timestamp)
    return alerts


RULES = {
    RULE_BRUTE_FORCE: rule_brute_force,
    RULE_SUCCESSFUL_BRUTE_FORCE: rule_successful_brute_force,
    RULE_SUSPICIOUS_POST_LOGIN: rule_suspicious_process_post_login,
}


def apply_rules(events: Sequence[CorrelatedEvent], config: Dict[str, Any]) -> List[Alert]:
    """Run all enabled rules in sequence and return the combined alert list."""
    alerts: List[Alert] = []
    for rule_func in (rule_brute_force, rule_successful_brute_force, rule_suspicious_process_post_login):
        try:
            produced = rule_func(events, config)
        except Exception:
            logger.exception("Rule %s raised an error; continuing with remaining rules", rule_func.__name__)
            continue
        logger.info("Rule %s produced %s alert(s)", rule_func.__name__, len(produced))
        alerts.extend(produced)
    alerts.sort(key=lambda item: (item.timestamp, item.rule_name))
    return alerts


__all__ = [
    "CorrelatedEvent",
    "RULES",
    "RULE_BRUTE_FORCE",
    "RULE_SUCCESSFUL_BRUTE_FORCE",
    "RULE_SUSPICIOUS_POST_LOGIN",
    "apply_rules",
    "find_failure_bursts",
    "load_events",
    "rule_brute_force",
    "rule_successful_brute_force",
    "rule_suspicious_process_post_login",
]
