"""Rule 2 tests: successful brute force escalation (positive and negative cases)."""

from datetime import datetime, timedelta

from conftest import make_event

from src.correlation.rules import RULE_SUCCESSFUL_BRUTE_FORCE, load_events, rule_successful_brute_force
from src.normalization.schema import Severity

BASE = datetime.fromisoformat("2024-01-15T14:00:00+00:00")
ATTACKER_IP = "203.0.113.66"


def iso(offset_minutes: float) -> str:
    return (BASE + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def burst(count: int = 5, src_ip: str = ATTACKER_IP, user: str = "alice"):
    return [
        make_event(
            f"fail-{index}",
            iso(index * 0.3),
            event_type="logon_failure",
            src_ip=src_ip,
            user=user,
        )
        for index in range(count)
    ]


def test_burst_followed_by_success_escalates_to_critical(sample_config):
    hits = burst() + [make_event("success-1", iso(2), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")]
    alerts = rule_successful_brute_force(load_events(hits), sample_config)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == RULE_SUCCESSFUL_BRUTE_FORCE
    assert alert.severity is Severity.CRITICAL
    assert alert.src_ip == ATTACKER_IP
    assert alert.user == "alice"
    assert len(alert.evidence_event_ids) == 6
    assert alert.evidence_event_ids[-1] == "success-1"
    assert "succeeded" in alert.reasoning.lower()
    assert "gained access" in alert.reasoning.lower()


def test_success_outside_ten_minute_window_does_not_escalate(sample_config):
    hits = burst() + [make_event("success-late", iso(11), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")]
    assert rule_successful_brute_force(load_events(hits), sample_config) == []


def test_four_failures_then_success_does_not_escalate(sample_config):
    hits = burst(4) + [make_event("success-1", iso(2), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")]
    assert rule_successful_brute_force(load_events(hits), sample_config) == []


def test_success_from_different_source_ip_does_not_escalate(sample_config):
    hits = burst() + [make_event("success-1", iso(2), event_type="logon_success", src_ip="198.51.100.4", user="alice")]
    assert rule_successful_brute_force(load_events(hits), sample_config) == []


def test_success_before_the_burst_does_not_escalate(sample_config):
    hits = [make_event("success-early", iso(-5), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")] + burst()
    assert rule_successful_brute_force(load_events(hits), sample_config) == []


def test_success_for_different_user_still_escalates_but_records_actual_user(sample_config):
    hits = burst(user="alice") + [
        make_event("success-1", iso(2), event_type="logon_success", src_ip=ATTACKER_IP, user="svc_backup")
    ]
    alerts = rule_successful_brute_force(load_events(hits), sample_config)
    assert len(alerts) == 1
    assert alerts[0].user == "svc_backup"
    assert alerts[0].dedup_key != ""


def test_two_separate_bursts_each_escalate(sample_config):
    first = burst(5, src_ip=ATTACKER_IP, user="alice")
    first_success = [make_event("success-1", iso(2), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")]
    second = [
        make_event(
            f"fail2-{index}",
            (BASE + timedelta(minutes=40, seconds=index * 15)).isoformat().replace("+00:00", "Z"),
            event_type="logon_failure",
            src_ip=ATTACKER_IP,
            user="alice",
        )
        for index in range(5)
    ]
    second_success = [
        make_event("success-2", (BASE + timedelta(minutes=42)).isoformat().replace("+00:00", "Z"),
                   event_type="logon_success", src_ip=ATTACKER_IP, user="alice")
    ]
    alerts = rule_successful_brute_force(load_events(first + first_success + second + second_success), sample_config)
    assert len(alerts) == 2


def test_rule_disabled(sample_config):
    config = {
        **sample_config,
        "rules": {
            **sample_config["rules"],
            "successful_brute_force": {**sample_config["rules"]["successful_brute_force"], "enabled": False},
        },
    }
    hits = burst() + [make_event("success-1", iso(2), event_type="logon_success", src_ip=ATTACKER_IP, user="alice")]
    assert rule_successful_brute_force(load_events(hits), config) == []
