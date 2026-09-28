"""Rule 1 tests: brute force detection (positive and negative cases)."""

import pytest
from conftest import make_event

from src.correlation.rules import (
    RULE_BRUTE_FORCE,
    find_failure_bursts,
    load_events,
    rule_brute_force,
)
from src.normalization.schema import Severity


def failures(count: int, start: str = "2024-01-15T14:00:00Z", step_seconds: int = 20, src_ip: str = "203.0.113.45", user: str = "root"):
    from datetime import datetime, timedelta

    base = datetime.fromisoformat(start.replace("Z", "+00:00"))
    return [
        make_event(
            f"fail-{index}",
            (base + timedelta(seconds=index * step_seconds)).isoformat().replace("+00:00", "Z"),
            event_type="logon_failure",
            src_ip=src_ip,
            user=user,
        )
        for index in range(count)
    ]


def test_five_failures_in_window_triggers_high_alert(sample_config):
    events = load_events(failures(5))
    alerts = rule_brute_force(events, sample_config)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == RULE_BRUTE_FORCE
    assert alert.severity is Severity.HIGH
    assert alert.src_ip == "203.0.113.45"
    assert alert.user == "root"
    assert alert.host == "web-01"
    assert len(alert.evidence_event_ids) == 5
    assert alert.evidence_event_ids[0] == "fail-0"
    assert "exceeded the threshold of 5" in alert.reasoning
    assert alert.first_seen < alert.last_seen


def test_four_failures_do_not_trigger(sample_config):
    assert rule_brute_force(load_events(failures(4)), sample_config) == []


def test_failures_spread_beyond_window_do_not_trigger(sample_config):
    # 5 failures, but 20 minutes apart: each 5-minute window holds at most one.
    assert rule_brute_force(load_events(failures(5, step_seconds=1200)), sample_config) == []


def test_failures_split_across_two_windows_trigger_two_alerts(sample_config):
    # Two separate bursts of 5 failures each, 30 minutes apart.
    first = failures(5, start="2024-01-15T14:00:00Z", step_seconds=15)
    second = failures(5, start="2024-01-15T14:30:00Z", step_seconds=15)
    alerts = rule_brute_force(load_events(first + second), sample_config)
    assert len(alerts) == 2


def test_different_source_ips_do_not_merge(sample_config):
    from datetime import datetime, timedelta

    base = datetime.fromisoformat("2024-01-15T14:00:00+00:00")
    hits = []
    for index in range(3):
        hits.append(make_event(f"a-{index}", (base + timedelta(seconds=index * 10)).isoformat(), src_ip="203.0.113.1"))
        hits.append(make_event(f"b-{index}", (base + timedelta(seconds=index * 10)).isoformat(), src_ip="203.0.113.2"))
    assert rule_brute_force(load_events(hits), sample_config) == []


def test_events_without_src_ip_are_ignored(sample_config):
    hits = failures(5)
    for hit in hits:
        hit["_source"]["src_ip"] = "unknown"
    assert rule_brute_force(load_events(hits), sample_config) == []


def test_success_in_window_suppresses_rule_1(sample_config):
    hits = failures(5)
    hits.append(
        make_event("success-1", "2024-01-15T14:00:45Z", event_type="logon_success", src_ip="203.0.113.45", user="root")
    )
    assert rule_brute_force(load_events(hits), sample_config) == []


def test_rule_disabled_by_config(sample_config):
    config = {**sample_config, "rules": {**sample_config["rules"], "brute_force": {**sample_config["rules"]["brute_force"], "enabled": False}}}
    assert rule_brute_force(load_events(failures(5)), config) == []


def test_threshold_is_tunable(sample_config):
    config = {**sample_config, "rules": {**sample_config["rules"], "brute_force": {**sample_config["rules"]["brute_force"], "min_failures": 3}}}
    alerts = rule_brute_force(load_events(failures(3)), config)
    assert len(alerts) == 1


def test_find_failure_bursts_returns_non_overlapping_clusters(sample_config):
    bursts = find_failure_bursts(load_events(failures(7)), 5, 5)
    assert len(bursts) == 1
    assert len(bursts[0]) == 7
