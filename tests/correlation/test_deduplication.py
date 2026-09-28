"""Deduplication tests: 30-minute window and evidence-change re-alerting."""

from datetime import datetime, timedelta, timezone

import pytest

from src.correlation.deduplication import AlertDeduplicator
from src.normalization.schema import Alert, Severity

BASE = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)


def make_alert(offset_minutes: float, evidence: list, rule: str = "brute_force") -> Alert:
    timestamp = BASE + timedelta(minutes=offset_minutes)
    return Alert(
        rule_name=rule,
        severity=Severity.HIGH,
        timestamp=timestamp,
        first_seen=timestamp - timedelta(minutes=2),
        last_seen=timestamp,
        reasoning="test",
        evidence_event_ids=evidence,
        src_ip="203.0.113.45",
        user="root",
        host="web-01",
    )


@pytest.fixture
def dedup(tmp_path) -> AlertDeduplicator:
    return AlertDeduplicator(window_minutes=30, min_new_evidence=2, cache_path=str(tmp_path / "dedup.json"))


def test_first_alert_is_emitted(dedup):
    emit, suppress = dedup.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    assert len(emit) == 1
    assert suppress == []


def test_identical_repeat_within_window_is_suppressed(dedup):
    alert = make_alert(0, ["a", "b", "c", "d", "e"])
    dedup.filter_alerts([alert])
    emit, suppress = dedup.filter_alerts([make_alert(1, ["a", "b", "c", "d", "e"])])
    assert emit == []
    assert len(suppress) == 1


def test_single_new_evidence_event_is_not_enough_to_realert(dedup):
    dedup.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    emit, suppress = dedup.filter_alerts([make_alert(2, ["a", "b", "c", "d", "e", "f"])])
    assert emit == []
    assert len(suppress) == 1


def test_two_new_evidence_events_trigger_realert(dedup):
    dedup.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    emit, suppress = dedup.filter_alerts([make_alert(2, ["a", "b", "c", "d", "e", "f", "g"])])
    assert len(emit) == 1
    assert suppress == []


def test_alert_after_window_expires_is_emitted(dedup):
    dedup.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    emit, _ = dedup.filter_alerts([make_alert(31, ["a", "b", "c", "d", "e"])])
    assert len(emit) == 1


def test_different_dedup_keys_do_not_suppress_each_other(dedup):
    dedup.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    emit, _ = dedup.filter_alerts([make_alert(1, ["x", "y", "z"], rule="successful_brute_force")])
    assert len(emit) == 1


def test_seed_from_stored_alerts_suppresses_after_restart(dedup):
    stored = make_alert(0, ["a", "b", "c", "d", "e"])
    dedup.seed_from_alerts([stored])
    emit, suppress = dedup.filter_alerts([make_alert(1, ["a", "b", "c", "d", "e"])])
    assert emit == []
    assert len(suppress) == 1


def test_cache_round_trips_through_disk(tmp_path):
    path = str(tmp_path / "dedup.json")
    first = AlertDeduplicator(cache_path=path)
    first.filter_alerts([make_alert(0, ["a", "b", "c", "d", "e"])])
    first.save()

    second = AlertDeduplicator(cache_path=path)
    assert len(second) == 1
    emit, suppress = second.filter_alerts([make_alert(1, ["a", "b", "c", "d", "e"])])
    assert emit == []
    assert len(suppress) == 1


def test_corrupt_cache_file_is_ignored(tmp_path):
    path = tmp_path / "dedup.json"
    path.write_text("{not valid json", encoding="utf-8")
    dedup = AlertDeduplicator(cache_path=str(path))
    assert len(dedup) == 0
