"""Tests for the common event schema and validation rules."""

from datetime import datetime, timedelta, timezone

import pytest

from src.normalization.schema import (
    Alert,
    EventType,
    NormalizedEvent,
    SchemaError,
    Severity,
    SourceType,
    build_dedup_key,
    compute_event_document_id,
    validate_event_payload,
)
from src.utils.time_utils import utc_now


def build_event(**overrides) -> NormalizedEvent:
    defaults = dict(
        timestamp=utc_now(),
        source_type=SourceType.LINUX_AUTH,
        event_type=EventType.LOGON_FAILURE,
        host="web-01",
        user="alice",
        severity=Severity.MEDIUM,
        raw_event="Sep 25 17:20:01 web-01 sshd[1]: Failed password for alice from 10.0.0.5 port 22 ssh2",
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def test_valid_event_passes_and_serializes():
    event = build_event()
    payload = event.to_dict()

    assert payload["@timestamp"].endswith("Z")
    assert payload["event_type"] == "logon_failure"
    assert payload["source_type"] == "linux_auth"
    assert payload["severity"] == "medium"
    assert payload["host"] == "web-01"
    assert payload["parser_version"] == "1.0"
    assert "message" in payload
    assert event.index_name().startswith("normalized-events-")


def test_round_trip_from_dict():
    event = build_event()
    restored = NormalizedEvent.from_dict(event.to_dict())
    assert restored.event_type is EventType.LOGON_FAILURE
    # Serialization keeps millisecond precision.
    assert restored.timestamp.replace(microsecond=0) == event.timestamp.replace(microsecond=0)
    assert abs((restored.timestamp - event.timestamp).total_seconds()) < 0.001
    assert restored.user == event.user


@pytest.mark.parametrize("field", ["host", "user", "raw_event"])
def test_missing_required_fields_raise(field):
    with pytest.raises(SchemaError):
        build_event(**{field: ""})


def test_invalid_ip_raises():
    with pytest.raises(SchemaError):
        build_event(src_ip="999.999.999.999")
    with pytest.raises(SchemaError):
        build_event(dst_ip="not-an-ip")


def test_unknown_ip_is_allowed_in_memory_but_serialized_as_null():
    # In memory the "unknown" sentinel is kept; Elasticsearch `ip` fields reject it,
    # so the serialized document must carry null instead.
    event = build_event(src_ip="unknown", dst_ip=None)
    payload = event.to_dict()
    assert event.src_ip == "unknown"
    assert payload["src_ip"] is None
    assert payload["dst_ip"] is None


def test_real_ip_is_serialized_unchanged():
    payload = build_event(src_ip="10.0.0.5", dst_ip="8.8.8.8").to_dict()
    assert payload["src_ip"] == "10.0.0.5"
    assert payload["dst_ip"] == "8.8.8.8"


def test_timestamp_must_not_be_far_in_the_future():
    with pytest.raises(SchemaError):
        build_event(timestamp=utc_now() + timedelta(hours=1), ingest_timestamp=utc_now() + timedelta(hours=2))


def test_ingest_timestamp_must_not_precede_event():
    with pytest.raises(SchemaError):
        build_event(timestamp=utc_now(), ingest_timestamp=utc_now() - timedelta(hours=1))


def test_unknown_process_field_rejected():
    with pytest.raises(SchemaError):
        build_event(process={"name": "cmd.exe", "owner": "attacker"})


def test_validate_event_payload_reports_errors():
    good = build_event().to_dict()
    assert validate_event_payload(good) == []

    bad = dict(good)
    bad["event_type"] = "not_a_type"
    bad["@timestamp"] = "yesterday"
    errors = validate_event_payload(bad)
    assert any("event_type" in error for error in errors)
    assert any("@timestamp" in error for error in errors)


def test_document_id_is_deterministic_and_unique():
    # The timestamp is pinned deliberately. `build_event()` defaults to
    # `utc_now()`, and the document id hashes a millisecond-truncated
    # timestamp, so two consecutive calls usually land in the same millisecond
    # and only sometimes do not. Measured at 8 failures in 2,000 consecutive
    # pairs - a 0.4% coin flip that has nothing to do with the thing under test.
    # What is being asserted is that the id is a pure function of the event's
    # content, so the content must be held still.
    stamp = utc_now().replace(microsecond=0)
    first = build_event(timestamp=stamp)
    second = build_event(timestamp=stamp)
    assert compute_event_document_id(first) == compute_event_document_id(second)

    other = build_event(timestamp=stamp, src_ip="10.0.0.9")
    assert compute_event_document_id(first) != compute_event_document_id(other)


def test_dedup_key_is_stable_and_rule_specific():
    key_a = build_dedup_key("brute_force", "10.0.0.1", "alice")
    key_b = build_dedup_key("brute_force", "10.0.0.1", "alice")
    key_c = build_dedup_key("successful_brute_force", "10.0.0.1", "alice")
    assert key_a == key_b
    assert key_a != key_c


def test_alert_defaults_and_serialization():
    moment = datetime(2024, 1, 15, 14, 32, 45, tzinfo=timezone.utc)
    alert = Alert(
        rule_name="brute_force",
        severity=Severity.HIGH,
        timestamp=moment,
        first_seen=moment - timedelta(minutes=2),
        last_seen=moment,
        reasoning="5 failures from 10.0.0.1",
        evidence_event_ids=["a", "b"],
        src_ip="10.0.0.1",
        user="alice",
        host="web-01",
    )
    payload = alert.to_dict()
    assert payload["rule_name"] == "brute_force"
    assert payload["severity"] == "high"
    assert payload["evidence_count"] == 2
    assert payload["dedup_key"] == build_dedup_key("brute_force", "10.0.0.1", "alice")
    assert alert.index_name() == "security-alerts-2024-01-15"
    assert payload["false_positive_feedback"] == "unreviewed"


def test_alert_requires_rule_name():
    with pytest.raises(SchemaError):
        Alert(
            rule_name="",
            severity=Severity.HIGH,
            timestamp=utc_now(),
            first_seen=utc_now(),
            last_seen=utc_now(),
            reasoning="x",
        )
