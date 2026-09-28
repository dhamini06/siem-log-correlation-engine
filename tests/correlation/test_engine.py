"""Correlation engine tests: event fetching, alert persistence, and status."""

from datetime import timedelta

from conftest import make_event

from src.correlation.engine import CorrelationEngine
from src.utils.time_utils import timestamp_to_iso8601, utc_now


def index_failure_burst(fake_es, count=5, src_ip="203.0.113.45", user="root", minutes_ago=5):
    from src.normalization.schema import compute_event_document_id, NormalizedEvent, EventType, Severity, SourceType

    base = utc_now() - timedelta(minutes=minutes_ago)
    for index in range(count):
        event = NormalizedEvent(
            timestamp=base + timedelta(seconds=index * 20),
            source_type=SourceType.LINUX_AUTH,
            event_type=EventType.LOGON_FAILURE,
            host="web-01",
            user=user,
            src_ip=src_ip,
            severity=Severity.MEDIUM,
            raw_event=f"Failed password for {user} from {src_ip} attempt {index}",
        )
        payload = event.to_dict()
        fake_es.index_event(event.index_name(), payload, compute_event_document_id(event))
    return fake_es


def build_engine(fake_es, sample_config, tmp_path) -> CorrelationEngine:
    config = {
        **sample_config,
        "correlation": {
            **sample_config["correlation"],
            "dedup_cache_path": str(tmp_path / "dedup-cache.json"),
        },
    }
    return CorrelationEngine(es_client=fake_es, config=config)


def test_cycle_creates_and_indexes_alert(fake_es, sample_config, tmp_path):
    index_failure_burst(fake_es)
    engine = build_engine(fake_es, sample_config, tmp_path)

    result = engine.run_correlation_cycle()

    assert result.events_scanned == 5
    assert result.alerts_created == 1
    assert result.alerts_by_rule == {"brute_force": 1}

    alerts = fake_es.alerts()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_name"] == "brute_force"
    assert alert["severity"] == "high"
    assert alert["src_ip"] == "203.0.113.45"
    assert len(alert["evidence_event_ids"]) == 5
    assert alert["dedup_key"]
    assert alert["timestamp"].endswith("Z")


def test_second_cycle_with_unchanged_evidence_is_suppressed(fake_es, sample_config, tmp_path):
    index_failure_burst(fake_es)
    engine = build_engine(fake_es, sample_config, tmp_path)

    first = engine.run_correlation_cycle()
    second = engine.run_correlation_cycle()

    assert first.alerts_created == 1
    assert second.alerts_created == 0
    assert second.alerts_suppressed == 1
    assert len(fake_es.alerts()) == 1


def test_cycle_with_no_events_is_a_no_op(fake_es, sample_config, tmp_path):
    engine = build_engine(fake_es, sample_config, tmp_path)
    result = engine.run_correlation_cycle()
    assert result.events_scanned == 0
    assert result.alerts_created == 0
    assert result.errors == []


def test_out_of_window_events_are_ignored(fake_es, sample_config, tmp_path):
    old = make_event("old-1", timestamp_to_iso8601(utc_now() - timedelta(days=2)), src_ip="203.0.113.9")
    for index in range(5):
        hit = make_event(
            f"old-{index}",
            timestamp_to_iso8601(utc_now() - timedelta(days=2, seconds=-index * 20)),
            src_ip="203.0.113.9",
        )
        fake_es.index_event("normalized-events-2024-01-15", hit["_source"], hit["_id"])

    engine = build_engine(fake_es, sample_config, tmp_path)
    result = engine.run_correlation_cycle()
    assert result.events_scanned == 0
    assert result.alerts_created == 0


def test_engine_status_reports_last_run(fake_es, sample_config, tmp_path):
    index_failure_burst(fake_es)
    engine = build_engine(fake_es, sample_config, tmp_path)
    engine.run_correlation_cycle()
    status = engine.status()
    assert status["last_alert_count"] == 1
    assert status["total_alerts"] == 1
    assert status["error_count"] == 0
    assert status["last_run_time"] is not None
    assert status["lookback_minutes"] == sample_config["correlation"]["lookback_window_minutes"]


def test_indexing_failure_is_reported_not_raised(fake_es, sample_config, tmp_path):
    index_failure_burst(fake_es)
    engine = build_engine(fake_es, sample_config, tmp_path)

    def boom(index, document, doc_id):
        raise RuntimeError("index unavailable")

    fake_es.index_alert = boom
    result = engine.run_correlation_cycle()
    assert result.alerts_created == 0
    assert result.errors and "index unavailable" in result.errors[0]
