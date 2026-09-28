"""End-to-end test: generate sample logs -> normalize -> index -> correlate -> alert.

Uses the in-memory FakeESClient so the full pipeline is exercised without Docker.
"""

from src.correlation.engine import CorrelationEngine
from src.normalization.ingestion import NormalizationEngine
from src.normalization.sample_generator import generate_sample_logs


def run_pipeline(fake_es, sample_config, tmp_path, scenario, source_types):
    output_dir = str(tmp_path / "generated")
    generate_sample_logs(output_dir, scenario, minutes_ago=3)

    engine = NormalizationEngine(es_client=fake_es)
    result = engine.ingest_directory(output_dir)
    assert result.errors == [], result.errors

    correlation = CorrelationEngine(
        es_client=fake_es,
        config={
            **sample_config,
            "correlation": {
                **sample_config["correlation"],
                "dedup_cache_path": str(tmp_path / "dedup-cache.json"),
            },
        },
    )
    cycle = correlation.run_correlation_cycle()
    return result, cycle


def test_brute_force_scenario_produces_rule_1_alert(fake_es, sample_config, tmp_path):
    result, cycle = run_pipeline(fake_es, sample_config, tmp_path, "brute_force", None)

    assert result.parsed >= 10
    assert cycle.alerts_by_rule.get("brute_force") == 1

    alert = fake_es.alerts()[0]
    assert alert["severity"] == "high"
    assert alert["src_ip"] == "203.0.113.45"
    assert len(alert["evidence_event_ids"]) >= 5
    assert alert["reasoning"]

    # Evidence IDs must resolve to real indexed events.
    evidence = fake_es.search_hits("normalized-events-*", {"ids": {"values": alert["evidence_event_ids"]}}, size=50)
    assert len(evidence) == len(alert["evidence_event_ids"])


def test_successful_brute_force_scenario_produces_critical_alert(fake_es, sample_config, tmp_path):
    _result, cycle = run_pipeline(fake_es, sample_config, tmp_path, "successful_brute_force", None)

    assert cycle.alerts_by_rule.get("successful_brute_force") == 1
    alert = fake_es.alerts()[0]
    assert alert["rule_name"] == "successful_brute_force"
    assert alert["severity"] == "critical"
    assert alert["src_ip"] == "203.0.113.66"
    assert len(alert["evidence_event_ids"]) == 6


def test_post_login_exec_scenario_produces_rule_3_alerts(fake_es, sample_config, tmp_path):
    _result, cycle = run_pipeline(fake_es, sample_config, tmp_path, "post_login_exec", None)

    assert cycle.alerts_by_rule.get("suspicious_process_post_login") == 2
    rules = {alert["rule_name"] for alert in fake_es.alerts()}
    assert rules == {"suspicious_process_post_login"}
    severities = {alert["severity"] for alert in fake_es.alerts()}
    assert severities == {"high"}


def test_normal_day_scenario_produces_no_alerts(fake_es, sample_config, tmp_path):
    result, cycle = run_pipeline(fake_es, sample_config, tmp_path, "normal_day", None)

    assert result.parsed > 10
    assert cycle.alerts_created == 0
    assert fake_es.alerts() == []


def test_false_positive_mix_scenario_produces_no_alerts(fake_es, sample_config, tmp_path):
    _result, cycle = run_pipeline(fake_es, sample_config, tmp_path, "false_positive_mix", None)
    assert cycle.alerts_created == 0


def test_reingestion_is_idempotent(fake_es, sample_config, tmp_path):
    output_dir = str(tmp_path / "generated")
    generate_sample_logs(output_dir, "brute_force", minutes_ago=3)

    engine = NormalizationEngine(es_client=fake_es)
    first = engine.ingest_directory(output_dir)
    count_after_first = len(fake_es.normalized())
    second = engine.ingest_directory(output_dir)

    assert first.indexed == second.indexed
    assert len(fake_es.normalized()) == count_after_first
    assert count_after_first == first.indexed
