"""Tests for the ingestion pipeline and source-type detection."""

from datetime import timedelta

import pytest

from src.normalization.ingestion import (
    NormalizationEngine,
    detect_source_type,
    resolve_source_type,
)
from src.normalization.schema import SourceType
from src.normalization.sample_generator import generate_sample_logs
from src.utils.time_utils import utc_now


def syslog_line(minutes_ago: float = 5.0, **overrides) -> str:
    """Build a linux auth.log line anchored in the recent past."""
    moment = utc_now() - timedelta(minutes=minutes_ago)
    values = {
        "ts": moment.strftime("%b %d %H:%M:%S"),
        "host": "web-01",
        "pid": 1,
        "user": "alice",
        "ip": "10.0.0.5",
        "port": 51234,
    }
    values.update(overrides)
    return (
        f"{values['ts']} {values['host']} sshd[{values['pid']}]: Failed password for "
        f"{values['user']} from {values['ip']} port {values['port']} ssh2"
    )


AUTH_LINE = syslog_line()
WINDOWS_LINE = (
    '{"EventID": 4625, "TimeCreated": "2024-01-15T14:32:45.000Z", "Computer": "APP-01", '
    '"EventData": {"TargetUserName": "jdoe", "TargetDomainName": "CORP", "IpAddress": "10.0.0.7"}}'
)
FIREWALL_LINE = (
    'Sep 25 17:30:05 fw-01 %ASA-4-106023: Deny tcp src outside:203.0.113.45/51234 dst inside:10.0.0.10/22'
)


def test_detect_source_type_by_filename(tmp_path):
    auth = tmp_path / "web_auth.log"
    auth.write_text(AUTH_LINE, encoding="utf-8")
    windows = tmp_path / "events_windows.jsonl"
    windows.write_text(WINDOWS_LINE, encoding="utf-8")
    firewall = tmp_path / "edge-firewall.log"
    firewall.write_text(FIREWALL_LINE, encoding="utf-8")
    sniffer = tmp_path / "mystery.txt"
    sniffer.write_text(FIREWALL_LINE, encoding="utf-8")

    assert detect_source_type(str(auth)) is SourceType.LINUX_AUTH
    assert detect_source_type(str(windows)) is SourceType.WINDOWS_SYSMON
    assert detect_source_type(str(firewall)) is SourceType.FIREWALL_SYSLOG
    assert detect_source_type(str(sniffer)) is SourceType.FIREWALL_SYSLOG


def test_detect_source_type_raises_for_unknown_content(tmp_path):
    unknown = tmp_path / "data.log"
    unknown.write_text("completely opaque payload", encoding="utf-8")
    with pytest.raises(ValueError):
        detect_source_type(str(unknown))


def test_resolve_source_type_validation():
    assert resolve_source_type("linux_auth") is SourceType.LINUX_AUTH
    with pytest.raises(ValueError):
        resolve_source_type("smoke_signals")


def test_ingest_file_indexes_with_daily_index(fake_es, tmp_path):
    moment = utc_now() - timedelta(minutes=6)
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "\n".join([syslog_line(6), syslog_line(5, pid=2, port=51235)]) + "\n", encoding="utf-8"
    )

    engine = NormalizationEngine(es_client=fake_es)
    result = engine.ingest_file(str(log_file), SourceType.LINUX_AUTH)

    assert result.lines_read == 2
    assert result.parsed == 2
    assert result.skipped == 0
    assert result.invalid == 0
    assert result.indexed == 2
    expected_index = f"normalized-events-{moment.strftime('%Y-%m-%d')}"
    assert list(result.indices) == [expected_index]
    assert fake_es.refresh_count == 1


def test_ingest_counts_unparseable_lines(fake_es, tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join([AUTH_LINE, "gibberish", ""]) + "\n", encoding="utf-8")
    result = NormalizationEngine(es_client=fake_es).ingest_file(str(log_file), SourceType.LINUX_AUTH)
    assert result.parsed == 1
    assert result.skipped == 1


def test_dry_run_does_not_index(fake_es, tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(AUTH_LINE + "\n", encoding="utf-8")
    result = NormalizationEngine(es_client=fake_es, dry_run=True).ingest_file(str(log_file), SourceType.LINUX_AUTH)
    assert result.parsed == 1
    assert result.indexed == 0
    assert fake_es.normalized() == []
    assert "dry run" in result.summary()


def test_missing_file_is_reported(fake_es, tmp_path):
    result = NormalizationEngine(es_client=fake_es).ingest_file(str(tmp_path / "nope.log"))
    assert result.errors
    assert "not found" in result.errors[0]


def test_ingest_directory_handles_mixed_sources(fake_es, tmp_path):
    log_dir = tmp_path / "mixed"
    log_dir.mkdir()
    (log_dir / "a_auth.log").write_text(AUTH_LINE + "\n", encoding="utf-8")
    (log_dir / "b_windows.jsonl").write_text(WINDOWS_LINE + "\n", encoding="utf-8")
    (log_dir / "c_firewall.log").write_text(FIREWALL_LINE + "\n", encoding="utf-8")

    result = NormalizationEngine(es_client=fake_es).ingest_directory(str(log_dir))
    assert result.parsed == 3
    assert result.indexed == 3
    assert result.errors == []

    indexed = fake_es.normalized()
    assert {event["source_type"] for event in indexed} == {
        "linux_auth", "windows_sysmon", "firewall_syslog",
    }


def test_forced_source_type_overrides_detection(fake_es, tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(AUTH_LINE + "\n", encoding="utf-8")
    result = NormalizationEngine(es_client=fake_es).ingest_file(str(log_file), SourceType.LINUX_AUTH)
    assert result.parsed == 1
    assert fake_es.normalized()[0]["source_type"] == "linux_auth"


def test_generated_logs_are_all_ingestible(fake_es, tmp_path):
    output_dir = str(tmp_path / "generated")
    generate_sample_logs(output_dir, "normal_day", minutes_ago=2)
    result = NormalizationEngine(es_client=fake_es).ingest_directory(output_dir)
    assert result.errors == []
    assert result.parsed == result.lines_read
    assert result.indexed > 0
