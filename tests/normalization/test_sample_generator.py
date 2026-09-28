"""Tests for the deterministic sample log generator."""

from datetime import datetime, timezone

import pytest

from src.normalization.firewall_syslog import FirewallSyslogParser
from src.normalization.linux_auth import LinuxAuthParser
from src.normalization.sample_generator import SCENARIOS, generate_sample_logs
from src.normalization.windows_sysmon import WindowsSysmonParser

ANCHOR = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)


def read_lines(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return [line for line in handle.read().splitlines() if line.strip()]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_scenario_writes_three_files(scenario, tmp_path):
    paths = generate_sample_logs(str(tmp_path), scenario, base_time=ANCHOR)
    assert set(paths) == {"auth", "windows", "firewall"}
    for path in paths.values():
        assert path.endswith((".log", ".jsonl"))


def test_output_is_reproducible_for_a_fixed_seed(tmp_path):
    first = generate_sample_logs(str(tmp_path / "a"), "brute_force", base_time=ANCHOR, seed=7)
    second = generate_sample_logs(str(tmp_path / "b"), "brute_force", base_time=ANCHOR, seed=7)
    for kind in first:
        assert read_lines(first[kind]) == read_lines(second[kind])


def test_brute_force_scenario_has_ten_failures_from_one_ip(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "brute_force", base_time=ANCHOR)
    events = LinuxAuthParser().parse_file(paths["auth"])
    assert len(events) == 10
    assert {event.event_type.value for event in events} == {"logon_failure"}
    assert {event.src_ip for event in events} == {"203.0.113.45"}


def test_successful_brute_force_has_failures_then_success(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "successful_brute_force", base_time=ANCHOR)
    events = LinuxAuthParser().parse_file(paths["auth"])
    kinds = [event.event_type.value for event in events]
    assert kinds.count("logon_failure") == 5
    assert kinds[-1] == "logon_success"
    success = events[-1]
    first_failure = events[0]
    assert 0 <= (success.timestamp - first_failure.timestamp).total_seconds() <= 600


def test_post_login_exec_has_login_then_process(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "post_login_exec", base_time=ANCHOR)
    events = WindowsSysmonParser().parse_file(paths["windows"])
    kinds = [event.event_type.value for event in events]
    assert "logon_success" in kinds
    assert "process_create" in kinds
    login_index = kinds.index("logon_success")
    assert "process_create" in kinds[login_index + 1:]


def test_false_positive_mix_stays_below_thresholds(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "false_positive_mix", base_time=ANCHOR)
    auth_events = LinuxAuthParser().parse_file(paths["auth"])
    failures = [event for event in auth_events if event.event_type.value == "logon_failure"]
    assert len(failures) == 4


def test_normal_day_is_mostly_successful_logins(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "normal_day", base_time=ANCHOR)
    events = LinuxAuthParser().parse_file(paths["auth"])
    successes = [event for event in events if event.event_type.value == "logon_success"]
    assert len(successes) >= 6


def test_firewall_lines_parse(tmp_path):
    paths = generate_sample_logs(str(tmp_path), "brute_force", base_time=ANCHOR)
    events = FirewallSyslogParser().parse_file(paths["firewall"])
    assert len(events) == 3
    assert {event.severity.value for event in events} == {"high"}


def test_unknown_scenario_raises(tmp_path):
    with pytest.raises(ValueError):
        generate_sample_logs(str(tmp_path), "does_not_exist", base_time=ANCHOR)
