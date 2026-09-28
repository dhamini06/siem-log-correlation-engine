"""Data-driven rule tests driven by tests/data/{positive,negative}_cases.json."""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest
from conftest import make_event

from src.correlation.rules import (
    RULE_BRUTE_FORCE,
    RULE_SUCCESSFUL_BRUTE_FORCE,
    RULE_SUSPICIOUS_POST_LOGIN,
    apply_rules,
    load_events,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tests", "data")


def load_cases(filename: str) -> List[Dict[str, Any]]:
    with open(os.path.join(DATA_DIR, filename), "r", encoding="utf-8") as handle:
        return json.load(handle)["cases"]


def build_hits(case: Dict[str, Any], base: datetime) -> List[Dict[str, Any]]:
    hits = []
    for index, event in enumerate(case["events"]):
        moment = base + timedelta(seconds=event.get("offset_seconds", 0))
        hits.append(
            make_event(
                f"{case['name']}-{index}",
                moment.isoformat().replace("+00:00", "Z"),
                event_type=event["event_type"],
                src_ip=event.get("src_ip", "unknown"),
                user=event.get("user", "unknown"),
                host=event.get("host", "unknown"),
                process=event.get("process"),
            )
        )
    return hits


POSITIVE_CASES = load_cases("positive_cases.json")
NEGATIVE_CASES = load_cases("negative_cases.json")


@pytest.mark.parametrize("case", POSITIVE_CASES, ids=[case["name"] for case in POSITIVE_CASES])
def test_positive_cases_trigger_expected_rule(case, sample_config):
    base = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
    alerts = apply_rules(load_events(build_hits(case, base)), sample_config)
    rules = {alert.rule_name for alert in alerts}
    assert case["expected_rule"] in rules


@pytest.mark.parametrize("case", NEGATIVE_CASES, ids=[case["name"] for case in NEGATIVE_CASES])
def test_negative_cases_trigger_no_alerts(case, sample_config):
    base = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
    alerts = apply_rules(load_events(build_hits(case, base)), sample_config)
    assert alerts == [], f"Unexpected alerts: {[alert.rule_name for alert in alerts]}"


@pytest.mark.parametrize("case", POSITIVE_CASES, ids=[case["name"] for case in POSITIVE_CASES])
def test_positive_cases_never_leak_other_rules(case, sample_config):
    """A scenario triggers exactly one rule (Rule 1 defers to Rule 2 on success)."""
    base = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
    alerts = apply_rules(load_events(build_hits(case, base)), sample_config)
    rules = {alert.rule_name for alert in alerts}
    assert rules == {case["expected_rule"]}
    if case["expected_rule"] == RULE_SUCCESSFUL_BRUTE_FORCE:
        assert RULE_BRUTE_FORCE not in rules
    if case["expected_rule"] == RULE_SUSPICIOUS_POST_LOGIN:
        assert RULE_SUCCESSFUL_BRUTE_FORCE not in rules


def test_case_files_cover_all_three_rules():
    expected = {RULE_BRUTE_FORCE, RULE_SUCCESSFUL_BRUTE_FORCE, RULE_SUSPICIOUS_POST_LOGIN}
    assert {case["expected_rule"] for case in POSITIVE_CASES} == expected
    assert all(case["expected_rule"] is None for case in NEGATIVE_CASES)
