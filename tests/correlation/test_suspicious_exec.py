"""Rule 3 tests: suspicious post-login execution (positive and negative cases)."""

from datetime import datetime, timedelta

from conftest import make_event

from src.correlation.rules import RULE_SUSPICIOUS_POST_LOGIN, load_events, rule_suspicious_process_post_login
from src.normalization.schema import Severity

BASE = datetime.fromisoformat("2024-01-15T14:00:00+00:00")


def iso(offset_minutes: float) -> str:
    return (BASE + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def login(event_id="login-1", offset=0.0, user="CORP\\jdoe", host="app-01", src_ip="198.51.100.25"):
    return make_event(
        event_id, iso(offset), event_type="logon_success", user=user, host=host, src_ip=src_ip, severity="low"
    )


def process(event_id, offset, name="cmd.exe", command="cmd.exe /c whoami", host="app-01", user="CORP\\jdoe"):
    return make_event(
        event_id,
        iso(offset),
        event_type="process_create",
        user=user,
        host=host,
        src_ip="unknown",
        severity="high",
        process={"name": name, "path": f"C:\\Windows\\System32\\{name}", "command_line": command},
    )


def test_login_then_cmd_triggers_high_alert(sample_config):
    events = load_events([login(), process("proc-1", 0.3)])
    alerts = rule_suspicious_process_post_login(events, sample_config)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == RULE_SUSPICIOUS_POST_LOGIN
    assert alert.severity is Severity.HIGH
    assert alert.host == "app-01"
    assert alert.user == "jdoe"
    assert alert.src_ip == "198.51.100.25"
    assert alert.evidence_event_ids == ["login-1", "proc-1"]
    assert "suspicious process" in alert.reasoning


def test_login_then_bash_interactive_shell_triggers(sample_config):
    events = load_events(
        [
            login(host="web-01", src_ip="198.51.100.77"),
            process("proc-1", 1.0, name="bash", command="/bin/bash -i", host="web-01"),
        ]
    )
    alerts = rule_suspicious_process_post_login(events, sample_config)
    assert len(alerts) == 1
    assert "bash -i" in alerts[0].reasoning


def test_process_after_two_minutes_does_not_trigger(sample_config):
    events = load_events([login(), process("proc-1", 2.5)])
    assert rule_suspicious_process_post_login(events, sample_config) == []


def test_process_before_login_does_not_trigger(sample_config):
    events = load_events([process("proc-1", -0.2), login()])
    assert rule_suspicious_process_post_login(events, sample_config) == []


def test_process_on_different_host_does_not_trigger(sample_config):
    events = load_events([login(host="app-01"), process("proc-1", 0.4, host="app-02")])
    assert rule_suspicious_process_post_login(events, sample_config) == []


def test_expected_process_is_excluded(sample_config):
    events = load_events(
        [login(), process("proc-1", 0.3, name="svchost.exe", command="svchost.exe -k netsvcs")]
    )
    assert rule_suspicious_process_post_login(events, sample_config) == []


def test_benign_process_not_in_suspicious_list_does_not_trigger(sample_config):
    events = load_events([login(), process("proc-1", 0.3, name="notepad.exe", command="notepad.exe notes.txt")])
    assert rule_suspicious_process_post_login(events, sample_config) == []


def test_no_login_means_no_alert(sample_config):
    assert rule_suspicious_process_post_login(load_events([process("proc-1", 0.1)]), sample_config) == []


def test_one_alert_per_login_even_with_multiple_processes(sample_config):
    events = load_events(
        [
            login(),
            process("proc-1", 0.2, name="cmd.exe", command="cmd.exe /c whoami"),
            process("proc-2", 0.5, name="powershell.exe", command="powershell.exe -enc SQBFAFgA"),
        ]
    )
    alerts = rule_suspicious_process_post_login(events, sample_config)
    assert len(alerts) == 1
    assert alerts[0].evidence_event_ids == ["login-1", "proc-1"]


def test_process_allowlist_is_tunable(sample_config):
    config = {
        **sample_config,
        "rules": {
            **sample_config["rules"],
            "suspicious_exec": {
                **sample_config["rules"]["suspicious_exec"],
                "suspicious_processes": ["notepad.exe"],
            },
        },
    }
    events = load_events([login(), process("proc-1", 0.3, name="notepad.exe", command="notepad.exe notes.txt")])
    alerts = rule_suspicious_process_post_login(events, config)
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.HIGH


def test_rule_disabled(sample_config):
    config = {
        **sample_config,
        "rules": {
            **sample_config["rules"],
            "suspicious_exec": {**sample_config["rules"]["suspicious_exec"], "enabled": False},
        },
    }
    assert rule_suspicious_process_post_login(load_events([login(), process("proc-1", 0.3)]), config) == []
