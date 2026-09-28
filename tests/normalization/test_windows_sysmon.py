"""Tests for the Windows Security / Sysmon JSON parser."""

import json

import pytest

from src.normalization.schema import EventType, Severity, SourceType
from src.normalization.windows_sysmon import (
    WindowsSysmonParser,
    format_windows_user,
    is_suspicious_process,
)


def record(event_id: int, data: dict, computer: str = "APP-01", time_created: str = "2024-01-15T14:32:45.123Z") -> str:
    return json.dumps(
        {
            "EventID": event_id,
            "TimeCreated": time_created,
            "Computer": computer,
            "EventData": data,
        }
    )


LOGON_SUCCESS = record(
    4624,
    {"TargetUserName": "jdoe", "TargetDomainName": "CORP", "IpAddress": "198.51.100.25", "LogonType": 3},
)
LOGON_FAILURE = record(
    4625,
    {"TargetUserName": "jdoe", "TargetDomainName": "CORP", "IpAddress": "203.0.113.9", "Status": "0xC000006D"},
)
PROCESS_CMD = record(
    4688,
    {
        "SubjectUserName": "jdoe",
        "SubjectDomainName": "CORP",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ProcessId": "4321",
        "ParentProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "ParentProcessId": "812",
    },
)
PROCESS_SVCHOST = record(
    4688,
    {
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "NewProcessName": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k netsvcs",
        "ProcessId": "900",
        "ParentProcessName": "C:\\Windows\\System32\\services.exe",
    },
)
PRIVILEGE = record(4672, {"SubjectUserName": "Administrator", "SubjectDomainName": "CORP"})


@pytest.fixture
def parser() -> WindowsSysmonParser:
    return WindowsSysmonParser()


def test_logon_success(parser):
    event = parser.parse(LOGON_SUCCESS)
    assert event is not None
    assert event.event_type is EventType.LOGON_SUCCESS
    assert event.severity is Severity.LOW
    assert event.user == "CORP\\jdoe"
    assert event.host == "app-01"
    assert event.src_ip == "198.51.100.25"
    assert event.source_type is SourceType.WINDOWS_SYSMON
    assert event.timestamp.year == 2024


def test_logon_failure_is_medium_severity(parser):
    event = parser.parse(LOGON_FAILURE)
    assert event is not None
    assert event.event_type is EventType.LOGON_FAILURE
    assert event.severity is Severity.MEDIUM
    assert event.user == "CORP\\jdoe"
    assert event.src_ip == "203.0.113.9"


def test_process_creation_by_user_is_high_severity(parser):
    event = parser.parse(PROCESS_CMD)
    assert event is not None
    assert event.event_type is EventType.PROCESS_CREATE
    assert event.severity is Severity.HIGH
    assert event.process["name"] == "cmd.exe"
    assert event.process["parent_name"] == "winlogon.exe"
    assert event.process["pid"] == 4321
    assert event.process["parent_pid"] == 812
    assert "whoami" in event.process["command_line"]


def test_service_process_creation_is_medium_severity(parser):
    event = parser.parse(PROCESS_SVCHOST)
    assert event is not None
    assert event.event_type is EventType.PROCESS_CREATE
    assert event.severity is Severity.MEDIUM
    assert event.process["name"] == "svchost.exe"


def test_privilege_escalation_event(parser):
    event = parser.parse(PRIVILEGE)
    assert event is not None
    assert event.event_type is EventType.PRIVILEGE_ESCALATION
    assert event.user == "CORP\\Administrator"


def test_logstash_style_event_data_list(parser):
    payload = json.dumps(
        {
            "EventID": 4625,
            "TimeCreated": "2024-01-15T14:32:45Z",
            "Computer": "APP-02",
            "EventData": [
                {"Key": "TargetUserName", "Value": "svc"},
                {"Key": "TargetDomainName", "Value": "CORP"},
                {"Key": "IpAddress", "Value": "10.0.0.9"},
            ],
        }
    )
    event = parser.parse(payload)
    assert event is not None
    assert event.user == "CORP\\svc"
    assert event.src_ip == "10.0.0.9"


def test_malformed_and_unsupported_input_returns_none(parser):
    assert parser.parse("not json") is None
    assert parser.parse(json.dumps({"EventID": 9999, "EventData": {}})) is None
    assert parser.parse(json.dumps({"no_event_id": True})) is None
    assert parser.parse("") is None


def test_user_formatting_helper():
    assert format_windows_user("CORP", "alice") == "CORP\\alice"
    assert format_windows_user("-", "alice") == "alice"
    assert format_windows_user(None, "alice") == "alice"
    assert format_windows_user("CORP", "") == "unknown"
    assert format_windows_user("CORP", "ANONYMOUS LOGON") == "ANONYMOUS LOGON"


@pytest.mark.parametrize(
    "name,command,expected",
    [
        ("cmd.exe", "cmd.exe /c whoami", True),
        ("powershell.exe", "powershell.exe -File x.ps1", True),
        ("bash", "/bin/bash -i", True),
        ("explorer.exe", "explorer.exe", False),
        ("svchost.exe", "svchost.exe -k netsvcs", False),
        ("python.exe", "python.exe script.py", False),
    ],
)
def test_suspicious_process_detection(name, command, expected):
    assert is_suspicious_process(name, command) is expected
