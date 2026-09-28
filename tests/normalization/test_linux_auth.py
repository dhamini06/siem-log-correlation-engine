"""Tests for the Linux auth.log parser."""

import pytest

from src.normalization.linux_auth import LinuxAuthParser, normalize_linux_user
from src.normalization.schema import EventType, Severity, SourceType

FAILED = "Sep 25 17:20:01 web-01 sshd[12345]: Failed password for alice from 10.0.0.5 port 51234 ssh2"
INVALID_USER = "Sep 25 17:20:02 web-01 sshd[12345]: Invalid user admin from 203.0.113.45 port 51235"
ACCEPTED = "Sep 25 17:21:01 web-01 sshd[12345]: Accepted password for alice from 10.0.0.5 port 51240 ssh2"
SUDO_BASH = (
    "Sep 25 17:22:00 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -i"
)
SUDO_SERVICE = (
    "Sep 25 17:23:00 web-01 sudo: carol : TTY=pts/1 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
)
PAM_FAILURE = (
    "Sep 25 17:24:00 web-01 su[999]: pam_unix(su:auth): authentication failure; "
    "logname= uid=0 euid=0 tty=pts/2 ruser=alice user=root rhost=10.0.0.5"
)


@pytest.fixture
def parser() -> LinuxAuthParser:
    return LinuxAuthParser()


def test_failed_password_maps_to_logon_failure(parser):
    event = parser.parse(FAILED)
    assert event is not None
    assert event.event_type is EventType.LOGON_FAILURE
    assert event.severity is Severity.MEDIUM
    assert event.user == "alice"
    assert event.host == "web-01"
    assert event.src_ip == "10.0.0.5"
    assert event.source_type is SourceType.LINUX_AUTH
    assert event.timestamp.strftime("%H:%M:%S") == "17:20:01"
    assert event.raw_event == FAILED


def test_invalid_user_line_is_a_failure(parser):
    event = parser.parse(INVALID_USER)
    assert event is not None
    assert event.event_type is EventType.LOGON_FAILURE
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.45"


def test_accepted_password_maps_to_logon_success(parser):
    event = parser.parse(ACCEPTED)
    assert event is not None
    assert event.event_type is EventType.LOGON_SUCCESS
    assert event.severity is Severity.LOW
    assert event.protocol == "ssh"
    assert event.port == 51240
    assert event.src_ip == "10.0.0.5"


def test_sudo_to_root_bash_is_high_severity_privilege_escalation(parser):
    event = parser.parse(SUDO_BASH)
    assert event is not None
    assert event.event_type is EventType.PRIVILEGE_ESCALATION
    assert event.severity is Severity.HIGH
    assert event.user == "deploy"
    assert event.process["command_line"] == "/bin/bash -i"
    assert event.process["name"] == "/bin/bash"


def test_sudo_service_command_is_medium_severity(parser):
    event = parser.parse(SUDO_SERVICE)
    assert event is not None
    assert event.event_type is EventType.PRIVILEGE_ESCALATION
    assert event.severity is Severity.MEDIUM
    assert "systemctl" in event.process["command_line"]


def test_pam_failure_maps_to_logon_failure(parser):
    event = parser.parse(PAM_FAILURE)
    assert event is not None
    assert event.event_type is EventType.LOGON_FAILURE
    assert event.user == "root"
    assert event.src_ip == "10.0.0.5"


def test_unrelated_line_returns_none(parser):
    assert parser.parse("Sep 25 17:25:00 web-01 cron: session opened for user root") is None
    assert parser.parse("") is None
    assert parser.parse("random noise without structure") is None


def test_user_normalization():
    assert normalize_linux_user("alice@CORP") == "alice"
    assert normalize_linux_user("root") == "root"
    assert normalize_linux_user(None) == "unknown"
    assert normalize_linux_user("") == "unknown"


def test_parse_file_counts_and_skips(tmp_path, parser):
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join([FAILED, "", "unstructured noise", ACCEPTED, PAM_FAILURE]) + "\n", encoding="utf-8")
    events = parser.parse_file(str(log_file))
    assert len(events) == 3
    assert parser.skipped_count == 1
