"""Tests for the firewall syslog parser."""

import pytest

from src.normalization.firewall_syslog import FirewallSyslogParser
from src.normalization.schema import EventType, Severity, SourceType

ASA_DENY = (
    "Sep 25 17:30:05 fw-01 %ASA-4-106023: Deny tcp src outside:203.0.113.45/51234 "
    "dst inside:10.0.0.10/22 by access-group \"OUTSIDE_IN\""
)
ASA_ALLOW = (
    "Sep 25 17:30:06 fw-01 %ASA-6-302013: Built inbound TCP connection 1234 "
    "src outside:10.0.0.21/51000 dst inside:10.0.0.10/443"
)
UFW_BLOCK = (
    "Sep 25 17:30:07 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.99 DST=10.0.0.10 "
    "PROTO=TCP SPT=40000 DPT=3389"
)
UFW_ALLOW = (
    "Sep 25 17:30:08 fw-01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.21 DST=93.184.216.34 "
    "PROTO=UDP SPT=53000 DPT=53"
)
PALO_DENY = "Sep 25 17:30:09 fw-01 firewall: deny tcp 198.51.100.7/44444 -> 10.0.0.10/22"


@pytest.fixture
def parser() -> FirewallSyslogParser:
    return FirewallSyslogParser()


def test_asa_deny_is_high_severity(parser):
    event = parser.parse(ASA_DENY)
    assert event is not None
    assert event.event_type is EventType.NETWORK_CONNECTION
    assert event.severity is Severity.HIGH
    assert event.src_ip == "203.0.113.45"
    assert event.dst_ip == "10.0.0.10"
    assert event.port == 22
    assert event.protocol == "tcp"
    assert event.host == "fw-01"
    assert event.source_type is SourceType.FIREWALL_SYSLOG


def test_asa_allow_is_low_severity(parser):
    event = parser.parse(ASA_ALLOW)
    assert event is not None
    assert event.severity is Severity.LOW
    assert event.dst_ip == "10.0.0.10"
    assert event.port == 443


def test_ufw_block_line(parser):
    event = parser.parse(UFW_BLOCK)
    assert event is not None
    assert event.severity is Severity.HIGH
    assert event.src_ip == "10.0.0.99"
    assert event.dst_ip == "10.0.0.10"
    assert event.port == 3389
    assert event.protocol == "tcp"


def test_ufw_allow_line(parser):
    event = parser.parse(UFW_ALLOW)
    assert event is not None
    assert event.severity is Severity.LOW
    assert event.dst_ip == "93.184.216.34"
    assert event.port == 53
    assert event.protocol == "udp"


def test_palo_alto_deny_line(parser):
    event = parser.parse(PALO_DENY)
    assert event is not None
    assert event.severity is Severity.HIGH
    assert event.src_ip == "198.51.100.7"
    assert event.dst_ip == "10.0.0.10"
    assert event.port == 22


def test_unparseable_line_returns_none(parser):
    assert parser.parse("Sep 25 17:30:10 fw-01 sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2") is None
    assert parser.parse("") is None


def test_parse_file(parser, tmp_path):
    log_file = tmp_path / "firewall.log"
    log_file.write_text("\n".join([ASA_DENY, "noise", UFW_BLOCK]) + "\n", encoding="utf-8")
    events = parser.parse_file(str(log_file))
    assert len(events) == 2
    assert parser.skipped_count == 1
