"""Firewall syslog parser for SIEM Lab.

Supported line formats (Cisco ASA / iptables-kernel / Palo Alto style):
  Sep 25 17:20:05 fw-01 %ASA-4-106023: Deny tcp src outside:10.0.0.5/51234 dst inside:10.0.0.10/22 by access-group "OUTSIDE_IN"
  Sep 25 17:20:05 fw-01 %ASA-6-302013: Built inbound TCP connection 1234 ... outside:10.0.0.5/51234 to inside:10.0.0.10/443
  Sep 25 17:20:05 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP SPT=51234 DPT=22
  Sep 25 17:20:05 fw-01 firewall: deny tcp 10.0.0.5/51234 -> 10.0.0.10/22
"""

import logging
import re
from typing import Optional

from .parsers import LogParser, clean_ip, parse_syslog_header
from .schema import EventType, NormalizedEvent, Severity, SourceType

logger = logging.getLogger(__name__)

ASA_RE = re.compile(
    r"%ASA-\d-\d+:\s*(?P<action>Built inbound|Built outbound|Deny)\s+"
    r"(?P<proto>\w+).*?src\s+(?P<src_zone>[\w-]+):(?P<src_ip>[0-9.]+)(?:/(?P<spt>\d+))?\s+"
    r"dst\s+(?P<dst_zone>[\w-]+):(?P<dst_ip>[0-9.]+)(?:/(?P<dpt>\d+))?",
    re.IGNORECASE,
)

UFW_RE = re.compile(
    r"(?P<action>\[UFW\s+(?P<ufw_action>\w+)\]).*?"
    r"SRC=(?P<src_ip>[0-9.]+)\s+DST=(?P<dst_ip>[0-9.]+)\s+"
    r"PROTO=(?P<proto>\w+)(?:\s+SPT=(?P<spt>\d+))?(?:\s+DPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)

PALO_RE = re.compile(
    r"(?P<action>deny|allow|drop|accept)\s+(?P<proto>\w+)\s+"
    r"(?P<src_ip>[0-9.]+)(?:/(?P<spt>\d+))?\s*(?:->|to)\s*"
    r"(?P<dst_ip>[0-9.]+)(?:/(?P<dpt>\d+))?",
    re.IGNORECASE,
)

BLOCKED_ACTIONS = {"deny", "block", "drop", "blocked"}


class FirewallSyslogParser(LogParser):
    """Parse firewall syslog lines into network_connection events."""

    source_type = SourceType.FIREWALL_SYSLOG

    def parse(self, raw_log_line: str) -> Optional[NormalizedEvent]:
        line = raw_log_line.strip()
        if not line:
            return None

        timestamp, host, message = parse_syslog_header(line)
        if not message:
            return None

        for regex in (ASA_RE, UFW_RE, PALO_RE):
            match = regex.search(message)
            if not match:
                continue
            groups = match.groupdict()
            action = (groups.get("action") or "").lower()
            blocked = any(word in action for word in BLOCKED_ACTIONS)
            event = self._build(
                event_type=EventType.NETWORK_CONNECTION,
                host=host,
                user="unknown",
                severity=Severity.HIGH if blocked else Severity.LOW,
                raw_event=line,
                timestamp=timestamp,
                src_ip=clean_ip(groups.get("src_ip")),
                dst_ip=clean_ip(groups.get("dst_ip")),
                port=int(groups["dpt"]) if groups.get("dpt") else (
                    int(groups["spt"]) if groups.get("spt") else None
                ),
                protocol=(groups.get("proto") or "tcp").lower(),
            )
            self.parsed_count += 1
            return event

        self.skipped_count += 1
        logger.debug("Unparsed firewall line: %s", line[:100])
        return None


__all__ = ["FirewallSyslogParser"]
