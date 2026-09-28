"""Base log parser class and shared parsing utilities for SIEM Lab.

All parsers subclass LogParser and return NormalizedEvent objects.
Unparseable lines are logged and yield None so ingestion never aborts.
"""

import abc
import logging
import re
from datetime import datetime
from typing import List, Optional

from .schema import EventType, NormalizedEvent, Severity, SourceType
from ..utils.time_utils import normalize_to_utc, utc_now

logger = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def clean_ip(value: Optional[str]) -> str:
    """Return a validated IPv4 string or 'unknown' when absent/invalid."""
    if not value:
        return "unknown"
    candidate = value.strip().strip("[]")
    if candidate.endswith("/32"):
        candidate = candidate[:-3]
    match = IPV4_RE.search(candidate)
    if not match:
        return "unknown"
    octets = match.group(1).split(".")
    if all(0 <= int(o) <= 255 for o in octets):
        return match.group(1)
    return "unknown"


def parse_syslog_header(line: str) -> tuple:
    """Split a classic syslog line into (timestamp, host, message).

    Format: "Sep 25 17:20:01 hostname program[pid]: message"
    Returns (datetime|None, host, message) and tolerates missing hostname.
    """
    pattern = re.compile(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<msg>.*)$"
    )
    match = pattern.match(line)
    if not match:
        return None, "unknown", line

    timestamp: Optional[datetime]
    try:
        timestamp = normalize_to_utc(match.group("ts"))
    except ValueError:
        timestamp = None

    host = match.group("host")
    if host.endswith(":") or ":" in host and "[" in host:
        host = host.split(":")[0]
    return timestamp, host or "unknown", match.group("msg")


class LogParser(abc.ABC):
    """Abstract base class for SIEM log parsers."""

    source_type: SourceType

    def __init__(self) -> None:
        self.parsed_count = 0
        self.skipped_count = 0

    @abc.abstractmethod
    def parse(self, raw_log_line: str) -> Optional[NormalizedEvent]:
        """Convert one raw log line into a NormalizedEvent, or None if unparseable."""

    def parse_file(self, path: str) -> List[NormalizedEvent]:
        """Parse a whole log file, skipping blank and unparseable lines.

        Counters are maintained by parse(); this method only aggregates events.
        """
        events: List[NormalizedEvent] = []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                event = self.parse(line)
                if event is not None:
                    events.append(event)
        return events

    def _build(
        self,
        event_type: EventType,
        host: str,
        user: str,
        severity: Severity,
        raw_event: str,
        timestamp: Optional[datetime] = None,
        **kwargs,
    ) -> NormalizedEvent:
        """Construct a validated NormalizedEvent with ingestion metadata."""
        return NormalizedEvent(
            timestamp=timestamp or utc_now(),
            source_type=self.source_type,
            event_type=event_type,
            host=host or "unknown",
            user=user or "unknown",
            severity=severity,
            raw_event=raw_event,
            ingest_timestamp=utc_now(),
            **kwargs,
        )


__all__ = ["LogParser", "clean_ip", "parse_syslog_header"]
