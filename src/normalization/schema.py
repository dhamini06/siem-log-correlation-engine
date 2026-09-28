"""Common event schema, validation, and alert schema for SIEM Lab.

Implements the authoritative schema from MASTER_PROMPT.md Section I.C with
plain dataclasses so the schema can be validated and serialized without any
third-party dependency.

Normalized events are serialized for Elasticsearch with the key
``@timestamp`` (the field name required by the common event schema).
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import ipaddress

from ..utils.time_utils import ensure_utc, timestamp_to_iso8601

PARSER_VERSION = "1.0"


class SchemaError(ValueError):
    """Raised when an event or alert fails common schema validation."""


class SourceType(str, Enum):
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUTH = "linux_auth"
    FIREWALL_SYSLOG = "firewall_syslog"


class EventType(str, Enum):
    LOGON_SUCCESS = "logon_success"
    LOGON_FAILURE = "logon_failure"
    PROCESS_CREATE = "process_create"
    NETWORK_CONNECTION = "network_connection"
    ACCOUNT_UNLOCK = "account_unlock"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProcessInfo:
    """Nested process metadata container (kept as a plain dict for ES mapping)."""

    ALLOWED_KEYS = (
        "name", "path", "pid", "parent_name", "parent_pid", "command_line",
    )


@dataclass
class NormalizedEvent:
    """Unified common event schema for all log sources."""

    timestamp: datetime
    source_type: SourceType
    event_type: EventType
    host: str
    user: str
    severity: Severity
    raw_event: str
    src_ip: Optional[str] = "unknown"
    dst_ip: Optional[str] = "unknown"
    port: Optional[int] = None
    protocol: Optional[str] = None
    process: Optional[Dict[str, Any]] = None
    parser_version: str = PARSER_VERSION
    ingest_timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.ingest_timestamp is None:
            self.ingest_timestamp = datetime.now(timezone.utc)
        self.validate()

    # -- Validation --

    def validate(self) -> "NormalizedEvent":
        """Validate the event against the common event schema rules."""
        if not isinstance(self.timestamp, datetime):
            raise SchemaError("@timestamp must be a datetime")
        self.timestamp = ensure_utc(self.timestamp)
        self.ingest_timestamp = ensure_utc(self.ingest_timestamp)

        if self.source_type not in SourceType:
            raise SchemaError(f"Invalid source_type: {self.source_type}")
        if self.event_type not in EventType:
            raise SchemaError(f"Invalid event_type: {self.event_type}")
        if self.severity not in Severity:
            raise SchemaError(f"Invalid severity: {self.severity}")

        if not self.host:
            raise SchemaError("host is required")
        if not self.user:
            raise SchemaError("user is required (use 'unknown' when unavailable)")
        if self.raw_event is None or self.raw_event == "":
            raise SchemaError("raw_event is required")

        for field_name in ("src_ip", "dst_ip"):
            validate_ip(getattr(self, field_name), field_name)

        if self.port is not None and not isinstance(self.port, int):
            raise SchemaError("port must be an integer")

        now = datetime.now(timezone.utc)
        if self.timestamp - now > timedelta(minutes=5):
            raise SchemaError("@timestamp cannot be in the future")

        if self.ingest_timestamp < self.timestamp:
            # Small clock skew is tolerated; a large gap means the event time is wrong.
            if (self.timestamp - self.ingest_timestamp).total_seconds() > 300:
                raise SchemaError("@timestamp must be <= ingest_timestamp")

        if self.process is not None:
            if not isinstance(self.process, dict):
                raise SchemaError("process must be an object or null")
            for key in self.process:
                if key not in ProcessInfo.ALLOWED_KEYS:
                    raise SchemaError(f"Unknown process field: {key}")
        return self

    # -- Serialization --

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to an Elasticsearch-friendly dict using the ``@timestamp`` key."""
        return {
            "@timestamp": timestamp_to_iso8601(self.timestamp),
            "source_type": self.source_type.value,
            "event_type": self.event_type.value,
            "host": self.host,
            "user": self.user,
            # src_ip/dst_ip are mapped as Elasticsearch `ip` fields, which reject the
            # "unknown" sentinel, so absent addresses are written as null.
            "src_ip": ip_or_none(self.src_ip),
            "dst_ip": ip_or_none(self.dst_ip),
            "port": self.port,
            "protocol": self.protocol,
            "severity": self.severity.value,
            "process": self.process,
            "message": self.build_message(),
            "raw_event": self.raw_event,
            "parser_version": self.parser_version,
            "ingest_timestamp": timestamp_to_iso8601(self.ingest_timestamp),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NormalizedEvent":
        """Rebuild a NormalizedEvent from its serialized dict (used by correlation)."""
        from ..utils.time_utils import normalize_to_utc

        raw_timestamp = data.get("@timestamp") or data.get("timestamp")
        payload = {
            key: value
            for key, value in data.items()
            if key in cls.__dataclass_fields__ and key not in ("message", "event_id")
        }
        payload["timestamp"] = normalize_to_utc(str(raw_timestamp))
        ingest = payload.pop("ingest_timestamp", None)
        payload["ingest_timestamp"] = normalize_to_utc(ingest) if ingest else None
        payload["source_type"] = SourceType(payload["source_type"])
        payload["event_type"] = EventType(payload["event_type"])
        payload["severity"] = Severity(payload["severity"])
        return cls(**payload)

    def build_message(self) -> str:
        """Build a human-readable one-line summary of the event."""
        ts = timestamp_to_iso8601(self.timestamp)
        base = f"{ts} {self.host} {self.event_type.value} user={self.user} src_ip={self.src_ip}"
        if self.process and self.process.get("name"):
            base += f" process={self.process['name']}"
        if self.dst_ip and self.dst_ip != "unknown":
            base += f" dst_ip={self.dst_ip}"
        return base

    def index_name(self) -> str:
        """Rolling daily index name derived from the event timestamp."""
        return f"normalized-events-{self.timestamp.strftime('%Y-%m-%d')}"


def validate_ip(value: Optional[str], field_name: str = "ip") -> Optional[str]:
    """Validate an IPv4/IPv6 address, allowing None/'unknown'/empty values."""
    if value is None or value == "" or value == "unknown":
        return value
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise SchemaError(f"Invalid {field_name} address: {value}") from exc
    return value


def ip_or_none(value: Optional[str]) -> Optional[str]:
    """Return a real IP string, or None when the field is not applicable.

    Elasticsearch `ip` fields reject the "unknown" sentinel used in memory, so
    documents are written with null for absent addresses.
    """
    if not value or value in ("unknown", "-", "N/A", "n/a"):
        return None
    return value


@dataclass
class Alert:
    """Correlation alert written to the security-alerts-* indices."""

    rule_name: str
    severity: Severity
    timestamp: datetime
    first_seen: datetime
    last_seen: datetime
    reasoning: str
    evidence_event_ids: List[str] = field(default_factory=list)
    src_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    dedup_key: str = ""
    dedup_window_minutes: int = 30

    def __post_init__(self) -> None:
        self.timestamp = ensure_utc(self.timestamp)
        self.first_seen = ensure_utc(self.first_seen)
        self.last_seen = ensure_utc(self.last_seen)
        if self.severity not in Severity:
            raise SchemaError(f"Invalid alert severity: {self.severity}")
        if not self.rule_name:
            raise SchemaError("rule_name is required")
        if not self.dedup_key:
            self.dedup_key = build_dedup_key(self.rule_name, self.src_ip, self.user)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the alert for Elasticsearch indexing."""
        return {
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "timestamp": timestamp_to_iso8601(self.timestamp),
            # Mapped as an Elasticsearch `ip` field: emit null rather than "unknown".
            "src_ip": ip_or_none(self.src_ip),
            "user": self.user or "unknown",
            "host": self.host or "unknown",
            "evidence_event_ids": list(self.evidence_event_ids),
            "evidence_count": len(self.evidence_event_ids),
            "reasoning": self.reasoning,
            "first_seen": timestamp_to_iso8601(self.first_seen),
            "last_seen": timestamp_to_iso8601(self.last_seen),
            "dedup_key": self.dedup_key,
            "dedup_window_minutes": self.dedup_window_minutes,
            "false_positive_feedback": "unreviewed",
        }

    def index_name(self) -> str:
        """Rolling daily index name derived from the alert timestamp."""
        return f"security-alerts-{self.timestamp.strftime('%Y-%m-%d')}"


def build_dedup_key(rule_name: str, src_ip: Optional[str], user: Optional[str]) -> str:
    """Build the dedup key: hash of (rule_name, src_ip, user)."""
    import hashlib

    raw = f"{rule_name}|{src_ip or 'unknown'}|{user or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def compute_event_document_id(event: NormalizedEvent) -> str:
    """Deterministic ES document ID for idempotent re-ingestion.

    Hash of host + timestamp + event_type + src_ip + raw_event.
    """
    import hashlib

    raw = "|".join([
        event.host,
        timestamp_to_iso8601(event.timestamp),
        event.event_type.value,
        event.src_ip or "unknown",
        event.raw_event.strip(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_event_payload(payload: Dict[str, Any]) -> List[str]:
    """Validate a raw serialized event dict; return a list of error strings.

    Empty list means the payload is schema compliant.
    """
    errors: List[str] = []
    for required in ("@timestamp", "source_type", "event_type", "host", "severity", "raw_event"):
        if required not in payload or payload[required] in (None, ""):
            errors.append(f"missing required field: {required}")

    if "@timestamp" in payload:
        try:
            from ..utils.time_utils import normalize_to_utc

            normalize_to_utc(str(payload["@timestamp"]))
        except ValueError as exc:
            errors.append(f"invalid @timestamp: {exc}")

    if "source_type" in payload:
        try:
            SourceType(payload["source_type"])
        except ValueError:
            errors.append(f"invalid source_type: {payload['source_type']}")

    if "event_type" in payload:
        try:
            EventType(payload["event_type"])
        except ValueError:
            errors.append(f"invalid event_type: {payload['event_type']}")

    if "severity" in payload:
        try:
            Severity(payload["severity"])
        except ValueError:
            errors.append(f"invalid severity: {payload['severity']}")

    for ip_field in ("src_ip", "dst_ip"):
        if ip_field in payload:
            try:
                validate_ip(payload[ip_field], ip_field)
            except SchemaError as exc:
                errors.append(str(exc))

    return errors


__all__ = [
    "Alert",
    "EventType",
    "NormalizedEvent",
    "PARSER_VERSION",
    "SchemaError",
    "Severity",
    "SourceType",
    "build_dedup_key",
    "compute_event_document_id",
    "ip_or_none",
    "validate_event_payload",
    "validate_ip",
]
