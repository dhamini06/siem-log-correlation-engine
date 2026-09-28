"""Log normalization package: schema, parsers, sample generator, ingestion."""

from .schema import (  # noqa: F401
    Alert,
    EventType,
    NormalizedEvent,
    SchemaError,
    Severity,
    SourceType,
    compute_event_document_id,
    validate_event_payload,
)
from .parsers import LogParser  # noqa: F401
from .linux_auth import LinuxAuthParser  # noqa: F401
from .windows_sysmon import WindowsSysmonParser  # noqa: F401
from .firewall_syslog import FirewallSyslogParser  # noqa: F401
from .ingestion import IngestionResult, NormalizationEngine, detect_source_type  # noqa: F401
