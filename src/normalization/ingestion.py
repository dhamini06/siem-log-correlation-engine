"""Normalization and ingestion pipeline (Phase 2).

Flow per log line: detect source -> parse -> schema validation ->
deterministic document ID -> index into normalized-events-{YYYY-MM-DD}.
"""

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .firewall_syslog import FirewallSyslogParser
from .linux_auth import LinuxAuthParser
from .parsers import LogParser
from .schema import (
    SourceType,
    compute_event_document_id,
    validate_event_payload,
)
from .windows_sysmon import WindowsSysmonParser

logger = logging.getLogger(__name__)

PARSERS: Dict[SourceType, LogParser] = {
    SourceType.LINUX_AUTH: LinuxAuthParser(),
    SourceType.WINDOWS_SYSMON: WindowsSysmonParser(),
    SourceType.FIREWALL_SYSLOG: FirewallSyslogParser(),
}

FILE_SIGNATURES = (
    ("windows", SourceType.WINDOWS_SYSMON),
    ("sysmon", SourceType.WINDOWS_SYSMON),
    ("evtx", SourceType.WINDOWS_SYSMON),
    ("jsonl", SourceType.WINDOWS_SYSMON),
    ("auth", SourceType.LINUX_AUTH),
    ("secure", SourceType.LINUX_AUTH),
    ("firewall", SourceType.FIREWALL_SYSLOG),
    ("fw", SourceType.FIREWALL_SYSLOG),
    ("syslog", SourceType.FIREWALL_SYSLOG),
)


@dataclass
class IngestionResult:
    """Counters and documents produced by one ingestion run."""

    files: List[str] = field(default_factory=list)
    lines_read: int = 0
    parsed: int = 0
    skipped: int = 0
    invalid: int = 0
    indexed: int = 0
    indices: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = [f"lines_read={self.lines_read}", f"parsed={self.parsed}", f"skipped={self.skipped}"]
        if self.invalid:
            parts.append(f"invalid={self.invalid}")
        if self.indexed:
            per_index = ", ".join(f"{name}={count}" for name, count in sorted(self.indices.items()))
            parts.append(f"indexed={self.indexed} ({per_index})")
        else:
            parts.append("indexed=0 (dry run)")
        return " | ".join(parts)

    def merge(self, other: "IngestionResult") -> "IngestionResult":
        self.files.extend(other.files)
        self.lines_read += other.lines_read
        self.parsed += other.parsed
        self.skipped += other.skipped
        self.invalid += other.invalid
        self.indexed += other.indexed
        for name, count in other.indices.items():
            self.indices[name] = self.indices.get(name, 0) + count
        self.errors.extend(other.errors)
        return self


def resolve_source_type(value: str) -> SourceType:
    """Map a CLI/config string to a SourceType enum member."""
    try:
        return SourceType(value)
    except ValueError as exc:
        valid = ", ".join(item.value for item in SourceType)
        raise ValueError(f"Unknown source type '{value}'. Valid values: {valid}") from exc


def detect_source_type(path: str) -> SourceType:
    """Detect the log source from the filename, falling back to content sniffing."""
    name = os.path.basename(path).lower()
    for signature, source in FILE_SIGNATURES:
        if signature in name:
            return source
    if name.endswith((".json", ".jsonl", ".ndjson")):
        return SourceType.WINDOWS_SYSMON

    # Ambiguous extension: inspect the first line before defaulting to auth.log.
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        first_line = handle.readline().strip()
    if first_line.startswith("{"):
        return SourceType.WINDOWS_SYSMON
    if "sshd" in first_line or "sudo:" in first_line or "pam_unix" in first_line:
        return SourceType.LINUX_AUTH
    if "%ASA" in first_line or "UFW" in first_line or "PROTO=" in first_line:
        return SourceType.FIREWALL_SYSLOG
    raise ValueError(f"Unable to detect source type for {path}; pass --source-type explicitly")


def get_parser(source_type: SourceType) -> LogParser:
    """Return the parser instance for a source type."""
    return PARSERS[source_type]


class NormalizationEngine:
    """Parse, validate, and index log files into normalized-events-*."""

    def __init__(self, es_client: Optional[Any] = None, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self._es = es_client
        if es_client is None and not dry_run:
            from ..elasticsearch_client import get_es_client

            self._es = get_es_client()

    @property
    def es(self) -> Any:
        if self._es is None:
            from ..elasticsearch_client import get_es_client

            self._es = get_es_client()
        return self._es

    def ingest_file(self, path: str, source_type: Optional[SourceType] = None) -> IngestionResult:
        """Ingest a single log file."""
        result = IngestionResult(files=[path])
        if not os.path.isfile(path):
            result.errors.append(f"File not found: {path}")
            return result

        if source_type is None:
            try:
                source_type = detect_source_type(path)
            except ValueError as exc:
                result.errors.append(str(exc))
                return result

        parser = get_parser(source_type)
        logger.info("Ingesting %s as %s", path, source_type.value)

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                result.lines_read += 1
                try:
                    event = parser.parse(line)
                except Exception as exc:  # never abort the run on one bad line
                    result.skipped += 1
                    result.errors.append(f"{path}:{line_number} parse error: {exc}")
                    logger.warning("Parse error at %s:%s: %s", path, line_number, exc)
                    continue

                if event is None:
                    result.skipped += 1
                    continue

                payload = event.to_dict()
                validation_errors = validate_event_payload(payload)
                if validation_errors:
                    result.invalid += 1
                    result.errors.append(f"{path}:{line_number} schema invalid: {'; '.join(validation_errors)}")
                    logger.warning("Schema validation failed at %s:%s: %s", path, line_number, validation_errors)
                    continue

                result.parsed += 1
                if self.dry_run:
                    continue

                index_name = event.index_name()
                doc_id = compute_event_document_id(event)
                try:
                    self.es.index_event(index_name, payload, doc_id)
                    result.indexed += 1
                    result.indices[index_name] = result.indices.get(index_name, 0) + 1
                except Exception as exc:
                    result.errors.append(f"{path}:{line_number} index error: {exc}")
                    logger.error("Failed to index event from %s:%s: %s", path, line_number, exc)

        if result.indexed and not self.dry_run:
            self.es.refresh()
        return result

    def ingest_directory(
        self,
        log_dir: str,
        source_type: Optional[SourceType] = None,
        pattern: str = "*.log",
        extra_patterns: tuple = ("*.jsonl", "*.json", "*.evtx.txt", "*.txt"),
    ) -> IngestionResult:
        """Ingest every matching file in a directory."""
        combined = IngestionResult()
        if not os.path.isdir(log_dir):
            combined.errors.append(f"Directory not found: {log_dir}")
            return combined

        patterns = (pattern,) + tuple(extra_patterns)
        paths = [
            os.path.join(log_dir, name)
            for name in sorted(os.listdir(log_dir))
            if os.path.isfile(os.path.join(log_dir, name))
            and any(fnmatch.fnmatch(name.lower(), candidate) for candidate in patterns)
        ]

        for path in paths:
            per_file_source = source_type
            if per_file_source is None:
                try:
                    per_file_source = detect_source_type(path)
                except ValueError as exc:
                    combined.errors.append(str(exc))
                    continue
            combined.merge(self.ingest_file(path, per_file_source))
        return combined


__all__ = [
    "IngestionResult",
    "NormalizationEngine",
    "detect_source_type",
    "get_parser",
    "resolve_source_type",
]
