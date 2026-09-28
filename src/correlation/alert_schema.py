"""Alert schema for the SIEM correlation engine.

The Alert dataclass itself lives in ``src.normalization.schema`` so the alert
and event schemas stay together. This module re-exports it and provides the
deterministic Elasticsearch document ID used for idempotent alert writes.
"""

import hashlib
from typing import Dict, List

from ..normalization.schema import Alert, Severity, build_dedup_key  # noqa: F401
from ..utils.time_utils import timestamp_to_iso8601


def alert_document_id(alert: Alert) -> str:
    """Deterministic alert document ID: hash(dedup_key + first_seen).

    Re-running the engine over the same evidence therefore updates the same
    document instead of creating duplicates.
    """
    raw = f"{alert.dedup_key}|{timestamp_to_iso8601(alert.first_seen)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def severity_rank(severity: Severity) -> int:
    """Numeric rank for sorting (low=1 ... critical=4)."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        severity.value if isinstance(severity, Severity) else str(severity), 0
    )


__all__ = ["Alert", "Severity", "alert_document_id", "build_dedup_key", "severity_rank"]
