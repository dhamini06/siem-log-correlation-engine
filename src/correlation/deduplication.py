"""Alert deduplication for the SIEM correlation engine (Phase 3).

Policy (Lab #07): do not re-alert on the same (rule_name, src_ip, user) within
30 minutes unless the evidence grew by at least ``min_new_evidence`` (default 2)
new event IDs. The cache is persisted to ``./data/dedup-cache.json`` so
suppression survives engine restarts.
"""

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from ..normalization.schema import Alert
from ..utils.time_utils import ensure_utc, timestamp_to_iso8601, normalize_to_utc

logger = logging.getLogger(__name__)

DEFAULT_CACHE_PATH = os.path.join("data", "dedup-cache.json")
DEFAULT_WINDOW_MINUTES = 30
DEFAULT_MIN_NEW_EVIDENCE = 2


@dataclass
class DedupEntry:
    """State tracked per dedup key."""

    last_alert_time: datetime
    evidence_ids: Set[str] = field(default_factory=set)
    alert_count: int = 1

    def to_json(self) -> Dict[str, object]:
        return {
            "last_alert_time": timestamp_to_iso8601(self.last_alert_time),
            "evidence_ids": sorted(self.evidence_ids),
            "alert_count": self.alert_count,
        }

    @classmethod
    def from_json(cls, data: Dict[str, object]) -> "DedupEntry":
        return cls(
            last_alert_time=ensure_utc(normalize_to_utc(str(data["last_alert_time"]))),
            evidence_ids=set(data.get("evidence_ids", []) or []),
            alert_count=int(data.get("alert_count", 1) or 1),
        )


class AlertDeduplicator:
    """Suppress repeated alerts unless new evidence appears."""

    def __init__(
        self,
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
        min_new_evidence: int = DEFAULT_MIN_NEW_EVIDENCE,
        cache_path: Optional[str] = None,
    ) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.min_new_evidence = min_new_evidence
        self.cache_path = cache_path if cache_path is not None else DEFAULT_CACHE_PATH
        self._entries: Dict[str, DedupEntry] = {}
        self._lock = threading.Lock()
        self.load()

    # -- Decision API --

    def filter_alerts(self, alerts: List[Alert]) -> Tuple[List[Alert], List[Alert]]:
        """Split alerts into (new alerts to emit, suppressed duplicates).

        Emitted alerts update the cache; suppressed ones are logged at INFO.
        """
        emit: List[Alert] = []
        suppress: List[Alert] = []
        with self._lock:
            for alert in alerts:
                evidence = set(alert.evidence_event_ids)
                entry = self._entries.get(alert.dedup_key)

                if entry is None:
                    self._entries[alert.dedup_key] = DedupEntry(
                        last_alert_time=alert.timestamp,
                        evidence_ids=evidence,
                    )
                    emit.append(alert)
                    continue

                within_window = alert.timestamp - entry.last_alert_time < self.window
                if not within_window:
                    self._entries[alert.dedup_key] = DedupEntry(
                        last_alert_time=alert.timestamp,
                        evidence_ids=evidence,
                        alert_count=entry.alert_count + 1,
                    )
                    emit.append(alert)
                    continue

                new_evidence = evidence - entry.evidence_ids
                if len(new_evidence) >= self.min_new_evidence:
                    entry.evidence_ids |= evidence
                    entry.last_alert_time = alert.timestamp
                    entry.alert_count += 1
                    emit.append(alert)
                    logger.info(
                        "Re-alerting %s for %s: %s new evidence event(s)",
                        alert.rule_name, alert.src_ip, len(new_evidence),
                    )
                else:
                    suppress.append(alert)
                    logger.info(
                        "Suppressed duplicate %s for %s (%s new evidence < %s required)",
                        alert.rule_name, alert.src_ip, len(new_evidence), self.min_new_evidence,
                    )
        return emit, suppress

    def seed_from_alerts(self, alerts: List[Alert]) -> None:
        """Prime the cache from alerts already stored in Elasticsearch."""
        with self._lock:
            for alert in alerts:
                existing = self._entries.get(alert.dedup_key)
                evidence = set(alert.evidence_event_ids)
                if existing is None or alert.timestamp > existing.last_alert_time:
                    self._entries[alert.dedup_key] = DedupEntry(
                        last_alert_time=alert.timestamp,
                        evidence_ids=evidence,
                        alert_count=existing.alert_count if existing else 1,
                    )

    # -- Persistence --

    def load(self) -> None:
        """Load persisted dedup state; missing or corrupt files are ignored."""
        if not self.cache_path or not os.path.isfile(self.cache_path):
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            entries = data.get("entries", data) if isinstance(data, dict) else {}
            for key, value in entries.items():
                self._entries[key] = DedupEntry.from_json(value)
            logger.info("Loaded %s dedup entries from %s", len(self._entries), self.cache_path)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.warning("Ignoring unreadable dedup cache %s: %s", self.cache_path, exc)

    def save(self) -> None:
        """Persist dedup state to disk (best effort)."""
        if not self.cache_path:
            return
        try:
            directory = os.path.dirname(self.cache_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            payload = {
                "saved_at": timestamp_to_iso8601(datetime.now(timezone.utc)),
                "entries": {key: entry.to_json() for key, entry in self._entries.items()},
            }
            with open(self.cache_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except OSError as exc:
            logger.warning("Could not persist dedup cache: %s", exc)

    # -- Introspection --

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, dedup_key: str) -> Optional[DedupEntry]:
        return self._entries.get(dedup_key)


__all__ = [
    "AlertDeduplicator",
    "DEFAULT_CACHE_PATH",
    "DEFAULT_MIN_NEW_EVIDENCE",
    "DEFAULT_WINDOW_MINUTES",
    "DedupEntry",
]
