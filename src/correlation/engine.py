"""Correlation engine orchestrator (Phase 3).

One cycle:
  1. Query normalized-events-* for the lookback window.
  2. Apply the three mandatory rules in sequence.
  3. Deduplicate against recent alerts (30-minute window, 2 new evidence events).
  4. Write new alerts to security-alerts-{YYYY-MM-DD} with evidence IDs.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..config import get_config
from ..normalization.schema import Alert
from ..utils.time_utils import (
    normalize_to_utc,
    query_time_range,
    timestamp_to_iso8601,
    utc_now,
)
from .alert_schema import alert_document_id
from .deduplication import AlertDeduplicator
from .rules import apply_rules, load_events

logger = logging.getLogger(__name__)

NORMALIZED_INDEX = "normalized-events-*"
ALERT_INDEX = "security-alerts-*"
MAX_EVENTS_PER_CYCLE = 10000


@dataclass
class CycleResult:
    """Outcome of a single correlation cycle."""

    started_at: datetime
    events_scanned: int = 0
    alerts_created: int = 0
    alerts_suppressed: int = 0
    alerts_by_rule: Dict[str, int] = field(default_factory=dict)
    indices_written: Dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        rules = ", ".join(f"{name}={count}" for name, count in sorted(self.alerts_by_rule.items()))
        return (
            f"Correlation cycle complete: events={self.events_scanned} "
            f"alerts_created={self.alerts_created} suppressed={self.alerts_suppressed} "
            f"[{rules}] in {self.duration_seconds:.2f}s"
        )


class CorrelationEngine:
    """Runs correlation rules over normalized events and writes deduplicated alerts."""

    def __init__(
        self,
        es_client: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
        dedup: Optional[AlertDeduplicator] = None,
    ) -> None:
        self.config = config or get_config()
        if es_client is None:
            from ..elasticsearch_client import get_es_client

            es_client = get_es_client()
        self.es = es_client

        correlation_cfg = self.config.get("correlation", {}) or {}
        self.lookback_minutes = int(correlation_cfg.get("lookback_window_minutes", 120))
        self.frequency_seconds = int(correlation_cfg.get("engine_frequency_seconds", 60))
        self.dedup_window_minutes = int(correlation_cfg.get("alert_dedup_window_minutes", 30))
        self.min_new_evidence = int(correlation_cfg.get("min_new_evidence_for_realert", 2))

        self.dedup = dedup or AlertDeduplicator(
            window_minutes=self.dedup_window_minutes,
            min_new_evidence=self.min_new_evidence,
            cache_path=correlation_cfg.get("dedup_cache_path", "data/dedup-cache.json"),
        )
        self._seeded = False

        self.last_run_time: Optional[datetime] = None
        self.last_alert_count = 0
        self.total_alerts = 0
        self.error_count = 0
        self.last_result: Optional[CycleResult] = None

    # -- Data access --

    def fetch_events(
        self,
        since: datetime,
        until: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch normalized events in [since, until) with their document IDs."""
        query = {"bool": {"filter": [query_time_range("@timestamp", since, until or utc_now())]}}
        return self.es.search_hits(
            index=NORMALIZED_INDEX,
            query=query,
            size=MAX_EVENTS_PER_CYCLE,
        )

    def fetch_recent_alerts(self, within_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch alerts from the dedup window so restarts do not re-alert."""
        minutes = within_minutes if within_minutes is not None else self.dedup_window_minutes
        since = utc_now() - timedelta(minutes=minutes)
        query = {"bool": {"filter": [query_time_range("timestamp", since, utc_now())]}}
        try:
            # Alert documents are sorted on `timestamp` (they have no @timestamp field).
            return self.es.search_hits(
                index=ALERT_INDEX,
                query=query,
                size=1000,
                sort=[{"timestamp": {"order": "asc"}}],
            )
        except Exception as exc:
            logger.warning("Could not load recent alerts for dedup seeding: %s", exc)
            return []

    @staticmethod
    def _alert_from_hit(hit: Dict[str, Any]) -> Optional[Alert]:
        source = hit.get("_source", {})
        try:
            return Alert(
                rule_name=source["rule_name"],
                severity=source["severity"],
                timestamp=normalize_to_utc(str(source["timestamp"])),
                first_seen=normalize_to_utc(str(source["first_seen"])),
                last_seen=normalize_to_utc(str(source["last_seen"])),
                reasoning=source.get("reasoning", ""),
                evidence_event_ids=list(source.get("evidence_event_ids", [])),
                src_ip=source.get("src_ip"),
                user=source.get("user"),
                host=source.get("host"),
                dedup_key=source.get("dedup_key", ""),
                dedup_window_minutes=int(source.get("dedup_window_minutes", 30)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning("Skipping malformed stored alert %s: %s", hit.get("_id"), exc)
            return None

    # -- Main cycle --

    def run_correlation_cycle(self) -> CycleResult:
        """Execute one full correlation cycle and persist new alerts."""
        started = utc_now()
        result = CycleResult(started_at=started)
        cycle_start = time.perf_counter()

        try:
            if not self._seeded:
                stored = [self._alert_from_hit(hit) for hit in self.fetch_recent_alerts()]
                self.dedup.seed_from_alerts([alert for alert in stored if alert])
                self._seeded = True

            since = started - timedelta(minutes=self.lookback_minutes)
            hits = self.fetch_events(since, started)
            result.events_scanned = len(hits)
            if not hits:
                logger.info("No normalized events in the last %s minutes", self.lookback_minutes)
                self._finish(result, cycle_start)
                return result

            events = load_events(hits)
            alerts = apply_rules(events, self.config)
            to_emit, suppressed = self.dedup.filter_alerts(alerts)
            result.alerts_suppressed = len(suppressed)

            for alert in to_emit:
                index_name = alert.index_name()
                try:
                    self.es.index_alert(index_name, alert.to_dict(), alert_document_id(alert))
                    result.alerts_created += 1
                    result.indices_written[index_name] = result.indices_written.get(index_name, 0) + 1
                except Exception as exc:
                    message = f"Failed to index alert {alert.rule_name}/{alert.dedup_key}: {exc}"
                    result.errors.append(message)
                    logger.error(message)

            for alert in to_emit:
                result.alerts_by_rule[alert.rule_name] = result.alerts_by_rule.get(alert.rule_name, 0) + 1

            if result.alerts_created:
                self.es.refresh(index="security-alerts-*")
        except Exception as exc:
            message = f"Correlation cycle error: {exc}"
            result.errors.append(message)
            self.error_count += 1
            logger.exception(message)

        self.dedup.save()
        self._finish(result, cycle_start)
        return result

    def _finish(self, result: CycleResult, cycle_start: float) -> None:
        result.duration_seconds = round(time.perf_counter() - cycle_start, 3)
        self.last_run_time = result.started_at
        self.last_alert_count = result.alerts_created
        self.total_alerts += result.alerts_created
        self.error_count += len(result.errors)
        self.last_result = result
        logger.info(result.summary())

    # -- Scheduling --

    def start_scheduler(self) -> Any:
        """Start the APScheduler background job (every engine_frequency_seconds)."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            logger.error(
                "APScheduler is not installed; run 'pip install apscheduler' or use --run-once"
            )
            return None

        def job() -> None:
            try:
                self.run_correlation_cycle()
            except Exception:  # never let a job kill the scheduler
                logger.exception("Unhandled error in correlation job")

        scheduler = BackgroundScheduler()
        scheduler.add_job(
            job,
            "interval",
            seconds=self.frequency_seconds,
            id="siem-correlation",
            max_instances=1,
            coalesce=True,
        )
        scheduler.start()
        logger.info(
            "Correlation scheduler started: every %ss (lookback %s minutes)",
            self.frequency_seconds, self.lookback_minutes,
        )
        return scheduler

    def status(self) -> Dict[str, Any]:
        """Engine status suitable for logs or a health endpoint."""
        return {
            "last_run_time": timestamp_to_iso8601(self.last_run_time) if self.last_run_time else None,
            "last_alert_count": self.last_alert_count,
            "total_alerts": self.total_alerts,
            "error_count": self.error_count,
            "frequency_seconds": self.frequency_seconds,
            "lookback_minutes": self.lookback_minutes,
            "dedup_entries": len(self.dedup),
        }


__all__ = ["ALERT_INDEX", "CorrelationEngine", "CycleResult", "NORMALIZED_INDEX"]
