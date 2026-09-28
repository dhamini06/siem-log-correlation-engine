"""Evidence linking for SIEM alerts (Phase 3).

Alerts persist the Elasticsearch document IDs of the events that triggered
them (``evidence_event_ids``). This module builds those ID lists from matched
events and resolves them back into full event documents for Kibana drill-down.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..utils.time_utils import normalize_to_utc, timestamp_to_iso8601

logger = logging.getLogger(__name__)


def build_evidence_ids(events: Iterable[Dict[str, Any]]) -> List[str]:
    """Extract document IDs from ES hits, preserving order and dropping blanks."""
    ids: List[str] = []
    for hit in events:
        source = hit.get("_source", hit)
        doc_id = hit.get("_id") or source.get("event_id")
        if doc_id:
            ids.append(str(doc_id))
    return ids


def evidence_summary(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compact per-event summary for human review of an alert's evidence."""
    summary: List[Dict[str, Any]] = []
    for hit in events:
        source = hit.get("_source", hit)
        timestamp = source.get("@timestamp") or source.get("timestamp")
        try:
            iso_timestamp = timestamp_to_iso8601(normalize_to_utc(str(timestamp)))
        except (ValueError, TypeError):
            iso_timestamp = None
        summary.append(
            {
                "event_id": str(hit.get("_id") or source.get("event_id") or ""),
                "@timestamp": iso_timestamp,
                "event_type": source.get("event_type"),
                "host": source.get("host"),
                "user": source.get("user"),
                "src_ip": source.get("src_ip"),
                "severity": source.get("severity"),
                "message": source.get("message"),
                "raw_event": source.get("raw_event"),
            }
        )
    return summary


def fetch_evidence(es_client: Any, event_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Fetch full event documents for the given IDs using an mget-style lookup.

    Events are looked up in the normalized-events-* indices; missing or deleted
    documents are skipped rather than failing the whole drill-down.
    """
    if not event_ids:
        return []

    query = {"ids": {"values": list(event_ids)}}
    try:
        return es_client.search(index="normalized-events-*", query=query, size=len(event_ids))
    except Exception as exc:
        logger.warning("Evidence lookup failed for %s event(s): %s", len(event_ids), exc)
        return []


def build_kibana_link(kibana_url: str, index_pattern_id: str, event_id: str,
                      from_time: Optional[str] = None, to_time: Optional[str] = None) -> str:
    """Build a Kibana Discover deep link for a single evidence event."""
    base = f"{kibana_url.rstrip('/')}/app/discover#/?index={index_pattern_id}"
    if event_id:
        base += f"&id={event_id}"
    if from_time:
        base += f"&from={from_time}&to={to_time}"
    return base


__all__ = [
    "build_evidence_ids",
    "build_kibana_link",
    "evidence_summary",
    "fetch_evidence",
]
