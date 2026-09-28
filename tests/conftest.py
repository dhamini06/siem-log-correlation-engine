"""Shared pytest fixtures for the SIEM Lab test suite."""

import fnmatch
import os
import sys
from typing import Any, Dict, List, Optional

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.config import load_app_config  # noqa: E402
from src.utils.time_utils import normalize_to_utc, timestamp_to_iso8601  # noqa: E402


@pytest.fixture(scope="session")
def project_root() -> str:
    return PROJECT_ROOT


@pytest.fixture
def sample_config() -> Dict[str, Any]:
    """Lab defaults loaded from config/app-config.yaml."""
    return load_app_config()


class FakeESClient:
    """In-memory stand-in for ESClient used by unit and integration tests.

    Supports the subset of the API the application uses: idempotent indexing,
    range/id/match_all search, terms aggregations, counts, and refresh.
    """

    def __init__(self) -> None:
        self.docs: Dict[str, Dict[str, Any]] = {}
        self.refresh_count = 0
        self.indices: Dict[str, int] = {}

    # -- Indexing --

    def _put(self, index: str, document: Dict[str, Any], doc_id: str) -> str:
        stored = dict(document)
        stored.setdefault("event_id", doc_id)
        self.docs[doc_id] = {"_index": index, "_source": stored}
        self.indices[index] = self.indices.get(index, 0) + 1
        return doc_id

    def index_event(self, index: str, document: Dict[str, Any], doc_id: str) -> str:
        return self._put(index, document, doc_id)

    def index_alert(self, index: str, alert_document: Dict[str, Any], doc_id: str) -> str:
        return self._put(index, alert_document, doc_id)

    def document_exists(self, index: str, doc_id: str) -> bool:
        return doc_id in self.docs

    def refresh(self, index: Optional[str] = None) -> None:
        self.refresh_count += 1

    # -- Query helpers --

    @staticmethod
    def _matches(doc: Dict[str, Any], query: Optional[Dict[str, Any]]) -> bool:
        if not query:
            return True
        if "match_all" in query:
            return True
        if "ids" in query:
            return doc.get("event_id") in query["ids"].get("values", [])
        if "bool" in query:
            filters = query["bool"].get("filter", [])
            return all(FakeESClient._matches(doc, item) for item in filters)
        if "range" in query:
            for field, bounds in query["range"].items():
                value = doc.get(field)
                if not value:
                    return False
                moment = normalize_to_utc(str(value))
                if "gte" in bounds and moment < normalize_to_utc(bounds["gte"]):
                    return False
                if "lt" in bounds and moment >= normalize_to_utc(bounds["lt"]):
                    return False
                if "lte" in bounds and moment > normalize_to_utc(bounds["lte"]):
                    return False
            return True
        if "term" in query:
            field, value = next(iter(query["term"].items()))
            return doc.get(field) == value
        if "terms" in query:
            field, values = next(iter(query["terms"].items()))
            return doc.get(field) in values
        return True

    def _select(self, index: str, query: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        selected = [
            doc for doc in self.docs.values()
            if fnmatch.fnmatch(doc["_index"], index) and self._matches(doc["_source"], query)
        ]
        return selected

    @staticmethod
    def _sort_key(doc: Dict[str, Any]) -> str:
        return str(doc["_source"].get("@timestamp") or doc["_source"].get("timestamp") or "")

    def _query(self, index: str, query, size) -> List[Dict[str, Any]]:
        selected = sorted(self._select(index, query), key=self._sort_key)
        if size:
            selected = selected[:size]
        return [
            {"_id": doc["_source"].get("event_id"), "_index": doc["_index"], "_source": doc["_source"]}
            for doc in selected
        ]

    # -- Public API --

    def search(self, index: str, query=None, size: int = 1000, sort=None, source_fields=None):
        return [hit["_source"] for hit in self._query(index, query, size)]

    def search_hits(self, index: str, query=None, size: int = 1000, sort=None):
        return self._query(index, query, size)

    def count(self, index: str, query=None) -> int:
        return len(self._select(index, query))

    def aggregate(self, index: str, query, aggs: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
        selected = self._select(index, query)
        result: Dict[str, Any] = {}
        for agg_name, agg_body in aggs.items():
            field_name = agg_body["terms"]["field"]
            buckets: Dict[Any, int] = {}
            for doc in selected:
                key = doc["_source"].get(field_name)
                if key is not None:
                    buckets[key] = buckets.get(key, 0) + 1
            ordered = sorted(buckets.items(), key=lambda item: item[1], reverse=True)
            result[agg_name] = {
                "buckets": [{"key": key, "doc_count": count} for key, count in ordered]
            }
        return result

    # -- Test helpers --

    def docs_in(self, index_pattern: str) -> List[Dict[str, Any]]:
        return [doc["_source"] for doc in self._select(index_pattern, None)]

    def alerts(self) -> List[Dict[str, Any]]:
        return self.docs_in("security-alerts-*")

    def normalized(self) -> List[Dict[str, Any]]:
        return self.docs_in("normalized-events-*")

    def health_check(self, retries: int = 1, delay_seconds: float = 0.0) -> bool:
        return True

    def close(self) -> None:
        return None


@pytest.fixture
def fake_es() -> FakeESClient:
    return FakeESClient()


@pytest.fixture
def temp_log_dir(tmp_path) -> str:
    directory = tmp_path / "logs"
    directory.mkdir()
    return str(directory)


def make_event(
    event_id: str,
    timestamp: str,
    event_type: str = "logon_failure",
    src_ip: str = "10.0.0.1",
    user: str = "alice",
    host: str = "web-01",
    process: Optional[Dict[str, Any]] = None,
    severity: str = "medium",
) -> Dict[str, Any]:
    """Build an ES-style hit for correlation tests."""
    source: Dict[str, Any] = {
        "@timestamp": timestamp_to_iso8601(normalize_to_utc(timestamp)),
        "source_type": "linux_auth",
        "event_type": event_type,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "dst_ip": "unknown",
        "severity": severity,
        "process": process,
        "message": f"{event_type} {user}@{host} from {src_ip}",
        "raw_event": f"raw {event_id}",
        "parser_version": "1.0",
        "ingest_timestamp": timestamp_to_iso8601(normalize_to_utc(timestamp)),
    }
    return {"_id": event_id, "_index": "normalized-events-2024-01-15", "_source": source}
