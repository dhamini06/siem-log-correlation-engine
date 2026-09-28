"""Elasticsearch client wrapper for the SIEM Lab.

Single connection factory with retry/backoff, health checks, idempotent
indexing (deterministic document IDs), daily rolling index helpers, and
search utilities used by the correlation engine.
"""

import logging
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch

from .config import get_es_host, get_es_port

logger = logging.getLogger(__name__)


class ESClient:
    """Thin Elasticsearch wrapper. Construct directly or via get_es_client()."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        self.host = host or get_es_host()
        self.port = int(port or get_es_port())
        self.url = f"http://{self.host}:{self.port}"
        self.es = Elasticsearch(
            self.url,
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
            retry_on_status=(429, 502, 503, 504),
        )
        logger.debug("Elasticsearch client configured for %s", self.url)

    # -- Health / lifecycle --

    def health_check(self, retries: int = 1, delay_seconds: float = 0.0) -> bool:
        """Return True when the cluster reports green or yellow status."""
        import time

        for attempt in range(max(1, retries)):
            try:
                health = self.es.cluster.health()
                status = health.get("status")
                if status in ("green", "yellow"):
                    return True
                logger.warning("Elasticsearch cluster status is %s", status)
            except Exception as exc:
                logger.warning(
                    "Elasticsearch health check failed (attempt %s/%s): %s",
                    attempt + 1, retries, exc,
                )
            if delay_seconds and attempt + 1 < retries:
                time.sleep(delay_seconds)
        return False

    def close(self) -> None:
        """Close the underlying transport."""
        try:
            self.es.close()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Error closing ES client: %s", exc)

    # -- Index templates --

    def put_index_template(self, name: str, body: Dict[str, Any]) -> None:
        """Create or replace a composable index template."""
        self.es.indices.put_index_template(name=name, **body)
        logger.info("Index template '%s' applied", name)

    def index_template_exists(self, name: str) -> bool:
        return bool(self.es.indices.exists_index_template(name=name))

    # -- Indexing --

    def index_event(self, index: str, document: Dict[str, Any], doc_id: str) -> str:
        """Index one event using a deterministic doc_id.

        Indexing the same logical event twice overwrites the same document,
        which makes re-ingestion idempotent.

        Returns:
            The document ID.
        """
        self.es.index(index=index, id=doc_id, document=document)
        return doc_id

    def index_alert(self, index: str, alert_document: Dict[str, Any], doc_id: str) -> str:
        """Index one alert using a deterministic doc_id (same idempotency rules)."""
        self.es.index(index=index, id=doc_id, document=alert_document)
        return doc_id

    def document_exists(self, index: str, doc_id: str) -> bool:
        """Return True when a document ID already exists in the index."""
        return bool(self.es.exists(index=index, id=doc_id))

    # -- Search --

    def search(
        self,
        index: str,
        query: Optional[Dict[str, Any]] = None,
        size: int = 1000,
        sort: Optional[List[Any]] = None,
        source_fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Run a search and return the hit sources.

        Args:
            index: Index or index pattern.
            query: Elasticsearch query DSL body (bool query expected).
            size: Maximum hits to return.
            sort: Optional sort clause, defaults to ascending @timestamp.
            source_fields: Optional _source filtering.

        Returns:
            List of `_source` dictionaries.
        """
        body: Dict[str, Any] = {
            "query": query or {"match_all": {}},
            "size": size,
            "sort": sort or [{"@timestamp": {"order": "asc"}}],
        }
        if source_fields:
            body["_source"] = source_fields

        result = self.es.search(index=index, body=body)
        return [hit.get("_source", {}) for hit in result.get("hits", {}).get("hits", [])]

    def search_hits(
        self,
        index: str,
        query: Optional[Dict[str, Any]] = None,
        size: int = 1000,
        sort: Optional[List[Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Run a search and return full hits, each with its ``_id`` and ``_source``.

        The correlation engine needs document IDs to build alert evidence links.
        """
        body: Dict[str, Any] = {
            "query": query or {"match_all": {}},
            "size": size,
            "sort": sort or [{"@timestamp": {"order": "asc"}}],
        }
        result = self.es.search(index=index, body=body)
        hits: List[Dict[str, Any]] = []
        for hit in result.get("hits", {}).get("hits", []):
            source = dict(hit.get("_source", {}))
            source.setdefault("event_id", hit.get("_id"))
            hits.append({"_id": hit.get("_id"), "_index": hit.get("_index"), "_source": source})
        return hits

    def count(self, index: str, query: Optional[Dict[str, Any]] = None) -> int:
        """Return the number of documents matching the query."""
        result = self.es.count(index=index, query=query or {"match_all": {}})
        return int(result.get("count", 0))

    def aggregate(self, index: str, query: Dict[str, Any], aggs: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
        """Run a search returning only aggregation results."""
        result = self.es.search(index=index, query=query, aggs=aggs, size=size)
        return result.get("aggregations", {})

    def refresh(self, index: Optional[str] = None) -> None:
        """Refresh indices so freshly indexed documents become searchable."""
        self.es.indices.refresh(index=index or "_all")


_client: Optional[ESClient] = None


def get_es_client() -> ESClient:
    """Return the process-wide ESClient singleton."""
    global _client
    if _client is None:
        _client = ESClient()
    return _client


def reset_es_client() -> None:
    """Drop the cached singleton (used by tests)."""
    global _client
    if _client is not None:
        _client.close()
    _client = None


__all__ = [
    "ESClient",
    "get_es_client",
    "reset_es_client",
]
