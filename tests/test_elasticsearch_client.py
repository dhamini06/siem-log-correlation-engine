"""Tests for the Elasticsearch client wrapper (mocked transport)."""

import pytest

from src import elasticsearch_client as es_module
from src.elasticsearch_client import ESClient, get_es_client, reset_es_client


class FakeIndices:
    def __init__(self, owner):
        self.owner = owner
        self.templates = {}

    def put_index_template(self, name, **body):
        self.templates[name] = body

    def exists_index_template(self, name):
        return name in self.templates

    def refresh(self, index=None):
        self.owner.refreshed = index


class FakeCluster:
    def __init__(self, owner):
        self.owner = owner

    def health(self):
        if self.owner.fail_health:
            raise RuntimeError("cluster unreachable")
        return {"status": self.owner.status}


class FakeElasticsearch:
    def __init__(self, url, **kwargs):
        self.url = url
        self.kwargs = kwargs
        self.indexed = []
        self.searches = []
        self.status = "yellow"
        self.fail_health = False
        self.indices = FakeIndices(self)
        self.cluster = FakeCluster(self)
        self.refreshed = None
        self.closed = False

    def index(self, index, id, document):
        self.indexed.append({"index": index, "id": id, "document": document})
        return {"_id": id}

    def search(self, index, body):
        self.searches.append({"index": index, "body": body})
        return {"hits": {"hits": [{"_id": "1", "_source": {"event_type": "logon_failure"}}]}}

    def count(self, index, query=None):
        return {"count": 7}

    def close(self):
        self.closed = True


@pytest.fixture
def fake_es(monkeypatch):
    created = {}

    def factory(url, **kwargs):
        client = FakeElasticsearch(url, **kwargs)
        created["client"] = client
        return client

    monkeypatch.setattr(es_module, "Elasticsearch", factory)
    reset_es_client()
    yield created
    reset_es_client()


def test_client_uses_configured_url(fake_es):
    client = ESClient(host="localhost", port=9200)
    assert client.url == "http://localhost:9200"
    assert fake_es["client"].kwargs["max_retries"] == 3
    assert fake_es["client"].kwargs["retry_on_status"] == (429, 502, 503, 504)


def test_health_check_true_for_yellow_and_green(fake_es):
    client = ESClient()
    assert client.health_check() is True
    fake_es["client"].status = "green"
    assert client.health_check() is True


def test_health_check_false_when_unreachable(fake_es):
    client = ESClient()
    fake_es["client"].fail_health = True
    assert client.health_check() is False


def test_index_event_and_alert_use_supplied_ids(fake_es):
    client = ESClient()
    client.index_event("normalized-events-2024-01-15", {"event_type": "logon_failure"}, "doc-1")
    client.index_alert("security-alerts-2024-01-15", {"rule_name": "brute_force"}, "alert-1")
    assert [entry["id"] for entry in fake_es["client"].indexed] == ["doc-1", "alert-1"]


def test_search_returns_sources_and_default_sort(fake_es):
    client = ESClient()
    results = client.search("normalized-events-*", {"match_all": {}}, size=10)
    assert results == [{"event_type": "logon_failure"}]
    body = fake_es["client"].searches[0]["body"]
    assert body["size"] == 10
    assert body["sort"] == [{"@timestamp": {"order": "asc"}}]


def test_search_hits_includes_document_ids(fake_es):
    client = ESClient()
    hits = client.search_hits("normalized-events-*", {"match_all": {}})
    assert hits[0]["_id"] == "1"
    assert hits[0]["_source"]["event_id"] == "1"


def test_index_template_and_refresh(fake_es):
    client = ESClient()
    client.put_index_template("normalized-events", {"index_patterns": ["normalized-events-*"]})
    assert client.index_template_exists("normalized-events") is True
    client.refresh(index="security-alerts-*")
    assert fake_es["client"].refreshed == "security-alerts-*"


def test_count_and_close(fake_es):
    client = ESClient()
    assert client.count("normalized-events-*") == 7
    client.close()
    assert fake_es["client"].closed is True


def test_singleton_is_reused_and_resettable(fake_es):
    first = get_es_client()
    assert get_es_client() is first
    reset_es_client()
    assert get_es_client() is not first
