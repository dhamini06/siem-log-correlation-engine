"""Tests for the Kibana SOC Triage Board saved objects.

These guard the exact defect that broke the dashboard: Kibana only resolves a
saved visualization's data view when its searchSource carries an `indexRefName`
pointer that matches a `references` entry. Without it every panel renders
"Could not find the data view: -".
"""

import importlib.util
import json
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NDJSON_PATH = os.path.join(REPO_ROOT, "dashboards", "soc-triage-board.ndjson")
GENERATOR_PATH = os.path.join(REPO_ROOT, "scripts", "build_dashboard.py")

ALERTS_DV = "siem-security-alerts"
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"
REQUIRED_PANEL_TITLES = {
    "SIEM Alerts by Severity",
    "Alert Timeline (by severity)",
    "Top Source IPs by Alert Count",
    "Suspicious Hosts by Alert Count",
}
REQUIRED_VIS = {
    "siem-vis-alerts-by-severity",
    "siem-vis-alert-timeline",
    "siem-vis-top-src-ips",
    "siem-vis-suspicious-hosts",
}


def load_generator():
    spec = importlib.util.spec_from_file_location("build_dashboard", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator():
    return load_generator()


def read_objects():
    with open(NDJSON_PATH, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# Loaded at import time so pytest.mark.parametrize can index them.
OBJECTS = read_objects()
BY_ID = {(o["type"], o["id"]): o for o in OBJECTS}
SEARCHABLE = [o for o in OBJECTS if o["type"] in ("visualization", "dashboard")]


@pytest.fixture
def objects():
    return OBJECTS


@pytest.fixture
def by_id():
    return BY_ID


# -- The regression that broke the dashboard --------------------------------

@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_search_source_has_index_ref_name(obj):
    """Kibana injects the data view id only from indexRefName."""
    source = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    assert source.get("indexRefName") == INDEX_REF_NAME, (
        f"{obj['id']}: searchSourceJSON must carry indexRefName={INDEX_REF_NAME!r}, "
        f"otherwise the panel resolves to 'Could not find the data view: -'"
    )


@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_search_source_has_no_literal_index(obj):
    """Kibana strips the literal index and replaces it with a reference."""
    source = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    assert "index" not in source


@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_index_ref_name_matches_a_reference(obj):
    source = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    matching = [r for r in obj.get("references", []) if r["name"] == source["indexRefName"]]
    assert matching, f"{obj['id']}: no reference named {source['indexRefName']!r}"
    assert matching[0]["type"] == "index-pattern"
    assert matching[0]["id"] == ALERTS_DV


def test_injection_resolves_the_alerts_data_view():
    """Port of Kibana's inject_references.js: indexRefName + reference -> index."""
    for obj in SEARCHABLE:
        source = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
        reference = next(r for r in obj["references"] if r["name"] == source["indexRefName"])
        assert source["indexRefName"] == reference["name"]
        assert reference["id"] == ALERTS_DV


# -- Data views -------------------------------------------------------------

def test_alerts_data_view_uses_timestamp_time_field(by_id):
    data_view = by_id[("index-pattern", ALERTS_DV)]
    assert data_view["attributes"]["title"] == "security-alerts-*"
    assert data_view["attributes"]["timeFieldName"] == "timestamp"


def test_events_data_view_exists(by_id):
    data_view = by_id[("index-pattern", "siem-normalized-events")]
    assert data_view["attributes"]["title"] == "normalized-events-*"
    assert data_view["attributes"]["timeFieldName"] == "@timestamp"


# -- Dashboard wiring -------------------------------------------------------

def test_dashboard_has_the_four_required_panels(by_id):
    dashboard = by_id[("dashboard", "siem-soc-triage-board")]
    panels = json.loads(dashboard["attributes"]["panelsJSON"])
    assert len(panels) == 4
    assert {p["title"] for p in panels} == REQUIRED_PANEL_TITLES


def test_every_panel_reference_resolves_to_a_visualization(by_id):
    dashboard = by_id[("dashboard", "siem-soc-triage-board")]
    panels = json.loads(dashboard["attributes"]["panelsJSON"])
    references = dashboard.get("references", [])
    for panel in panels:
        name = f"{panel['panelIndex']}:{panel['panelRefName']}"
        match = [r for r in references if r["name"] == name]
        assert match, f"panel {panel['panelIndex']} has no reference {name!r}"
        assert match[0]["type"] == "visualization"
        assert ("visualization", match[0]["id"]) in by_id


def test_dashboard_time_range_covers_sample_data(by_id):
    dashboard = by_id[("dashboard", "siem-soc-triage-board")]
    assert dashboard["attributes"]["timeFrom"] == "now-7d"
    assert dashboard["attributes"]["timeTo"] == "now"


# -- Whole-file integrity ---------------------------------------------------

def test_no_broken_references():
    broken = [
        f"{o['type']}/{o['id']} -> {r['type']}/{r['id']}"
        for o in OBJECTS
        for r in o.get("references", [])
        if (r["type"], r["id"]) not in BY_ID
    ]
    assert not broken, f"dangling references: {broken}"


def test_all_four_visualizations_present(by_id):
    assert REQUIRED_VIS <= {oid for (kind, oid) in by_id if kind == "visualization"}


def test_visualizations_reference_the_alerts_data_view(by_id):
    for oid in REQUIRED_VIS:
        obj = by_id[("visualization", oid)]
        refs = [r for r in obj["references"] if r["type"] == "index-pattern"]
        assert [r["id"] for r in refs] == [ALERTS_DV]


def test_visualization_fields_exist_in_the_data_view():
    """Every field a panel aggregates on must be a real mapped field."""
    with open(os.path.join(REPO_ROOT, "config", "elasticsearch-alert-template.json"),
              encoding="utf-8") as handle:
        template = json.load(handle)
    mapped = set(template["template"]["mappings"]["properties"])
    for obj in SEARCHABLE:
        if obj["type"] != "visualization":
            continue
        vis = json.loads(obj["attributes"]["visState"])
        for agg in vis.get("aggs", []):
            field = (agg.get("params") or {}).get("field")
            if field:
                assert field in mapped, f"{obj['id']} aggregates on unmapped field {field!r}"
    assert BY_ID[("index-pattern", ALERTS_DV)]["attributes"]["timeFieldName"] in mapped


# -- Generator self-validation ---------------------------------------------

def test_generator_output_passes_its_own_validator(generator):
    assert generator.validate(generator.build_objects()) == []


def test_generator_check_accepts_the_committed_file(generator):
    assert generator.check(NDJSON_PATH) == 0


def test_generator_validator_catches_a_missing_index_ref_name(generator):
    """The guard must actually fail on the defect it exists to prevent."""
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "visualization":
            source = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            source.pop("indexRefName")
            obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(source)
    errors = generator.validate(broken)
    assert errors
    assert any("indexRefName" in error for error in errors)


def test_generator_validator_catches_a_dangling_data_view_reference(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "visualization":
            for ref in obj["references"]:
                if ref["type"] == "index-pattern":
                    ref["id"] = "does-not-exist"
    assert generator.validate(broken)
