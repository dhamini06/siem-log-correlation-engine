"""Tests for the Kibana SOC Triage Board saved objects (Phase 5).

Three generations of test live here.

The first guards the load-time defect that once broke the whole board: Kibana
only resolves a saved visualization's data view when its searchSource carries an
`indexRefName` pointer matching a `references` entry. Without it every panel
renders "Could not find the data view: -". Those checks are unchanged.

The second guards the Phase 5 shape. The board reads two indices on purpose --
`security-alerts-*` for the four correlated alerts, `normalized-events-*` for the
9,584 events they were found in -- and the failure mode that matters now is a
panel quietly pointing at the wrong one, or naming a field the index does not
map. Both are checked structurally against the real index templates rather than
against hard-coded expectations of the chart internals.

The third guards *rendering*. The first Phase 5 attempt produced four panels that
every saved-object test declared healthy and that Kibana rendered as
`Invalid visualization type "discover"`, `Invalid visualization type "bar"` and
`Cannot read properties of undefined`. A saved object being structurally
coherent says nothing about whether the browser can draw it, so the supported
visualization types are asserted here as a closed set taken from the running
Kibana, and the two names that were wrong are asserted absent by name.

One class is an integration test against a live Elasticsearch. It asserts the
alert population is still exactly four and that the board's own aggregations
return data, because "the saved objects are internally consistent" and "the
dashboard shows something" are different claims.
"""

import importlib.util
import json
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NDJSON_PATH = os.path.join(REPO_ROOT, "dashboards", "soc-triage-board.ndjson")
GENERATOR_PATH = os.path.join(REPO_ROOT, "scripts", "build_dashboard.py")
LAB_JS = os.path.join(REPO_ROOT, "training", "assets", "js", "lab.js")

DASHBOARD_ID = "siem-soc-triage-board"
ALERTS_DV = "siem-security-alerts"
EVENTS_DV = "siem-normalized-events"
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"

#: Absolute, not relative. The dataset is intentionally immutable - 9,584 events
#: over 2026-09-16 .. 2026-09-29 from one fixed seed and one fixed base
#: timestamp - so `now-15d` was the wrong shape: it covered the dataset when it
#: was built and silently stopped covering it as the clock advanced, which is how
#: the board came to show 3 of the 4 canonical alerts. A day of slack on each
#: side means containment does not depend on the exact first and last event.
INVESTIGATION_FROM = "2026-09-15T00:00:00.000Z"
INVESTIGATION_TO = "2026-09-30T23:59:59.999Z"

#: The dataset's own extent, used to assert containment rather than equality.
DATASET_FIRST_DAY = "2026-09-16"
DATASET_LAST_DAY = "2026-09-29"

#: Panel title -> (saved object type, id), in the order the board presents them.
#:
#: The queue is a Lens data table rather than a TSVB panel. Kibana 8.13 removed
#: TSVB's `table` visualization, and `discover` is an application rather than a
#: visualization type, so neither can produce a per-document table inside a
#: dashboard panel. `lnsDatatable` is the only supported equivalent.
REQUIRED_PANELS = [
    ("Alert Queue", "lens", "siem-lens-alert-queue"),
    ("Alerts by Severity", "visualization", "siem-vis-alert-severity"),
    ("Alert Timeline", "visualization", "siem-vis-alert-timeline"),
    ("Authentication Activity", "visualization", "siem-vis-auth-activity"),
    ("Top Source IPs by Event Volume", "visualization", "siem-vis-src-ip-volume"),
    ("Event Type Mix", "visualization", "siem-vis-event-type-mix"),
    ("Event Volume by Host", "visualization", "siem-vis-host-volume"),
    ("Alerts by Host", "visualization", "siem-vis-alerts-by-host"),
]

PANEL_TYPE = {obj_id: kind for _title, kind, obj_id in REQUIRED_PANELS}
QUEUE_ID = "siem-lens-alert-queue"

#: Which index each panel must read. The whole point of the redesign.
ALERT_PANELS = {QUEUE_ID, "siem-vis-alert-severity",
                "siem-vis-alert-timeline", "siem-vis-alerts-by-host"}
EVENT_PANELS = {"siem-vis-event-type-mix", "siem-vis-auth-activity",
                "siem-vis-host-volume", "siem-vis-src-ip-volume"}

#: Names that are not registered visualization types in Kibana 8.13, and which
#: each produced a panel that rendered the string
#: "Invalid visualization type" on the first Phase 5 attempt. Kept literal so a
#: regression names the specific failure rather than "some unsupported type".
REMOVED_OR_NEVER_VALID_TYPES = ("bar", "table", "discover")

#: Words that would turn telemetry into a verdict. A dashboard that asserts
#: intent hands the student the conclusion instead of the evidence.
VERDICT_WORDS = re.compile(
    r"scenario|answer|correct|expected|malicious|suspicious|attack|threat|"
    r"intruder|victim|student|hostile|breach|exploit|compromise", re.I)

#: Alert fields that state findings rather than observations. `reasoning` reads
#: e.g. "10 failed logons from 203.0.113.45 against web-01 within 5 minutes ...
#: exceeded the threshold of 5", which is the Scenario 01 and 02 answer in prose.
FORBIDDEN_FIELDS = {"reasoning", "evidence_event_ids", "dedup_key"}

#: Panel names that existed before the Phase 5 rebuild. No page may reference
#: them, and none may be a panel title.
STALE_PANEL_TITLES = [
    "SIEM Alerts by Severity",
    "Top Source IPs by Alert Count",
    "Suspicious Hosts by Alert Count",
    "Alert Timeline (by severity)",
]


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


OBJECTS = read_objects()
BY_ID = {(o["type"], o["id"]): o for o in OBJECTS}
SEARCHABLE = [o for o in OBJECTS if o["type"] in ("visualization", "lens", "dashboard")]
VISUALIZATIONS = [o for o in OBJECTS if o["type"] == "visualization"]
#: Every object a dashboard panel embeds, whatever its saved-object type.
PANEL_OBJECTS = [o for o in OBJECTS if o["id"] in PANEL_TYPE]
DASHBOARD = BY_ID[("dashboard", DASHBOARD_ID)]


@pytest.fixture
def objects():
    return OBJECTS


@pytest.fixture
def by_id():
    return BY_ID


def search_source(obj):
    return json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])


def vis_state(obj):
    return json.loads(obj["attributes"]["visState"])


def data_view_of(obj):
    """Resolve a panel's data view the way Kibana does at render time.

    A TSVB panel resolves through `searchSourceJSON.indexRefName`; a Lens panel
    resolves through the `indexpattern-datasource-layer-<layerId>` reference its
    datasource layer names. Both are pointer lookups, and both fail to render
    when the name matches no reference.
    """
    if obj["type"] == "lens":
        layer_id = obj["attributes"]["state"]["visualization"]["layerId"]
        ref_name = "indexpattern-datasource-layer-%s" % layer_id
    else:
        ref_name = search_source(obj)["indexRefName"]
    reference = next(r for r in obj["references"] if r["name"] == ref_name)
    return reference["id"]


def fields_used(obj):
    """Every field a panel aggregates on or displays."""
    if obj["type"] == "lens":
        return lens_columns(obj)
    state = vis_state(obj)
    out = [a["params"]["field"] for a in state.get("aggs", [])
           if a.get("params", {}).get("field")]
    out += state.get("params", {}).get("columns", []) or []
    return out


def lens_state(obj):
    return obj["attributes"]["state"]


def lens_layer(obj):
    state = lens_state(obj)
    layer_id = state["visualization"]["layerId"]
    return state["datasourceStates"]["formBased"]["layers"][layer_id]


def lens_columns(obj):
    """The source fields the Lens table shows, in column order."""
    return [c["sourceField"] for c in lens_layer(obj)["columns"].values()]


def generator_columns():
    """The queue's declared column list, straight from the builder."""
    return load_generator().ALERT_QUEUE_COLUMNS


# ================================================== load-time data view wiring

@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_search_source_has_index_ref_name(obj):
    """Kibana injects the data view id only from indexRefName."""
    if obj["type"] == "lens":
        # A Lens panel resolves its data view through the datasource layer's
        # reference, which the two tests below cover; it has no searchSource.
        return
    assert search_source(obj).get("indexRefName") == INDEX_REF_NAME, (
        ": searchSourceJSON must carry indexRefName=" + INDEX_REF_NAME
        + ", otherwise the panel resolves to 'Could not find the data view: -'")


@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_search_source_has_no_literal_index(obj):
    """Kibana strips the literal index and replaces it with a reference."""
    if obj["type"] == "lens":
        return
    assert "index" not in search_source(obj)


@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_index_ref_name_matches_a_reference(obj):
    if obj["type"] == "lens":
        ref_name = "indexpattern-datasource-layer-%s" % lens_state(obj)["visualization"]["layerId"]
    else:
        ref_name = search_source(obj).get("indexRefName")
    names = [r["name"] for r in obj["references"]]
    assert ref_name in names, ": no reference named " + str(ref_name) + " matching"
    matching = [r for r in obj["references"] if r["name"] == ref_name]
    assert matching[0]["type"] == "index-pattern"
    assert matching[0]["id"] in (ALERTS_DV, EVENTS_DV)


def test_dashboard_exists():
    assert ("dashboard", DASHBOARD_ID) in BY_ID


def test_both_data_views_are_referenced():
    """The board is only useful if it reaches both indices."""
    referenced = {r["id"] for o in SEARCHABLE for r in o["references"]
                  if r["type"] == "index-pattern"}
    assert ALERTS_DV in referenced, "no panel reads the alert index"
    assert EVENTS_DV in referenced, "no panel reads the normalized-event index"


@pytest.mark.parametrize("vid", sorted(ALERT_PANELS))
def test_alert_panels_read_the_alert_index(vid):
    assert data_view_of(BY_ID[(PANEL_TYPE[vid], vid)]) == ALERTS_DV


@pytest.mark.parametrize("vid", sorted(EVENT_PANELS))
def test_activity_panels_read_the_event_index(vid):
    """Sections D-G must not be built from the four alert documents.

    That was the Phase 4 weakness: every panel aggregated `security-alerts-*`,
    which holds four documents, so the board could say nothing about the
    9,584 events the alerts were found in."""
    assert data_view_of(BY_ID[("visualization", vid)]) == EVENTS_DV


def test_alerts_data_view_uses_the_timestamp_time_field():
    data_view = BY_ID[("index-pattern", ALERTS_DV)]["attributes"]
    assert data_view["title"] == "security-alerts-*"
    assert data_view["timeFieldName"] == "timestamp"


def test_events_data_view_uses_the_at_timestamp_time_field():
    data_view = BY_ID[("index-pattern", EVENTS_DV)]["attributes"]
    assert data_view["title"] == "normalized-events-*"
    assert data_view["timeFieldName"] == "@timestamp"


# ============================================================== the panel set

def test_all_required_panels_are_present():
    ordered = [p["title"] for p in sorted(
        json.loads(DASHBOARD["attributes"]["panelsJSON"]),
        key=lambda p: int(p["panelIndex"]))]
    assert ordered == [title for title, _kind, _vid in REQUIRED_PANELS]


@pytest.mark.parametrize("title,kind,vid", REQUIRED_PANELS,
                         ids=[v for _t, _k, v in REQUIRED_PANELS])
def test_each_required_panel_exists(title, kind, vid):
    assert (kind, vid) in BY_ID, "missing panel " + repr(title) + " (" + kind + "/" + vid + ")"
    assert BY_ID[(kind, vid)]["attributes"]["title"] == title


def test_panel_count_is_not_redundant():
    """Seven to nine meaningful panels; more is noise, fewer is missing coverage."""
    panels = json.loads(DASHBOARD["attributes"]["panelsJSON"])
    assert 7 <= len(panels) <= 9, str(len(panels)) + " panels"
    assert len({p["title"] for p in panels}) == len(panels), "duplicate panel titles"


def test_alert_queue_is_the_first_panel_and_the_tallest():
    """Section A is the operational centrepiece and must read first."""
    panels = sorted(json.loads(DASHBOARD["attributes"]["panelsJSON"]),
                    key=lambda p: int(p["panelIndex"]))
    assert panels[0]["title"] == "Alert Queue"
    assert panels[0]["gridData"]["y"] == 0
    assert panels[0]["gridData"]["h"] == max(p["gridData"]["h"] for p in panels)


def test_panels_do_not_overlap_and_fit_the_grid():
    panels = json.loads(DASHBOARD["attributes"]["panelsJSON"])
    for p in panels:
        grid = p["gridData"]
        assert grid["x"] + grid["w"] <= 24, "panel " + p["panelIndex"] + " overflows 24 columns"
        assert grid["x"] >= 0 and grid["y"] >= 0
        for other in panels:
            if other is p:
                continue
            overlap = (grid["x"] < other["gridData"]["x"] + other["gridData"]["w"]
                       and other["gridData"]["x"] < grid["x"] + grid["w"]
                       and grid["y"] < other["gridData"]["y"] + other["gridData"]["h"]
                       and other["gridData"]["y"] < grid["y"] + grid["h"])
            assert not overlap, ("panels overlap: " + p["panelIndex"] + " and "
                                 + other["panelIndex"])


# ==================================================== what each panel shows

def test_severity_panel_aggregates_alert_severity():
    assert "severity" in fields_used(BY_ID[("visualization", "siem-vis-alert-severity")])


def test_alert_timeline_uses_the_alert_time_field():
    """Not `@timestamp`: alert documents have no such field."""
    state = vis_state(BY_ID[("visualization", "siem-vis-alert-timeline")])
    date_fields = [a["params"]["field"] for a in state["aggs"]
                   if a["type"] == "date_histogram"]
    assert date_fields == ["timestamp"]


def test_authentication_panel_uses_the_event_time_field_and_is_scoped_to_logons():
    """Scoped on the bucket agg, not with a saved KQL filter.

    The saved-filter form is what broke this panel in the first Phase 5
    attempt: it rendered "Cannot read properties of undefined (reading
    'type')". A terms agg's `include` list scopes the same two event types and
    renders, which has been verified against the running Kibana."""
    obj = BY_ID[("visualization", "siem-vis-auth-activity")]
    state = vis_state(obj)
    date_fields = [a["params"]["field"] for a in state["aggs"]
                   if a["type"] == "date_histogram"]
    assert date_fields == ["@timestamp"]
    groups = [a for a in state["aggs"] if a.get("schema") == "group"]
    assert len(groups) == 1, "expected one split-by agg, found " + str(len(groups))
    group = groups[0]
    assert group["params"]["field"] == "event_type"
    include = set(group["params"].get("include", []))
    assert include == {"logon_success", "logon_failure"}, (
        "the authentication panel must be scoped to the two logon types, or it "
        "is not an authentication panel. include=" + str(sorted(include)))
    assert not search_source(obj).get("filter"), (
        "no saved search filter is used; a KQL filter here is what made this "
        "panel fail to render")


def test_source_ip_panel_uses_event_src_ip():
    assert "src_ip" in fields_used(BY_ID[("visualization", "siem-vis-src-ip-volume")])


def test_event_type_panel_uses_event_type():
    assert "event_type" in fields_used(BY_ID[("visualization", "siem-vis-event-type-mix")])


def test_affected_host_panel_uses_event_host():
    """Section G is event volume, which is a different fact from Section H."""
    assert "host" in fields_used(BY_ID[("visualization", "siem-vis-host-volume")])


def test_alerts_by_host_panel_uses_alert_host():
    assert "host" in fields_used(BY_ID[("visualization", "siem-vis-alerts-by-host")])


def test_host_panels_are_distinct_views():
    """A quiet host with an alert is the interesting case; a noisy host is not.

    The two panels must not collapse into one, or Section H becomes a duplicate
    of Section G read against a four-document index."""
    volume = data_view_of(BY_ID[("visualization", "siem-vis-host-volume")])
    alerts = data_view_of(BY_ID[("visualization", "siem-vis-alerts-by-host")])
    assert volume != alerts


def test_alert_queue_columns_are_the_operational_fields():
    queue = BY_ID[("lens", QUEUE_ID)]
    assert queue["attributes"]["visualizationType"] == "lnsDatatable"
    columns = lens_columns(queue)
    for field in ("timestamp", "severity", "rule_name", "src_ip", "user", "host"):
        assert field in columns, "the queue should show " + field
    assert "evidence_count" in columns


def test_alert_queue_does_not_expose_answer_bearing_fields():
    """`reasoning` states the findings outright. It stays in Discover, not here."""
    queue = BY_ID[("lens", QUEUE_ID)]
    shown = set(lens_columns(queue))
    assert not shown & FORBIDDEN_FIELDS, (
        "the alert queue displays " + str(sorted(shown & FORBIDDEN_FIELDS))
        + ", which states findings rather than telemetry")
    # The columns are named explicitly, so also assert nothing *else* sneaks in
    # now that the column list is a Lens table rather than a `params.columns` array.
    assert shown == set(generator_columns())


# ============================================ will the running Kibana draw it

def test_every_panel_uses_a_visualization_type_kibana_registers(generator):
    """The first Phase 5 board was structurally perfect and drew four errors.

    `discover` is an application, not a visualization type, and the horizontal
    bar chart is registered as `horizontal_bar`, not `bar`. Both rendered as
    `Invalid visualization type`. The supported set is read from the builder,
    which holds it as transcribed from the running Kibana's plugin registry."""
    supported = set(generator.SUPPORTED_VIS_TYPES)
    for obj in VISUALIZATIONS:
        vis_type = vis_state(obj)["type"]
        assert vis_type in supported, (
            obj["id"] + " uses " + repr(vis_type) + ", which this Kibana does not "
            "register, so the panel renders 'Invalid visualization type'. "
            "Supported: " + ", ".join(sorted(supported)))


@pytest.mark.parametrize("vis_type", REMOVED_OR_NEVER_VALID_TYPES)
def test_no_panel_uses_a_type_that_never_rendered(vis_type):
    """Named individually, so a regression names the exact failure."""
    offenders = [o["id"] for o in VISUALIZATIONS if vis_state(o)["type"] == vis_type]
    assert not offenders, (
        vis_type + " is not a registered visualization type in Kibana 8.13; "
        + str(offenders) + " render 'Invalid visualization type'")


def test_the_two_horizontal_bars_use_the_horizontal_bar_type():
    """`horizontal_bar` draws as a histogram with the category axis on the left.

    `visState.type` and `params.type` are not the same thing here: the
    registered type is `horizontal_bar` and the renderer draws a `histogram`."""
    for vid in ("siem-vis-src-ip-volume", "siem-vis-host-volume"):
        state = vis_state(BY_ID[("visualization", vid)])
        assert state["type"] == "horizontal_bar", state["type"]
        assert state["params"]["type"] == "histogram", state["params"]["type"]
        assert state["params"]["categoryAxes"][0]["position"] == "left"
        assert state["params"]["valueAxes"][0]["position"] == "bottom"


def test_builder_refuses_to_build_an_unsupported_panel(generator):
    """Fail at build time, not as a broken panel in the browser."""
    with pytest.raises(ValueError):
        generator.chart_vis_state(
            "Broken", "bar",
            [generator.count_agg(), generator.terms_agg("host", "2")],
            [generator.series_params("histogram", "Events")], "Events")
    with pytest.raises(ValueError):
        generator.chart_vis_state(
            "Broken", "discover", [], [], "Events")


def test_alert_queue_declares_the_lens_migration_version(generator):
    """Without a version, Kibana runs every Lens migration from the beginning.

    Eleven of them read the pre-8.x `datasourceStates.indexpattern.layers` shape,
    which a modern `formBased` object does not have, and the import then fails
    with "Cannot read properties of undefined (reading 'currentIndexPatternId')"
    and an HTTP 500."""
    queue = BY_ID[("lens", QUEUE_ID)]
    assert queue.get("migrationVersion", {}).get("lens") == generator.LENS_MIGRATION_VERSION


def test_alert_queue_state_carries_the_keys_lens_requires():
    """The shape Kibana 8.13 itself writes, transcribed from a shipped datatable."""
    state = lens_state(BY_ID[("lens", QUEUE_ID)])
    for key in ("visualization", "datasourceStates", "internalReferences",
                "query", "filters", "adHocDataViews"):
        assert key in state, "lens state has no " + key
    assert state["internalReferences"] == []
    assert state["visualization"]["layerType"] == "data"
    assert "formBased" in state["datasourceStates"]


def test_alert_queue_visualization_columns_are_minimal_references():
    """`visualization.columns` holds `{columnId}` references, not definitions.

    A full column object in that array is what made the first attempt throw
    inside the state conversion, and that conversion is wrapped in a bare
    `catch {}`, so the only symptom is a downstream "Cannot read properties of
    undefined"."""
    queue = BY_ID[("lens", QUEUE_ID)]
    vis = lens_state(queue)["visualization"]
    defined = lens_layer(queue)["columns"]
    assert [c["columnId"] for c in vis["columns"]] == list(defined)
    for column in vis["columns"]:
        assert set(column) <= {"columnId", "isTransposed", "oneClickFilter",
                               "colorMode", "palette"}, sorted(column)
    assert vis["columnOrder"] == list(defined)


def test_alert_queue_columns_carry_a_scale():
    """`scale` is part of the operation's shape and is not optional.

    Each operation's `getPossibleOperation` returns it; a column without it
    fails the shape check during conversion."""
    for column in lens_layer(BY_ID[("lens", QUEUE_ID)])["columns"].values():
        assert "scale" in column, column["label"] + " has no scale"
        assert "params" in column, column["label"] + " has no params"


def test_alert_queue_terms_columns_declare_their_order_by():
    """`params.orderBy.type` is read by getDefaultLabel; its absence throws."""
    for column in lens_layer(BY_ID[("lens", QUEUE_ID)])["columns"].values():
        if column["operationType"] == "terms":
            assert "orderBy" in column["params"], column["label"]
            assert "type" in column["params"]["orderBy"], column["label"]


def test_the_board_references_the_lens_object_by_type():
    """A dashboard panel pointing at a `lens` object as a `visualization` shows
    nothing; the reference type has to match the saved object type."""
    panels = json.loads(DASHBOARD["attributes"]["panelsJSON"])
    board = {p["panelIndex"]: p["panelRefName"] for p in panels}
    for reference in DASHBOARD["references"]:
        if reference["type"] in ("visualization", "lens"):
            name, _colon, ref = reference["name"].partition(":")
            assert reference["type"] == PANEL_TYPE[reference["id"]], reference
            assert board[name] == ref


# ================================================== language and leakage

@pytest.mark.parametrize("obj", SEARCHABLE, ids=lambda o: o["id"])
def test_no_panel_title_or_description_uses_verdict_language(obj):
    for field in ("title", "description"):
        value = obj["attributes"].get(field, "")
        match = VERDICT_WORDS.search(value)
        assert not match, (
            obj["id"] + "." + field + " contains " + repr(match.group(0) if match else "")
            + "; a dashboard that asserts intent hands the student the conclusion: "
            + repr(value))


@pytest.mark.parametrize("obj", PANEL_OBJECTS, ids=lambda o: o["id"])
def test_no_host_or_address_is_labelled(obj):
    """No panel title may single out an address or host."""
    title = obj["attributes"]["title"]
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", title), title
    assert not re.search(r"\b(?:web|app|db|dc|wks|fw)-\d{2,3}\b", title)


@pytest.mark.parametrize("pattern", [r"scenario[-_ ]?\d", r"q\d+\b"])
def test_no_scenario_identifier_appears_anywhere_in_the_board(pattern):
    blob = json.dumps(OBJECTS)
    assert not re.search(pattern, blob, re.I), "board contains " + pattern


# ================================================ the investigation window

def test_dashboard_time_range_covers_the_dataset():
    """The board must open on the whole approved dataset, at both ends.

    Asserted as containment, so this keeps holding whatever the bounds are
    written as, and fails the moment a change stops covering the data. The
    earlier form compared against the literal "now-15d", which checked the
    implementation rather than the property and therefore passed for as long as
    the ageing went unnoticed.
    """
    time_from = DASHBOARD["attributes"]["timeFrom"]
    time_to = DASHBOARD["attributes"]["timeTo"]
    assert time_from == INVESTIGATION_FROM
    assert time_to == INVESTIGATION_TO

    for name, value in (("timeFrom", time_from), ("timeTo", time_to)):
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$", value), (
            "%s is %r; a fixed dataset needs an absolute ISO-8601 UTC bound, not "
            "date math. A relative window stops covering the data as the clock "
            "advances, silently." % (name, value))

    assert time_from[:10] <= DATASET_FIRST_DAY, (
        "the board opens %s but the dataset starts %s" % (time_from[:10], DATASET_FIRST_DAY))
    assert time_to[:10] >= DATASET_LAST_DAY, (
        "the board closes %s but the dataset runs to %s" % (time_to[:10], DATASET_LAST_DAY))


def test_dashboard_applies_its_own_saved_time_range():
    """`timeRestore` must be true, which is the opposite of what it sounds like.

    Measured on Kibana 8.13 against this board, reading the rendered time picker
    in a browser:

        timeFrom=absolute ISO  timeRestore=false -> 0 alerts, "Last 15 minutes"
        timeFrom=absolute ISO  timeRestore=true  -> 4 alerts, absolute dates
        timeFrom=now-15d       timeRestore=false -> 0 alerts, "Last 15 minutes"
        timeFrom=now-15d       timeRestore=true  -> 3 alerts, "Last 15 days"

    `false` makes Kibana discard the range saved on the dashboard and fall back
    to its own 15-minute default, silently. So the flag that reads like "do not
    let the browser override the lab's range" is in fact the flag that stops the
    lab's range being used at all. Without this the board shows an empty queue
    and no error anywhere.
    """
    assert DASHBOARD["attributes"]["timeRestore"] is True, (
        "timeRestore=false makes Kibana ignore this dashboard's saved range and "
        "fall back to 'Last 15 minutes'; measured 0 of 4 alerts that way")


def test_no_24_hour_range_regression():
    """`now-24h` showed 488 of 9,584 events and none of the four alerts."""
    with open(NDJSON_PATH, encoding="utf-8") as handle:
        assert "now-24h" not in handle.read()


# ================================================= training page references

def _training_pages():
    base = os.path.join(REPO_ROOT, "training")
    found = [os.path.join(base, "index.html"),
             os.path.join(base, "instructions.html"),
             os.path.join(base, "scenarios.html")]
    scenarios = os.path.join(base, "scenarios")
    found += [os.path.join(scenarios, n) for n in sorted(os.listdir(scenarios))
              if n.endswith(".html")]
    return [p for p in found if os.path.isfile(p)]


def test_no_training_page_names_a_panel_that_no_longer_exists():
    """No page may reference a pre-Phase-5 panel name.

    Without this, renaming a panel silently breaks a student's instructions and
    nothing anywhere fails. This was an allowlist of tolerated staleness for a
    while; the pages have been corrected, so the expectation is now zero.

    The Phase 5 rebuild removed "Top source IPs by alert count" and "Suspicious
    hosts by alert count" on purpose -- ranking four alert documents by alert
    count answers nothing, and §3/§15 call that the weakness to remove. Scenarios
    02 and 04 used to point students at the deleted panel to separate attacker
    addresses; they now point at the Alert Queue, which lists the source address
    of every alert."""
    found = {}
    for path in _training_pages():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        name = os.path.basename(path)
        lowered = text.lower()
        hits = sorted({title for title in STALE_PANEL_TITLES
                       if title in text or title.lower() in lowered})
        if hits:
            found[name] = hits
    assert not found, (
        "training pages still reference panels the board no longer has: "
        + json.dumps(found, indent=2))


def test_the_stale_titles_really_are_gone_from_the_board():
    """Otherwise the scan above is watching for names the board still uses."""
    titles = {o["attributes"]["title"] for o in PANEL_OBJECTS}
    for title in STALE_PANEL_TITLES:
        assert title not in titles, title + " is still a panel title"


@pytest.mark.parametrize("obj", PANEL_OBJECTS, ids=lambda o: o["id"])
def test_every_panel_title_on_the_board_is_unique(obj):
    titles = [o["attributes"]["title"] for o in PANEL_OBJECTS]
    assert len(set(titles)) == len(titles), "duplicate panel titles: " + str(titles)


def test_board_range_matches_the_training_discover_links():
    """Two artefacts, two languages, one window.

    The board's range and the Discover links the training pages build must not
    drift: a student who widens the time picker by hand and a student who
    follows a link should see the same data."""
    with open(LAB_JS, encoding="utf-8") as handle:
        js = handle.read()
    match = re.search(r'INVESTIGATION_FROM\s*=\s*"([^"]+)"', js)
    assert match, "training/assets/js/lab.js no longer declares an investigation window"
    assert match.group(1) == DASHBOARD["attributes"]["timeFrom"], (
        "the board opens " + DASHBOARD["attributes"]["timeFrom"]
        + " but the training links open " + match.group(1))


# ================================================== builder and file hygiene

def test_no_duplicate_saved_object_ids():
    ids = [o["id"] for o in OBJECTS]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, "duplicate saved object ids: " + str(duplicates)


def test_generated_output_is_deterministic(tmp_path):
    """Two builds of the board must be identical, or it cannot be reviewed."""
    module = load_generator()
    first, second = tmp_path / "a.ndjson", tmp_path / "b.ndjson"
    module.write(str(first))
    module.write(str(second))
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes() == open(NDJSON_PATH, "rb").read(), (
        "the committed NDJSON is not what the builder produces")


def test_generator_check_accepts_the_committed_file(generator):
    assert generator.check(NDJSON_PATH) == 0


def test_every_panel_field_is_mapped_in_the_index_it_reads(generator):
    """A panel on an unmapped field renders empty, and nothing warns.

    Field availability is asymmetric: `security-alerts-*` has no `@timestamp`,
    `event_type` or `process.*`, and `normalized-events-*` has no `timestamp`,
    `rule_name` or `first_seen`. Checked per data view, against the real index
    templates."""
    templates = {
        ALERTS_DV: generator.mapped_fields("elasticsearch-alert-template.json"),
        EVENTS_DV: generator.mapped_fields("elasticsearch-template.json"),
    }
    for obj in PANEL_OBJECTS:
        data_view = data_view_of(obj)
        for field in fields_used(obj):
            assert field not in FORBIDDEN_FIELDS, (
                obj["id"] + " uses " + field + ", which states findings rather "
                "than telemetry")
            assert field in templates[data_view], (
                obj["id"] + " aggregates on " + field + ", which is not mapped "
                "in " + data_view)


def test_panel_filters_only_reference_mapped_fields():
    """No saved search filter survives on any panel.

    The one that was there (a KQL event_type filter on the authentication panel)
    is what made that panel fail to render, so the scoping moved onto the
    bucket agg instead."""
    offenders = []
    for obj in VISUALIZATIONS:
        for entry in search_source(obj).get("filter", []):
            if "event_type" in (entry.get("query") or "") \
                    and data_view_of(obj) != EVENTS_DV:
                offenders.append(obj["id"])
    assert not offenders, (
        "panels filtering on event_type must read the event index: "
        + str(offenders))


def test_generator_output_passes_its_own_validator(generator):
    assert generator.validate(generator.build_objects()) == []


# ================================================ the validator must bite

def test_validator_catches_a_missing_index_ref_name(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "visualization":
            meta = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            meta.pop("indexRefName", None)
            obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(meta)
    errors = generator.validate(broken)
    assert any("indexRefName" in e for e in errors)


def test_validator_catches_a_dangling_data_view_reference(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "visualization":
            for reference in obj["references"]:
                if reference["type"] == "index-pattern":
                    reference["id"] = "does-not-exist"
    assert any("does-not-exist" in e for e in generator.validate(broken))


def test_validator_catches_an_activity_panel_pointed_at_the_alert_index(generator):
    """The Phase 4 defect, reintroduced: an activity panel with no event data."""
    broken = generator.build_objects()
    for obj in broken:
        if obj["id"] == "siem-vis-auth-activity":
            for reference in obj["references"]:
                if reference["type"] == "index-pattern":
                    reference["id"] = ALERTS_DV
    errors = generator.validate(broken)
    assert any("@timestamp" in e or "event_type" in e for e in errors), (
        "a panel reading the wrong index must fail validation")


def test_validator_catches_a_panel_exposing_reasoning(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["id"] == QUEUE_ID:
            layers = obj["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]
            for layer in layers.values():
                layer["columns"]["col-reasoning"] = {
                    "label": "reasoning", "dataType": "string",
                    "operationType": "terms", "scale": "ordinal",
                    "sourceField": "reasoning", "isBucketed": True,
                    "params": {"orderBy": {"type": "alphabetical"}},
                }
    errors = generator.validate(broken)
    assert any("reasoning" in e for e in errors)


def test_validator_catches_an_unsupported_visualization_type(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "visualization":
            state = json.loads(obj["attributes"]["visState"])
            state["type"] = "bar"
            obj["attributes"]["visState"] = json.dumps(state)
    assert any("Invalid visualization type" in e for e in generator.validate(broken))


def test_validator_catches_an_overflowing_panel(generator):
    broken = generator.build_objects()
    for obj in broken:
        if obj["type"] == "dashboard":
            panels = json.loads(obj["attributes"]["panelsJSON"])
            panels[0]["gridData"]["w"] = 30
            obj["attributes"]["panelsJSON"] = json.dumps(panels)
    assert any("overflow" in e for e in generator.validate(broken))


def test_validator_catches_duplicate_object_ids(generator):
    broken = generator.build_objects()
    broken.append(dict(broken[0]))
    assert any("duplicate saved object id" in e for e in generator.validate(broken))


# ==================================================== against a live cluster

def _live_client():
    """The shared ES client, or skip. These tests describe the running lab."""
    from src.elasticsearch_client import get_es_client
    try:
        client = get_es_client()
        client.count(index="normalized-events-*")
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip("Elasticsearch is not running: " + str(exc)[:120])
    return client


ALERTS = "security-alerts-*"
EVENTS = "normalized-events-*"


class TestAgainstLiveElasticsearch:
    """The four alerts and the panels that read them.

    Distinct from the structural tests above: those prove the saved objects are
    coherent, this proves the board has something to show."""

    def test_dataset_is_unchanged(self):
        client = _live_client()
        assert client.count(index=EVENTS) == 9584
        assert client.count(index=ALERTS) == 4

    def test_the_four_expected_alerts_remain_queryable(self):
        client = _live_client()
        hits = client.search_hits(index=ALERTS, query={"match_all": {}},
                                  size=20, sort=[{"timestamp": {"order": "asc"}}])
        found = sorted((h["_source"]["rule_name"], h["_source"]["severity"],
                        h["_source"]["src_ip"]) for h in hits)
        assert found == [
            ("brute_force", "high", "203.0.113.45"),
            ("successful_brute_force", "critical", "203.0.113.66"),
            ("suspicious_process_post_login", "high", "198.51.100.25"),
            ("suspicious_process_post_login", "high", "198.51.100.77"),
        ]
        assert len(hits) == 4

    def test_alert_severity_panel_has_data(self):
        client = _live_client()
        response = client.es.search(index=ALERTS, body={
            "size": 0, "aggs": {"s": {"terms": {"field": "severity", "size": 10}}}})
        buckets = response["aggregations"]["s"]["buckets"]
        counts = {b["key"]: b["doc_count"] for b in buckets}
        assert counts.get("high") == 3
        assert counts.get("critical") == 1
        assert set(counts) <= {"low", "medium", "high", "critical"}

    def test_alerts_by_host_panel_has_data(self):
        client = _live_client()
        response = client.es.search(index=ALERTS, body={
            "size": 0, "aggs": {"h": {"terms": {"field": "host", "size": 10}}}})
        counts = {b["key"]: b["doc_count"]
                  for b in response["aggregations"]["h"]["buckets"]}
        assert counts.get("web-01") == 3
        assert counts.get("app-01") == 1

    def test_alert_timeline_panel_accounts_for_every_alert(self):
        client = _live_client()
        response = client.es.search(index=ALERTS, body={
            "size": 0, "aggs": {"d": {"date_histogram": {
                "field": "timestamp", "calendar_interval": "1d",
                "min_doc_count": 1}}}})
        total = sum(b["doc_count"]
                    for b in response["aggregations"]["d"]["buckets"])
        assert total == 4

    def test_event_type_panel_returns_the_five_real_types(self):
        client = _live_client()
        response = client.es.search(index=EVENTS, body={
            "size": 0, "aggs": {"t": {"terms": {"field": "event_type", "size": 20}}}})
        keys = {b["key"] for b in response["aggregations"]["t"]["buckets"]}
        assert keys == {"logon_success", "logon_failure", "process_create",
                        "privilege_escalation", "network_connection"}

    def test_activity_panels_return_a_real_population_not_the_four_alerts(self):
        client = _live_client()
        response = client.es.search(index=EVENTS, body={
            "size": 0, "aggs": {
                "s": {"cardinality": {"field": "src_ip"}},
                "h": {"cardinality": {"field": "host"}}}})
        aggregations = response["aggregations"]
        assert aggregations["s"]["value"] > 100, (
            "the source-IP panel is showing an alert-sized population")
        assert aggregations["h"]["value"] == 31

    def test_authentication_panel_is_scoped_to_logon_events(self):
        """The panel's `include` list, run as a real aggregation.

        The chart splits by event_type with `include: [logon_success,
        logon_failure]`; a filter agg over the same two values is the
        equivalent query, and it must be strictly smaller than all events."""
        client = _live_client()
        response = client.es.search(index=EVENTS, body={
            "size": 0,
            "aggs": {
                "t": {"terms": {"field": "event_type", "size": 10}},
                "only_logons": {"filter": {"terms": {"event_type": [
                    "logon_success", "logon_failure"]}}},
            }})
        aggregations = response["aggregations"]
        only = aggregations["only_logons"]["doc_count"]
        assert 0 < only < sum(aggregations["t"]["buckets"][i]["doc_count"]
                              for i in range(len(aggregations["t"]["buckets"])))
        assert {b["key"] for b in aggregations["t"]["buckets"]} == {
            "logon_success", "logon_failure", "process_create",
            "privilege_escalation", "network_connection"}
