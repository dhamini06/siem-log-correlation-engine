"""Build and validate the Kibana SOC Triage Board saved objects (Phase 5).

Generates `dashboards/soc-triage-board.ndjson` for Kibana 8.13, and validates an
existing file with `--check`.

Why this script exists
----------------------
Kibana stores the data view of a saved visualization *twice*: as a `references`
entry AND as an `indexRefName` pointer inside `kibanaSavedObjectMeta.searchSourceJSON`.

From @kbn/data-plugin/common/search/search_source/extract_references.js (save):

    const refName = 'kibanaSavedObjectMeta.searchSourceJSON.index';
    references.push({ name: refName, type: 'index-pattern', id: indexId });
    searchSourceFields = { ...searchSourceFields, indexRefName: refName, index: undefined };

and from inject_references.js (load):

    if (searchSourceFields.indexRefName) {
      searchSourceReturnFields.index = reference.id;   // resolved from references
    }

A saved object with the `references` entry but no `indexRefName` loads with an
empty data view, and every panel fails with "Could not find the data view: -".
`--check` enforces that invariant so it cannot come back.

Why the board is split across two data views
--------------------------------------------
The board has two jobs, and they read different indices:

* **Alert views** answer "what needs attention?" and read `security-alerts-*`,
  which holds the four documents the correlation engine produced.
* **Activity views** answer "is this normal?" and read `normalized-events-*`,
  which holds the 9,584-document fortnight.

Before Phase 5 every panel read `security-alerts-*`, so four of the panels
aggregated the same four documents and the board could not tell an analyst
anything about the data those alerts were found in. That is why each
visualization below names its own data view and why `validate()` resolves the
expected data view per object instead of assuming one.

Field availability is not symmetric, and that is verified against the real
mappings rather than assumed:

* `security-alerts-*` has `timestamp`, `first_seen`, `rule_name`,
  `evidence_count`. It has **no** `@timestamp`, `event_type` or `process.*`.
* `normalized-events-*` has `@timestamp`, `event_type`, `process.*`. It has
  **no** `timestamp`, `rule_name` or `first_seen`.
"""

import argparse
import hashlib
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_ROOT, "dashboards", "soc-triage-board.ndjson")

#: The exact reference name Kibana expects inside searchSourceJSON (see docstring).
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"

#: The investigation window, absolute rather than relative.
#:
#: The Phase 4A dataset is intentionally immutable: 9,584 events over
#: 2026-09-16 00:01:07Z .. 2026-09-29 23:57:07Z, from one fixed seed and one
#: fixed base timestamp, so every cohort reads the same evidence. A window
#: expressed relative to "now" therefore has the wrong shape: `now-15d`
#: covered the dataset when it was built and silently stopped covering it as
#: the clock advanced, at which point the board showed 3 of the 4 canonical
#: alerts instead of 4. An absolute window cannot age.
#:
#: The bounds carry a day of slack on each side, so containment does not
#: depend on the exact first and last event. If the dataset is ever
#: deliberately re-anchored, these two values change deliberately and together
#: with it - they are never derived from the clock.
#:
#: Kept in step with `INVESTIGATION_FROM` in training/assets/js/lab.js, which
#: builds the training pages' Discover links. Both are plain unquoted ISO
#: strings, because that is what Kibana stores in a saved object's `timeFrom`
#: and because tests/test_ui_render_contracts.py compares the two byte for
#: byte; the Rison quoting that Discover's URL needs is applied in lab.js at
#: the point of serialisation, not baked into the value.
INVESTIGATION_FROM = "2026-09-15T00:00:00.000Z"
INVESTIGATION_TO = "2026-09-30T23:59:59.999Z"

#: Kibana's `timeRestore`, and it is the opposite of what its name suggests.
#:
#: Measured on Kibana 8.13 against this board, reading the rendered time picker
#: in a real browser for each combination:
#:
#:     timeFrom=absolute ISO  timeRestore=false -> 0 rows, picker "Last 15 minutes"
#:     timeFrom=absolute ISO  timeRestore=true  -> 4 alerts, picker shows the dates
#:     timeFrom=now-15d       timeRestore=false -> 0 rows, picker "Last 15 minutes"
#:     timeFrom=now-15d       timeRestore=true  -> 3 alerts, picker "Last 15 days"
#:
#: So `false` makes Kibana discard the range saved on the dashboard and fall
#: back to its own 15-minute default - silently, with no error and no "No
#: results" anywhere. It does not mean "pin the lab's range"; it means "ignore
#: the lab's range", which is worse than the ageing problem this window exists
#: to solve. `true` is what applies the saved range.
#:
#: Set from measurement, not from the name. An earlier revision of this file set
#: it to `false` on the reasonable-sounding assumption that `false` would pin
#: the lab's range against a student's browser-local choice; the browser
#: experiment above is what disproved that.
TIME_RESTORE = True

#: Logical data-view keys. `time_field` is verified against the real index
#: mappings, not hard-coded from memory.
DATA_VIEWS = {
    "alerts": {
        "id": "siem-security-alerts",
        "title": "security-alerts-*",
        "time_field": "timestamp",
        "template": "elasticsearch-alert-template.json",
    },
    "events": {
        "id": "siem-normalized-events",
        "title": "normalized-events-*",
        "time_field": "@timestamp",
        "template": "elasticsearch-template.json",
    },
}

ALERTS = "alerts"
EVENTS = "events"


class DataViewError(Exception):
    pass


def resolve_data_view(dv):
    """Accept either a logical key or a raw data view id."""
    if dv in DATA_VIEWS:
        return dv
    for key, spec in DATA_VIEWS.items():
        if spec["id"] == dv:
            return key
    raise DataViewError(f"unknown data view {dv!r}")


def mapped_fields(template_name):
    """Every field name a template maps, flattened so `process.name` resolves."""
    path = os.path.join(REPO_ROOT, "config", template_name)
    with open(path, "r", encoding="utf-8") as handle:
        template = json.load(handle)
    out = set()

    def walk(prefix, node):
        for key, value in node.get("properties", {}).items():
            here = prefix + key
            out.add(here)
            if "properties" in value:
                walk(here + ".", value)

    walk("", template["template"]["mappings"])
    return out


# Fields that must never reach a panel. `reasoning` is the alert's own prose
# summary and it states the findings outright - e.g. "10 failed logons from
# 203.0.113.45 against web-01 within 5 minutes ... exceeded the threshold of 5" -
# which is the answer to the Scenario 01 and 02 questions. It stays in
# Elasticsearch for the instructor and for Discover, and out of the board.
FORBIDDEN_FIELDS = {"reasoning", "evidence_event_ids", "dedup_key"}


#: Visualization types this Kibana actually registers.
#:
#: Read out of the running Kibana, not assumed. Kibana 8.13 registers the XY
#: family as `area`, `line`, `histogram` and `horizontal_bar` - **not** `bar`.
#: TSVB's `table` type was removed years earlier, and `discover` is an
#: application, not a visualization type, so it cannot be embedded in a panel
#: either. All three mistakes were made in the first Phase 5 attempt and all
#: three produced a panel that failed to render, which is exactly what the
#: saved-object tests could not see.
XY_TYPES = ("area", "line", "histogram", "horizontal_bar")
SUPPORTED_VIS_TYPES = XY_TYPES + ("pie", "metric", "gauge", "tagcloud", "heatmap")

#: Names that look plausible and are not registered. Generating any of them
#: yields a panel that renders the string "Invalid visualization type".
UNSUPPORTED_VIS_TYPES = ("bar", "table", "discover", "goal", "markdown", "xy")

#: Declared on the Lens object so Kibana runs no saved-object migration against
#: it. Kibana reports this as the highest Lens migration it knows: with no
#: version at all it runs every migration from the beginning, and eleven of
#: those read the pre-8.x `datasourceStates.indexpattern.layers` shape that a
#: modern `formBased` object does not have - the import then dies with
#: "Cannot read properties of undefined (reading 'currentIndexPatternId')" and an
#: HTTP 500. Declaring a version *newer* than this is rejected outright with
#: "belongs to a more recent version of Kibana", so it must match exactly.
LENS_MIGRATION_VERSION = "8.9.0"


# ---------------------------------------------------------------- vis builders

def category_axis(position="bottom", truncate=100):
    return {"id": "CategoryAxis-1", "type": "category", "position": position, "show": True,
            "style": {}, "scale": {"type": "linear"},
            "labels": {"show": True, "truncate": truncate}, "title": {}}


def value_axis(label, position="left"):
    return {"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": position,
            "show": True, "style": {}, "scale": {"type": "linear"},
            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
            "title": {"text": label}}


def series_params(series_type, label, group_id=None, stacked=True):
    data = {"label": label, "id": "1"}
    if group_id:
        data["group"] = group_id
    return {"show": True, "type": series_type, "mode": "stacked" if stacked else "normal",
            "data": data, "valueAxis": "ValueAxis-1",
            "drawLinesBetweenPoints": True, "showCircles": True}


def count_agg(agg_id="1"):
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms_agg(field, agg_id, schema="segment", size=10):
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "isBucketed": True, "showLabels": True, "showTooltip": False,
                       "parentFormat": "as %s", "aggregationLabel": "",
                       "otherBucket": False, "missingBucket": False}}


def logon_terms_agg(agg_id):
    """A group bucket restricted to the two authentication event types.

    TSVB's terms bucket takes an `include` array of exact values, so this scopes
    the chart to logon_success and logon_failure without needing a saved search
    filter. The equivalent KQL filter on the search source made this panel throw
    at render time.
    """
    agg = terms_agg("event_type", agg_id, schema="group", size=2)
    agg["params"]["include"] = ["logon_success", "logon_failure"]
    agg["params"]["includeIsRegex"] = False
    agg["params"]["otherBucket"] = False
    return agg


def date_hist_agg(field, agg_id, interval="auto"):
    return {"id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": field, "interval": interval, "useNormalizedEsInterval": True,
                       "scaleMetricValues": False, "drop_partials": False, "min_doc_count": 1,
                       "extended_bounds": {}, "hard_bounds": {},
                       "timeRange": {"from": INVESTIGATION_FROM, "to": INVESTIGATION_TO}}}


def chart_vis_state(title, vis_type, aggs, series, metric_label, legend=True,
                    add_time_marker=False):
    """Build a TSVB visState.

    Two names are involved and they are not the same. `visState.type` is the
    registered visualization type; `params.type` is the internal chart type the
    renderer draws with. For most XY charts they match, but a horizontal bar is
    registered as `horizontal_bar` and drawn as a `histogram`, and its category
    axis is on the left with the value axis underneath. Getting this wrong
    renders nothing useful.
    """
    if vis_type in UNSUPPORTED_VIS_TYPES:
        raise ValueError(
            "%r is not a visualization type this Kibana registers. Registered: %s"
            % (vis_type, ", ".join(SUPPORTED_VIS_TYPES)))
    horizontal = vis_type == "horizontal_bar"
    internal_type = "histogram" if horizontal else vis_type
    return json.dumps({
        "title": title,
        "type": vis_type,
        "aggs": aggs,
        "params": {
            "type": internal_type,
            "grid": {},
            "categoryAxes": [category_axis(position="left" if horizontal else "bottom",
                                            truncate=200 if horizontal else 100)],
            "valueAxes": [value_axis(metric_label, position="bottom" if horizontal else "left")],
            "seriesParams": series,
            "addTooltip": True,
            "addLegend": legend,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": add_time_marker,
        },
    })


def _column_id(field):
    """A stable, UUID-shaped column id.

    Lens column ids are UUIDs. They have to be stable for the generated NDJSON to
    be byte-for-byte reproducible, so this derives one from the field name
    rather than generating a random UUID.
    """
    digest = hashlib.sha1(("siem-lens:" + field).encode("utf-8")).hexdigest()
    return "%s-%s-%s-%s-%s" % (digest[0:8], digest[8:12], digest[12:16],
                               digest[16:20], digest[20:32])


def doc_table_saved_object(oid, title, description, dv, columns):
    """A Lens data table: the only document table this Kibana can embed.

    TSVB's `table` visualization was removed before 8.13 and `discover` is an
    application rather than a visualization type, so neither can produce a
    per-document table in a dashboard panel. `lnsDatatable` is the supported
    equivalent.

    The shape below is transcribed from a datatable Kibana 8.13.0 ships with
    (the APM static dashboard), not guessed. Three details are load-bearing and
    each one produced a panel that failed to render when omitted:

    * ``state.visualization.columns`` holds *minimal* references -
      ``{"columnId": ..., "isTransposed": false}`` - not the column definitions.
      The definitions live only in the datasource layer.
    * ``state.internalReferences`` must be present (an empty list is fine).
    * every column carries ``scale`` and, for a terms bucket, a complete
      ``params`` including ``orderBy`` and ``parentFormat``.

    The column set is explicit. A Lens table showing every field would include
    the alert's `reasoning`, which states the findings outright, so the columns
    are named here and the forbidden ones are rejected outright.
    """
    forbidden = [c for c in columns if c in FORBIDDEN_FIELDS]
    if forbidden:
        raise ValueError("a Lens column would expose %r" % forbidden)

    layer_id = "siem-alerts-layer"
    index_ref = "indexpattern-datasource-layer-%s" % layer_id
    layer_columns, column_ids = {}, []

    for field in columns:
        column_id = _column_id(field)
        column_ids.append(column_id)
        if field in ("timestamp", "first_seen", "last_seen") or field.endswith("_at"):
            column = {"label": field, "dataType": "date",
                      "operationType": "date_histogram", "scale": "interval",
                      "sourceField": field, "isBucketed": True, "customLabel": True,
                      # The interval is pinned to a day on purpose. A finer one
                      # is worse here, not better: at ten-minute buckets Lens
                      # renders time-of-day only, so a fortnight-long queue showed
                      # "17:30" with no date at all, and the displayed value was
                      # the bucket start rather than the alert's own time. A day
                      # bucket gives the date, which is the triage question
                      # ("which day do I look at"), and the Alert Timeline panel
                      # carries the precise time. Verified by rendering.
                      "params": {"interval": "1d", "includeEmptyRows": True,
                                 "dropPartials": False, "timeZone": "UTC"}}
        elif field in ("evidence_count", "port", "process.pid", "process.parent_pid"):
            # A numeric field is a metric, so it aggregates per row instead of
            # expanding into one column per value.
            column = {"label": field, "dataType": "number", "operationType": "average",
                      "scale": "ratio", "sourceField": field, "isBucketed": False,
                      "customLabel": True, "params": {"emptyAsNull": True}}
        else:
            column = {"label": field, "dataType": "string", "operationType": "terms",
                      "scale": "ordinal", "sourceField": field, "isBucketed": True,
                      "customLabel": True,
                      "params": {"size": 10, "orderBy": {"type": "alphabetical"},
                                 "orderDirection": "asc", "otherBucket": False,
                                 "missingBucket": False, "parentFormat": {"id": "terms"},
                                 "include": [], "exclude": [],
                                 "includeIsRegex": False, "excludeIsRegex": False,
                                 "emptyAsNull": True}}
        layer_columns[column_id] = column

    state = {
        "visualization": {
            "layerId": layer_id,
            "layerType": "data",
            # Minimal references, not definitions. This is the detail that made
            # the first attempt fail: the datatable reads each entry's
            # columnId and colour settings, and a full column object there
            # throws inside the (silently caught) state conversion.
            "columns": [{"columnId": cid, "isTransposed": False} for cid in column_ids],
            "columnOrder": list(column_ids),
            "hideChart": False,
            "primaryGroups": [],
            "secondaryGroups": [],
            "valueLabels": "hide",
            "fittingFunction": "None",
            "legend": {"isVisible": True, "showSingleSeries": True},
        },
        "datasourceStates": {
            "formBased": {
                "layers": {
                    layer_id: {
                        "columnOrder": list(column_ids),
                        "columns": layer_columns,
                        "ignoreGlobalFilters": False,
                        "incompleteColumns": {},
                        "sampling": 1,
                        "index": index_ref,
                    },
                },
            },
        },
        "internalReferences": [],
        "query": {"query": "", "language": "kuery"},
        "filters": [],
        "adHocDataViews": {},
    }

    return {
        "type": "lens",
        "id": oid,
        "attributes": {
            "title": title,
            "description": description,
            "visualizationType": "lnsDatatable",
            "state": state,
        },
        "references": [{"name": index_ref, "type": "index-pattern",
                        "id": DATA_VIEWS[resolve_data_view(dv)]["id"]}],
        # Without this, Kibana treats the document as pre-history and runs every
        # Lens migration on it. Eleven of those read the pre-8.x
        # `datasourceStates.indexpattern.layers` shape that a modern `formBased`
        # object does not have, and the import dies with
        # "Cannot read properties of undefined (reading 'currentIndexPatternId')"
        # and an HTTP 500. Declaring a version *newer* than this is rejected
        # outright, so it must match exactly - Kibana reported 8.9.0.
        "migrationVersion": {"lens": LENS_MIGRATION_VERSION},
    }


def search_source(kuery_filter=None):
    """Search source as Kibana persists it: indexRefName pointer, no literal index.

    `kuery_filter` is a native Kibana filter, used to scope one panel to a
    subset of its data view. It is a saved filter, not custom code.
    """
    body = {
        "indexRefName": INDEX_REF_NAME,
        "query": {"query": "", "language": "kuery"},
        "filter": ([{"query": kuery_filter, "language": "kuery"}] if kuery_filter else []),
    }
    return json.dumps(body)


def data_view_reference(dv):
    return {"name": INDEX_REF_NAME, "type": "index-pattern",
            "id": DATA_VIEWS[resolve_data_view(dv)]["id"]}


def visualization(vid, title, description, vis_state, dv, kuery_filter=None):
    return {
        "type": "visualization",
        "id": vid,
        "attributes": {
            "title": title,
            "description": description,
            "visState": vis_state,
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(kuery_filter)},
        },
        "references": [data_view_reference(dv)],
    }


def index_pattern(key):
    spec = DATA_VIEWS[key]
    return {
        "type": "index-pattern",
        "id": spec["id"],
        "attributes": {
            "title": spec["title"],
            "timeFieldName": spec["time_field"],
            "fields": "[]",
            "fieldFormatMap": "{}",
            "runtimeFieldMap": "{}",
            "sourceFilters": "[]",
            "allowNoIndex": True,
        },
        "references": [],
        "migrationVersion": {"index-pattern": "8.0.0"},
    }


def panel(panel_index, x, y, w, h, title):
    return {"version": "8.13.0", "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
            "panelIndex": panel_index, "embeddableConfig": {},
            "panelRefName": f"panel_{panel_index}", "title": title}


# ------------------------------------------------------------------ the board

ALERT_QUEUE_COLUMNS = ["timestamp", "severity", "rule_name", "src_ip", "user",
                       "host", "evidence_count"]

# (panel index, x, y, w, h, saved object id)
LAYOUT = [
    ("1", 0, 0, 24, 18, "siem-lens-alert-queue"),
    ("2", 0, 18, 8, 14, "siem-vis-alert-severity"),
    ("3", 8, 18, 16, 14, "siem-vis-alert-timeline"),
    ("4", 0, 32, 24, 14, "siem-vis-auth-activity"),
    ("5", 0, 46, 12, 14, "siem-vis-src-ip-volume"),
    ("6", 12, 46, 12, 14, "siem-vis-event-type-mix"),
    ("7", 0, 60, 12, 14, "siem-vis-host-volume"),
    ("8", 12, 60, 12, 14, "siem-vis-alerts-by-host"),
]


def visualizations():
    """Every panel, in the order the dashboard references them.

    Titles and descriptions describe the telemetry and the data source. They do
    not characterise any host, address or account, because a frequency or a
    volume says nothing about intent and a board that asserts intent hands the
    student its conclusions.
    """
    return [
        # -- Section B: alert severity ---------------------------------------
        visualization(
            "siem-vis-alert-severity",
            "Alerts by Severity",
            "Alert count by severity, from security-alerts-*. Severity is set by "
            "the correlation rule that fired.",
            chart_vis_state(
                "Alerts by Severity", "histogram",
                [count_agg("1"), terms_agg("severity", "2", size=5)],
                [series_params("histogram", "Alerts", stacked=False)],
                "Alerts",
            ),
            ALERTS,
        ),
        # -- Section C: alert timeline ---------------------------------------
        visualization(
            "siem-vis-alert-timeline",
            "Alert Timeline",
            "Correlated alerts over the investigation window, split by severity, "
            "from security-alerts-*. Use it to see when activity was detected "
            "across the fortnight.",
            chart_vis_state(
                "Alert Timeline", "area",
                [count_agg("1"), date_hist_agg(DATA_VIEWS[ALERTS]["time_field"], "2"),
                 terms_agg("severity", "3", schema="group", size=5)],
                [series_params("area", "Alerts", group_id="3")],
                "Alerts",
                add_time_marker=True,
            ),
            ALERTS,
        ),
        # -- Section D: authentication activity ------------------------------
        # Scoped with an `include` filter on the bucket agg rather than a
        # saved KQL filter on the search source. The saved filter made TSVB's
        # params resolution throw "Cannot read properties of undefined" at
        # render time; the panel is scoped the same way, on the data.
        visualization(
            "siem-vis-auth-activity",
            "Authentication Activity",
            "Successful and failed logons per day, from normalized-events-*. This "
            "is the baseline the alerts are read against: a failure burst only "
            "means something next to the ordinary failure rate.",
            chart_vis_state(
                "Authentication Activity", "area",
                [count_agg("1"), date_hist_agg(DATA_VIEWS[EVENTS]["time_field"], "2"),
                 logon_terms_agg("3")],
                [series_params("area", "Logons", group_id="3")],
                "Logons",
            ),
            EVENTS,
        ),
        # -- Section E: source address activity ------------------------------
        visualization(
            "siem-vis-src-ip-volume",
            "Top Source IPs by Event Volume",
            "Source addresses ranked by event volume, from normalized-events-*. "
            "Volume reflects how much an address appears in the logs, not what it "
            "means. Events without a source address are excluded.",
            chart_vis_state(
                "Top Source IPs by Event Volume", "horizontal_bar",
                [count_agg("1"), terms_agg("src_ip", "2", size=10)],
                [series_params("histogram", "Events", stacked=False)],
                "Events", legend=False,
            ),
            EVENTS,
        ),
        # -- Section F: telemetry mix ----------------------------------------
        visualization(
            "siem-vis-event-type-mix",
            "Event Type Mix",
            "Share of each event type across the dataset, from normalized-events-*. "
            "Shows which kinds of telemetry the collectors are producing.",
            chart_vis_state(
                "Event Type Mix", "pie",
                [count_agg("1"), terms_agg("event_type", "2", size=10)],
                [series_params("pie", "Events", stacked=False)],
                "Events",
            ),
            EVENTS,
        ),
        # -- Section G: host activity ----------------------------------------
        visualization(
            "siem-vis-host-volume",
            "Event Volume by Host",
            "Hosts ranked by event volume, from normalized-events-*. The most "
            "active hosts are usually the busiest, not the most interesting.",
            chart_vis_state(
                "Event Volume by Host", "horizontal_bar",
                [count_agg("1"), terms_agg("host", "2", size=10)],
                [series_params("histogram", "Events", stacked=False)],
                "Events", legend=False,
            ),
            EVENTS,
        ),
        # -- Section H: alerts by host ---------------------------------------
        visualization(
            "siem-vis-alerts-by-host",
            "Alerts by Host",
            "Hosts that currently carry a correlated alert, from "
            "security-alerts-*. Compare against Event Volume by Host to tell a "
            "noisy host from a quiet one that drew attention.",
            chart_vis_state(
                "Alerts by Host", "histogram",
                [count_agg("1"), terms_agg("host", "2", size=10)],
                [series_params("histogram", "Alerts", stacked=False)],
                "Alerts",
            ),
            ALERTS,
        ),
    ]


def alert_queue():
    """Section A, the operational centrepiece. A Lens data table over the alerts."""
    return doc_table_saved_object(
        "siem-lens-alert-queue",
        "Alert Queue",
        "Correlated alerts from security-alerts-*, one row per alert the engine "
        "produced, newest first. Open an alert in Discover to reach its "
        "supporting events. The alert's own reasoning text is deliberately not "
        "shown here: it states the findings, which would hand over the "
        "conclusion before any evidence was read.",
        ALERTS,
        ALERT_QUEUE_COLUMNS,
    )


def build_panels():
    titles = {v["id"]: v["attributes"]["title"] for v in visualizations()}
    titles[alert_queue()["id"]] = alert_queue()["attributes"]["title"]
    return [panel(i, x, y, w, h, titles[vid]) for i, x, y, w, h, vid in LAYOUT]


def build_objects():
    panels = build_panels()
    return [
        index_pattern(ALERTS),
        index_pattern(EVENTS),
        alert_queue(),
        *visualizations(),
        {
            "type": "dashboard",
            "id": "siem-soc-triage-board",
            "attributes": {
                "title": "SOC Triage Board",
                "description": (
                    "Alert triage for the lab dataset. The queue and the severity, "
                    "timeline and per-host panels read security-alerts-*. The "
                    "authentication, source address, event type and host volume "
                    "panels read normalized-events-* and give context for the "
                    "alerts. Use the time picker to change the window."
                ),
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({
                    "useMargins": True, "syncColors": True, "syncCursor": True,
                    "syncTooltips": False, "hidePanelTitles": False,
                    "filterNav": False, "hidePanelTitlesInPopover": False,
                }),
                "version": 1,
                # Must stay True: see TIME_RESTORE above. False makes Kibana
                # ignore this dashboard's saved range and show 15 minutes.
                "timeRestore": TIME_RESTORE,
                # Absolute, and deliberately so - see INVESTIGATION_FROM above.
                # Kept in step with training/assets/js/lab.js by
                # tests/test_dashboard_ndjson.py.
                "timeFrom": INVESTIGATION_FROM,
                "timeTo": INVESTIGATION_TO,
                "refreshInterval": {"pause": False, "value": 60000},
                "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
            },
            "references": [data_view_reference(ALERTS)] + [
                {"name": f"{p['panelIndex']}:{p['panelRefName']}",
                 "type": "lens" if vid.startswith("siem-lens-") else "visualization",
                 "id": vid} for p, vid in zip(panels, [row[5] for row in LAYOUT])
            ],
        },
    ]


# ------------------------------------------------------------------ validation

def vis_fields(vis_state):
    """Every field name a TSVB visState aggregates on."""
    state = json.loads(vis_state)
    return [a["params"]["field"] for a in state.get("aggs", [])
            if a.get("params", {}).get("field")]


def lens_fields(obj):
    """Every field name a Lens data table shows."""
    state = obj["attributes"]["state"]
    layers = state.get("datasourceStates", {}).get("formBased", {}).get("layers", {})
    out = []
    for layer in layers.values():
        for column in layer.get("columns", {}).values():
            if column.get("sourceField"):
                out.append(column["sourceField"])
    return out


def panel_objects(objects):
    """Every object that a dashboard panel embeds, with its data view."""
    out = []
    for obj in objects:
        if obj["type"] == "visualization":
            ss = json.loads(obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            ref = next((r for r in obj["references"]
                        if r["name"] == ss.get("indexRefName")), None)
            fields = vis_fields(obj["attributes"]["visState"])
            out.append((obj, ref["id"] if ref else None, fields))
        elif obj["type"] == "lens":
            ref = obj["references"][0] if obj["references"] else None
            out.append((obj, ref["id"] if ref else None, lens_fields(obj)))
    return out


def validate(objects):
    """Return a list of consistency errors (empty means the file is importable)."""
    errors = []
    by_id = {(o["type"], o["id"]): o for o in objects}
    templates = {key: mapped_fields(spec["template"]) for key, spec in DATA_VIEWS.items()}
    id_to_key = {spec["id"]: key for key, spec in DATA_VIEWS.items()}

    # -- visualization types must exist in the running Kibana ---------------
    for obj in objects:
        if obj["type"] != "visualization":
            continue
        vis_type = json.loads(obj["attributes"]["visState"]).get("type")
        if vis_type in UNSUPPORTED_VIS_TYPES:
            errors.append(
                f"visualization/{obj['id']}: type {vis_type!r} is not registered by this "
                f"Kibana and renders 'Invalid visualization type'. Supported: "
                f"{', '.join(SUPPORTED_VIS_TYPES)}")
        elif vis_type not in SUPPORTED_VIS_TYPES:
            errors.append(
                f"visualization/{obj['id']}: type {vis_type!r} is not a known Kibana "
                f"visualization type. Supported: {', '.join(SUPPORTED_VIS_TYPES)}")

    # -- the indexRefName invariant, which applies to TSVB objects ----------
    for obj in objects:
        kind, oid = obj["type"], obj["id"]
        refs = obj.get("references", [])

        if kind in ("visualization", "dashboard"):
            raw = obj["attributes"].get("kibanaSavedObjectMeta", {}).get("searchSourceJSON")
            if not raw:
                errors.append(f"{kind}/{oid}: missing searchSourceJSON")
                continue
            ss = json.loads(raw)
            ref_name = ss.get("indexRefName")
            if not ref_name:
                errors.append(
                    f"{kind}/{oid}: searchSourceJSON has no 'indexRefName' -> the panel will "
                    f'resolve to "Could not find the data view: -"'
                )
            if ref_name and ref_name != INDEX_REF_NAME:
                errors.append(f"{kind}/{oid}: indexRefName is {ref_name!r}, expected {INDEX_REF_NAME!r}")
            if ss.get("index"):
                errors.append(f"{kind}/{oid}: searchSourceJSON must not carry a literal 'index'")
            match = [r for r in refs if r["name"] == (ref_name or INDEX_REF_NAME)]
            if not match:
                errors.append(f"{kind}/{oid}: no reference named {INDEX_REF_NAME!r}")
            elif match[0]["type"] != "index-pattern":
                errors.append(f"{kind}/{oid}: data view reference type is {match[0]['type']!r}")
            elif match[0]["id"] not in id_to_key:
                errors.append(f"{kind}/{oid}: data view reference points at "
                              f"{match[0]['id']!r}, which is not a lab data view")

    # -- per-panel data view and field existence ---------------------------
    for obj, data_view, fields in panel_objects(objects):
        if data_view not in id_to_key:
            errors.append(f"{obj['type']}/{obj['id']}: no resolvable data view reference")
            continue
        key = id_to_key[data_view]
        for field in fields:
            if field in FORBIDDEN_FIELDS:
                errors.append(f"{obj['type']}/{obj['id']}: panel displays {field!r}, which "
                              f"states findings rather than telemetry")
            elif field not in templates[key]:
                errors.append(f"{obj['type']}/{obj['id']}: {field!r} is not mapped in "
                              f"{DATA_VIEWS[key]['title']}")

    # -- dashboard layout and panel wiring ---------------------------------
    for obj in objects:
        kind, oid = obj["type"], obj["id"]
        refs = obj.get("references", [])
        if kind == "dashboard":
            panels = json.loads(obj["attributes"]["panelsJSON"])
            if len(panels) != len(LAYOUT):
                errors.append(f"{oid}: expected {len(LAYOUT)} panels, found {len(panels)}")
            seen = set()
            board_ids = {row[5] for row in LAYOUT}
            for p in panels:
                expected = f"{p['panelIndex']}:{p['panelRefName']}"
                match = [r for r in refs if r["name"] == expected]
                if not match:
                    errors.append(f"{oid}: panel {p['panelIndex']} has no matching reference {expected!r}")
                elif (match[0]["type"], match[0]["id"]) not in by_id:
                    errors.append(f"{oid}: panel {p['panelIndex']} targets "
                                  f"{match[0]['type']}/{match[0]['id']}, which is not in this file")
                if p["panelIndex"] in seen:
                    errors.append(f"{oid}: duplicate panelIndex {p['panelIndex']}")
                seen.add(p["panelIndex"])
                grid = p["gridData"]
                if grid["x"] + grid["w"] > 24:
                    errors.append(f"{oid}: panel {p['panelIndex']} overflows the 24-column grid")
            for ref in refs:
                if ref["type"] in ("visualization", "lens") and ref["id"] not in board_ids:
                    errors.append(f"{oid}: references {ref['type']} {ref['id']!r} "
                                  f"which is not part of the board")

        for ref in refs:
            if ref["type"] == "index-pattern" and ("index-pattern", ref["id"]) not in by_id:
                errors.append(f"{kind}/{oid}: reference target index-pattern/{ref['id']} not in file")
            if ref["type"] in ("visualization", "lens") and (ref["type"], ref["id"]) not in by_id:
                errors.append(f"{kind}/{oid}: reference target {ref['type']}/{ref['id']} not in file")

    for key, spec in DATA_VIEWS.items():
        dv = by_id.get(("index-pattern", spec["id"]))
        if not dv:
            errors.append(f"index-pattern/{spec['id']}: missing from the file")
            continue
        if dv["attributes"].get("title") != spec["title"]:
            errors.append(f"index-pattern/{spec['id']}: title must be {spec['title']!r}")
        if dv["attributes"].get("timeFieldName") != spec["time_field"]:
            errors.append(f"index-pattern/{spec['id']}: timeFieldName must be {spec['time_field']!r}")
        if spec["time_field"] not in templates[key]:
            errors.append(f"index-pattern/{spec['id']}: timeFieldName {spec['time_field']!r} "
                          f"is not mapped in the {spec['title']} template")

    ids = [o["id"] for o in objects]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        errors.append(f"duplicate saved object ids: {duplicates}")
    return errors


def write(path):
    objects = build_objects()
    errors = validate(objects)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for obj in objects:
            handle.write(json.dumps(obj) + "\n")
    print(f"Wrote {len(objects)} saved objects to {path}")
    return 0


def check(path):
    if not os.path.isfile(path):
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 1
    objects, bad = [], 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"ERROR: line {number} is not valid JSON: {exc}", file=sys.stderr)
                bad = 1
    errors = validate(objects)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
        bad = 1
    if not bad:
        kinds = {}
        for o in objects:
            kinds[o["type"]] = kinds.get(o["type"], 0) + 1
        print(f"OK: {len(objects)} objects, references consistent: {kinds}")
    return bad


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", default=OUTPUT_PATH, help="NDJSON output path")
    parser.add_argument("--check", action="store_true",
                        help="Validate an existing NDJSON file instead of writing one")
    args = parser.parse_args()
    return check(args.output) if args.check else write(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
