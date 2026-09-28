"""Build and validate the Kibana SOC Triage Board saved objects (Lab #07).

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
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_ROOT, "dashboards", "soc-triage-board.ndjson")

# Saved object ids. The visualizations, the dashboard, and the data views all
# resolve to ALERTS_DV; the normalized-events data view exists for drill-down.
ALERTS_DV_ID = "siem-security-alerts"
ALERTS_DV_TITLE = "security-alerts-*"
ALERTS_TIME_FIELD = "timestamp"
EVENTS_DV_ID = "siem-normalized-events"
EVENTS_DV_TITLE = "normalized-events-*"
EVENTS_TIME_FIELD = "@timestamp"

# The exact reference name Kibana expects inside searchSourceJSON (see docstring).
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"

CATEGORY_AXES = [{
    "id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
    "style": {}, "scale": {"type": "linear"},
    "labels": {"show": True, "truncate": 100}, "title": {},
}]
VALUE_AXES = [{
    "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
    "style": {}, "scale": {"type": "linear"},
    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
    "title": {"text": "Alerts"},
}]


def search_source() -> str:
    """Search source as Kibana persists it: indexRefName pointer, no literal index."""
    return json.dumps({
        "indexRefName": INDEX_REF_NAME,
        "query": {"query": "", "language": "kuery"},
        "filter": [],
    })


def data_view_reference() -> dict:
    return {"name": INDEX_REF_NAME, "type": "index-pattern", "id": ALERTS_DV_ID}


def count_agg(agg_id: str = "1") -> dict:
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms_agg(field: str, agg_id: str, schema: str = "segment", size: int = 10) -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "terms", "schema": schema,
        "params": {
            "field": field, "orderBy": "1", "order": "desc", "size": size,
            "isBucketed": True, "showLabels": True, "showTooltip": False,
            "parentFormat": "as %s", "aggregationLabel": "",
            "otherBucket": False, "missingBucket": False,
        },
    }


def date_hist_agg(field: str, agg_id: str) -> dict:
    return {
        "id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
        "params": {
            "field": field, "interval": "auto", "useNormalizedEsInterval": True,
            "scaleMetricValues": False, "drop_partials": False, "min_doc_count": 1,
            "extended_bounds": {}, "hard_bounds": {},
            "timeRange": {"from": "now-15m", "to": "now"},
        },
    }


def chart_vis_state(title: str, vis_type: str, aggs: list, series: list,
                    add_time_marker: bool = False) -> str:
    return json.dumps({
        "title": title,
        "type": vis_type,
        "aggs": aggs,
        "params": {
            "type": vis_type,
            "grid": {},
            "categoryAxes": CATEGORY_AXES,
            "valueAxes": VALUE_AXES,
            "seriesParams": series,
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": add_time_marker,
        },
    })


def table_vis_state(title: str, aggs: list, per_page: int = 10) -> str:
    return json.dumps({
        "title": title,
        "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": per_page,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showMeta": False,
            "sort": {"columnIndex": 1, "direction": "desc"},
            "showTotal": True,
            "totalFunc": "sum",
        },
    })


def series_params(series_type: str, group_id: str = None) -> dict:
    data = {"label": "Alerts", "id": "1"}
    if group_id:
        data["group"] = group_id
    return {
        "show": True, "type": series_type, "mode": "stacked", "data": data,
        "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True,
    }


def visualization(vid: str, title: str, description: str, vis_state: str) -> dict:
    return {
        "type": "visualization",
        "id": vid,
        "attributes": {
            "title": title,
            "description": description,
            "visState": vis_state,
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
        },
        "references": [data_view_reference()],
    }


def index_pattern(pid: str, title: str, time_field: str) -> dict:
    return {
        "type": "index-pattern",
        "id": pid,
        "attributes": {
            "title": title,
            "timeFieldName": time_field,
            "fields": "[]",
            "fieldFormatMap": "{}",
            "runtimeFieldMap": "{}",
            "sourceFilters": "[]",
            "allowNoIndex": True,
        },
        "references": [],
        "migrationVersion": {"index-pattern": "8.0.0"},
    }


def panel(panel_index: str, x: int, y: int, w: int, h: int, title: str) -> dict:
    return {
        "version": "8.13.0",
        "type": "visualization",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
        "panelIndex": panel_index,
        "embeddableConfig": {},
        "panelRefName": f"panel_{panel_index}",
        "title": title,
    }


PANELS = [
    panel("1", 0, 0, 24, 15, "SIEM Alerts by Severity"),
    panel("2", 0, 15, 24, 15, "Alert Timeline (by severity)"),
    panel("3", 0, 30, 12, 15, "Top Source IPs by Alert Count"),
    panel("4", 12, 30, 12, 15, "Suspicious Hosts by Alert Count"),
]


def build_objects() -> list:
    return [
        index_pattern(ALERTS_DV_ID, ALERTS_DV_TITLE, ALERTS_TIME_FIELD),
        index_pattern(EVENTS_DV_ID, EVENTS_DV_TITLE, EVENTS_TIME_FIELD),
        visualization(
            "siem-vis-alerts-by-severity",
            "SIEM Alerts by Severity",
            "Bar chart: alert count grouped by severity (low/medium/high/critical).",
            chart_vis_state(
                "SIEM Alerts by Severity", "histogram",
                [count_agg("1"), terms_agg("severity", "2", size=5)],
                [series_params("histogram")],
            ),
        ),
        visualization(
            "siem-vis-top-src-ips",
            "Top Source IPs by Alert Count",
            "Table: source IPs ranked by alert count with the most common targeted user.",
            table_vis_state(
                "Top Source IPs by Alert Count",
                [count_agg("1"), terms_agg("src_ip", "2", schema="bucket", size=10),
                 terms_agg("user", "3", schema="bucket", size=1)],
            ),
        ),
        visualization(
            "siem-vis-suspicious-hosts",
            "Suspicious Hosts by Alert Count",
            "Table: hosts ranked by alert count with the rules that fired on them.",
            table_vis_state(
                "Suspicious Hosts by Alert Count",
                [count_agg("1"), terms_agg("host", "2", schema="bucket", size=10),
                 terms_agg("rule_name", "3", schema="bucket", size=3)],
            ),
        ),
        visualization(
            "siem-vis-alert-timeline",
            "Alert Timeline (by severity)",
            "Line chart: alert volume over time split by severity for the selected range.",
            chart_vis_state(
                "Alert Timeline (by severity)", "line",
                [count_agg("1"), date_hist_agg(ALERTS_TIME_FIELD, "2"),
                 terms_agg("severity", "3", schema="group", size=5)],
                [series_params("line", group_id="3")],
                add_time_marker=True,
            ),
        ),
        {
            "type": "dashboard",
            "id": "siem-soc-triage-board",
            "attributes": {
                "title": "SOC Triage Board",
                "description": (
                    "Lab #07 SIEM alert triage. Panels: alert count by severity, alert timeline, "
                    "top source IPs, suspicious hosts. Filter by severity, rule_name, src_ip, or date range."
                ),
                "panelsJSON": json.dumps(PANELS),
                "optionsJSON": json.dumps({
                    "useMargins": True, "syncColors": False, "syncCursor": True,
                    "syncTooltips": False, "hidePanelTitles": False,
                }),
                "version": 1,
                "timeRestore": True,
                # Sample alerts are generated relative to "now"; a 7-day window keeps
                # this training dashboard populated whenever it is opened.
                "timeFrom": "now-7d",
                "timeTo": "now",
                "refreshInterval": {"pause": False, "value": 60000},
                "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
            },
            "references": [data_view_reference()] + [
                {"name": f"{p['panelIndex']}:{p['panelRefName']}", "type": "visualization",
                 "id": vid}
                for p, vid in zip(PANELS, [
                    "siem-vis-alerts-by-severity",
                    "siem-vis-alert-timeline",
                    "siem-vis-top-src-ips",
                    "siem-vis-suspicious-hosts",
                ])
            ],
        },
    ]


def validate(objects: list) -> list:
    """Return a list of consistency errors (empty means the file is importable)."""
    errors = []
    by_id = {(o["type"], o["id"]): o for o in objects}

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
            elif match[0]["id"] != ALERTS_DV_ID:
                errors.append(f"{kind}/{oid}: data view reference points at "
                              f"{match[0]['id']!r}, expected {ALERTS_DV_ID!r}")
            elif match[0]["type"] != "index-pattern":
                errors.append(f"{kind}/{oid}: data view reference type is {match[0]['type']!r}")

        if kind == "dashboard":
            panels = json.loads(obj["attributes"]["panelsJSON"])
            if len(panels) != 4:
                errors.append(f"{oid}: expected 4 panels, found {len(panels)}")
            for p in panels:
                expected = f"{p['panelIndex']}:{p['panelRefName']}"
                if not any(r["name"] == expected and r["type"] == "visualization" for r in refs):
                    errors.append(f"{oid}: panel {p['panelIndex']} has no matching reference {expected!r}")
                elif _panel_target(p, refs) is None:
                    errors.append(f"{oid}: panel {p['panelIndex']} reference target unresolved")

        for ref in refs:
            if ("index-pattern", ref["id"]) not in by_id and ref["type"] == "index-pattern":
                errors.append(f"{kind}/{oid}: reference target index-pattern/{ref['id']} not in file")
            if ref["type"] == "visualization" and ("visualization", ref["id"]) not in by_id:
                errors.append(f"{kind}/{oid}: reference target visualization/{ref['id']} not in file")

    dv = by_id.get(("index-pattern", ALERTS_DV_ID))
    if dv and dv["attributes"].get("timeFieldName") != ALERTS_TIME_FIELD:
        errors.append(f"index-pattern/{ALERTS_DV_ID}: timeFieldName must be {ALERTS_TIME_FIELD!r}")
    if dv and dv["attributes"].get("title") != ALERTS_DV_TITLE:
        errors.append(f"index-pattern/{ALERTS_DV_ID}: title must be {ALERTS_DV_TITLE!r}")
    return errors


def _panel_target(p: dict, refs: list):
    for r in refs:
        if r["name"] == f"{p['panelIndex']}:{p['panelRefName']}":
            return r["id"]
    return None


def write(path: str) -> int:
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


def check(path: str) -> int:
    if not os.path.isfile(path):
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 1
    objects, bad = [], 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", default=OUTPUT_PATH, help="NDJSON output path")
    parser.add_argument("--check", action="store_true",
                        help="Validate an existing NDJSON file instead of writing one")
    args = parser.parse_args()
    return check(args.output) if args.check else write(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
