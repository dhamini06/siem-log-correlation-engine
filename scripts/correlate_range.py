"""Run the correlation rules over a whole date range and write the alerts.

Why this exists
---------------
``CorrelationEngine.run_correlation_cycle()`` scans ``[now - 120min, now]``,
which is the right behaviour for a live engine watching a moving window. The
Phase 4A dataset deliberately spans fourteen days, so a single ``correlate
--run-once`` would see roughly one hour of it and produce nothing.

This script is a *backfill*: it widens the time range and changes nothing else.
It calls the engine's own ``fetch_events``, the same ``apply_rules``, the same
``AlertDeduplicator.filter_alerts``, the same ``index_alert`` call and the same
``alert_document_id``. No rule, no threshold, no alert shape and no
deduplication behaviour differs from the scheduled engine.

Because the document id is a deterministic function of the alert's content,
running this twice over the same data overwrites the same documents rather than
duplicating them.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.config import get_config  # noqa: E402
from src.correlation.alert_schema import alert_document_id  # noqa: E402
from src.correlation.engine import CorrelationEngine  # noqa: E402
from src.correlation.rules import apply_rules, load_events  # noqa: E402
from src.utils.time_utils import query_time_range  # noqa: E402

NORMALIZED_INDEX = "normalized-events-*"
#: The engine's per-cycle cap. This script does not raise it silently: if the
#: range holds more events than this, the run is refused rather than quietly
#: correlating a prefix of the data.
MAX_EVENTS = 10000


def parse_utc(value):
    text = value.replace("+00:00", "Z")
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def backfill(engine, since, until):
    """Evaluate the rules across [since, until) and index any new alerts."""
    available = engine.es.count(
        index=NORMALIZED_INDEX,
        query={"bool": {"filter": [query_time_range("@timestamp", since, until)]}},
    )
    if available > MAX_EVENTS:
        raise SystemExit(
            "range holds %d events, more than the %d-event cap. Narrow the range "
            "rather than correlating a silent prefix of the data."
            % (available, MAX_EVENTS))

    hits = engine.fetch_events(since, until)
    print("  events in range : %d" % len(hits))
    if not hits:
        print("  nothing to correlate")
        return {"events": 0, "created": 0, "suppressed": 0, "by_rule": {}}

    alerts = apply_rules(load_events(hits), engine.config)
    to_emit, suppressed = engine.dedup.filter_alerts(alerts)

    by_rule = {}
    for alert in to_emit:
        engine.es.index_alert(alert.index_name(), alert.to_dict(), alert_document_id(alert))
        by_rule[alert.rule_name] = by_rule.get(alert.rule_name, 0) + 1
        print("      %-30s %-9s %-16s %s"
              % (alert.rule_name, alert.severity.value, alert.src_ip, alert.host))
    if to_emit:
        engine.es.refresh(index="security-alerts-*")
    engine.dedup.save()

    if len(suppressed):
        print("      (%d suppressed as duplicates of recent alerts)" % len(suppressed))
    return {"events": len(hits), "created": len(to_emit),
            "suppressed": len(suppressed), "by_rule": by_rule}


def main():
    parser = argparse.ArgumentParser(
        description="Correlate a whole date range and write the alerts (backfill)")
    parser.add_argument("--since", required=True,
                        help="Start of the range, ISO-8601 UTC")
    parser.add_argument("--until", default=None,
                        help="End of the range (default: now)")
    parser.add_argument("--expect-alerts", type=int, default=None,
                        help="Exit non-zero unless exactly this many alerts are written")
    args = parser.parse_args()

    since = parse_utc(args.since)
    until = parse_utc(args.until) if args.until else datetime.now(timezone.utc)
    if until <= since:
        print("--until must be after --since", file=sys.stderr)
        return 1

    from src.elasticsearch_client import get_es_client
    es = get_es_client()
    if not es.health_check():
        print("Elasticsearch is not reachable at %s" % es.url, file=sys.stderr)
        return 1

    engine = CorrelationEngine(es_client=es, config=get_config())
    print("Correlation backfill  %s  ->  %s"
          % (since.isoformat(), until.isoformat()))
    result = backfill(engine, since, until)
    print("  alerts written  : %d (suppressed %d)"
          % (result["created"], result["suppressed"]))
    if result["by_rule"]:
        print("  by rule         : %s" % json.dumps(result["by_rule"], sort_keys=True))

    if args.expect_alerts is not None and result["created"] != args.expect_alerts:
        print("EXPECTED %d ALERTS, WROTE %d" % (args.expect_alerts, result["created"]),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
