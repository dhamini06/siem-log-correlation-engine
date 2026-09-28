"""SIEM Log Correlation Engine entry point.

Usage (Windows PowerShell):
  python -m src.main init-templates
  python -m src.main generate-samples --scenario all --output ./logs/generated
  python -m src.main ingest --log-dir ./logs/generated [--source-type linux_auth] [--dry-run]
  python -m src.main correlate --run-once
  python -m src.main correlate                 # scheduled daemon (default 60s)
  python -m src.main stats
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from .config import get_config
from .utils.logging_config import setup_logging

logger = logging.getLogger("siem.main")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_TEMPLATE_PATH = os.path.join(REPO_ROOT, "config", "elasticsearch-template.json")
ALERT_TEMPLATE_PATH = os.path.join(REPO_ROOT, "config", "elasticsearch-alert-template.json")
RAW_TEMPLATE_PATH = os.path.join(REPO_ROOT, "config", "elasticsearch-raw-template.json")


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _es_client():
    from .elasticsearch_client import get_es_client

    return get_es_client()


# -- Commands --

def cmd_init_templates(args: argparse.Namespace) -> int:
    """Apply the normalized-events, security-alerts and raw-events index templates."""
    es = _es_client()
    if not es.health_check():
        print(f"Elasticsearch is not reachable at {es.url}", file=sys.stderr)
        return 1

    applied = []
    for path, name in (
        (INDEX_TEMPLATE_PATH, "normalized-events"),
        (ALERT_TEMPLATE_PATH, "security-alerts"),
        # raw-events backs the optional Filebeat path (docs/TRAINING_PLATFORM.md).
        # The local sample workflow never writes to it, so installing the template
        # is inert: no index is created until Filebeat actually ships a document.
        (RAW_TEMPLATE_PATH, "raw-events"),
    ):
        if not os.path.isfile(path):
            print(f"Template file missing: {path}", file=sys.stderr)
            return 1
        body = _load_json(path)
        es.put_index_template(name, body)
        applied.append(name)
        print(f"Applied index template: {name}")

    print(f"Done. Templates applied: {', '.join(applied)}")
    return 0


def cmd_generate_samples(args: argparse.Namespace) -> int:
    """Generate synthetic sample logs for one or all scenarios."""
    from .normalization.sample_generator import SCENARIOS, generate_sample_logs

    scenarios: List[str] = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for scenario in scenarios:
        paths = generate_sample_logs(
            args.output, scenario, seed=args.seed, minutes_ago=args.minutes_ago
        )
        print(f"[{scenario}]")
        for kind, path in paths.items():
            print(f"  {kind:<9} -> {path}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Parse, validate, and index logs into normalized-events-*."""
    from .normalization.ingestion import NormalizationEngine, resolve_source_type

    source_type = resolve_source_type(args.source_type) if args.source_type else None
    engine = NormalizationEngine(dry_run=args.dry_run)

    if args.file:
        result = engine.ingest_file(args.file, source_type)
    else:
        result = engine.ingest_directory(args.log_dir, source_type)

    for error in result.errors[:20]:
        print(f"  ! {error}", file=sys.stderr)
    if len(result.errors) > 20:
        print(f"  ! ... and {len(result.errors) - 20} more error(s)", file=sys.stderr)

    print(f"Ingestion result: {result.summary()}")
    if not args.dry_run and result.indexed:
        for index_name, count in sorted(result.indices.items()):
            print(f"  Indexed {count} event(s) into {index_name}")
    return 0 if result.parsed or not result.errors else 1


def cmd_correlate(args: argparse.Namespace) -> int:
    """Run correlation once, or start the scheduled engine."""
    from .correlation.engine import CorrelationEngine

    es = _es_client()
    if not es.health_check():
        print(f"Elasticsearch is not reachable at {es.url}", file=sys.stderr)
        return 1

    engine = CorrelationEngine(es_client=es)
    if args.run_once:
        result = engine.run_correlation_cycle()
        print(result.summary())
        for rule, count in sorted(result.alerts_by_rule.items()):
            print(f"  {rule}: {count} alert(s) written")
        for error in result.errors:
            print(f"  ! {error}", file=sys.stderr)
        return 0

    scheduler = engine.start_scheduler()
    if scheduler is None:
        return 1

    engine.run_correlation_cycle()
    print(
        f"Correlation engine running every {engine.frequency_seconds}s "
        f"(Ctrl+C to stop). Engine status: {json.dumps(engine.status())}"
    )

    stop = False

    def handle_signal(signum, frame):  # pragma: no cover - signal path
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    try:
        signal.signal(signal.SIGTERM, handle_signal)
    except (AttributeError, ValueError):  # pragma: no cover - Windows without SIGTERM
        pass

    try:
        while not stop:
            time.sleep(1)
    finally:
        scheduler.shutdown(wait=False)
        engine.dedup.save()
        print(f"Correlation engine stopped. Status: {json.dumps(engine.status())}")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Print event and alert counts grouped by type/severity/rule."""
    es = _es_client()
    if not es.health_check():
        print(f"Elasticsearch is not reachable at {es.url}", file=sys.stderr)
        return 1

    events = es.count(index="normalized-events-*")
    alerts = es.count(index="security-alerts-*")
    print(f"normalized-events-* documents: {events}")
    print(f"security-alerts-* documents:  {alerts}")

    if events:
        by_type = es.aggregate(
            index="normalized-events-*",
            query={"match_all": {}},
            aggs={"event_types": {"terms": {"field": "event_type", "size": 20}}},
        )
        for bucket in by_type.get("event_types", {}).get("buckets", []):
            print(f"  {bucket['key']}: {bucket['doc_count']}")
    if alerts:
        by_sev = es.aggregate(
            index="security-alerts-*",
            query={"match_all": {}},
            aggs={"severities": {"terms": {"field": "severity", "size": 10}}},
        )
        for bucket in by_sev.get("severities", {}).get("buckets", []):
            print(f"  severity {bucket['key']}: {bucket['doc_count']}")
        by_rule = es.aggregate(
            index="security-alerts-*",
            query={"match_all": {}},
            aggs={"rules": {"terms": {"field": "rule_name", "size": 10}}},
        )
        for bucket in by_rule.get("rules", {}).get("buckets", []):
            print(f"  rule {bucket['key']}: {bucket['doc_count']}")
    return 0


def cmd_import_dashboard(args: argparse.Namespace) -> int:
    """Import the Kibana saved objects (SOC Triage Board) via the Kibana API."""
    import requests

    path = os.path.abspath(args.file)
    if not os.path.isfile(path):
        print(f"Dashboard file not found: {path}", file=sys.stderr)
        return 1

    base_url = args.kibana_url.rstrip("/")
    with open(path, "rb") as handle:
        response = requests.post(
            f"{base_url}/api/saved_objects/_import",
            params={"overwrite": "true"},
            headers={"kbn-xsrf": "siem-lab"},
            files={"file": (os.path.basename(path), handle, "application/ndjson")},
            timeout=args.timeout,
        )
    if response.status_code >= 400:
        print(f"Kibana import failed (HTTP {response.status_code}): {response.text[:400]}", file=sys.stderr)
        return 1

    payload = response.json()
    if not payload.get("success"):
        print(f"Kibana import reported failure: {payload}", file=sys.stderr)
        return 1

    print(f"Imported {payload.get('successCount', 0)} saved object(s) from {path} into {base_url}")
    for warning in payload.get("warnings", []):
        print(f"  ! {warning.get('message', warning)}", file=sys.stderr)
    for result in payload.get("successResults", []):
        print(f"  {result['type']}/{result['id']}  '{result.get('meta', {}).get('title', '')}'")
    print(f"Open the dashboard at: {base_url}/app/dashboards#/view/siem-soc-triage-board")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Shared option so --log-level works both before and after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR")

    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="SIEM Log Correlation Engine (Lab #07)",
    )
    parser.add_argument("--log-level", dest="global_log_level", default=None, help="DEBUG, INFO, WARNING, ERROR")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-templates", parents=[common], help="Create Elasticsearch index templates")
    init_parser.set_defaults(func=cmd_init_templates)

    samples_parser = subparsers.add_parser("generate-samples", parents=[common], help="Generate synthetic sample logs")
    from .normalization.sample_generator import SCENARIOS

    samples_parser.add_argument(
        "--scenario", default="all", choices=list(SCENARIOS) + ["all"], help="Scenario to generate"
    )
    samples_parser.add_argument("--output", default="./logs/generated", help="Output directory")
    samples_parser.add_argument("--seed", type=int, default=1337, help="RNG seed")
    samples_parser.add_argument(
        "--minutes-ago", type=int, default=5, help="Anchor scenario this many minutes in the past"
    )
    samples_parser.set_defaults(func=cmd_generate_samples)

    ingest_parser = subparsers.add_parser("ingest", parents=[common], help="Normalize and index log files")
    ingest_parser.add_argument("--log-dir", default="./logs/generated", help="Directory of log files")
    ingest_parser.add_argument("--file", help="Ingest a single file instead of a directory")
    ingest_parser.add_argument(
        "--source-type",
        choices=["linux_auth", "windows_sysmon", "firewall_syslog"],
        help="Force the source type instead of auto-detecting",
    )
    ingest_parser.add_argument(
        "--dry-run", action="store_true", help="Parse and validate without indexing"
    )
    ingest_parser.set_defaults(func=cmd_ingest)

    correlate_parser = subparsers.add_parser("correlate", parents=[common], help="Run correlation rules")
    correlate_parser.add_argument(
        "--run-once", action="store_true", help="Run a single cycle and exit"
    )
    correlate_parser.set_defaults(func=cmd_correlate)

    stats_parser = subparsers.add_parser("stats", parents=[common], help="Show event and alert counts")
    stats_parser.set_defaults(func=cmd_stats)

    import_parser = subparsers.add_parser(
        "import-dashboard", parents=[common], help="Import Kibana saved objects (SOC Triage Board)"
    )
    import_parser.add_argument(
        "--file",
        default=os.path.join(REPO_ROOT, "dashboards", "soc-triage-board.ndjson"),
        help="Saved objects NDJSON file to import",
    )
    import_parser.add_argument(
        "--kibana-url",
        default=os.environ.get("KIBANA_URL", "http://localhost:5601"),
        help="Kibana base URL (env: KIBANA_URL)",
    )
    import_parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout in seconds")
    import_parser.set_defaults(func=cmd_import_dashboard)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = (
        getattr(args, "log_level", None)
        or getattr(args, "global_log_level", None)
        or get_config().get("app", {}).get("log_level", "INFO")
    )
    setup_logging(log_level=log_level, log_to_file=True)

    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("Interrupted.")
        return 130
    except Exception as exc:
        logger.exception("Command failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
