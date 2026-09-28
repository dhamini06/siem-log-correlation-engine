"""Reset the SIEM lab to a known-clean state.

The training lab must always start from the same dataset: 50 normalized events
and 4 alerts, which is what the five scenarios and the instructor answer key are
written against.

Re-running the pipeline without a reset does NOT reproduce that state. The
Windows sample records carry millisecond timestamps taken from the clock at
generation time, so their deterministic document IDs change on every run and six
duplicate events accumulate per cycle (the syslog records are second-resolution
and collapse onto the same IDs).

This script therefore deletes only the two regenerable lab indices plus the
dedup cache. It never touches the Elasticsearch or Kibana volumes, index
templates, data views, dashboards, or the correlation configuration.

    python scripts/reset_lab_data.py --yes
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.config import get_config  # noqa: E402
from src.elasticsearch_client import get_es_client  # noqa: E402

LAB_INDICES = ("normalized-events-*", "security-alerts-*")


def lab_counts(es_client=None):
    """Current (events, alerts) document counts, or (None, None) if unavailable."""
    es = es_client or get_es_client()
    counts = []
    for pattern in LAB_INDICES:
        try:
            counts.append(es.count(pattern))
        except Exception:
            counts.append(None)
    return counts[0], counts[1]


def resolve_indices(es, pattern):
    """Expand a pattern such as ``normalized-events-*`` into concrete index names.

    Elasticsearch 8 defaults to ``action.destructive_requires_name=true``, which
    rejects wildcard deletions outright, so the names must be resolved first and
    each concrete index deleted by name.
    """
    try:
        response = es.es.indices.get(
            index=pattern,
            allow_no_indices=True,
            ignore_unavailable=True,
            expand_wildcards="all",
        )
        return sorted(response.keys())
    except Exception:
        return []


def reset(es_client=None, dedup_cache_path: str = None) -> dict:
    """Delete the lab indices and dedup cache.

    Returns a summary dict of what was removed, including the counts afterwards so
    the caller can confirm the reset actually happened.
    """
    es = es_client or get_es_client()
    config = get_config()
    if dedup_cache_path is None:
        dedup_cache_path = config.get("correlation", {}).get(
            "dedup_cache_path", "data/dedup-cache.json"
        )
    if not os.path.isabs(dedup_cache_path):
        dedup_cache_path = os.path.join(ROOT, dedup_cache_path)

    before_events, before_alerts = lab_counts(es)
    removed, errors = [], []
    for pattern in LAB_INDICES:
        for name in resolve_indices(es, pattern):
            try:
                es.es.indices.delete(index=name, ignore_unavailable=True)
                removed.append(name)
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"{name}: {exc}")

    cache_removed = False
    if os.path.isfile(dedup_cache_path):
        os.remove(dedup_cache_path)
        cache_removed = True

    after_events, after_alerts = lab_counts(es)
    return {
        "events_before": before_events,
        "alerts_before": before_alerts,
        "events_after": after_events,
        "alerts_after": after_alerts,
        "indices_deleted": removed,
        "errors": errors,
        "dedup_cache_removed": cache_removed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset the SIEM lab dataset")
    parser.add_argument("--yes", action="store_true", help="Confirm the deletion")
    args = parser.parse_args()

    es = get_es_client()
    if not es.health_check():
        print(f"Elasticsearch is not reachable at {es.url}", file=sys.stderr)
        return 1

    events, alerts = lab_counts(es)
    targets = []
    for pattern in LAB_INDICES:
        targets.extend(resolve_indices(es, pattern))
    print("=" * 66)
    print("  SIEM lab data reset")
    print("=" * 66)
    print(f"  current normalized events : {events}")
    print(f"  current security alerts   : {alerts}")
    if targets:
        print("  will delete indices       :")
        for name in targets:
            print(f"    - {name}")
    else:
        print("  will delete indices       : (none exist - already clean)")
    print("  will delete dedup cache   : data/dedup-cache.json")
    print("  (Elasticsearch and Kibana volumes, templates and dashboards are untouched)")
    print("=" * 66)

    if not args.yes:
        print("\nRe-run with --yes to proceed.", file=sys.stderr)
        return 1

    summary = reset(es)
    for name in summary["indices_deleted"]:
        print(f"  deleted index  : {name}")
    for error in summary["errors"]:
        print(f"  DELETE FAILED  : {error}", file=sys.stderr)
    if summary["dedup_cache_removed"]:
        print("  deleted        : data/dedup-cache.json")

    # Never report success unless the indices are actually gone.
    remaining = summary["events_after"] or summary["alerts_after"]
    if summary["errors"] or remaining:
        print(
            f"\n  RESET INCOMPLETE: normalized-events={summary['events_after']} "
            f"security-alerts={summary['alerts_after']} remain.",
            file=sys.stderr,
        )
        return 1

    print(f"  verified empty : normalized-events={summary['events_after']} "
          f"security-alerts={summary['alerts_after']}")
    print("\n  Lab data cleared. Now run:")
    print("    python -m src.main generate-samples --scenario all")
    print("    python -m src.main ingest --log-dir .\\logs\\generated")
    print("    python -m src.main correlate --run-once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
