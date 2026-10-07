"""Reset the SIEM lab to a known-clean state.

The training lab must always start from the same dataset. Two datasets exist and
they are alternatives, never layers:

* the **enterprise** dataset - 9,584 events over fourteen days plus 4 alerts,
  which is what the approved training content and the instructor answer key are
  written against;
* the **per-scenario demonstration** fixtures - 50 events plus 4 alerts, which
  `generate-samples` can recreate on demand.

Re-running either pipeline without a reset does NOT reproduce its state. The
Windows records carry millisecond timestamps taken from the clock at generation
time, so their deterministic document IDs change on every run and six duplicate
events accumulate per cycle (the syslog records are second-resolution and
collapse onto the same IDs).

This script therefore deletes only the two regenerable lab indices plus the
dedup cache. It never touches the Elasticsearch or Kibana volumes, index
templates, data views, dashboards, or the correlation configuration.

**It also refuses to delete a dataset it cannot rebuild.** A reset that is not
followed by the matching rebuild leaves an empty lab, so the preflight below
establishes which dataset is installed and whether its source is present before
anything is removed. ``--yes`` confirms the deletion; it does not bypass that
check.

    python scripts/reset_lab_data.py --yes
    python scripts/reset_lab_data.py --check
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

#: Where both datasets' files live. Only used with the enterprise generator's own
#: helpers, so this module never enumerates the directory itself.
DEFAULT_LOG_DIR = os.path.join(ROOT, "logs", "generated")

DATASET_MODES = ("auto", "enterprise", "demo")

#: The enterprise dataset's own date span. `correlate --run-once` scans only
#: `[now - 120min, now]`, which sees about an hour of a fortnight-long dataset,
#: so the enterprise rebuild correlates the range rather than a single cycle.
ENTERPRISE_SINCE = "2026-09-16T00:00:00Z"
ENTERPRISE_UNTIL = "2026-09-30T00:00:00Z"


def enterprise_source_files(log_dir: str = DEFAULT_LOG_DIR):
    """The enterprise dataset's source files that are actually present.

    Which files count as the enterprise dataset is not decided here:
    ``dataset_paths`` is the generator's own definition, so this cannot drift
    from whatever the generator writes.
    """
    from src.normalization.enterprise_generator import dataset_paths

    return [p for p in dataset_paths(log_dir).values() if os.path.isfile(p)]


def rebuild_commands(mode: str, log_dir: str = DEFAULT_LOG_DIR):
    """The commands that rebuild `mode` after a reset. Verified commands only.

    The enterprise path ingests the three files *by name*. Directory ingestion
    cannot be used for it: the per-scenario demonstration fixtures share
    ``logs/generated``, and a directory holding both datasets is refused by the
    ingestion guard. Naming each file is unambiguous and is never refused.
    """
    from src.normalization.enterprise_generator import dataset_paths

    if mode == "enterprise":
        paths = [os.path.relpath(p, ROOT) for p in dataset_paths(log_dir).values()]
        return (
            ["python -m src.main ingest --file %s" % p for p in paths]
            + ["python scripts\\correlate_range.py --since %s --until %s --expect-alerts 4"
               % (ENTERPRISE_SINCE, ENTERPRISE_UNTIL)]
        )
    return [
        "python -m src.main generate-samples --scenario all",
        "python -m src.main ingest --log-dir .\\logs\\generated",
        "python -m src.main correlate --run-once",
    ]


def preflight(mode: str = "auto", log_dir: str = DEFAULT_LOG_DIR):
    """Decide whether a reset here could be followed by a rebuild.

    Returns a dict with ``safe`` and a ``reason``. Never destructive, so it is
    safe to call for reporting.

    The rule is deliberately conservative and needs no guessing about what is
    currently in Elasticsearch:

    * the enterprise dataset is present exactly when its own source files are;
    * it can only be rebuilt from those files;
    * therefore a reset may proceed in enterprise mode only when they are all
      present, and in demo mode only when they are not - because a demo reset
      over an installed enterprise dataset replaces the approved training data
      with 50 demonstration events and cannot put it back.
    """
    present = enterprise_source_files(log_dir)
    complete = len(present) == 3

    if mode == "enterprise":
        resolved = "enterprise"
        safe = complete
        reason = ("enterprise source files are all present, so the dataset can be "
                  "rebuilt" if safe else
                  "enterprise mode was requested but its source files are missing from "
                  "%s, so deleting the dataset could not be undone" % log_dir)
    elif mode == "demo":
        resolved = "demo"
        safe = not complete
        reason = ("no enterprise dataset is installed, so the demonstration fixtures "
                  "can be regenerated" if safe else
                  "demo mode was requested but the enterprise source files are present "
                  "in %s. Deleting now would replace the approved training dataset "
                  "with 50 demonstration events that cannot restore it. Use the "
                  "enterprise rebuild, or move the enterprise files out of the way "
                  "first." % log_dir)
    else:
        resolved = "enterprise" if complete else "demo"
        safe = True
        reason = ("enterprise source files present, so this resolves to the enterprise "
                  "rebuild" if complete else
                  "no enterprise source files present, so this resolves to the "
                  "demonstration rebuild")

    return {
        "requested": mode,
        "resolved": resolved,
        "safe": safe,
        "reason": reason,
        "enterprise_source": present,
        "enterprise_source_complete": complete,
        "rebuild": rebuild_commands(resolved, log_dir),
    }


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
    parser.add_argument("--check", action="store_true",
                        help="Report whether a reset would be safe, then stop")
    parser.add_argument("--print-mode", action="store_true",
                        help="Print only the resolved dataset mode, for scripts to read")
    parser.add_argument("--mode", choices=DATASET_MODES, default="auto",
                        help="Which dataset this reset is in service of (default: auto)")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR,
                        help="Directory holding the datasets' files")
    args = parser.parse_args()

    # Safety first, and before Elasticsearch is even contacted: a reset that
    # cannot be followed by a rebuild is refused whatever --yes says. `--yes`
    # confirms the deletion, it does not authorise destroying data.
    plan = preflight(args.mode, args.log_dir)
    print("=" * 66)
    print("  SIEM lab data reset")
    print("=" * 66)
    print(f"  dataset mode        : {plan['requested']} -> {plan['resolved']}")
    print(f"  enterprise source   : {len(plan['enterprise_source'])} of 3 file(s) present"
          f" in {args.log_dir}")
    print(f"  rebuild safety      : {'SAFE' if plan['safe'] else 'REFUSED'}")
    print(f"                        {plan['reason']}")
    print("=" * 66)

    if args.print_mode:
        # One bare token on stdout, so a launcher can branch on it without
        # parsing the human-readable report. Non-zero when the reset is unsafe,
        # which lets the caller stop before it deletes anything.
        if not plan["safe"]:
            print(plan["reason"], file=sys.stderr)
            return 1
        print(plan["resolved"])
        return 0

    if not plan["safe"]:
        print("\n  Nothing has been deleted. Refusing to reset a dataset that cannot "
              "be\n  rebuilt from what is on disk.", file=sys.stderr)
        print("\n  Rebuild commands for the dataset that *is* installed:")
        for command in plan["rebuild"]:
            print(f"    {command}")
        return 1

    if args.check:
        print("\n  --check: stopping before any deletion.")
        return 0

    es = get_es_client()
    if not es.health_check():
        print(f"Elasticsearch is not reachable at {es.url}", file=sys.stderr)
        return 1

    events, alerts = lab_counts(es)
    targets = []
    for pattern in LAB_INDICES:
        targets.extend(resolve_indices(es, pattern))
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
    print(f"\n  Lab data cleared. Rebuild the {plan['resolved']} dataset with:")
    for command in plan["rebuild"]:
        print(f"    {command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
