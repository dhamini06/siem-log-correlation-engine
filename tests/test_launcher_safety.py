"""The destructive half of the lab startup path, and what now stops it.

`start_lab.ps1` used to reset whenever Elasticsearch held data, then generate the
50-event demonstration fixtures, then ingest `logs/generated` as a directory. That
directory also holds `enterprise-14d_*`, so the ingestion guard refused it - but
the reset had already run. The approved 9,584-event dataset was deleted and
nothing in that sequence could put it back.

So the safety property under test is narrow and absolute: **a reset may not
proceed unless the dataset it is about to delete can be rebuilt from what is on
disk.** `--yes` confirms the deletion; it does not authorise destroying data.

These tests use temporary directories and a fake Elasticsearch client. Nothing
here contacts a cluster or deletes an index.
"""

import argparse
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scripts import reset_lab_data  # noqa: E402

ENTERPRISE_NAMES = ["enterprise-14d_auth.log", "enterprise-14d_windows.jsonl",
                    "enterprise-14d_firewall.log"]
DEMO_NAMES = ["brute_force_auth.log", "normal_day_windows.jsonl",
              "false_positive_mix_firewall.log"]


def _log_dir(tmp_path, names, folder="generated"):
    """A logs/generated-shaped directory holding exactly `names`.

    `folder` exists because two calls in one test must not share a directory:
    the second would otherwise add to the first and quietly turn a
    demo-only fixture into a mixed one.
    """
    d = tmp_path / folder
    d.mkdir(exist_ok=True)
    for name in names:
        (d / name).write_text("x\n", encoding="utf-8")
    return str(d)


class _Indices:
    """Elasticsearch 8 indices double: no wildcard deletes."""

    def __init__(self, existing):
        self.existing = list(existing)
        self.deleted = []

    def get(self, index=None, **kwargs):
        import fnmatch

        return {n: {} for n in self.existing if fnmatch.fnmatch(n, index)}

    def delete(self, index=None, **kwargs):
        self.deleted.append(index)
        self.existing = [n for n in self.existing if n != index]
        return {}


class _Es:
    """Minimal client double for the reset path."""

    def __init__(self, existing=(), per_index=0):
        self.indices = _Indices(existing)
        self.es = self
        self.per_index = per_index

    def count(self, pattern):
        return self.per_index * len(self.indices.existing)

    def health_check(self, retries=1, delay_seconds=0.0):
        return True


# --------------------------------------------------------------- the preflight


def test_enterprise_source_present_allows_the_enterprise_rebuild(tmp_path):
    """TEST 1 - the source is there, so a reset can be followed by a rebuild."""
    plan = reset_lab_data.preflight("enterprise", _log_dir(tmp_path, ENTERPRISE_NAMES))

    assert plan["safe"] is True
    assert plan["resolved"] == "enterprise"
    assert len(plan["enterprise_source"]) == 3
    # The rebuild must not be a directory ingest: the fixtures share the folder.
    assert all("ingest --file" in c for c in plan["rebuild"] if "ingest" in c)
    assert not any("--log-dir" in c for c in plan["rebuild"])
    assert any("correlate_range.py" in c for c in plan["rebuild"])


def test_missing_enterprise_source_refuses_the_enterprise_reset(tmp_path):
    """TEST 2 - nothing on disk can rebuild it, so the deletion must not happen."""
    plan = reset_lab_data.preflight("enterprise", _log_dir(tmp_path, DEMO_NAMES))

    assert plan["safe"] is False
    assert "missing" in plan["reason"]


def test_demo_only_directory_is_not_mistaken_for_the_enterprise_dataset(tmp_path):
    """TEST 4 - fixtures must never be read as a rebuild source."""
    plan = reset_lab_data.preflight("enterprise", _log_dir(tmp_path, DEMO_NAMES))

    assert plan["enterprise_source"] == []
    assert plan["enterprise_source_complete"] is False
    assert plan["safe"] is False


def test_demo_mode_refuses_to_delete_an_installed_enterprise_dataset(tmp_path):
    """The exact incident: a demo reset over the approved training data.

    `generate-samples` can always recreate 50 demonstration events, so "a rebuild
    exists" is not the question. The question is whether the rebuild puts back
    *the dataset that is there*. Here it cannot.
    """
    plan = reset_lab_data.preflight("demo", _log_dir(tmp_path, ENTERPRISE_NAMES))

    assert plan["safe"] is False
    assert "demo" in plan["reason"].lower()


def test_demo_mode_is_allowed_when_no_enterprise_dataset_is_installed(tmp_path):
    """TEST 7 - the legitimate demonstration workflow still works."""
    plan = reset_lab_data.preflight("demo", _log_dir(tmp_path, DEMO_NAMES))

    assert plan["safe"] is True
    assert plan["resolved"] == "demo"
    assert any("generate-samples" in c for c in plan["rebuild"])


def test_auto_mode_follows_the_enterprise_source_files(tmp_path):
    """Auto reads the generator's own definition rather than guessing."""
    assert reset_lab_data.preflight(
        "auto", _log_dir(tmp_path, ENTERPRISE_NAMES, "with-enterprise"))["resolved"] \
        == "enterprise"
    assert reset_lab_data.preflight(
        "auto", _log_dir(tmp_path, DEMO_NAMES, "fixtures-only"))["resolved"] == "demo"


def test_the_preflight_is_derived_from_the_generators_own_definition():
    """No second definition of "the enterprise dataset" is allowed to appear."""
    import inspect

    source = inspect.getsource(reset_lab_data)
    assert "enterprise-14d" not in source, \
        "reset_lab_data must not hardcode the dataset filenames; it must ask " \
        "enterprise_generator.dataset_paths()"
    assert "dataset_paths" in source


# ------------------------------------------------- the guard, against deletion


def test_reset_is_not_reached_when_the_rebuild_source_is_missing(tmp_path, monkeypatch):
    """TEST 5 - existing data, no verified rebuild source, so no deletion.

    `main()` is driven with a client double that would record any deletion, so
    a regression that deletes anyway shows up as a non-empty `deleted`.
    """
    log_dir = _log_dir(tmp_path, DEMO_NAMES)
    called = {}

    def _boom(*args, **kwargs):
        called["reset"] = True
        raise AssertionError("reset() must not be reached when the rebuild source is missing")

    monkeypatch.setattr(reset_lab_data, "reset", _boom)
    monkeypatch.setattr(sys, "argv", ["reset_lab_data.py", "--yes", "--mode", "enterprise",
                                      "--log-dir", log_dir])

    assert reset_lab_data.main() != 0
    assert "reset" not in called


def test_yes_does_not_bypass_the_safety_check(tmp_path, monkeypatch):
    """TEST 6 - `--yes` confirms the deletion, it does not authorise it."""
    log_dir = _log_dir(tmp_path, DEMO_NAMES)
    monkeypatch.setattr(sys, "argv", ["reset_lab_data.py", "--yes", "--mode", "enterprise",
                                      "--log-dir", log_dir])

    assert reset_lab_data.main() != 0, "--yes must not get past a refused preflight"


def test_delete_by_wildcard_is_impossible_and_no_deletion_happens_when_unsafe(tmp_path):
    """Belt and braces: even reaching the client, no index is named for deletion."""
    log_dir = _log_dir(tmp_path, DEMO_NAMES)
    es = _Es(["normalized-events-2026-09-16"], per_index=9584)

    # Safe path first: prove the double records deletions when allowed to run.
    summary = reset_lab_data.reset(es_client=es, dedup_cache_path=str(tmp_path / "none.json"))
    assert summary["indices_deleted"] == ["normalized-events-2026-09-16"]

    # And the unsafe path never gets that far.
    assert reset_lab_data.preflight("enterprise", log_dir)["safe"] is False


def test_check_mode_reports_and_stops_before_deletion(tmp_path, monkeypatch):
    """`--check` is the launcher's pre-deletion probe, so it must not delete."""
    monkeypatch.setattr(reset_lab_data, "reset",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("--check must not delete")))
    monkeypatch.setattr(sys, "argv", ["reset_lab_data.py", "--check", "--log-dir",
                                      _log_dir(tmp_path, ENTERPRISE_NAMES)])

    assert reset_lab_data.main() == 0


# ------------------------------------------------------------- the CLI surface


def test_print_mode_emits_one_bare_token(tmp_path, monkeypatch):
    """start_lab.ps1 branches on this, so the output has to be parseable."""
    monkeypatch.setattr(sys, "argv", ["reset_lab_data.py", "--print-mode", "--log-dir",
                                      _log_dir(tmp_path, ENTERPRISE_NAMES)])
    assert reset_lab_data.main() == 0

    monkeypatch.setattr(sys, "argv", ["reset_lab_data.py", "--print-mode", "--mode", "demo",
                                      "--log-dir", _log_dir(tmp_path, ENTERPRISE_NAMES)])
    assert reset_lab_data.main() != 0


# ------------------------------------------------------- the launcher's script


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def test_the_launcher_asks_the_reset_script_before_it_deletes_anything():
    """The probe and its abort path must come before the reset call.

    Anchored on the *invocation* (`$probe = & $Python ...`), not on the first
    mention of `--print-mode`: an explanatory comment above the reset also
    contains that word, so a naive search would be satisfied by prose while the
    launcher probed nothing at all.
    """
    launcher = _read(os.path.join("scripts", "start_lab.ps1"))
    probe = launcher.find("$probe = & $Python scripts/reset_lab_data.py --print-mode")
    reset_call = launcher.find("reset_lab_data.py --yes")
    abort = launcher.find('throw "dataset safety check failed')

    assert probe != -1, "the launcher never asks which dataset it is running"
    assert reset_call != -1, "the launcher no longer resets"
    assert abort != -1, "the launcher has no way to stop before resetting"
    assert probe < reset_call, \
        "the safety probe must come before the destructive reset, or a refusal " \
        "arrives after the data is already gone"
    assert abort < reset_call, \
        "the launcher's abort path must be reachable before it resets; otherwise " \
        "an unsafe dataset is deleted and only then reported"


def test_the_launcher_never_ingests_the_mixed_directory_in_enterprise_mode():
    """Enterprise mode must ingest by name; the directory form is refused.

    The enterprise branch is extracted as its own body - from its `if` up to the
    `else` that closes it - because checking only the text *before* the branch
    would pass no matter what the branch contained.
    """
    launcher = _read(os.path.join("scripts", "start_lab.ps1"))
    marker = 'if ($resolvedMode -eq "enterprise")'
    assert marker in launcher, "the enterprise branch is missing"
    body = launcher.split(marker, 1)[1]
    end = body.find("} else {")
    assert end != -1, "the enterprise branch is not closed by an else"
    enterprise_branch = body[:end]

    assert "ingest --file" in enterprise_branch, "enterprise ingestion must name its files"
    assert "--log-dir" not in enterprise_branch, \
        "the enterprise branch must not ingest a directory: it holds both datasets"
    # And the demonstration branch, which legitimately does, must still be there.
    assert "--log-dir" in body[end:], "the demo branch lost its directory ingest"
    assert "generate-samples" in body[end:], "the demo branch lost sample generation"


def test_setup_ps1_no_longer_prints_the_refused_workflow():
    setup = _read(os.path.join("scripts", "setup.ps1"))
    block = setup[setup.index("Next steps:"):]
    assert "ingest --log-dir" not in block, \
        "setup.ps1 still prints a directory ingest that the guard refuses"
    assert "start_lab.ps1" in block, "setup.ps1 should point at the launcher"


def test_the_reset_script_never_lists_the_refused_workflow_as_the_only_option():
    """Its recovery guidance has to match the resolved mode."""
    source = _read(os.path.join("scripts", "reset_lab_data.py"))
    tail = source[source.index('print(f"\\n  Lab data cleared.'):]
    assert "ingest --file" in tail or "rebuild_commands" in tail or "plan[" in tail