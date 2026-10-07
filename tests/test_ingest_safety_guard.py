"""The ingestion guard against mixed-dataset directories.

`ingest --log-dir` indexes every log file it finds in the directory. The
approved enterprise dataset (`enterprise-14d_*`) and the per-scenario
demonstration fixtures are *alternatives*, not layers, so a directory holding
both would be indexed as two datasets in one pass: duplicate attack fixtures,
two different timestamp anchors, and an event count nobody can explain.

That is not a hypothetical. It has happened twice in this lab, and both times
the damage was silent - the ingestion reported success, and the wrong result was
only discovered later by checking the alert count. Three of the four alert tests
passed throughout, because they assert rule, severity and address rather than
which dataset the events came from.

`enterprise_generator.foreign_log_files()` already knew how to recognise this
condition, but it was only consulted when the *generator* ran. The guard here
reuses that same definition on the ingestion side, so the two cannot drift.
"""

import argparse
import os

import pytest

from src.main import cmd_ingest, mixed_dataset_conflict
from src.normalization import ingestion as ingestion_module
from src.normalization.enterprise_generator import DATASET_NAME, dataset_paths

ENTERPRISE_FILES = ["enterprise-14d_auth.log", "enterprise-14d_windows.jsonl",
                    "enterprise-14d_firewall.log"]
DEMO_FILES = ["brute_force_auth.log", "normal_day_windows.jsonl",
              "false_positive_mix_firewall.log"]

AUTH_LINE = ("Sep 17 12:00:00 web-01 sshd[1]: Failed password for alice from "
             "203.0.113.45 port 51234 ssh2")


def _write(directory, name, body=AUTH_LINE + "\n"):
    path = os.path.join(str(directory), name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


def _enterprise_dir(directory):
    """A directory holding exactly the approved enterprise dataset."""
    directory.mkdir(exist_ok=True)
    for name in ENTERPRISE_FILES:
        _write(directory, name, body=AUTH_LINE + "\n")
    return str(directory)


def _demo_dir(directory):
    """A directory holding only per-scenario demonstration fixtures."""
    directory.mkdir(exist_ok=True)
    for name in DEMO_FILES:
        _write(directory, name, body=AUTH_LINE + "\n")
    return str(directory)


def _mixed_dir(directory):
    """The exact condition that caused the incident: both datasets together."""
    directory.mkdir(exist_ok=True)
    for name in ENTERPRISE_FILES:
        _write(directory, name, body=AUTH_LINE + "\n")
    for name in DEMO_FILES:
        _write(directory, name, body=AUTH_LINE + "\n")
    return str(directory)


def _args(log_dir, file=None, dry_run=True):
    return argparse.Namespace(file=file, log_dir=str(log_dir), source_type=None,
                              dry_run=dry_run)


class _EngineMustNotBeBuilt:
    """Fails loudly if the guard lets anything reach the Elasticsearch client.

    The point of the guard is that it fires *before* the first write, and
    `NormalizationEngine.__init__` is what acquires an Elasticsearch client. So
    "the engine was never constructed" is a stronger statement than "nothing was
    indexed", and it is the one worth asserting.
    """

    def __init__(self, *args, **kwargs):
        raise AssertionError(
            "NormalizationEngine was constructed on a mixed directory; the guard "
            "must refuse before any Elasticsearch client is acquired")


# ------------------------------------------------------- the guard itself


def test_a_mixed_directory_is_a_conflict(tmp_path):
    conflict = mixed_dataset_conflict(_mixed_dir(tmp_path / "logs"))
    assert conflict is not None, "a directory holding both datasets was not detected"
    enterprise, foreign = conflict
    assert sorted(enterprise) == sorted(ENTERPRISE_FILES)
    assert sorted(foreign) == sorted(DEMO_FILES)


def test_the_conflict_names_the_files_from_both_datasets(tmp_path):
    """The operator has to be told *which* files, or they cannot act on it."""
    enterprise, foreign = mixed_dataset_conflict(_mixed_dir(tmp_path / "logs"))
    for name in ENTERPRISE_FILES:
        assert name in enterprise
    for name in DEMO_FILES:
        assert name in foreign


def test_enterprise_only_directory_is_not_a_conflict(tmp_path):
    """The approved dataset must stay ingestible - that is the whole point."""
    assert mixed_dataset_conflict(_enterprise_dir(tmp_path / "logs")) is None


def test_demo_only_directory_is_not_a_conflict(tmp_path):
    """A demonstration-only directory is a legitimate, supported workflow."""
    assert mixed_dataset_conflict(_demo_dir(tmp_path / "logs")) is None


def test_a_non_log_file_does_not_create_a_conflict(tmp_path):
    """`foreign_log_files` looks at log suffixes, and so should the guard.

    A stray README next to the dataset is untidy, not dangerous: nothing indexes
    it, so refusing here would be a false positive that trains operators to
    ignore the guard.
    """
    directory = _enterprise_dir(tmp_path / "logs")
    _write(directory, "readme.md", body="# notes\n")
    _write(directory, "notes.txt", body="x\n")
    assert mixed_dataset_conflict(directory) is None


def test_missing_and_empty_directories_are_not_conflicts(tmp_path):
    assert mixed_dataset_conflict(str(tmp_path / "does-not-exist")) is None
    empty = tmp_path / "empty"
    empty.mkdir()
    assert mixed_dataset_conflict(str(empty)) is None


def test_the_guard_agrees_with_the_generator_about_what_is_ours(tmp_path):
    """Both halves of the decision come from the generator, not a restatement."""
    directory = _enterprise_dir(tmp_path / "logs")
    enterprise, _ = mixed_dataset_conflict(_mixed_dir(tmp_path / "logs"))
    assert set(enterprise) == {os.path.basename(p) for p in dataset_paths(directory).values()}
    assert all(DATASET_NAME in name for name in enterprise)


# ---------------------------------------------------- the command's behaviour


def test_ingest_refuses_a_mixed_directory_and_indexes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ingestion_module, "NormalizationEngine", _EngineMustNotBeBuilt)

    code = cmd_ingest(_args(_mixed_dir(tmp_path / "logs"), dry_run=False))

    assert code != 0, "a mixed directory must exit non-zero"
    err = capsys.readouterr().err
    assert "Refusing to ingest" in err
    assert "Nothing has been indexed." in err
    for name in ENTERPRISE_FILES + DEMO_FILES:
        assert name in err, "the refusal does not name %s" % name


def test_the_refusal_points_at_both_ways_out(tmp_path, monkeypatch, capsys):
    """A refusal that does not say what to do instead gets worked around."""
    monkeypatch.setattr(ingestion_module, "NormalizationEngine", _EngineMustNotBeBuilt)

    cmd_ingest(_args(_mixed_dir(tmp_path / "logs"), dry_run=False))

    err = capsys.readouterr().err
    assert "--file" in err, "the refusal does not mention --file"
    assert "--log-dir" in err or "separate" in err.lower(), \
        "the refusal does not mention separating the directories"


def test_a_dry_run_on_a_mixed_directory_also_refuses(tmp_path, monkeypatch, capsys):
    """Refusing on --dry-run too: it is a preview of an ingest that must not happen.

    A dry run that succeeded here would tell the operator the directory is fine,
    which is the opposite of true and the most dangerous possible outcome.
    """
    monkeypatch.setattr(ingestion_module, "NormalizationEngine", _EngineMustNotBeBuilt)

    code = cmd_ingest(_args(_mixed_dir(tmp_path / "logs"), dry_run=True))

    assert code != 0
    assert "Refusing to ingest" in capsys.readouterr().err


def test_ingest_still_accepts_an_enterprise_only_directory(tmp_path, capsys):
    """Regression guard: the guard must not block the approved dataset.

    Uses --dry-run, so this exercises the real ingestion path without an
    Elasticsearch client: `NormalizationEngine.__init__` skips `get_es_client()`
    when dry_run is set, and a dry run never indexes.
    """
    directory = _enterprise_dir(tmp_path / "logs")

    code = cmd_ingest(_args(directory, dry_run=True))

    assert code == 0
    assert "Refusing to ingest" not in capsys.readouterr().err


def test_ingest_still_accepts_a_demo_only_directory(tmp_path, capsys):
    """Regression guard: the sample training workflow must keep working."""
    directory = _demo_dir(tmp_path / "logs")

    code = cmd_ingest(_args(directory, dry_run=True))

    assert code == 0
    assert "Refusing to ingest" not in capsys.readouterr().err


def test_an_explicit_file_is_allowed_even_in_a_mixed_directory(tmp_path, capsys):
    """--file is an explicit, unambiguous choice and must not be second-guessed.

    An operator pointing at one named file has already answered the question the
    guard asks. Blocking this would leave no way to ingest anything out of a
    directory that has both datasets in it.
    """
    directory = _mixed_dir(tmp_path / "logs")
    chosen = os.path.join(directory, DEMO_FILES[0])

    code = cmd_ingest(_args(directory, file=chosen, dry_run=True))

    assert code == 0
    assert "Refusing to ingest" not in capsys.readouterr().err


def test_a_missing_directory_keeps_its_existing_error(tmp_path, capsys):
    """The guard adds no opinion where there was none before."""
    code = cmd_ingest(_args(tmp_path / "nope", dry_run=True))

    assert code != 0, "a missing directory still has to fail"
    assert "not found" in capsys.readouterr().err.lower()