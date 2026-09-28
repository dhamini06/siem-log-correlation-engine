"""Tests for the command-line interface (src/main.py)."""

import os

import pytest

from src import main as main_module
from src.main import build_parser, main


def test_parser_exposes_all_commands():
    parser = build_parser()
    for command in ("init-templates", "generate-samples", "ingest", "correlate", "stats", "import-dashboard"):
        args = parser.parse_args([command])
        assert args.command == command
        assert callable(args.func)


def test_log_level_accepted_before_and_after_subcommand():
    parser = build_parser()
    assert parser.parse_args(["--log-level", "DEBUG", "stats"]).global_log_level == "DEBUG"
    assert parser.parse_args(["ingest", "--log-level", "DEBUG"]).log_level == "DEBUG"


def test_ingest_parser_defaults_and_overrides():
    parser = build_parser()
    args = parser.parse_args(["ingest", "--log-dir", "./logs/x", "--source-type", "linux_auth", "--dry-run"])
    assert args.log_dir == "./logs/x"
    assert args.source_type == "linux_auth"
    assert args.dry_run is True


def test_correlate_run_once_flag():
    parser = build_parser()
    assert parser.parse_args(["correlate", "--run-once"]).run_once is True
    assert parser.parse_args(["correlate"]).run_once is False


def test_generate_samples_command_writes_files(tmp_path, capsys):
    output = str(tmp_path / "gen")
    exit_code = main(["generate-samples", "--scenario", "brute_force", "--output", output])
    assert exit_code == 0
    assert os.path.isfile(os.path.join(output, "brute_force_auth.log"))
    assert "brute_force" in capsys.readouterr().out


def test_ingest_dry_run_needs_no_elasticsearch(tmp_path, capsys):
    output = str(tmp_path / "gen")
    main(["generate-samples", "--scenario", "normal_day", "--output", output])
    exit_code = main(["ingest", "--log-dir", output, "--dry-run"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "dry run" in out
    assert "parsed=" in out


def test_commands_report_unreachable_elasticsearch(monkeypatch, capsys):
    class Unreachable:
        url = "http://localhost:9200"

        def health_check(self, retries=1, delay_seconds=0.0):
            return False

    monkeypatch.setattr(main_module, "_es_client", lambda: Unreachable())
    assert main(["correlate", "--run-once"]) == 1
    assert main(["stats"]) == 1
    assert main(["init-templates"]) == 1
    assert "not reachable" in capsys.readouterr().err


def test_main_reports_unknown_command():
    with pytest.raises(SystemExit):
        main(["not-a-command"])


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)

    def json(self):
        return self._payload


def test_import_dashboard_uploads_ndjson(tmp_path, monkeypatch, capsys):
    import requests

    dashboard = tmp_path / "board.ndjson"
    dashboard.write_text('{"type":"dashboard","id":"x"}\n', encoding="utf-8")
    captured = {}

    def fake_post(url, params=None, headers=None, files=None, timeout=None):
        captured.update(url=url, params=params, headers=headers, files=files)
        return FakeResponse(payload={
            "success": True,
            "successCount": 1,
            "warnings": [],
            "successResults": [{"type": "dashboard", "id": "x", "meta": {"title": "Board"}}],
        })

    monkeypatch.setattr(requests, "post", fake_post)
    exit_code = main(["import-dashboard", "--file", str(dashboard), "--kibana-url", "http://kibana:5601"])

    assert exit_code == 0
    assert captured["url"] == "http://kibana:5601/api/saved_objects/_import"
    assert captured["params"] == {"overwrite": "true"}
    assert "kbn-xsrf" in captured["headers"]
    assert captured["files"]["file"][0] == "board.ndjson"
    out = capsys.readouterr().out
    assert "Imported 1 saved object(s)" in out
    assert "dashboard/x" in out


def test_import_dashboard_missing_file_returns_1(tmp_path, capsys):
    assert main(["import-dashboard", "--file", str(tmp_path / "nope.ndjson")]) == 1
    assert "not found" in capsys.readouterr().err


def test_import_dashboard_reports_http_error(tmp_path, monkeypatch, capsys):
    import requests

    dashboard = tmp_path / "board.ndjson"
    dashboard.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(403, {"error": "forbidden"}))

    assert main(["import-dashboard", "--file", str(dashboard)]) == 1
    assert "HTTP 403" in capsys.readouterr().err
