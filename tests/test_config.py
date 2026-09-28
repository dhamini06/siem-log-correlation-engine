"""Tests for configuration loading, validation, and env var overrides."""

import os

import pytest

from src import config as config_module
from src.config import load_app_config, get_config, get_engine_frequency_seconds, get_rule_min_failures


@pytest.fixture(autouse=True)
def clear_singleton():
    if hasattr(get_config, "_config"):
        del get_config._config
    yield
    if hasattr(get_config, "_config"):
        del get_config._config


def test_loads_yaml_configuration():
    config = load_app_config()
    assert config["rules"]["brute_force"]["min_failures"] == 5
    assert config["rules"]["brute_force"]["time_window_minutes"] == 5
    assert config["rules"]["successful_brute_force"]["success_window_minutes"] == 10
    assert config["rules"]["suspicious_exec"]["time_after_login_minutes"] == 2
    assert config["correlation"]["engine_frequency_seconds"] == 60
    assert config["correlation"]["alert_dedup_window_minutes"] == 30
    assert "cmd.exe" in config["rules"]["suspicious_exec"]["suspicious_processes"]
    assert "explorer.exe" in config["rules"]["suspicious_exec"]["expected_processes"]


def test_singleton_returns_same_object():
    assert get_config() is get_config()


def test_convenience_accessors():
    assert get_rule_min_failures() == 5
    assert get_engine_frequency_seconds() == 60


def test_environment_overrides(monkeypatch):
    monkeypatch.setenv("ES_HOST", "es.internal")
    monkeypatch.setenv("ES_PORT", "9300")
    monkeypatch.setenv("RULE_MIN_FAILURES", "8")
    monkeypatch.setenv("RULE_TIME_WINDOW_MINUTES", "3")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    config = load_app_config()
    assert config["app"]["es_host"] == "es.internal"
    assert config["app"]["es_port"] == 9300
    assert config["app"]["log_level"] == "DEBUG"
    assert config["rules"]["brute_force"]["min_failures"] == 8
    assert config["rules"]["brute_force"]["time_window_minutes"] == 3


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda c: c.pop("rules"), "rules"),
        (lambda c: c["rules"].pop("brute_force"), "min_failures"),
        (lambda c: c["rules"]["brute_force"].update(min_failures=0), "min_failures"),
        (lambda c: c["rules"]["brute_force"].update(min_failures="five"), "min_failures"),
        (lambda c: c["rules"]["brute_force"].update(time_window_minutes=0), "time_window_minutes"),
        (lambda c: c["rules"]["successful_brute_force"].update(success_window_minutes=0), "success_window_minutes"),
        (lambda c: c["rules"]["suspicious_exec"].update(time_after_login_minutes=0), "time_after_login_minutes"),
        (lambda c: c["rules"]["suspicious_exec"].update(suspicious_processes=[]), "suspicious_processes"),
        (lambda c: c["correlation"].update(engine_frequency_seconds=0), "engine_frequency_seconds"),
        (lambda c: c["correlation"].update(alert_dedup_window_minutes=0), "alert_dedup_window_minutes"),
        (lambda c: c["correlation"].update(lookback_window_minutes=-1), "lookback_window_minutes"),
    ],
)
def test_invalid_configuration_raises(mutate, message):
    config = load_app_config()
    mutate(config)
    with pytest.raises(ValueError) as exc_info:
        config_module._validate_config(config)
    assert message in str(exc_info.value)


def test_config_path_points_at_repo_config():
    assert os.path.isfile(config_module.APP_CONFIG_PATH)
