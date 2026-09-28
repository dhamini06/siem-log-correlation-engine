"""Configuration loader and validation for SIEM Lab."""

import os
import yaml
from typing import Any, Dict

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
APP_CONFIG_PATH = os.path.join(CONFIG_DIR, "app-config.yaml")


def load_app_config() -> Dict[str, Any]:
    """Load application configuration from YAML file with env var overrides."""
    with open(APP_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    # Apply environment variable overrides
    if es_host := os.environ.get("ES_HOST"):
        config.setdefault("app", {})["es_host"] = es_host
    if es_port := os.environ.get("ES_PORT"):
        config.setdefault("app", {})["es_port"] = int(es_port)
    if rule_min_failures := os.environ.get("RULE_MIN_FAILURES"):
        config.setdefault("rules", {}).setdefault("brute_force", {})["min_failures"] = int(rule_min_failures)
    if rule_time_window := os.environ.get("RULE_TIME_WINDOW_MINUTES"):
        config.setdefault("rules", {}).setdefault("brute_force", {})["time_window_minutes"] = int(rule_time_window)
    if log_level := os.environ.get("LOG_LEVEL"):
        config.setdefault("app", {})["log_level"] = log_level

    # Validate required sections
    _validate_config(config)

    return config


def _validate_config(config: Dict[str, Any]) -> None:
    """Validate configuration has required fields."""
    if not config.get("rules"):
        raise ValueError("Configuration missing 'rules' section")

    # Validate brute force rule parameters
    bf = config["rules"].get("brute_force", {})
    if not isinstance(bf.get("min_failures"), int) or bf["min_failures"] < 1:
        raise ValueError("brute_force.min_failures must be a positive integer")
    if not isinstance(bf.get("time_window_minutes"), int) or bf["time_window_minutes"] < 1:
        raise ValueError("brute_force.time_window_minutes must be a positive integer")

    # Validate successful brute force parameters
    sbf = config["rules"].get("successful_brute_force", {})
    if not isinstance(sbf.get("success_window_minutes"), int) or sbf["success_window_minutes"] < 1:
        raise ValueError("successful_brute_force.success_window_minutes must be a positive integer")

    # Validate suspicious exec parameters
    se = config["rules"].get("suspicious_exec", {})
    if not isinstance(se.get("time_after_login_minutes"), int) or se["time_after_login_minutes"] < 1:
        raise ValueError("suspicious_exec.time_after_login_minutes must be a positive integer")
    if not isinstance(se.get("suspicious_processes", []), list) or not se["suspicious_processes"]:
        raise ValueError("suspicious_exec.suspicious_processes must be a non-empty list")
    if not isinstance(se.get("expected_processes", []), list):
        raise ValueError("suspicious_exec.expected_processes must be a list")

    # Validate engine config
    cf = config.get("correlation", {})
    if not isinstance(cf.get("engine_frequency_seconds"), int) or cf["engine_frequency_seconds"] < 1:
        raise ValueError("correlation.engine_frequency_seconds must be a positive integer")
    if not isinstance(cf.get("alert_dedup_window_minutes"), int) or cf["alert_dedup_window_minutes"] < 1:
        raise ValueError("correlation.alert_dedup_window_minutes must be a positive integer")
    if not isinstance(cf.get("lookback_window_minutes"), int) or cf["lookback_window_minutes"] < 1:
        raise ValueError("correlation.lookback_window_minutes must be a positive integer")


def get_config() -> Dict[str, Any]:
    """Singleton to get configured values."""
    if not hasattr(get_config, "_config"):
        get_config._config = load_app_config()
    return get_config._config


# Convenience accessors
def get_es_host() -> str:
    return get_config().get("app", {}).get("es_host", "localhost")


def get_es_port() -> int:
    return get_config().get("app", {}).get("es_port", 9200)


def get_rule_min_failures() -> int:
    return get_config()["rules"]["brute_force"]["min_failures"]


def get_rule_time_window_minutes() -> int:
    return get_config()["rules"]["brute_force"]["time_window_minutes"]


def get_engine_frequency_seconds() -> int:
    return get_config()["correlation"]["engine_frequency_seconds"]


def get_dedup_window_minutes() -> int:
    return get_config()["correlation"]["alert_dedup_window_minutes"]


def get_lookback_window_minutes() -> int:
    return get_config()["correlation"]["lookback_window_minutes"]