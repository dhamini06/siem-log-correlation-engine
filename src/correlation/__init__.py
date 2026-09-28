"""Correlation engine package: rules, deduplication, and orchestration."""

from .engine import CorrelationEngine, CycleResult  # noqa: F401
from .rules import (  # noqa: F401
    RULE_BRUTE_FORCE,
    RULE_SUCCESSFUL_BRUTE_FORCE,
    RULE_SUSPICIOUS_POST_LOGIN,
    CorrelatedEvent,
    apply_rules,
    find_failure_bursts,
    load_events,
    rule_brute_force,
    rule_successful_brute_force,
    rule_suspicious_process_post_login,
)
from .deduplication import AlertDeduplicator  # noqa: F401
