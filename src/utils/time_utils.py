"""Time utilities for SIEM Lab: UTC normalization, window queries, timestamp parsing."""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def normalize_to_utc(timestamp_str: str) -> datetime:
    """Normalize a timestamp string to a UTC datetime.

    Supported formats:
    - ISO8601 with Z: "2024-01-15T14:32:45.123Z"
    - ISO8601 with offset: "2024-01-15T14:32:45+05:30"
    - ISO8601 without timezone: "2024-01-15T14:32:45"
    - Space separated: "2024-01-15 14:32:45"
    - Syslog: "Jan 15 14:32:45" (year inferred from the current UTC year)
    - Syslog with year: "Jan 15 2024 14:32:45"

    Raises:
        ValueError: if the timestamp cannot be parsed.
    """
    ts = timestamp_str.strip()
    if not ts:
        raise ValueError("Empty timestamp")

    # ISO8601 (with or without timezone)
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", ts):
        normalized = ts.replace(" ", "T")
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"Unable to parse timestamp to UTC: {timestamp_str}") from exc
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    # Syslog with explicit year: "Jan 15 2024 14:32:45"
    match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$", ts)
    if match:
        month, day, year, hour, minute, second = match.groups()
        return datetime(
            int(year), MONTHS[month], int(day), int(hour), int(minute), int(second),
            tzinfo=timezone.utc,
        )

    # Classic syslog: "Jan 15 14:32:45" (no year)
    match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", ts)
    if match:
        month, day, hour, minute, second = match.groups()
        now = datetime.now(timezone.utc)
        dt = datetime(
            now.year, MONTHS[month], int(day), int(hour), int(minute), int(second),
            tzinfo=timezone.utc,
        )
        # Syslog omits the year. A timestamp more than a minute ahead of now cannot
        # be this year, so treat it as a previous-year entry instead of a future event.
        if dt - now > timedelta(minutes=1):
            dt = dt.replace(year=now.year - 1)
        return dt

    # Unix epoch seconds or milliseconds
    if re.match(r"^\d{10}$", ts):
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    if re.match(r"^\d{13}$", ts):
        return datetime.fromtimestamp(int(ts) / 1000, tz=timezone.utc)

    raise ValueError(f"Unable to parse timestamp to UTC: {timestamp_str}")


def utc_now() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


def timestamp_to_iso8601(dt: datetime) -> str:
    """Convert a datetime to an ISO8601 UTC string with millisecond precision."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def add_minutes(dt: datetime, minutes: int) -> datetime:
    """Add minutes to a datetime, preserving timezone."""
    return dt + timedelta(minutes=minutes)


def subtract_minutes(dt: datetime, minutes: int) -> datetime:
    """Subtract minutes from a datetime, preserving timezone."""
    return dt - timedelta(minutes=minutes)


def within_window(event_time: datetime, window_start: datetime, window_end: datetime) -> bool:
    """Check if event_time falls within [window_start, window_end)."""
    return window_start <= event_time < window_end


def ensure_utc(dt: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, assuming UTC when naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def query_time_range(
    field: str = "@timestamp",
    start: Optional[Union[datetime, str]] = None,
    end: Optional[Union[datetime, str]] = None,
) -> Dict[str, Any]:
    """Build an Elasticsearch range query dict for a time field.

    Args:
        field: Field to query (default: @timestamp)
        start: Start of range (datetime or ISO8601/syslog string)
        end: Exclusive end of range (datetime or ISO8601/syslog string)

    Returns:
        {"range": {field: {"gte": ..., "lt": ...}}} or {} when both are None.
    """
    start_dt = normalize_to_utc(start) if isinstance(start, str) else (ensure_utc(start) if start else None)
    end_dt = normalize_to_utc(end) if isinstance(end, str) else (ensure_utc(end) if end else None)

    range_obj: Dict[str, Any] = {}
    if start_dt:
        range_obj["gte"] = timestamp_to_iso8601(start_dt)
    if end_dt:
        range_obj["lt"] = timestamp_to_iso8601(end_dt)
    if not range_obj:
        return {}
    return {"range": {field: range_obj}}


def parse_window_minutes(window_str: str) -> Optional[timedelta]:
    """Parse a window string like '5m', '1h', '30m' into a timedelta."""
    match = re.match(r"^(\d+)\s*(m|h|d)$", window_str.strip())
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    return timedelta(days=value)
