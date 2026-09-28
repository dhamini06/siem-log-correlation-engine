"""Windows Security / Sysmon parser for SIEM Lab.

Input: one JSON object per line, as produced by an EVTX export
(`Get-WinEvent ... | ConvertTo-Json`) or by the Filebeat/Logstash pipeline.

Mapped event IDs:
  4624 - Logon success           -> logon_success
  4625 - Failed logon            -> logon_failure
  4688 / Sysmon 1 - Process create -> process_create
  4672 - Special privileges      -> privilege_escalation
"""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from .parsers import LogParser, clean_ip
from .schema import EventType, NormalizedEvent, Severity, SourceType
from ..utils.time_utils import normalize_to_utc, utc_now

logger = logging.getLogger(__name__)

EVENT_ID_MAP = {
    4624: EventType.LOGON_SUCCESS,
    4625: EventType.LOGON_FAILURE,
    4688: EventType.PROCESS_CREATE,
    1: EventType.PROCESS_CREATE,  # Sysmon process create
    4672: EventType.PRIVILEGE_ESCALATION,
}

SUSPICIOUS_PROCESSES = ("powershell.exe", "cmd.exe", "bash", "nc.exe", "nc", "wscript.exe", "cscript.exe")

# Accounts whose interactive shell use is normal, not suspicious.
INTERACTIVE_SYSTEM_USERS = {
    "nt authority\\system",
    "system",
    "local service",
    "network service",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "iucsadmin",
}


def format_windows_user(domain: Optional[str], username: Optional[str]) -> str:
    """Return DOMAIN\\user (or the bare username for local accounts)."""
    username = (username or "").strip()
    domain = (domain or "").strip()
    if not username:
        return "unknown"
    if not domain or domain.upper() in ("", "-", "NONE"):
        return username
    if username.upper() == "ANONYMOUS LOGON":
        return "ANONYMOUS LOGON"
    return f"{domain}\\{username}"


def is_suspicious_process(name: Optional[str], command_line: Optional[str]) -> bool:
    """True when a created process is in the Lab #07 suspicious process set."""
    if name:
        base = name.split("\\")[-1].lower()
        if base in SUSPICIOUS_PROCESSES:
            return True
    if command_line:
        lowered = command_line.lower()
        if "-enc" in lowered or "encodedcommand" in lowered or re.search(r"\b(bash|sh)\s+-i\b", lowered):
            return True
        if re.search(r"\bnc\b.*\s-e\b", lowered):
            return True
    return False


class WindowsSysmonParser(LogParser):
    """Parse Windows Event Log JSON records into NormalizedEvent objects."""

    source_type = SourceType.WINDOWS_SYSMON

    def parse(self, raw_log_line: str) -> Optional[NormalizedEvent]:
        line = raw_log_line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            self.skipped_count += 1
            logger.debug("Not valid JSON, skipping: %s", line[:100])
            return None
        if not isinstance(record, dict):
            self.skipped_count += 1
            return None

        event = self.parse_record(record, raw_event=line)
        if event is None:
            self.skipped_count += 1
        else:
            self.parsed_count += 1
        return event

    def parse_record(self, record: Dict[str, Any], raw_event: Optional[str] = None) -> Optional[NormalizedEvent]:
        """Convert a decoded Windows event record into a NormalizedEvent."""
        raw_event = raw_event if raw_event is not None else json.dumps(record)
        event_id = record.get("EventID") or record.get("EventId") or record.get("event_id")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            logger.debug("Windows record missing numeric EventID")
            return None

        event_type = EVENT_ID_MAP.get(event_id)
        if event_type is None:
            logger.debug("Ignoring unsupported Windows EventID %s", event_id)
            return None

        data = record.get("EventData")
        if isinstance(data, list):  # Logstash-style [{key, value}]
            data = {item.get("Key"): item.get("Value") for item in data if isinstance(item, dict)}
        if not isinstance(data, dict):
            data = record

        def pick(*names: str) -> Any:
            for name in names:
                if data.get(name) not in (None, ""):
                    return data[name]
                if record.get(name) not in (None, ""):
                    return record[name]
            return None

        timestamp = self._parse_timestamp(record, pick("@timestamp", "TimeCreated", "time_created", "UtcTime"))
        host = str(pick("Computer", "host", "Hostname", "ComputerName") or "unknown").lower()
        username = pick("TargetUserName", "SubjectUserName", "User", "user", "AccountName")
        domain = pick("TargetDomainName", "SubjectDomainName", "DomainName")
        user = format_windows_user(domain, username)

        process = self._build_process(pick)
        severity = self._assign_severity(event_type, user, process)

        return self._build(
            event_type=event_type,
            host=host,
            user=user,
            severity=severity,
            raw_event=raw_event,
            timestamp=timestamp,
            src_ip=clean_ip(str(pick("IpAddress", "SourceAddress", "src_ip") or "")) if event_type in (
                EventType.LOGON_SUCCESS, EventType.LOGON_FAILURE
            ) else "unknown",
            dst_ip=clean_ip(str(pick("DestinationIp", "dst_ip") or "")),
            port=self._as_int(pick("DestinationPort", "port")),
            protocol=str(pick("Protocol", "protocol") or "") or None,
            process=process,
        )

    # -- Helpers --

    @staticmethod
    def _parse_timestamp(record: Dict[str, Any], value: Any) -> datetime:
        candidates = [value, record.get("@timestamp"), record.get("TimeCreated")]
        for candidate in candidates:
            if not candidate:
                continue
            try:
                return normalize_to_utc(str(candidate).replace("+00:00", "Z"))
            except ValueError:
                continue
        return utc_now()

    @staticmethod
    def _as_int(value: Any) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _build_process(self, pick) -> Optional[Dict[str, Any]]:
        path = pick("NewProcessName", "ProcessName", "Image", "process_path")
        command = pick("CommandLine", "ProcessCommandLine", "command_line", "CommandLineText")
        if not path and not command:
            return None
        process: Dict[str, Any] = {
            "name": (str(path).split("\\")[-1] if path else str(command).split()[0]),
            "path": str(path) if path else None,
            "pid": self._as_int(pick("NewProcessId", "ProcessId", "pid")),
            "parent_name": self._parent_name(pick("ParentProcessName", "ParentImage", "parent_process")),
            "parent_pid": self._as_int(pick("ParentProcessId", "parent_pid")),
            "command_line": str(command) if command else None,
        }
        return process

    @staticmethod
    def _parent_name(value: Any) -> Optional[str]:
        if not value:
            return None
        return str(value).split("\\")[-1]

    @staticmethod
    def _assign_severity(event_type: EventType, user: str, process: Optional[Dict[str, Any]]) -> Severity:
        if event_type is EventType.LOGON_FAILURE:
            return Severity.MEDIUM
        if event_type is EventType.LOGON_SUCCESS:
            return Severity.LOW
        if event_type is EventType.PRIVILEGE_ESCALATION:
            return Severity.MEDIUM
        # process_create
        if process and is_suspicious_process(process.get("name"), process.get("command_line")):
            if user.lower() not in INTERACTIVE_SYSTEM_USERS:
                return Severity.HIGH
        return Severity.MEDIUM


__all__ = ["WindowsSysmonParser", "format_windows_user", "is_suspicious_process"]
