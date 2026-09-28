"""Linux auth.log parser (sshd, sudo, PAM) for SIEM Lab.

Supported line formats:
  Sep 25 17:20:01 server-01 sshd[1234]: Failed password for alice from 10.0.0.5 port 51234 ssh2
  Sep 25 17:20:01 server-01 sshd[1234]: Accepted password for alice from 10.0.0.5 port 51234 ssh2
  Sep 25 17:20:01 server-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
  Sep 25 17:20:01 server-01 su[1234]: pam_unix(su:auth): authentication failure; logname= uid=0 euid=0 tty=pts/0 ruser=alice rhost= user=root
  Sep 25 17:20:01 server-01 sshd[1234]: User child from 10.0.0.9 disconnected: Too many authentication failures
"""

import logging
import re
from typing import Optional

from .parsers import LogParser, clean_ip, parse_syslog_header
from .schema import EventType, NormalizedEvent, Severity, SourceType

logger = logging.getLogger(__name__)

SSH_FAILED_RE = re.compile(
    r"sshd(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?:Failed\s+(?:password|publickey|gssapi-with-mic|keyboard-interactive)"
    r"|Connection closed by (?:authenticating|invalid) user)\s+"
    r"(?:for\s+)?(?:invalid user\s+)?(?P<user>[^\s]+)"
    r"(?:\s+from\s+(?P<ip>[0-9a-fA-F.:]+))?",
    re.IGNORECASE,
)

SSH_INVALID_USER_RE = re.compile(
    r"sshd(?:\[(?P<pid>\d+)\])?:\s*Invalid user\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)",
    re.IGNORECASE,
)

SSH_ACCEPTED_RE = re.compile(
    r"sshd(?:\[(?P<pid>\d+)\])?:\s*Accepted\s+(?P<method>\S+)\s+for\s+"
    r"(?P<user>[^\s]+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

SUDO_RE = re.compile(
    r"sudo(?:\[(?P<pid>\d+)\])?:\s*(?P<user>[^\s:]+)\s*:\s*TTY=(?P<tty>[^;]*);\s*"
    r"PWD=(?P<pwd>[^;]*);\s*USER=(?P<target>[^;\s]+)\s*;\s*COMMAND=(?P<command>.+)$"
)

PAM_FAILURE_RE = re.compile(
    r"(?P<service>su|login|sshd)\S*:\s*pam_unix\([^)]*\):\s*authentication failure"
    r"(?:.*?\buser=(?P<user>\S+))?"
    r"(?:.*?\brhost=(?P<rhost>\S+))?",
    re.IGNORECASE,
)

# Interactive shells observed in sudo/auditd-style command records.
BASH_COMMAND_RE = re.compile(r"^(/usr/bin/(?:ba)?sh\s+-i|/bin/(?:ba)?sh\s+-i|/bin/bash\s+-i)")


def normalize_linux_user(user: Optional[str]) -> str:
    """Strip PAM/realm prefixes (e.g. 'alice@REALM') down to the account name."""
    if not user:
        return "unknown"
    user = user.strip()
    if user.lower() in ("root", "unknown", "(null)"):
        return user.lower() if user else "unknown"
    return user.split("@")[0]


class LinuxAuthParser(LogParser):
    """Parse Linux auth.log entries into NormalizedEvent objects."""

    source_type = SourceType.LINUX_AUTH

    def parse(self, raw_log_line: str) -> Optional[NormalizedEvent]:
        line = raw_log_line.strip()
        if not line:
            return None

        timestamp, host, message = parse_syslog_header(line)
        if not message:
            return None

        event = (
            self._parse_ssh_accepted(message, host, line, timestamp)
            or self._parse_ssh_failed(message, host, line, timestamp)
            or self._parse_invalid_user(message, host, line, timestamp)
            or self._parse_sudo(message, host, line, timestamp)
            or self._parse_pam_failure(message, host, line, timestamp)
        )
        if event is not None:
            self.parsed_count += 1
        else:
            self.skipped_count += 1
        return event

    # -- Individual pattern handlers --

    def _parse_ssh_accepted(self, message, host, line, timestamp) -> Optional[NormalizedEvent]:
        match = SSH_ACCEPTED_RE.search(message)
        if not match:
            return None
        process = None
        user = normalize_linux_user(match.group("user"))
        return self._build(
            event_type=EventType.LOGON_SUCCESS,
            host=host,
            user=user,
            severity=Severity.LOW,
            raw_event=line,
            timestamp=timestamp,
            src_ip=clean_ip(match.group("ip")),
            port=int(match.group("port")),
            protocol="ssh",
            process={"name": "sshd", "path": "/usr/sbin/sshd", "command_line": f"sshd: {user} [priv]"},
        )

    def _parse_ssh_failed(self, message, host, line, timestamp) -> Optional[NormalizedEvent]:
        match = SSH_FAILED_RE.search(message)
        if not match:
            return None
        return self._build(
            event_type=EventType.LOGON_FAILURE,
            host=host,
            user=normalize_linux_user(match.group("user")),
            severity=Severity.MEDIUM,
            raw_event=line,
            timestamp=timestamp,
            src_ip=clean_ip(match.group("ip")),
            protocol="ssh",
        )

    def _parse_invalid_user(self, message, host, line, timestamp) -> Optional[NormalizedEvent]:
        match = SSH_INVALID_USER_RE.search(message)
        if not match:
            return None
        return self._build(
            event_type=EventType.LOGON_FAILURE,
            host=host,
            user=normalize_linux_user(match.group("user")),
            severity=Severity.MEDIUM,
            raw_event=line,
            timestamp=timestamp,
            src_ip=clean_ip(match.group("ip")),
            protocol="ssh",
        )

    def _parse_sudo(self, message, host, line, timestamp) -> Optional[NormalizedEvent]:
        match = SUDO_RE.search(message)
        if not match:
            return None
        command = match.group("command").strip()
        target_user = match.group("target").strip()
        is_shell = bool(BASH_COMMAND_RE.search(command)) or command.endswith(("/bin/bash", "/bin/sh"))
        is_root = target_user == "root"
        return self._build(
            event_type=EventType.PRIVILEGE_ESCALATION,
            host=host,
            user=normalize_linux_user(match.group("user")),
            severity=Severity.HIGH if (is_root and is_shell) else Severity.MEDIUM,
            raw_event=line,
            timestamp=timestamp,
            process={
                "name": command.split()[0] if command else "sudo",
                "path": command.split()[0] if command else "/usr/bin/sudo",
                "command_line": command,
            },
        )

    def _parse_pam_failure(self, message, host, line, timestamp) -> Optional[NormalizedEvent]:
        match = PAM_FAILURE_RE.search(message)
        if not match:
            return None
        return self._build(
            event_type=EventType.LOGON_FAILURE,
            host=host,
            user=normalize_linux_user(match.group("user")),
            severity=Severity.MEDIUM,
            raw_event=line,
            timestamp=timestamp,
            src_ip=clean_ip(match.group("rhost")),
        )


__all__ = ["LinuxAuthParser", "normalize_linux_user"]
