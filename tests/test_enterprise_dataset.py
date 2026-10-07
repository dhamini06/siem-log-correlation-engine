"""Phase 4A - the deterministic enterprise SOC dataset.

These tests protect the properties that make the dataset usable as a lab:
it is reproducible, it is a realistic size and shape, its six false-positive
families stay silent, and - the reason the whole phase is constrained the way
it is - it does not move the answer key.

That last one is the important group. ``data/answer-key.json`` is authoritative
and out of scope for this phase, and 57 of its answer parts are pinned to values
a student discovers in the log data: source addresses, event counts, elapsed
seconds, rule thresholds, and the size and composition of the alert queue. A
dataset that "looks more realistic" but changes any of those is a content bug,
not a difficulty setting, so the pinned facts are asserted here directly.

Nothing in this file touches Elasticsearch or the training database. The rules
are run in memory against parsed events.
"""

import ast
import os
import re
import subprocess
import sys
from collections import defaultdict

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.config import load_app_config  # noqa: E402
from src.correlation.rules import _process_matches, apply_rules, load_events  # noqa: E402
from src.normalization import enterprise_generator as eg  # noqa: E402
from src.normalization.schema import compute_event_document_id, validate_event_payload  # noqa: E402

# One build for the whole module: it is deterministic, so this is safe and it
# keeps the suite fast.
_LINES = eg.build_lines()
_EVENTS = eg.parse_lines(_LINES)
_BY_TYPE = defaultdict(list)
for _e in _EVENTS:
    _BY_TYPE[_e.event_type.value].append(_e)


# --------------------------------------------------------------- determinism

def test_two_builds_are_identical():
    again = eg.build_lines()
    for kind in sorted(_LINES):
        assert _LINES[kind] == again[kind], "%s differs between builds" % kind


def test_two_processes_produce_the_same_digest():
    """Guards against module-level mutable state or import-order effects."""
    code = (
        "import sys, json, hashlib; sys.path.insert(0, %r)\n"
        "from src.normalization.enterprise_generator import build_lines\n"
        "print(hashlib.sha256(json.dumps(build_lines(), sort_keys=True)"
        ".encode('utf-8')).hexdigest())\n" % ROOT
    )
    digests = set()
    for _ in range(2):
        result = subprocess.run([sys.executable, "-c", code],
                                capture_output=True, text=True, check=True)
        digests.add(result.stdout.strip())
    assert len(digests) == 1, "generation is not reproducible across processes"


def test_the_seed_is_live():
    """A different seed must give different data, or determinism is trivial."""
    other = eg.build_lines(seed=eg.DEFAULT_SEED + 1)
    assert other["auth"] != _LINES["auth"]


def _module_tree():
    """AST of the generator, so source assertions are structural not textual."""
    import ast
    import inspect
    return ast.parse(inspect.getsource(eg))


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and body and \
                isinstance(body[0], ast.Expr) and \
                isinstance(body[0].value, ast.Constant) and \
                isinstance(body[0].value.value, str):
            ids.add(id(body[0].value))
    return ids


def test_generator_never_calls_the_clock():
    """The generation path must be a pure function of (base, seed).

    ``resolve_base_time`` reads the clock once, and only to mirror the year the
    log parsers already infer for a yearless syslog header. Nothing else may.
    Checked structurally rather than by grepping, so a mention in prose cannot
    hide a real call and a real call cannot hide behind a line break.
    """
    import ast

    tree = _module_tree()

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func.attr if isinstance(node.func, ast.Attribute) else \
            getattr(node.func, "id", None)
        if callee in ("now", "utc_now", "today"):
            offenders.append((callee, node.lineno))

    # Map every line inside a function to that function's name.
    owner = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                lineno = getattr(inner, "lineno", None)
                if lineno is not None:
                    owner.setdefault(lineno, node.name)

    assert offenders, "expected the single mirrored year read to still exist"
    for callee, lineno in offenders:
        assert owner.get(lineno) == "resolve_base_time", (
            "%s() at line %d is outside resolve_base_time (in %r)"
            % (callee, lineno, owner.get(lineno)))
    assert len(offenders) == 1, "expected exactly one clock read, found %d" % len(offenders)


def test_base_time_is_a_documented_constant():
    assert eg.DEFAULT_BASE_TIME == "2026-09-16T00:00:00Z"
    assert eg.DEFAULT_SEED == 1337
    assert eg.DATASET_DAYS == 14


def test_no_future_timestamps():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    assert max(e.timestamp for e in _EVENTS) < now


# ------------------------------------------------------------------- shape

def test_event_count_is_in_the_target_band():
    assert 8000 <= len(_EVENTS) <= 12000, "got %d events" % len(_EVENTS)


def test_host_diversity():
    hosts = {e.host for e in _EVENTS}
    assert len(hosts) >= 20, "only %d hosts" % len(hosts)
    assert len(eg.ALL_HOSTS) == 31


def test_source_ip_diversity():
    ips = {e.src_ip for e in _EVENTS if e.src_ip and e.src_ip != "unknown"}
    assert len(ips) >= 50, "only %d distinct source addresses" % len(ips)


def test_only_documentation_safe_or_private_addresses():
    """No address that could belong to a real system on the internet."""
    for e in _EVENTS:
        for value in (e.src_ip, e.dst_ip):
            if not value or value == "unknown":
                continue
            octets = [int(o) for o in value.split(".")]
            assert (octets[0] == 10                       # RFC 1918
                    or value.startswith("192.0.2.")       # RFC 5737
                    or value.startswith("198.51.100.")    # RFC 5737
                    or value.startswith("203.0.113.")), (
                "address %r is neither private nor documentation-reserved" % value)


def test_user_diversity():
    users = {e.user for e in _EVENTS}
    assert len(users) >= 15, "only %d users" % len(users)


def test_event_type_diversity_is_limited_by_the_schema():
    """Phase 4A must not widen the schema.

    The brief asked for dns_query / web_request / file_access / service_state.
    EventType has six members and adding to it is a schema change, which is out
    of scope, so the dataset uses what exists and represents the intent with
    the types it has.
    """
    from src.normalization.schema import EventType
    assert {e.value for e in EventType} == {
        "logon_success", "logon_failure", "process_create",
        "network_connection", "privilege_escalation", "account_unlock"}
    present = {e.event_type.value for e in _EVENTS}
    assert len(present) >= 5, "only %d event types: %s" % (len(present), present)
    # account_unlock has no parser that produces it, so it cannot appear
    assert "account_unlock" not in present


def test_time_span_is_fourteen_days():
    span = (max(e.timestamp for e in _EVENTS)
            - min(e.timestamp for e in _EVENTS)).total_seconds() / 86400
    assert 13.5 <= span <= 14.5, "span is %.2f days" % span


def test_severity_mix_is_mostly_baseline():
    """The schema has no 'informational' level; `low` is its baseline tier."""
    counts = defaultdict(int)
    for e in _EVENTS:
        counts[e.severity.value] += 1
    assert counts["low"] / len(_EVENTS) > 0.3
    assert counts["high"] / len(_EVENTS) < 0.10


# ------------------------------------------------------------------ schema

def test_every_event_validates():
    for e in _EVENTS[::200]:
        assert validate_event_payload(e.to_dict()) == [], e.raw_event[:80]


def test_raw_and_normalized_fields_agree():
    """A record must not claim a host or user it does not contain."""
    for e in _EVENTS[::200]:
        assert e.host in e.raw_event, "raw line lacks its own host: %r" % e.raw_event[:80]
        assert e.user, "event has no user"
        if e.event_type.value == "logon_failure" and e.user != "unknown":
            assert e.user.split("\\")[-1].split("@")[0] in e.raw_event, (
                "raw line lacks its own user: %r" % e.raw_event[:80])


def test_document_ids_are_unique_so_reingestion_is_idempotent():
    ids = [compute_event_document_id(e) for e in _EVENTS]
    assert len(set(ids)) == len(ids), (
        "%d duplicate ids: re-ingesting would overwrite distinct events"
        % (len(ids) - len(set(ids))))


def test_all_three_sources_are_represented():
    sources = {e.source_type.value for e in _EVENTS}
    assert sources == {"linux_auth", "windows_sysmon", "firewall_syslog"}


# ------------------------------------------------- output-directory safety

def test_generator_refuses_a_directory_holding_other_logs(tmp_path):
    """Two datasets in one directory would be indexed as one.

    ``ingest --log-dir`` indexes every log file it finds, so a directory holding
    this dataset alongside the older per-scenario files produces duplicate attack
    fixtures and an unexplainable event count. The generator must stop rather
    than allow it.
    """
    stale = tmp_path / "brute_force_auth.log"
    stale.write_text("Sep 16 03:00:00 web-01 sshd[1]: Failed password\n", encoding="utf-8")
    keep = tmp_path / "notes.txt"
    keep.write_text("not a log file", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        eg.generate_enterprise_logs(str(tmp_path))
    message = str(excinfo.value)
    assert "brute_force_auth.log" in message
    assert "--clean" in message
    # nothing was written or removed
    assert stale.exists() and keep.exists()
    assert not (tmp_path / ("%s_auth.log" % eg.DATASET_NAME)).exists()


def test_clean_removes_only_log_files(tmp_path):
    (tmp_path / "brute_force_auth.log").write_text("x\n", encoding="utf-8")
    (tmp_path / "old.jsonl").write_text("{}\n", encoding="utf-8")
    keep = tmp_path / "notes.txt"
    keep.write_text("keep me", encoding="utf-8")

    eg.generate_enterprise_logs(str(tmp_path), clean=True)

    assert keep.exists(), "clean removed a file that ingestion would never read"
    assert not (tmp_path / "brute_force_auth.log").exists()
    assert not (tmp_path / "old.jsonl").exists()
    for name in eg.dataset_paths(str(tmp_path)).values():
        assert os.path.isfile(name)


def test_foreign_log_files_detects_only_foreign_ones(tmp_path):
    eg.generate_enterprise_logs(str(tmp_path))
    assert eg.foreign_log_files(str(tmp_path)) == []
    (tmp_path / "leftover.log").write_text("x\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("x\n", encoding="utf-8")
    assert eg.foreign_log_files(str(tmp_path)) == ["leftover.log"]


# ------------------------------------------------- false-positive families

@pytest.mark.parametrize("src_ip,expected,label", [
    ("10.0.0.30", 4, "below threshold (canonical svc_backup)"),
    ("10.0.0.32", 6, "failures spread beyond the window"),
    ("10.0.0.41", 3, "split across source IPs, first half"),
    ("10.0.0.42", 3, "split across source IPs, second half"),
    ("10.0.0.50", 4, "late success, burst under threshold"),
])
def test_false_positive_families_are_present(src_ip, expected, label):
    got = [e for e in _BY_TYPE["logon_failure"] if e.src_ip == src_ip]
    assert len(got) == expected, "%s: %d failures, expected %d" % (label, len(got), expected)


def test_scheduled_task_family_is_present_and_out_of_window():
    ps = [e for e in _EVENTS
          if e.host == "app-02" and (e.process or {}).get("name") == "powershell.exe"]
    assert len(ps) == 1, "expected exactly one PowerShell on app-02, found %d" % len(ps)
    logons = [e.timestamp for e in _EVENTS
              if e.host == "app-02" and e.event_type.value == "logon_success"]
    nearest = min(abs((ps[0].timestamp - t).total_seconds()) for t in logons)
    assert nearest > 120, "the scheduled task is inside Rule 3's window (%.0fs)" % nearest


def test_expected_service_family_is_present():
    svc = [e for e in _EVENTS
           if e.host == "app-03" and (e.process or {}).get("name") == "svchost.exe"]
    assert svc, "no expected-service svchost on app-03"


def test_no_false_positive_family_raises_an_alert():
    produced = _all_alerts()
    for src_ip in ("10.0.0.30", "10.0.0.32", "10.0.0.41", "10.0.0.42", "10.0.0.50",
                   "10.0.0.60", "10.0.0.61"):
        assert src_ip not in {ip for _r, _s, ip in produced}, (
            "%s produced an alert" % src_ip)


# ----------------------------------------------------- canonical attack set

def test_alert_population_is_exactly_the_four_canonical_alerts():
    """The answer key pins the alert queue: 4 total, 3 high, 1 critical,
    2 from the post-login rule, 4 distinct source addresses."""
    found = _all_alerts()
    assert found == sorted(eg.CANONICAL_ALERTS), "alert population moved: %r" % (found,)
    severities = defaultdict(int)
    for _r, sev, _ip in found:
        severities[sev] += 1
    assert severities["high"] == 3 and severities["critical"] == 1
    assert len([1 for r, _s, _i in found
                if r == "suspicious_process_post_login"]) == 2
    assert len({ip for _r, _s, ip in found}) == 4


def test_scenario_one_burst_matches_the_pinned_evidence():
    s1 = sorted([e for e in _BY_TYPE["logon_failure"] if e.src_ip == "203.0.113.45"],
                key=lambda e: e.timestamp)
    assert len(s1) == 10, "Scenario 01 expects ten failures"
    assert {e.host for e in s1} == {"web-01"}
    span = (s1[-1].timestamp - s1[0].timestamp).total_seconds()
    assert span == 132, "the pinned window is 132 seconds, found %d" % span
    assert sorted({e.user for e in s1}) == ["admin", "root"]
    assert not [e for e in _BY_TYPE["logon_success"] if e.src_ip == "203.0.113.45"]


def test_scenario_one_firewall_corroboration_matches_the_pinned_evidence():
    fw = [e for e in _BY_TYPE["network_connection"] if e.src_ip == "203.0.113.45"]
    assert len(fw) == 3, "the key pins three blocked connections"
    assert {e.host for e in fw} == {"fw-01"}
    assert {e.dst_ip for e in fw} == {"10.0.0.10"}
    assert {e.port for e in fw} == {22}


def test_scenario_two_keeps_its_five_failure_fixture():
    """The brief's earlier suggestion of ten failures is explicitly overridden:
    the answer key is authoritative and was built against five."""
    fails = [e for e in _BY_TYPE["logon_failure"] if e.src_ip == "203.0.113.66"]
    succ = [e for e in _BY_TYPE["logon_success"] if e.src_ip == "203.0.113.66"]
    assert len(fails) == 5 and len(succ) == 1
    assert {e.user for e in fails + succ} == {"alice"}
    assert {e.host for e in fails + succ} == {"web-01"}


def test_scenario_three_keeps_its_twenty_second_gap():
    logon = [e for e in _BY_TYPE["logon_success"]
             if e.src_ip == "198.51.100.25" and e.host == "app-01"]
    procs = [e for e in _BY_TYPE["process_create"]
             if e.host == "app-01" and (e.process or {}).get("name") == "cmd.exe"]
    assert len(logon) == 1 and len(procs) == 1, (
        "a second cmd.exe on app-01 would make 'what was created' ambiguous")
    gap = (procs[0].timestamp - logon[0].timestamp).total_seconds()
    assert gap == 20, "the pinned gap is 20 seconds, found %d" % gap
    assert logon[0].user == "CORP\\jdoe"


def test_scenario_four_keeps_its_forty_five_second_gap():
    logon = [e for e in _BY_TYPE["logon_success"]
             if e.src_ip == "198.51.100.77" and e.host == "web-01"]
    sudo = [e for e in _BY_TYPE["privilege_escalation"]
            if e.host == "web-01"
            and (e.process or {}).get("command_line") == "/bin/bash -i"]
    assert len(logon) == 1 and len(sudo) == 1
    gap = (sudo[0].timestamp - logon[0].timestamp).total_seconds()
    assert gap == 45, "the pinned gap is 45 seconds, found %d" % gap
    assert logon[0].user == "deploy" and sudo[0].user == "deploy"


def test_scenario_four_has_benign_sudo_to_compare_against():
    benign = [e for e in _BY_TYPE["privilege_escalation"]
              if e.host == "web-01"
              and (e.process or {}).get("command_line") != "/bin/bash -i"]
    assert len(benign) >= 2, "the comparison question needs other sudo records"


def test_scenario_one_non_alerting_account_is_unambiguous():
    """The key pins svc_backup, four failures, from 10.0.0.30.

    If the background also produced failures for svc_backup, a student counting
    them would get a different number from the one expected.
    """
    hits = [e for e in _BY_TYPE["logon_failure"] if e.user == "svc_backup"]
    assert len(hits) == 4, "svc_backup has %d failures, the key pins four" % len(hits)
    assert {(e.src_ip, e.host) for e in hits} == {("10.0.0.30", "web-01")}
    assert [e for e in _BY_TYPE["logon_success"]
            if e.src_ip == "10.0.0.30" and e.user == "svc_backup"]


@pytest.mark.parametrize("account", ["alice", "admin", "root", "deploy", "jdoe"])
def test_scenario_accounts_do_not_appear_in_background_failures(account):
    """No answer-pinned account mistypes a password in the baseline."""
    allowed = {
        "alice": {"203.0.113.66"},
        "admin": {"203.0.113.45"},
        "root": {"203.0.113.45"},
        "deploy": set(),
        "jdoe": set(),
    }[account]
    origins = {e.src_ip for e in _BY_TYPE["logon_failure"] if e.user == account}
    assert origins <= allowed, (
        "%s also fails from %s, which changes the expected counts"
        % (account, sorted(origins - allowed)))


# ------------------------------------------------------- Rule 3 constraint

class _Proc:
    def __init__(self, process):
        self.process_name = (process or {}).get("name")
        self.process_path = (process or {}).get("path")
        self.command_line = (process or {}).get("command_line")


def test_baseline_keeps_suspicious_processes_out_of_logon_windows():
    """Documented limitation of the current rule model, enforced in the data.

    Rule 3 has no notion of a scheduled job, so the baseline places the
    suspicious process names only where no logon can pair with them. The only
    two exceptions are the Scenario 03 and Scenario 04 fixtures, which exist
    precisely to raise alerts.
    """
    suspicious = ("cmd.exe", "powershell.exe", "bash", "/bin/bash", "/bin/bash -i", "nc")
    expected = ("explorer.exe", "svchost.exe", "spoolsv.exe", "cron",
                "systemd-logind", "sshd")
    logons = defaultdict(list)
    for e in _EVENTS:
        if e.event_type.value == "logon_success":
            logons[e.host].append(e.timestamp)

    pairs = []
    for e in _EVENTS:
        if e.event_type.value not in ("process_create", "privilege_escalation"):
            continue
        proc = _Proc(e.process)
        if _process_matches(proc, expected) or not _process_matches(proc, suspicious):
            continue
        for stamp in logons.get(e.host, ()):
            if abs((e.timestamp - stamp).total_seconds()) <= 120:
                pairs.append((e.host, (e.process or {}).get("name")))
                break
    assert sorted(pairs) == [("app-01", "cmd.exe"), ("web-01", "/bin/bash")], (
        "unexpected suspicious process inside a logon window: %r" % (pairs,))


def test_the_limitation_is_documented():
    docs = os.path.join(ROOT, "docs", "DATASET.md")
    assert os.path.isfile(docs), "docs/DATASET.md is missing"
    text = open(docs, encoding="utf-8").read()
    assert "suspicious_processes" in text
    assert "limitation" in text.lower()
    assert "Phase 4A" in text


# ------------------------------------------------------------ answer safety

def test_no_record_is_labelled_with_what_it_is():
    """No generated line may name a scenario, an answer, or a verdict."""
    banned = re.compile(
        r"scenario[-_ ]?\d|answer|correct_ip|brute_force_attack|malicious|"
        r"attacker|intrusion|threat|true_positive|false_positive", re.IGNORECASE)
    for kind, lines in _LINES.items():
        for line in lines:
            assert not banned.search(line), "leaky metadata in %s: %r" % (kind, line[:120])


def test_answer_key_is_untouched_by_this_module():
    tree = _module_tree()
    key = os.path.join(ROOT, "data", "answer-key.json")
    # The key must still carry stable evidence values. svc_backup was named here
    # before Phase 6, but no question asks which account a near-miss belonged to,
    # so it is no longer an answer and the key no longer needs to carry it.
    # min_failures replaced it: s1e8 asks which rule condition fell short.
    text = open(key, encoding="utf-8").read()
    assert "203.0.113.45" in text and "min_failures" in text

    # The generator may *discuss* the answer key in a docstring; it may not
    # reference it from executable code. Checked on the AST so prose cannot
    # produce a false positive and a real read cannot hide inside a string.
    docstrings = _docstring_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                id(node) not in docstrings and \
                ("answer-key" in node.value or "answer_key" in node.value):
            raise AssertionError(
                "the generator references the answer key in code: %r" % node.value)


def test_generated_lines_never_quote_an_answer_token():
    """The dataset contains evidence; it must not contain a graded answer string.

    Only the canonical attack addresses are allowed, and only because they are
    also the log's own source addresses.
    """
    allowed = {"203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
               "10.0.0.10", "10.0.0.30", "10.0.0.32", "10.0.0.41", "10.0.0.42",
               "10.0.0.50", "10.0.1.40", "10.0.1.41", "10.0.1.42", "10.0.1.43"}
    blob = "\n".join(line for kind in sorted(_LINES) for line in _LINES[kind])
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        assert token in allowed or token.startswith(("10.", "198.51.100.", "192.0.2.")), (
            "unexpected address in generated data: %s" % token)


def _all_alerts():
    hits = [{"_id": e.raw_event, "_source": e.to_dict()} for e in _EVENTS]
    return sorted((a.rule_name, a.severity.value, a.src_ip or "")
                  for a in apply_rules(load_events(hits), load_app_config()))
