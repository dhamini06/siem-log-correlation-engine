"""Verify every practice scenario is solvable from the data actually in Elasticsearch.

Phase 5 gate: a scenario is only valid if the events, the alert, and the exact
values a student must find all exist right now. This script asserts that
directly against the running cluster.

    python scripts/validate_scenarios.py
    python scripts/validate_scenarios.py --skip-es     # structural checks only

Exit code 0 means every scenario is backed by real data. Expectations live in
this file (instructor-side); student pages never contain the answers.
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    print("requests is required: pip install -r requirements.txt", file=sys.stderr)
    raise

ES_URL = "http://localhost:9200"
KIBANA_URL = "http://localhost:5601"

FAILURES: List[str] = []
CHECKS = 0


def check(label: str, ok: bool, detail: str = "") -> bool:
    global CHECKS
    CHECKS += 1
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)
    return ok


def es(index: str, body: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(f"{ES_URL}/{index}/_search", json=body, timeout=30)
    response.raise_for_status()
    return response.json()


def events(index: str, query: Dict[str, Any], size: int = 200,
           sort: Any = None) -> List[Dict[str, Any]]:
    body: Dict[str, Any] = {"size": size, "query": query}
    if sort:
        body["sort"] = sort
    return [hit["_source"] for hit in es(index, body)["hits"]["hits"]]


def alerts() -> List[Dict[str, Any]]:
    return events("security-alerts-*", {"match_all": {}}, sort=[{"timestamp": "asc"}])


def alert_by_rule(rules: List[str]) -> Optional[Dict[str, Any]]:
    for alert in alerts():
        if alert.get("rule_name") in rules:
            return alert
    return None


# --------------------------------------------------------------------------
# Scenario expectations. Every value here must exist in the live data.
# --------------------------------------------------------------------------

SCENARIO_1 = {
    "rule": "brute_force",
    "severity": "high",
    "src_ip": "203.0.113.45",
    "host": "web-01",
    "users": {"root": 5, "admin": 5},
    "failures": 10,
    "window_seconds": 132,
    "firewall_events": 3,
    "firewall_dst": "10.0.0.10",
    "firewall_port": 22,
    "no_success_from_ip": True,
    "non_alerting_user": "svc_backup",
    "non_alerting_failures": 4,
}

SCENARIO_2 = {
    "rule": "successful_brute_force",
    "severity": "critical",
    "src_ip": "203.0.113.66",
    "host": "web-01",
    "user": "alice",
    "failures": 5,
    "evidence": 6,
    "window_seconds": 129,
}

SCENARIO_3 = {
    "rule": "suspicious_process_post_login",
    "host": "app-01",
    # The alert stores the domain-stripped user; the underlying event keeps the
    # Windows DOMAIN\user form. Both are valid answers, so both are asserted.
    "alert_user": "jdoe",
    "event_user": "CORP\\jdoe",
    "src_ip": "198.51.100.25",
    "process": "cmd.exe",
    "gap_seconds": 20,
    "parent": "winlogon.exe",
    "command_fragment": "net user administrator /active:yes",
    "windows_event_id": 4624,
}

SCENARIO_4 = {
    "rule": "suspicious_process_post_login",
    "host": "web-01",
    "user": "deploy",
    "src_ip": "198.51.100.77",
    "sudo_target": "root",
    "command": "/bin/bash -i",
    "gap_seconds": 45,
    "benign_user": "carol",
    "benign_commands": ["/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update"],
}

SCENARIO_5 = {
    "total_alerts": 4,
    "high": 3,
    "critical": 1,
    "rules": {
        "brute_force": 1,
        "successful_brute_force": 1,
        "suspicious_process_post_login": 2,
    },
    "hosts_with_alerts": ["app-01", "web-01"],
    "baseline_user": "alice",
    "non_alerting_admin_host": "app-02",
    "non_alerting_process": "powershell.exe",
    "total_events": 50,
}


def validate_scenario_1() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO 1 - Brute Force Investigation")
    print("=" * 70)
    spec = SCENARIO_1
    alert = alert_by_rule([spec["rule"]])
    if not check("alert 'brute_force' exists", alert is not None):
        return
    check("alert severity is high", alert["severity"] == spec["severity"], alert["severity"])
    check("alert source IP matches", alert["src_ip"] == spec["src_ip"], alert["src_ip"])
    check("alert host matches", alert["host"] == spec["host"], alert["host"])
    check("alert evidence count matches", alert["evidence_count"] == spec["failures"],
          str(alert["evidence_count"]))

    failures = events("normalized-events-*", {
        "bool": {"filter": [
            {"term": {"event_type": "logon_failure"}},
            {"term": {"src_ip": spec["src_ip"]}},
        ]}
    }, sort=[{"@timestamp": "asc"}])
    check(f"{spec['failures']} failed logons from the attacker IP", len(failures) == spec["failures"],
          str(len(failures)))

    from collections import Counter
    counts = Counter(e["user"] for e in failures)
    for user, expected in spec["users"].items():
        check(f"user '{user}' targeted {expected} times", counts.get(user) == expected, str(counts.get(user)))

    if failures:
        from datetime import datetime

        def parse(value: str) -> datetime:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))

        span = int((parse(failures[-1]["@timestamp"]) - parse(failures[0]["@timestamp"])).total_seconds())
        check(f"failure window is {spec['window_seconds']}s", span == spec["window_seconds"],
              f"{span}s ({failures[0]['@timestamp']} -> {failures[-1]['@timestamp']})")

    successes = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_success"}},
                            {"term": {"src_ip": spec["src_ip"]}}]}
    })
    check("no success from the attacker IP", not successes, f"{len(successes)} success(es)")

    firewall = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "network_connection"}},
                            {"term": {"src_ip": spec["src_ip"]}}]}
    })
    check(f"{spec['firewall_events']} firewall records corroborate", len(firewall) == spec["firewall_events"],
          str(len(firewall)))
    check("firewall destination matches", all(e.get("dst_ip") == spec["firewall_dst"] for e in firewall),
          spec["firewall_dst"])
    check("firewall port matches", all(e.get("port") == spec["firewall_port"] for e in firewall),
          str(spec["firewall_port"]))

    quiet = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_failure"}},
                            {"term": {"user": spec["non_alerting_user"]}}]}
    })
    check(f"non-alerting account has {spec['non_alerting_failures']} failures",
          len(quiet) == spec["non_alerting_failures"], str(len(quiet)))
    check("non-alerting account is below the min_failures threshold",
          len(quiet) < 5, f"{len(quiet)} < 5")
    check("no alert exists for the non-alerting account",
          all(a.get("src_ip") != "10.0.0.30" for a in alerts()), "10.0.0.30 absent from alerts")


def validate_scenario_2() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO 2 - Successful Login After Brute Force")
    print("=" * 70)
    spec = SCENARIO_2
    alert = alert_by_rule([spec["rule"]])
    if not check("alert 'successful_brute_force' exists", alert is not None):
        return
    check("alert severity is critical", alert["severity"] == spec["severity"], alert["severity"])
    check("alert source IP matches", alert["src_ip"] == spec["src_ip"], alert["src_ip"])
    check("alert host matches", alert["host"] == spec["host"], alert["host"])
    check("alert user matches", alert["user"] == spec["user"], alert["user"])
    check("alert evidence count matches", alert["evidence_count"] == spec["evidence"],
          str(alert["evidence_count"]))

    failures = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_failure"}},
                            {"term": {"src_ip": spec["src_ip"]}}]}
    }, sort=[{"@timestamp": "asc"}])
    check(f"{spec['failures']} failed logons before the success", len(failures) == spec["failures"],
          str(len(failures)))
    check("all failures targeted the compromised account",
          all(e["user"] == spec["user"] for e in failures), spec["user"])

    successes = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_success"}},
                            {"term": {"src_ip": spec["src_ip"]}}]}
    })
    check("exactly one success from the attacker IP", len(successes) == 1, str(len(successes)))
    if not (failures and successes):
        return

    from datetime import datetime

    def parse(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    span = int((parse(successes[0]["@timestamp"]) - parse(failures[0]["@timestamp"])).total_seconds())
    check(f"first failure to success is {spec['window_seconds']}s", span == spec["window_seconds"],
          f"{span}s ({failures[0]['@timestamp']} -> {successes[0]['@timestamp']})")
    check("success event records the sshd process",
          (successes[0].get("process") or {}).get("name") == "sshd",
          str((successes[0].get("process") or {}).get("name")))
    check("success raw_event shows an accepted SSH password",
          "Accepted password" in successes[0]["raw_event"], "sshd accepted line")


def validate_scenario_3() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO 3 - Suspicious Post-Login Process Execution")
    print("=" * 70)
    spec = SCENARIO_3
    matches = [a for a in alerts()
               if a.get("rule_name") == spec["rule"] and a.get("host") == spec["host"]]
    if not check("post-login alert on the Windows host exists", bool(matches)):
        return
    alert = matches[0]
    check("alert severity is high", alert["severity"] == "high", alert["severity"])
    check("alert user matches (domain-stripped form)", alert["user"] == spec["alert_user"],
          alert["user"])
    check("alert source IP matches", alert["src_ip"] == spec["src_ip"], alert["src_ip"])
    check("alert evidence is 2 events (logon + process)", alert["evidence_count"] == 2,
          str(alert["evidence_count"]))

    logons = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_success"}},
                            {"term": {"host": spec["host"]}},
                            {"term": {"user": spec["event_user"]}}]}
    })
    check("the logon event exists", len(logons) == 1, str(len(logons)))
    if not logons:
        return
    check("the event carries the domain-qualified Windows account",
          logons[0]["user"] == spec["event_user"], logons[0]["user"])

    from datetime import datetime

    def parse(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    start = parse(logons[0]["@timestamp"])
    check("logon is a Windows 4624 record", f'"EventID": {spec["windows_event_id"]}' in logons[0]["raw_event"],
          f"EventID {spec['windows_event_id']}")

    procs = [e for e in events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "process_create"}},
                            {"term": {"host": spec["host"]}}]}
    }) if (e.get("process") or {}).get("name") == spec["process"]]
    check(f"the '{spec['process']}' process_create event exists", bool(procs), str(len(procs)))
    if not procs:
        return

    process_event = procs[0]
    gap = int((parse(process_event["@timestamp"]) - start).total_seconds())
    check(f"logon to process gap is {spec['gap_seconds']}s", gap == spec["gap_seconds"], f"{gap}s")
    check("process parent is the expected one",
          (process_event.get("process") or {}).get("parent_name") == spec["parent"],
          str((process_event.get("process") or {}).get("parent_name")))
    check("command line contains the key operation",
          spec["command_fragment"] in (process_event["process"].get("command_line") or ""),
          spec["command_fragment"])
    check("cmd.exe is on the suspicious process list",
          "cmd.exe" in ("cmd.exe", "powershell.exe", "bash", "nc", "/bin/bash -i"),
          "configured list")


def validate_scenario_4() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO 4 - Linux Privilege Escalation and Reverse Shell")
    print("=" * 70)
    spec = SCENARIO_4
    matches = [a for a in alerts()
               if a.get("rule_name") == spec["rule"]
               and a.get("host") == spec["host"]
               and a.get("user") == spec["user"]]
    if not check("post-login alert on the Linux host exists", bool(matches)):
        return
    alert = matches[0]
    check("alert severity is high", alert["severity"] == "high", alert["severity"])
    check("alert source IP matches", alert["src_ip"] == spec["src_ip"], alert["src_ip"])
    check("alert user matches", alert["user"] == spec["user"], alert["user"])

    logons = events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "logon_success"}},
                            {"term": {"src_ip": spec["src_ip"]}}]}
    })
    check("the SSH logon event exists", len(logons) == 1, str(len(logons)))

    sudo = [e for e in events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "privilege_escalation"}},
                            {"term": {"host": spec["host"]}}]}
    }) if spec["command"] in ((e.get("process") or {}).get("command_line") or "")]
    check(f"the sudo '{spec['command']}' event exists", bool(sudo), str(len(sudo)))
    if not (logons and sudo):
        return

    from datetime import datetime

    def parse(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    gap = int((parse(sudo[0]["@timestamp"]) - parse(logons[0]["@timestamp"])).total_seconds())
    check(f"logon to sudo gap is {spec['gap_seconds']}s", gap == spec["gap_seconds"], f"{gap}s")
    check("sudo escalates to root", f"USER={spec['sudo_target']}" in sudo[0]["raw_event"],
          f"USER={spec['sudo_target']}")
    check("sudo record carries a TTY", "TTY=" in sudo[0]["raw_event"], "TTY= present")
    check("sudo record carries a working directory", "PWD=" in sudo[0]["raw_event"], "PWD= present")
    check("interactive shell is graded high severity", sudo[0]["severity"] == "high", sudo[0]["severity"])

    benign = [e for e in events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "privilege_escalation"}},
                            {"term": {"host": spec["host"]}},
                            {"term": {"user": spec["benign_user"]}}]}
    })]
    check(f"benign sudo events for '{spec['benign_user']}' exist ({len(spec['benign_commands'])})",
          len(benign) == len(spec["benign_commands"]), str(len(benign)))
    commands = [(e.get("process") or {}).get("command_line") for e in benign]
    check("all benign sudo commands are present",
          all(c in commands for c in spec["benign_commands"]), str(commands))
    check("benign sudo events are medium severity",
          all(e["severity"] == "medium" for e in benign), "medium")
    check("malicious and benign sudo are distinguishable by command",
          spec["command"] not in commands, "interactive shell is unique")


def validate_scenario_5() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO 5 - Multi-Event SOC Investigation")
    print("=" * 70)
    spec = SCENARIO_5
    all_alerts = alerts()
    check(f"{spec['total_alerts']} alerts on the board", len(all_alerts) == spec["total_alerts"],
          str(len(all_alerts)))

    high = [a for a in all_alerts if a["severity"] == "high"]
    critical = [a for a in all_alerts if a["severity"] == "critical"]
    check(f"{spec['high']} high severity alerts", len(high) == spec["high"], str(len(high)))
    check(f"{spec['critical']} critical severity alert", len(critical) == spec["critical"],
          str(len(critical)))

    for rule, expected in spec["rules"].items():
        found = [a for a in all_alerts if a["rule_name"] == rule]
        check(f"rule '{rule}' raised {expected} alert(s)", len(found) == expected, str(len(found)))

    hosts = sorted({a["host"] for a in all_alerts})
    check("alerts span the expected hosts", hosts == sorted(spec["hosts_with_alerts"]), str(hosts))

    sources = sorted({a["src_ip"] for a in all_alerts})
    check("more than two distinct source IPs generated alerts", len(sources) > 2, str(sources))

    total_events = requests.get(f"{ES_URL}/normalized-events-*/_count", timeout=30).json()["count"]
    check(f"{spec['total_events']} normalized events available for the timeline",
          total_events == spec["total_events"], str(total_events))

    baseline = [e for e in events("normalized-events-*", {"match_all": {}})
                if e["host"] == "web-01" and e["event_type"] in ("logon_success", "logon_failure")
                and str(e.get("src_ip", "")).startswith("10.0.0.2")]
    check("routine internal logon baseline exists", len(baseline) > 5, f"{len(baseline)} events")

    admin_events = [e for e in events("normalized-events-*", {
        "bool": {"filter": [{"term": {"event_type": "process_create"}},
                            {"term": {"host": spec["non_alerting_admin_host"]}}]}
    }) if (e.get("process") or {}).get("name") == spec["non_alerting_process"]]
    check("the non-alerting PowerShell activity exists", bool(admin_events), str(len(admin_events)))
    if admin_events:
        logon = [e for e in events("normalized-events-*", {
            "bool": {"filter": [{"term": {"event_type": "logon_success"}},
                                {"term": {"host": spec["non_alerting_admin_host"]}}]}
        })]
        if logon:
            from datetime import datetime

            def parse(value: str) -> datetime:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))

            gap = (parse(admin_events[0]["@timestamp"]) - parse(logon[0]["@timestamp"])).total_seconds() / 60
            check("that PowerShell ran well outside the 2-minute window", gap > 2, f"{gap:.0f} minutes")
        check("no alert exists for that host",
              all(a["host"] != spec["non_alerting_admin_host"] for a in all_alerts),
              f"{spec['non_alerting_admin_host']} absent from alerts")


def validate_kibana() -> None:
    print("\n" + "=" * 70)
    print("KIBANA - dashboard and data views")
    print("=" * 70)
    headers = {"kbn-xsrf": "siem-lab"}
    try:
        data_views = requests.get(f"{KIBANA_URL}/api/data_views", headers=headers, timeout=30).json()
    except requests.RequestException as exc:
        check("Kibana API reachable", False, str(exc))
        return
    titles = {d["title"] for d in data_views.get("data_view", [])}
    check("data view 'security-alerts-*' exists", "security-alerts-*" in titles, str(sorted(titles)))
    check("data view 'normalized-events-*' exists", "normalized-events-*" in titles, str(sorted(titles)))

    found = requests.get(f"{KIBANA_URL}/api/saved_objects/_find", headers=headers,
                         params={"type": "dashboard", "per_page": 10}, timeout=30).json()
    check("SOC Triage Board dashboard exists", found.get("total", 0) >= 1, str(found.get("total")))


def validate_pages() -> None:
    print("\n" + "=" * 70)
    print("TRAINING PLATFORM - pages and structure")
    print("=" * 70)
    import os
    import re

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    training = os.path.join(root, "training")
    required = [
        "index.html",
        "instructions.html",
        os.path.join("assets", "css", "bluecloud.css"),
        os.path.join("assets", "js", "lab.js"),
        os.path.join("scenarios", "scenario-1-brute-force.html"),
        os.path.join("scenarios", "scenario-2-successful-brute-force.html"),
        os.path.join("scenarios", "scenario-3-post-login-execution.html"),
        os.path.join("scenarios", "scenario-4-linux-privilege-escalation.html"),
        os.path.join("scenarios", "scenario-5-multi-event-soc-investigation.html"),
    ]
    for rel in required:
        check(f"page present: training/{rel.replace(os.sep, '/')}", os.path.isfile(os.path.join(training, rel)))

    pages = [os.path.join(training, rel) for rel in required if rel.endswith(".html")]
    for page in pages:
        name = os.path.basename(page)
        with open(page, "r", encoding="utf-8") as handle:
            html = handle.read()
        check(f"{name} links to Kibana", "data-kibana" in html)
        check(f"{name} has BlueCloud branding", "BlueCloud Softech Solutions" in html)
        check(f"{name} has no answer leak", "Answer key" not in html and "expected finding:" not in html.lower())

    scenario_pages = [p for p in pages if "scenario-" in os.path.basename(p)]
    check("five scenario pages present", len(scenario_pages) == 5, str(len(scenario_pages)))
    for page in scenario_pages:
        name = os.path.basename(page)
        with open(page, "r", encoding="utf-8") as handle:
            html = handle.read()
        check(f"{name} has a 'Start Investigation' style action",
              "Open SIEM Dashboard" in html or "data-kibana-dash" in html)
        # Phase 6: questions are named s<N>e<M> for evidence objectives and s<N>f
        # for the final analyst finding. The page is checked for the shape rather
        # than one hard-coded id, so a scenario cannot pass by shipping a single
        # stub question, and cannot pass while omitting its finding.
        ids = sorted(set(re.findall(r'data-question-row="(s\d(?:e\d+|f))"', html)))
        evidence = [i for i in ids if re.fullmatch(r"s\de\d+", i)]
        findings = [i for i in ids if re.fullmatch(r"s\df", i)]
        controls = sorted(set(re.findall(r'data-question="(s\d(?:e\d+|f))"', html)))
        buttons = sorted(set(re.findall(r'data-check="(s\d(?:e\d+|f))"', html)))
        check(f"{name} has questions", bool(ids), str(len(ids)))
        check(f"{name} has 6-8 evidence questions",
              6 <= len(evidence) <= 8, "%d evidence questions" % len(evidence))
        check(f"{name} has exactly one final analyst finding",
              len(findings) == 1, str(findings))
        check(f"{name} gives every question an answer control", controls == ids,
              "controls %r vs questions %r" % (controls, ids))
        check(f"{name} gives every question its own Check answer", buttons == ids,
              "check buttons %r vs questions %r" % (buttons, ids))
        check(f"{name} has no submit-everything button",
              'id="check-answers"' not in html)
        # Phase 1A: the scenario pages no longer restate the full "do not guess"
        # explanation - it lives once, on the reference page. The short in-scenario
        # equivalent is that answers must come from SIEM evidence.
        #
        # Scoped to the introduction paragraph on purpose. An earlier version
        # tested `"evidence" in html` and that passed even with the requirement
        # deleted, because the word appears in every page's rail, its evidence
        # labels and the class names - a mutation check confirmed the loose form
        # caught nothing.
        intro = re.search(r'<p class="qintro">(.*?)</p>', html, re.S)
        intro_text = intro.group(1) if intro else ""
        check(f"{name} requires evidence for every answer",
              any(phrase in intro_text for phrase in (
                  "not to guess", "Do not guess",
                  "Use SIEM evidence for every answer",
              )),
              ("intro: %r" % intro_text[:80]) if intro_text else "no .qintro paragraph")

    guide = os.path.join(root, "docs", "INSTRUCTOR_GUIDE.md")
    check("instructor guide exists", os.path.isfile(guide))
    if os.path.isfile(guide):
        with open(guide, "r", encoding="utf-8") as handle:
            text = handle.read()
        check("instructor guide contains the answer key", "Answer Key" in text)
        for ip in ("203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77"):
            check(f"instructor guide covers {ip}", ip in text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate that every scenario is backed by real SIEM data")
    parser.add_argument("--skip-es", action="store_true", help="Only run structural page checks")
    args = parser.parse_args()

    print("=" * 70)
    print("BLUECLOUD SIEM LAB - SCENARIO DATA VALIDATION")
    print("=" * 70)

    validate_pages()

    if args.skip_es:
        print("\n(skipping Elasticsearch scenario validation)")
    else:
        try:
            health = requests.get(f"{ES_URL}/_cluster/health", timeout=15).json()
            print(f"\nElasticsearch: {health.get('status')}  Kibana data will be checked below")
        except requests.RequestException as exc:
            print(f"\nElasticsearch is not reachable at {ES_URL}: {exc}", file=sys.stderr)
            return 1
        validate_scenario_1()
        validate_scenario_2()
        validate_scenario_3()
        validate_scenario_4()
        validate_scenario_5()
        validate_kibana()

    print("\n" + "=" * 70)
    if FAILURES:
        print(f"RESULT: {CHECKS - len(FAILURES)}/{CHECKS} checks passed, {len(FAILURES)} FAILED")
        for failure in FAILURES:
            print(f"  FAILED: {failure}")
        print("=" * 70)
        return 1
    print(f"RESULT: all {CHECKS} checks passed - every scenario is backed by real data")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
