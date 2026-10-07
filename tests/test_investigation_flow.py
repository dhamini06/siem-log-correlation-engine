"""Tests for the Phase 6 investigation flow.

The worksheet model submitted every question at once and graded every question
back. Phase 6 replaces that with a queue: one objective, one Check answer button,
one verdict. This file covers the behaviour that change introduced and that the
pre-existing suites do not reach:

* checking a single question, and that the question filter cannot be used to
  reach anything else;
* the completion gate, in particular that evidence alone can never finish a
  scenario;
* the answer controls - text, count, duration, boolean, enum, ordering, finding -
  and that each renders the markup the client reads;
* that an ordered selection serialises to a string the existing containment
  matcher can grade, with no change to the grading engine;
* the UI contract: a Check button per question, feedback and retry affordances,
  and no submit-everything button.

The instructor answer key is server-side throughout; no test here reads it to
decide what a browser would see.
"""
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING = os.path.join(REPO_ROOT, "training")
SCENARIOS_DIR = os.path.join(TRAINING, "scenarios")
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
ANSWER_KEY = os.path.join(REPO_ROOT, "data", "answer-key.json")
LAB_CHECK_JS = os.path.join(TRAINING, "assets", "js", "lab-check.js")

sys.path.insert(0, SCRIPTS)
import answer_grader as G  # noqa: E402

SCENARIO_FILES = {
    "scenario-1": "scenario-1-brute-force.html",
    "scenario-2": "scenario-2-successful-brute-force.html",
    "scenario-3": "scenario-3-post-login-execution.html",
    "scenario-4": "scenario-4-linux-privilege-escalation.html",
    "scenario-5": "scenario-5-multi-event-soc-investigation.html",
}

EVIDENCE_ID = re.compile(r"^s(\d)e(\d+)$")
FINDING_ID = re.compile(r"^s(\d)f$")
CONTROLS = {"identifier", "count", "duration", "boolean", "enum", "ordering", "finding"}


def read(path):
    with io.open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def key():
    return G.load_key()


def page(scenario):
    return read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))


def ids(scenario, key=None):
    """(evidence ids in order, finding id) for a scenario."""
    key = key if key is not None else G.load_key()
    questions = key["scenarios"][scenario]["questions"]
    evidence = sorted((EVIDENCE_ID.match(q).group(2), q) for q in questions
                      if EVIDENCE_ID.match(q))
    findings = [q for q in questions if FINDING_ID.match(q)]
    assert len(findings) == 1, "%s: %d findings" % (scenario, len(findings))
    return [q for _, q in evidence], findings[0]


def row_of(html, qid):
    """The full markup of one question row, bounded by the next row's start."""
    starts = list(re.finditer(r'<li class="q-item[^"]*" data-question-row="([^"]+)"', html))
    target = [m for m in starts if m.group(1) == qid]
    assert target, "no row for %s" % qid
    start = target[0].start()
    after = [m.start() for m in starts if m.start() > start]
    end = after[0] if after else html.index("</ol>", start)
    return html[start:end]


# ============================================================ question model

def test_every_scenario_has_six_to_eight_evidence_questions_and_one_finding(key):
    """The Phase 6 shape, for every scenario."""
    for scenario in SCENARIO_FILES:
        evidence, finding = ids(scenario, key)
        assert 6 <= len(evidence) <= 8, (
            "%s: %d evidence questions" % (scenario, len(evidence)))
        assert finding.endswith("f"), (scenario, finding)


def test_question_ids_are_well_formed_and_unique(key):
    """No legacy worksheet ids, no duplicates, ids match their scenario."""
    seen = set()
    for scenario, spec in key["scenarios"].items():
        number = scenario.split("-")[1]
        for qid in spec["questions"]:
            assert EVIDENCE_ID.match(qid) or FINDING_ID.match(qid), (
                "malformed question id %r in %s" % (qid, scenario))
            assert qid.startswith("s%s" % number), (
                "%s carries %r, which belongs to another scenario" % (scenario, qid))
            assert qid not in seen, "duplicate question id %s" % qid
            seen.add(qid)
            assert not re.fullmatch(r"q\d+", qid), (
                "%s is a legacy worksheet id" % qid)


def test_evidence_ids_are_contiguous_from_one(key):
    for scenario in SCENARIO_FILES:
        evidence, _ = ids(scenario, key)
        numbers = [int(EVIDENCE_ID.match(q).group(2)) for q in evidence]
        assert numbers == list(range(1, len(numbers) + 1)), (scenario, numbers)


def test_every_question_is_required_and_the_finding_is_among_them(key):
    """Nothing sits outside required_total any more.

    Under the worksheet model the written answers had no parts, graded as
    `self_review` and were excluded from required_total, so a scenario could be
    completed without writing a finding at all.
    """
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            assert question.get("required") is True, "%s/%s is not required" % (scenario, qid)
            assert question.get("parts"), (
                "%s/%s has no parts, so it can never be correct" % (scenario, qid))
            assert question.get("solution"), "%s/%s has no model answer" % (scenario, qid)


def test_the_finding_declares_a_review_prompt_and_a_rubric(key):
    for scenario in SCENARIO_FILES:
        _, finding = ids(scenario, key)
        question = key["scenarios"][scenario]["questions"][finding]
        assert question["review_prompt"], scenario
        assert question.get("rubric"), "%s: the finding needs a rubric" % scenario
        assert len(question["parts"]) >= 3, (
            "%s: a rubric of %d elements is not a rubric" % (scenario, len(question["parts"])))
        for part in question["parts"]:
            assert part.get("hint"), "%s: rubric element without guidance" % scenario


def test_every_control_type_is_declared_and_used(key):
    declared = set(key.get("control_types") or {})
    used = set()
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            control = question["control"]
            assert control in CONTROLS, "%s/%s: unknown control %r" % (scenario, qid, control)
            used.add(control)
            if control in ("enum", "ordering"):
                # A <select> yields one value and an ordering list is fixed, so
                # neither can carry two graded facts.
                assert len(question.get("parts") or []) == 1, (
                    "%s/%s: a %s question cannot express %d parts"
                    % (scenario, qid, control, len(question.get("parts") or [])))
                assert question.get("options"), "%s/%s: no options to choose from" % (scenario, qid)
            if control == "boolean":
                assert len(question.get("parts") or []) >= 1
    assert used <= declared or not declared, (
        "undeclared control types in use: %s" % sorted(used - declared))
    # The model is supposed to use real controls, not be all free text.
    assert {"count", "duration", "boolean", "enum", "ordering"} <= used, (
        "the richer answer controls are not all in use: %s" % sorted(used))


def test_a_vague_finding_fails_and_a_complete_one_passes(key):
    for scenario in SCENARIO_FILES:
        _, finding = ids(scenario, key)
        vague = G.grade(scenario, {finding: "Something happened and it was bad."}, key)
        assert vague["questions"][finding]["status"] != "correct", scenario
        complete = G.grade(scenario, {finding: key["scenarios"][scenario]["questions"][finding]["solution"]},
                           key)
        assert complete["questions"][finding]["status"] == "correct", scenario


# ======================================================== single-question check

def test_a_filtered_check_grades_only_the_named_question(key):
    evidence, _ = ids("scenario-1", key)
    target = evidence[0]
    result = G.grade("scenario-1", {target: "203.0.113.45"}, key, questions=[target])
    assert sorted(result["questions"]) == [target]
    assert result["checked"] == [target]
    assert result["scoped"] is True
    # A scoped check knows nothing about the rest of the scenario.
    assert result["completed"] is False


def test_a_filtered_check_reports_counts_for_the_selection_only(key):
    evidence, _ = ids("scenario-1", key)
    target = evidence[0]
    result = G.grade("scenario-1", {target: "203.0.113.45"}, key, questions=[target])
    assert result["summary"]["correct"] == 1, result["summary"]
    assert result["summary"]["required_total"] == 1, result["summary"]


def test_a_filtered_check_does_not_touch_the_others(key):
    """A student who answers well must keep that credit while working elsewhere."""
    evidence, _ = ids("scenario-2", key)
    first, second = evidence[0], evidence[1]
    G.grade("scenario-2", {first: "alice"}, key, questions=[first])
    result = G.grade("scenario-2", {second: "root"}, key, questions=[second])
    assert sorted(result["questions"]) == [second]
    assert "first" not in json.dumps(sorted(result["questions"]))
    assert first not in result["questions"]
    assert result["questions"][second]["status"] == "incorrect"


@pytest.mark.parametrize("bad", [
    [],                      # empty selection
    ["q1"],                  # a legacy worksheet id
    ["s2e1"],                # another scenario's question
    ["s9e9"],                # a scenario that does not exist
    ["s1f", "s5e1"],         # a mix spanning scenarios
    "s1e1",                  # a string, not a list
    [123],                   # not even a string
    [{"question": "s1e1"}],  # an object
])
def test_the_question_filter_rejects_anything_it_should(key, bad):
    """The filter is validated against the scenario's own question set.

    Naming an id that does not belong would either grade nothing or disclose that
    the id exists elsewhere in the key, so it is an error rather than an empty
    result.
    """
    with pytest.raises(G.GradingError):
        G.grade("scenario-1", {"s1e1": "203.0.113.45"}, key, questions=bad)


def test_an_omitted_filter_still_checks_the_whole_scenario(key):
    """Backwards compatibility for any caller that does not filter."""
    evidence, finding = ids("scenario-1", key)
    result = G.grade("scenario-1", {}, key)
    assert result["scoped"] is False
    assert sorted(result["questions"]) == sorted(evidence + [finding])


def test_a_scoped_check_never_carries_a_model_answer(key):
    evidence, _ = ids("scenario-1", key)
    for qid in evidence:
        wrong = G.grade("scenario-1", {qid: "definitely wrong"}, key, questions=[qid])
        assert "solution" not in json.dumps(wrong), qid
        right = G.grade("scenario-1", {qid: "203.0.113.45"}, key, questions=[qid])
        assert "solution" not in json.dumps(right), qid


# ============================================================ completion gate

def test_evidence_alone_never_completes_a_scenario(key):
    """The requirement this phase exists to fix."""
    for scenario in SCENARIO_FILES:
        _, finding = ids(scenario, key)
        questions = key["scenarios"][scenario]["questions"]
        answers = {qid: q["solution"] for qid, q in questions.items()}
        answers[finding] = ""
        result = G.grade(scenario, answers, key)
        assert result["completed"] is False, (
            "%s completed with %d/%d correct and no finding"
            % (scenario, result["summary"]["required_correct"],
               result["summary"]["required_total"]))
        assert result["questions"][finding]["status"] == "incorrect", scenario


def test_the_finding_alone_never_completes_a_scenario(key):
    for scenario in SCENARIO_FILES:
        evidence, finding = ids(scenario, key)
        questions = key["scenarios"][scenario]["questions"]
        answers = {qid: questions[finding]["solution"] for qid in evidence}
        result = G.grade(scenario, answers, key)
        assert result["completed"] is False, scenario


def test_the_finding_is_graded_against_its_rubric_element_by_element(key):
    """A finding missing one rubric element is partial, not correct."""
    for scenario in ("scenario-1", "scenario-5"):
        _, finding = ids(scenario, key)
        question = key["scenarios"][scenario]["questions"][finding]
        parts = question["parts"]
        assert len(parts) >= 3, scenario

        full = G.grade(scenario, {finding: question["solution"]}, key)["questions"][finding]
        assert full["status"] == "correct", scenario
        assert all(p["ok"] for p in full["parts"]), scenario

        # An answer that hits nothing at all is plainly wrong.
        empty = G.grade(scenario, {finding: "no idea"}, key)["questions"][finding]
        assert empty["status"] == "incorrect", scenario
        assert not any(p["ok"] for p in empty["parts"]), scenario
        assert all(p.get("hint") for p in empty["parts"]), (
            "%s: an unmatched rubric element must offer guidance" % scenario)


# ======================================================== ordered selection

def test_ordered_questions_serialise_to_a_graded_string(key):
    """An ordering control submits 'a -> b -> c'; no grader change is needed."""
    ordering = []
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            if question["control"] == "ordering":
                ordering.append((scenario, qid, question))
    assert ordering, "no ordering questions in the model"

    for scenario, qid, question in ordering:
        options = question["options"]
        right = " -> ".join(options)
        wrong = " -> ".join(reversed(options))
        assert G.grade(scenario, {qid: right}, key)["questions"][qid]["status"] == "correct", qid
        assert G.grade(scenario, {qid: wrong}, key)["questions"][qid]["status"] != "correct", (
            "%s: the reversed order must not pass" % qid)


def test_ordered_questions_are_presented_out_of_order(key):
    """The list must not already be the answer.

    Emitting the options in the accepted order would let a student submit the
    question untouched and be right, which is not an ordering question at all.
    """
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            if question["control"] != "ordering":
                continue
            row = row_of(page(scenario), qid)
            labels = re.findall(r'<span class="ord-label">(.*?)</span>', row)
            options = list(question["options"])
            # Same items, presented rotated by one so the list never begins in the
            # accepted order. Anything else would let an untouched question pass.
            assert sorted(labels) == sorted(options), (
                "%s: the page lists %r but the key offers %r" % (qid, labels, options))
            assert labels == options[1:] + options[:1], (
                "%s: expected the rotated presentation %r, found %r"
                % (qid, options[1:] + options[:1], labels))


def test_the_page_ordering_list_is_not_the_accepted_order():
    """Guards the emitted order specifically, per ordering question."""
    key = G.load_key()
    found = 0
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            if question["control"] != "ordering":
                continue
            found += 1
            labels = re.findall(r'<span class="ord-label">(.*?)</span>',
                                row_of(page(scenario), qid))
            accepted = " -> ".join(question["options"])
            assert " -> ".join(labels) != accepted, (
                "%s: the emitted order is the accepted order" % qid)
    assert found >= 3, "expected several ordering questions, found %d" % found


# ============================================================ control markup

@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_question_renders_the_control_its_type_calls_for(scenario):
    """The markup a question declares is the markup it gets.

    Each control carries ``data-question``, because that attribute is how the
    client knows which question a value belongs to. A mismatch would silently
    grade one question against another's answer.
    """
    key = G.load_key()
    html = page(scenario)
    for qid, question in key["scenarios"][scenario]["questions"].items():
        row = row_of(html, qid)
        assert 'data-question="%s"' % qid in row, "%s: no answer control" % qid
        control = question["control"]
        if control == "count":
            assert 'type="number"' in row, "%s: count needs a number input" % qid
            assert 'inputmode="numeric"' in row, qid
        elif control == "duration":
            assert 'type="text"' in row, "%s: duration needs a text input" % qid
        elif control == "identifier":
            assert 'type="text"' in row, qid
        elif control == "boolean":
            assert 'class="btn-choice"' in row, "%s: boolean needs yes/no buttons" % qid
            assert 'data-choice="yes"' in row and 'data-choice="no"' in row, qid
            assert "answer-why" in row, "%s: boolean needs a justification box" % qid
        elif control == "enum":
            assert "<select" in row, "%s: enum needs a select" % qid
            for option in question["options"]:
                assert option.replace("&", "&amp;") in row or option in row, (
                    "%s: option %r missing from the select" % (qid, option))
        elif control == "ordering":
            assert "ordered-list" in row, qid
            assert row.count("ord-move") == 2 * len(question["options"]), (
                "%s: each option needs an up and a down control" % qid)
            assert "ord-value" in row, (
                "%s: the serialised order needs somewhere to live" % qid)
        elif control == "finding":
            assert "<textarea" in row, "%s: the finding needs a textarea" % qid
            assert 'rows="7"' in row, "%s: the finding should be writable" % qid


# ------------------------------------------------------- answer secrecy

def test_the_findings_rubric_note_does_not_spell_out_the_answer():
    """The rubric note is printed on the page, so it must describe, not answer.

    Regression: the note is the finding's ``review_prompt``, and the first version
    of it read "IMPACT: no account was taken over - no successful authentication
    followed", "ASSESSMENT: an automated credential attack ... spreading effort
    across more than one account name" and "RECOMMENDED RESPONSE: block the source
    address". A student who opened "What a complete finding covers" was handed the
    whole finding. The note must name the four elements and stop there.
    """
    key = G.load_key()
    for scenario in SCENARIO_FILES:
        _, finding = ids(scenario, key)
        question = key["scenarios"][scenario]["questions"][finding]
        prompt = question["review_prompt"]
        for element in question.get("rubric") or []:
            assert element.split(":")[0].lower() in prompt.lower(), (
                "%s: the rubric note does not mention %r" % (scenario, element))
        # Conclusions must not appear in the note.
        for verdict in ("no account was taken over", "nothing was obtained",
                        "achieved access rather than an attempt",
                        "valid session established",
                        "unrestricted root access",
                        "isolated by the perimeter"):
            assert verdict not in prompt.lower(), (
                "%s: the rubric note states the conclusion %r" % (scenario, verdict))
        # Nor the concrete evidence values the student has to find.
        for value in ("203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77"):
            assert value not in prompt, "%s: the rubric note names %s" % (scenario, value)


def test_the_rubric_note_is_the_only_prose_the_page_prints_for_the_finding():
    """Per-element hints belong to the Show a hint button, not the page."""
    key = G.load_key()
    for scenario in SCENARIO_FILES:
        _, finding = ids(scenario, key)
        row = row_of(page(scenario), finding)
        for part in key["scenarios"][scenario]["questions"][finding]["parts"]:
            hint = re.sub(r"\s+", " ", (part.get("hint") or "")).strip()
            if len(hint) < 30:
                continue
            assert hint not in row, (
                "%s/%s: the page prints a rubric element's hint verbatim" % (scenario, finding))
        # The element names are printed; that is the rubric.
        for part in key["scenarios"][scenario]["questions"][finding]["parts"]:
            assert part["label"] in row, "%s: rubric element %r missing" % (scenario, part["label"])


def test_no_part_hint_echoes_its_own_model_answer():
    """A hint is shown on request, so it must point rather than state.

    Guards every question, not only the findings: a hint that repeats the model
    answer's wording is that answer.
    """
    key = G.load_key()
    offenders = []
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            solution = G.normalize(question.get("solution", ""))
            if not solution:
                continue
            words = solution.split()
            for part in question.get("parts") or []:
                hint = G.normalize(part.get("hint", "") or "")
                if not hint:
                    continue
                for start in range(len(words) - 4):
                    run = " ".join(words[start:start + 5])
                    if run and run in hint:
                        offenders.append("%s/%s part %r echoes %r"
                                         % (scenario, qid, part.get("label"), run))
    assert not offenders, "\n".join(offenders)


def test_every_model_answer_satisfies_its_own_question():
    """The guide shows these to instructors and to students who reveal them.

    Regression: all five findings graded `partial` against the rubric they were
    written for, because the rubrics require the answer to quote its evidence and
    the model answers were prose summaries. A student who copied the model answer
    verbatim would have been marked wrong.
    """
    key = G.load_key()
    for scenario in SCENARIO_FILES:
        for qid, question in key["scenarios"][scenario]["questions"].items():
            result = G.grade(scenario, {qid: question["solution"]}, key)["questions"][qid]
            assert result["status"] == "correct", (
                "%s/%s: the model answer grades %s (unmatched: %s)"
                % (scenario, qid, result["status"],
                   [p["label"] for p in result["parts"] if not p["ok"]]))


def test_every_question_has_a_state_chip_and_a_feedback_region():
    for scenario in SCENARIO_FILES:
        html = page(scenario)
        for qid in re.findall(r'data-question-row="([^"]+)"', html):
            row = row_of(html, qid)
            assert "data-state-chip" in row, "%s/%s: no state chip" % (scenario, qid)
            assert "data-feedback" in row, "%s/%s: no feedback region" % (scenario, qid)
            assert row.count("data-check=") == 1, "%s/%s: check button count" % (scenario, qid)


def test_the_state_chip_starts_unstarted_with_the_finding_worded_differently():
    """No ambiguous starting state.

    An evidence question has not been started; the finding has not been
    submitted. Using the same word for both would leave a student unsure whether
    their prose had been received.
    """
    for scenario in SCENARIO_FILES:
        html = page(scenario)
        for qid in re.findall(r'data-question-row="([^"]+)"', html):
            row = row_of(html, qid)
            chip = re.search(r'data-state-chip>(.*?)</span>', row, re.S).group(1).strip()
            if FINDING_ID.match(qid):
                assert chip == "Not submitted", (scenario, qid, chip)
            else:
                assert chip == "Not started", (scenario, qid, chip)
            assert 'data-state="not_started"' in row, (scenario, qid)


def test_no_submit_everything_button_anywhere():
    """The control being retired, asserted rather than merely absent."""
    for scenario in SCENARIO_FILES:
        html = page(scenario)
        assert 'id="check-answers"' not in html, scenario
        assert "Check answers" not in html, scenario
    script = read(LAB_CHECK_JS)
    assert "collectAnswers()" in script, "the client should still collect answers"
    # The client posts one question at a time.
    assert "questions: [id]" in script, "the client should send a single-question filter"


def test_the_client_checks_one_question_at_a_time():
    script = read(LAB_CHECK_JS)
    assert 'var payload = { scenario: scenario, questions: [id], answers: {} };' in script, (
        "the per-question request shape changed")
    assert "payload.answers[id] = readAnswer(row);" in script, (
        "only the answered question should be sent")


def test_the_client_never_holds_answer_values():
    for secret in ("203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
                   "svc_backup", "min_failures", "expected_processes",
                   "suspicious_processes", "alice", "cmd.exe", "winlogon"):
        assert secret not in read(LAB_CHECK_JS), "lab-check.js leaks %r" % secret


def test_the_client_settles_completion_after_the_finding():
    """A scoped check cannot report completion, so one full check must follow.

    Without this the student could satisfy every question and never finish,
    because the loop only ever sends scoped requests.
    """
    script = read(LAB_CHECK_JS)
    assert "settleCompletion" in script, "the client never settles completion"
    assert "if (id === findingId()) settleCompletion();" in script, (
        "completion should be settled once the finding is correct")


def test_the_client_reads_progress_from_the_per_scenario_endpoint():
    """Root-relative on purpose.

    These pages are served from /scenarios/, so a relative
    "student/progress/..." resolves under /scenarios/ and 404s, which loses every
    verdict on reload. That was a real defect found in the browser.
    """
    script = read(LAB_CHECK_JS)
    assert 'API_STUDENT = "/api/student"' in script
    assert 'API_STUDENT + "/progress/"' in script
    assert 'fetch("student/progress/' not in script


def test_assistance_is_sticky_in_the_client():
    """Answering correctly after a reveal must not erase the record."""
    script = read(LAB_CHECK_JS)
    assert 'row.getAttribute("data-state") === "assisted"' in script, (
        "the client would overwrite the assisted mark")
    assert 'wasAssisted ? "assisted" : "correct"' in script


# ============================================================ HTTP surface

@pytest.fixture(scope="module")
def server():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SCRIPTS, "serve_training.py"),
         "--port", "8147", "--host", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = "http://127.0.0.1:8147"
    for _ in range(60):
        try:
            urllib.request.urlopen(base + "/", timeout=1).read()
            break
        except Exception:
            time.sleep(0.25)
    else:
        proc.kill()
        pytest.skip("training server did not start")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def post(base, path, payload):
    request = urllib.request.Request(
        base + path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"raw": body}


def test_http_single_question_check(server):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1", "questions": ["s1e1"],
                         "answers": {"s1e1": "203.0.113.45"}})
    assert status == 200
    assert sorted(body["questions"]) == ["s1e1"]
    assert body["scoped"] is True
    assert body["completed"] is False


def test_http_full_check_still_works(server):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1", "answers": {"s1e1": "203.0.113.45"}})
    assert status == 200
    assert body["scoped"] is False
    assert "s1e1" in body["questions"]


@pytest.mark.parametrize("bad", [["q1"], ["s2e1"], [], "s1e1", [1]])
def test_http_rejects_a_bad_question_filter(server, bad):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1", "questions": bad,
                         "answers": {"s1e1": "203.0.113.45"}})
    assert status == 400, (bad, status, body)
    assert "Traceback" not in json.dumps(body)


def test_http_check_never_returns_a_model_answer(server):
    for answers in ({"s1e1": "wrong"}, {"s1e1": "203.0.113.45"}, {}):
        status, body = post(server, "/api/check",
                            {"scenario": "scenario-1", "answers": answers})
        assert status == 200
        assert "solution" not in json.dumps(body), answers


def test_http_check_hints_do_not_leak_answers(server):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1",
                         "answers": {"s1e1": "wrong", "s1e4": "wrong", "s1f": "wrong"}})
    assert status == 200
    blob = json.dumps(body)
    for secret in ("203.0.113.45", "132"):
        assert secret not in blob, "the response leaked %r" % secret


def test_scenario_pages_are_served_behind_the_sign_in_gate(server):
    """An anonymous caller gets the gate, never the question page.

    This is the behaviour the brief requires, so it is asserted rather than
    assumed: the scenario markup carries the objectives, and the gate is the only
    thing standing between an anonymous request and it.
    """
    for name in SCENARIO_FILES.values():
        with urllib.request.urlopen(
                server + "/scenarios/" + name, timeout=10) as response:
            body = response.read().decode("utf-8")
        assert response.status == 200, name
        assert 'name="password"' in body, (
            "%s: the anonymous response is not the sign-in gate" % name)
        assert "data-question-row=" not in body, (
            "%s: question markup reached an anonymous caller" % name)


def test_the_gate_does_not_serve_the_answer_key(server):
    for path in ("/data/answer-key.json", "/../data/answer-key.json",
                 "/%2e%2e/data/answer-key.json",
                 "/scenarios/../../data/answer-key.json"):
        try:
            with urllib.request.urlopen(server + path, timeout=5) as response:
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            assert exc.code in (400, 401, 403, 404), (path, exc.code)
            continue
        assert "203.0.113.45" not in body, path
        assert '"accept"' not in body, path
        assert '"parts"' not in body, path