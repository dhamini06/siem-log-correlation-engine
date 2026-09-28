"""Tests for the student answer-checking workflow.

Covers the grader itself, the HTTP surface, and the guarantee that the
instructor answer key never reaches a student-facing asset.
"""

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
# The key lives under data/, which is git-ignored: the repository is public.
ANSWER_KEY = os.path.join(REPO_ROOT, "data", "answer-key.json")
LEGACY_ANSWER_KEY = os.path.join(REPO_ROOT, "docs", "answer-key.json")
INSTRUCTOR_GUIDE = os.path.join(REPO_ROOT, "docs", "INSTRUCTOR_GUIDE.md")

sys.path.insert(0, SCRIPTS)
import answer_grader as G  # noqa: E402

SCENARIO_FILES = {
    "scenario-1": "scenario-1-brute-force.html",
    "scenario-2": "scenario-2-successful-brute-force.html",
    "scenario-3": "scenario-3-post-login-execution.html",
    "scenario-4": "scenario-4-linux-privilege-escalation.html",
    "scenario-5": "scenario-5-multi-event-soc-investigation.html",
}


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def key():
    return G.load_key()


# --------------------------------------------------------------- key shape

def test_key_covers_all_five_scenarios(key):
    assert set(key["scenarios"]) == set(SCENARIO_FILES)


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_key_question_count_matches_the_page(key, scenario):
    """Every data-question on the page must have a key entry, and vice versa."""
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    page_ids = set(re.findall(r'data-question="(q\d+)"', html))
    key_ids = set(key["scenarios"][scenario]["questions"])
    assert key_ids == page_ids, f"{scenario}: key/page question mismatch"


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_part_has_a_hint_and_label(key, scenario):
    for qid, question in key["scenarios"][scenario]["questions"].items():
        for part in question.get("parts", []):
            assert part.get("label"), f"{scenario}/{qid} part without label"
            assert part.get("hint"), f"{scenario}/{qid} part without hint"
            assert part.get("accept") or part.get("patterns"), (
                f"{scenario}/{qid} part can never match anything"
            )


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_question_has_a_model_solution(key, scenario):
    for qid, question in key["scenarios"][scenario]["questions"].items():
        assert question.get("solution"), f"{scenario}/{qid} has no solution"


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_key_compiles_and_scenarios_are_gradeable(key, scenario):
    G.grade(scenario, {}, key)  # must not raise


# --------------------------------------------------------- answer secrecy
# The single most important guarantee: nothing that identifies the answer may
# appear in a student-facing file. A label or hint that names the expected value
# (an address, an account, a count, a duration) hands the answer over.

def _answer_tokens(question):
    """Values a student is expected to supply, taken from the key."""
    tokens = []
    for part in question.get("parts") or []:
        for token in part.get("accept") or []:
            token = G.normalize(token)
            if token:
                tokens.append(token)
    return tokens


def _text_a_student_can_read(scenario):
    """Student-facing text that legitimately pre-discloses an answer.

    Deliberately narrow: the scenario's own page plus the shared reference page.
    A value that merely happens to appear in the landing-page prose, the
    stylesheet or a script is not real disclosure and must not excuse a
    leaking hint.
    """
    blobs = [read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario])),
             read(os.path.join(TRAINING, "instructions.html"))]
    return "\n".join(blobs).lower()


def _discloses_answers(scenario, question, part):
    """Values that this part's label or hint gives away."""
    visible = f"{part.get('label', '')} {part.get('hint', '')}".lower()
    disclosed = _text_a_student_can_read(scenario)
    found = []
    for token in _answer_tokens(question):
        if token in disclosed:
            continue  # already public on a page the student reads
        if token in visible:
            found.append(token)
            continue
        # A short numeric token can be smuggled in as prose ("45 seconds"),
        # so look for it as a standalone number as well.
        if token.strip().isdigit() and len(token) <= 4:
            pattern = r"(?<![0-9a-z])" + re.escape(token) + r"(?![0-9a-z])"
            if re.search(pattern, visible):
                found.append(token)
    return found


def test_answer_key_file_is_outside_the_served_tree():
    """The key must not live under training/, or it would be a static asset."""
    assert os.path.commonpath([REPO_ROOT, ANSWER_KEY]) == REPO_ROOT
    served = os.path.join(REPO_ROOT, "training")
    assert not ANSWER_KEY.startswith(served + os.sep)
    assert not os.path.exists(os.path.join(served, "answer-key.json"))


def test_answer_key_is_not_committed_to_the_public_repository():
    """Regression: the repository is public, so the key must stay untracked.

    Guards both the current location and the legacy one, and asserts .gitignore
    still covers them so a well-meaning `git add .` cannot publish the answers.
    """
    tracked = set(subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout.split())
    assert "data/answer-key.json" not in tracked
    assert "docs/answer-key.json" not in tracked

    ignored = subprocess.run(
        ["git", "check-ignore", "-q", os.path.relpath(ANSWER_KEY, REPO_ROOT)],
        cwd=REPO_ROOT,
    ).returncode
    assert ignored == 0, "data/answer-key.json must be git-ignored"


def test_grader_finds_the_key_at_its_untracked_location():
    """The grader must resolve the key without any code change at call sites."""
    assert os.path.isfile(ANSWER_KEY), "local instructor key missing"
    assert G.ANSWER_KEY_PATH == ANSWER_KEY
    assert G.load_key()["scenarios"]


def test_missing_key_raises_an_actionable_error(tmp_path):
    with pytest.raises(G.GradingError) as exc:
        G.load_key(str(tmp_path / "absent.json"))
    message = str(exc.value)
    assert "not in version control" in message
    assert "SIEM_ANSWER_KEY" in message


def test_no_answer_key_reference_in_student_assets():
    """Student files must not even name the key file or the grader module."""
    for name in ("index.html", "instructions.html"):
        text = read(os.path.join(TRAINING, name))
        assert "answer-key" not in text, name
        assert "answer_grader" not in text, name
    for name in ("lab.js", "lab-check.js"):
        text = read(os.path.join(TRAINING, "assets", "js", name))
        assert "answer-key" not in text, name
        assert "answer_grader" not in text, name
    for name in SCENARIO_FILES.values():
        text = read(os.path.join(SCENARIOS_DIR, name))
        assert "answer-key" not in text, name
        assert "answer_grader" not in text, name


def test_grader_module_is_not_served_as_a_static_asset():
    for name in SCENARIO_FILES.values():
        text = read(os.path.join(SCENARIOS_DIR, name))
        assert "answer_grader" not in text, name


def test_checker_js_ships_no_answers():
    """lab-check.js holds the workflow only - no key values."""
    text = read(os.path.join(TRAINING, "assets", "js", "lab-check.js"))
    for secret in ("203.0.113.45", "203.0.113.66", "198.51.100.25",
                   "198.51.100.77", "svc_backup", "brute_force",
                   "successful_brute_force", "min_failures"):
        assert secret not in text, f"lab-check.js leaks {secret}"


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_labels_and_hints_do_not_disclose_undisclosed_answers(key, scenario):
    """A part's label/hint must not contain a value the page does not already show.

    Rule names and severities are usually exempt because each scenario page
    already prints them in its header chips, so naming them reveals nothing new.
    """
    offenders = []
    for qid, question in key["scenarios"][scenario]["questions"].items():
        for part in question.get("parts") or []:
            for token in _discloses_answers(scenario, question, part):
                offenders.append(
                    f"{scenario}/{qid} part {part.get('label')!r} reveals {token!r}")
    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_no_part_label_states_its_own_numeric_answer(key, scenario):
    """Regression: labels such as '45 seconds' or 'port 22' stated the answer."""
    offenders = []
    for qid, question in key["scenarios"][scenario]["questions"].items():
        for part in question.get("parts") or []:
            label = part.get("label", "")
            for token in part.get("accept") or []:
                if not token.strip().isdigit():
                    continue
                pattern = r"(?<![0-9a-z])" + re.escape(token) + r"(?![0-9a-z])"
                if re.search(pattern, label):
                    offenders.append(f"{scenario}/{qid} label {label!r} states {token!r}")
    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_hints_do_not_repeat_the_solution_text(key, scenario):
    """A hint must not be a paraphrase of the answer."""
    offenders = []
    for qid, question in key["scenarios"][scenario]["questions"].items():
        solution = G.normalize(question.get("solution", ""))
        for part in question.get("parts") or []:
            hint = G.normalize(part.get("hint", ""))
            if not hint or not solution:
                continue
            # Any 5-word run from the solution appearing in a hint is a giveaway.
            words = solution.split()
            for start in range(len(words) - 4):
                run = " ".join(words[start:start + 5])
                if run and run in hint:
                    offenders.append(f"{scenario}/{qid} hint echoes solution: {run!r}")
    assert not offenders, "\n".join(offenders)


# ------------------------------------------------------------ grader logic

def test_normalize_folds_case_dashes_quotes_and_space():
    assert G.normalize("  Web\u201301  ") == "web-01"
    assert G.normalize("CORP\u2019jdoe") == "corp'jdoe"
    assert G.normalize("a   b\n\tc") == "a b c"


def test_rule_name_separator_variants_all_match():
    for variant in ("brute_force", "brute force", "Brute-Force", "BRUTE_FORCE"):
        assert G.match_part(variant.lower(), "", {"accept": ["brute_force"]}), variant


def test_ip_and_host_match_case_insensitively():
    assert G.match_part("attacker 203.0.113.45 hit WEB-01", "",
                        {"accept": ["203.0.113.45"]})
    assert G.match_part("host was web-01", "", {"accept": ["web-01"]})


def test_short_numeric_token_respects_token_boundaries():
    assert G.match_part("there were 5 attempts", "", {"accept": ["5"]})
    assert not G.match_part("there were 15 attempts", "", {"accept": ["5"]})
    assert not G.match_part("port 224", "", {"accept": ["22"]})


def test_account_name_does_not_match_a_longer_word():
    assert G.match_part("the admin account", "", {"accept": ["root"]}) is False
    assert G.match_part("logged in as root", "", {"accept": ["root"]})


def test_windows_domain_form_is_accepted_for_the_same_account():
    assert G.match_part("user corp\\jdoe", "", {"accept": ["jdoe", "corp\\jdoe"]})


def test_duration_accepts_seconds_and_minute_second_forms():
    part = {"accept": ["132"], "patterns": [r"\b132\s*(?:s|sec|seconds)?\b",
                                             r"\b2\s*(?:min|mins|minutes)\s*12\b"]}
    for text in ("132", "132 seconds", "132s", "2 min 12 s", "2 minutes 12"):
        assert G.match_part(text.lower(), "", part), text
    assert not G.match_part("90 seconds", "", part)


def test_unrelated_prose_does_not_satisfy_a_value_part():
    part = {"accept": ["203.0.113.45"]}
    for text in ("an external host attacked the server",
                 "the address was not recorded",
                 "I could not determine the source"):
        assert not G.match_part(text.lower(), "", part), text


def test_broken_regex_never_grades_as_correct():
    part = {"patterns": ["(unclosed"], "accept": []}
    assert not G.match_part("anything", "", part)


# ------------------------------------------------------------ refusals
# Without a guard, a box containing "no idea" satisfies a yes/no question,
# because "no" is the expected negative answer.

@pytest.mark.parametrize("text", ["no idea", "No idea", "idk", "?", "...",
                                  "n/a", "don't know", "not sure", "unknown",
                                  "TBD", "skip", "stuck", "no", "x"])
def test_refusals_are_detected(text):
    assert G.is_refusal(text), text


@pytest.mark.parametrize("text", ["203.0.113.45", "no, none followed", "4 failures",
                                  "not 15 but 5", "no success followed"])
def test_real_answers_are_not_treated_as_refusals(text):
    assert not G.is_refusal(text), text


def test_refusal_does_not_satisfy_a_yes_no_question(key):
    """'no idea' must not be accepted as the answer 'no'."""
    result = G.grade("scenario-1", {"q5": "no idea"}, key)
    assert result["questions"]["q5"]["status"] == "incorrect"
    assert result["questions"]["q5"]["answered"] is False


def test_refusal_everywhere_does_not_inflate_the_score(key):
    refusals = {"q%d" % i: "no idea" for i in range(1, 10)}
    result = G.grade("scenario-1", refusals, key)
    assert result["verdict"] == "unanswered"
    assert result["summary"]["required_correct"] == 0


def test_genuine_negative_answer_still_passes(key):
    result = G.grade("scenario-1",
                     {"q5": "No, no logon_success event exists for that source"}, key)
    assert result["questions"]["q5"]["status"] == "correct"


# --------------------------------------------------------- verdict shaping

def test_empty_submission_is_unanswered(key):
    result = G.grade("scenario-1", {}, key)
    assert result["verdict"] == "unanswered"
    assert result["completed"] is False


def test_all_required_correct_completes(key):
    result = G.grade("scenario-1", CORRECT_S1, key)
    assert result["verdict"] == "complete"
    assert result["completed"] is True
    assert result["summary"]["required_correct"] == result["summary"]["required_total"]


def test_wrong_answers_do_not_complete(key):
    result = G.grade("scenario-1", WRONG_S1, key)
    assert result["completed"] is False
    assert result["summary"]["required_correct"] == 0


# ---------------------------------------------------------------------------
# Scenario 5, the capstone, must actually be completable.
#
# scenario-5/q5 is required, and its single part carries an empty "accept" list
# and is graded purely by its "patterns" list. Reading only "accept" makes that
# part look permanently unsatisfiable, and a hand-written probe once concluded
# the whole scenario could never be completed. It can: match_part() tries
# "patterns" before "accept". These tests pin the behaviour down, and
# test_no_required_question_is_permanently_unsatisfiable below would catch the
# real version of that bug if it ever appeared.
# ---------------------------------------------------------------------------


def test_scenario_five_completes_when_every_required_answer_is_correct(key):
    result = G.grade("scenario-5", CORRECT_S5, key)
    assert result["verdict"] == "complete"
    assert result["completed"] is True
    assert result["summary"]["required_total"] == 8
    assert result["summary"]["required_correct"] == 8
    assert result["questions"]["q5"]["status"] == "correct"


def test_scenario_five_still_requires_all_eight_graded_questions(key):
    questions = key["scenarios"]["scenario-5"]["questions"]
    required = sorted((q for q, v in questions.items() if v.get("required")),
                      key=lambda x: int(x[1:]))
    assert required == ["q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8"]

    empty = G.grade("scenario-5", {}, key)
    assert empty["summary"]["required_total"] == 8
    # The two written answers stay self-reviewed and are never counted.
    assert empty["questions"]["q9"]["status"] == "self_review"
    assert empty["questions"]["q10"]["status"] == "self_review"


@pytest.mark.parametrize("answer", [
    "They are separate incidents",
    "separate",
    "distinct",
    "different source IPs, so not the same incident",
    "Two unrelated incidents running in parallel",
])
def test_scenario_five_q5_accepts_the_intended_answer(key, answer):
    assert G.grade("scenario-5", {"q5": answer}, key)["questions"]["q5"]["status"] == "correct"


@pytest.mark.parametrize("answer", [
    "yes, it is one continuous incident",
    "banana",
    "the answer is 42",
    "purple monkey dishwasher",
    "",
])
def test_scenario_five_q5_rejects_an_obviously_wrong_answer(key, answer):
    result = G.grade("scenario-5", {"q5": answer}, key)
    assert result["questions"]["q5"]["status"] == "incorrect"
    assert result["completed"] is False


def test_scenario_five_wrong_answers_do_not_complete(key):
    result = G.grade("scenario-5", WRONG_S5, key)
    assert result["completed"] is False


def test_scenario_five_stays_incomplete_while_q5_is_left_blank(key):
    """q5 is graded by patterns rather than accept tokens, so an empty box fails.

    A build that filled a "perfect" submission from the accept lists alone would
    send nothing here and see 7 of 8 - the failure this test is written against.
    """
    answers = dict(CORRECT_S5)
    answers["q5"] = ""
    result = G.grade("scenario-5", answers, key)
    assert result["questions"]["q5"]["status"] == "incorrect"
    assert result["summary"]["required_correct"] == 7
    assert result["summary"]["required_total"] == 8
    assert result["completed"] is False


def test_no_required_question_is_permanently_unsatisfiable(key):
    """Every required question needs some route to a "correct" verdict.

    A part with an empty accept list is fine while it still carries patterns,
    because match_part() tries patterns first. A part with neither can never
    pass, which would lock that scenario's completion gate for good.
    """
    dead = []
    for scenario, spec in key["scenarios"].items():
        for qid, question in spec["questions"].items():
            if not question.get("required"):
                continue
            for part in question.get("parts") or []:
                if not (part.get("accept") or []) and not (part.get("patterns") or []):
                    dead.append(f"{scenario}/{qid} part {part.get('label')!r}")
    assert not dead, ("required questions that can never be graded correct: "
                      + "; ".join(dead))


def test_partially_correct_question_is_partial(key):
    result = G.grade("scenario-1", {"q1": "the source was 203.0.113.45"}, key)
    assert result["questions"]["q1"]["status"] == "partial"


def test_incorrect_parts_expose_a_hint_and_never_the_answer(key):
    result = G.grade("scenario-1", WRONG_S1, key)
    blob = json.dumps(result)
    for secret in ("203.0.113.45", "svc_backup", "132"):
        assert secret not in blob, f"grade() leaked {secret}"


def test_grade_response_has_no_solution_field(key):
    result = G.grade("scenario-1", CORRECT_S1, key)
    for entry in result["questions"].values():
        assert "solution" not in entry


def test_reveal_returns_the_solution_and_marks_it_assisted(key):
    data = G.reveal("scenario-1", "q1", key)
    assert data["assisted"] is True
    assert "203.0.113.45" in data["solution"]


def test_reveal_requires_the_flag_when_grading(key):
    without = G.grade("scenario-1", CORRECT_S1, key, reveal_solution=False)
    assert "solution" not in without["questions"]["q1"]
    with_flag = G.grade("scenario-1", CORRECT_S1, key, reveal_solution=True)
    assert with_flag["questions"]["q1"]["assisted"] is True


def test_unknown_scenario_and_question_are_rejected(key):
    with pytest.raises(G.GradingError):
        G.grade("scenario-99", {}, key)
    with pytest.raises(G.GradingError):
        G.reveal("scenario-1", "q99", key)


def test_self_review_questions_are_reported_separately(key):
    result = G.grade("scenario-1", {}, key)
    assert result["questions"]["q8"]["status"] == "self_review"
    assert result["questions"]["q8"]["required"] is False
    assert result["summary"]["self_review"] >= 1


def test_oversized_answer_is_truncated_not_rejected(key):
    result = G.grade("scenario-1", {"q1": "x" * (G.MAX_ANSWER_CHARS + 500)}, key)
    assert result["questions"]["q1"]["answered"] is True


# ------------------------------------------------------------- HTTP surface

@pytest.fixture(scope="module")
def server():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SCRIPTS, "serve_training.py"),
         "--port", "8137", "--host", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = "http://127.0.0.1:8137"
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
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_api_check_returns_complete_for_correct_answers(server, key):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1", "answers": CORRECT_S1})
    assert status == 200
    assert body["verdict"] == "complete"


def test_api_check_hints_do_not_leak_answers(server, key):
    status, body = post(server, "/api/check",
                        {"scenario": "scenario-1", "answers": WRONG_S1})
    assert status == 200
    blob = json.dumps(body)
    for secret in ("203.0.113.45", "svc_backup", "132"):
        assert secret not in blob, f"HTTP response leaked {secret}"


def test_api_reveal_requires_an_explicit_question(server, key):
    status, body = post(server, "/api/reveal",
                        {"scenario": "scenario-1", "question": "q1"})
    assert status == 200
    assert body["assisted"] is True
    assert "203.0.113.45" in body["solution"]


def test_api_rejects_bad_requests_without_a_traceback(server):
    for payload in ({"scenario": "nope", "answers": {}},
                    {"answers": {}},
                    {"scenario": "scenario-1", "answers": "not-an-object"}):
        request = urllib.request.Request(
            server + "/api/check", data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(request, timeout=10)
            raise AssertionError(f"expected 400 for {payload}")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
            body = exc.read().decode("utf-8")
            assert "Traceback" not in body


def test_answer_key_is_not_reachable_over_http(server):
    """Even a direct request for the key path must not serve it."""
    for path in ("/../docs/answer-key.json", "/answer-key.json",
                 "/%2e%2e/docs/answer-key.json",
                 "/../data/answer-key.json", "/%2e%2e/data/answer-key.json"):
        try:
            with urllib.request.urlopen(server + path, timeout=5) as response:
                body = response.read().decode("utf-8", "replace")
                assert "svc_backup" not in body, path
        except urllib.error.HTTPError as exc:
            assert exc.code in (400, 403, 404), (path, exc.code)


def test_pages_still_serve_after_the_api_was_added(server):
    for path in ("/", "/instructions.html",
                 "/scenarios/scenario-1-brute-force.html",
                 "/scenarios/scenario-5-multi-event-soc-investigation.html",
                 "/assets/js/lab-check.js", "/assets/css/bluecloud.css"):
        with urllib.request.urlopen(server + path, timeout=10) as response:
            assert response.status == 200, path


# ------------------------------------------------------- page integration

@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_page_has_the_checking_controls(scenario):
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    assert 'id="check-answers"' in html, scenario
    assert 'id="check-result"' in html, scenario
    assert "lab-check.js" in html, scenario
    assert 'id="check-gate-note"' in html, scenario


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_question_row_is_tagged_with_feedback_hooks(scenario):
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    rows = set(re.findall(r'data-question-row="(q\d+)"', html))
    answers = set(re.findall(r'data-question="(q\d+)"', html))
    assert rows == answers, scenario
    for qid in sorted(answers):
        assert f'class="answer-status" ' in html
        assert f'data-reveal="{qid}"' in html, f"{scenario}/{qid} missing reveal"


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_mark_complete_starts_disabled(scenario):
    """Completion must not be one unverified click away."""
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    assert re.search(r'id="mark-done"[^>]*disabled', html), scenario


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_self_review_checkboxes_match_the_key(scenario, key):
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    on_page = set(re.findall(r'data-self-review="(q\d+)"', html))
    in_key = {q for q, v in key["scenarios"][scenario]["questions"].items()
              if not v.get("required")}
    assert on_page == in_key, scenario


def test_pages_do_not_contain_answer_key_values():
    """A student reading the page source must not find the answers."""
    forbidden = ["svc_backup", "10.0.0.30", "/bin/bash -i",
                 "Inventory.ps1", "net user administrator"]
    for name in SCENARIO_FILES.values():
        html = read(os.path.join(SCENARIOS_DIR, name))
        for secret in forbidden:
            assert secret not in html, f"{name} exposes {secret}"


# ------------------------------------------- leak scan: every student page
# Field names, process sub-fields, event types and rule names are the vocabulary
# the lab exists to teach, so they are exempt. Everything else a student must
# *derive* is an answer, and may only appear on the scenario page whose
# question it answers.
_TEACHABLE = {
    # normalized-events / security-alerts fields
    "@timestamp", "source_type", "event_type", "host", "user", "src_ip", "dst_ip",
    "process", "port", "protocol", "severity", "message", "raw_event",
    "parser_version", "ingest_timestamp", "timestamp", "rule_name", "reasoning",
    "first_seen", "last_seen", "evidence_event_ids", "evidence_count",
    "dedup_key", "dedup_window_minutes", "false_positive_feedback",
    "process.name", "process.command_line", "command_line", "commandline",
    "command line", "raw event", "process.path", "process.pid",
    "process.parent_name", "process.parent_pid",
    # event_type enumeration
    "logon_failure", "logon_success", "process_create", "privilege_escalation",
    "network_connection", "account_unlock",
    # correlation rule names
    "brute_force", "successful_brute_force", "suspicious_process_post_login",
}

# The lab's four hosts are shared context: each is named in its own scenario brief
# and several scenarios touch the same machine, so a host appearing on a sibling
# scenario page is not an answer leak.
_SHARED_HOSTS = {"web-01", "app-01", "app-02", "fw-01"}

# Account and host words that are also ordinary English / sysadmin vocabulary.
# "root shell" or "administrator" in unrelated prose does not hand a student the
# username an SSH brute force targeted; the discriminating context does.
_GENERIC_TERMS = {"root", "admin", "administrator", "user", "host", "unknown"}


def _appears(text, token):
    """Word-boundary containment, so 'admin' does not match 'administrator'."""
    pattern = r"(?<![0-9a-z])" + re.escape(token) + r"(?![0-9a-z])"
    return re.search(pattern, text) is not None


def _skip_token(token):
    return (len(token) < 4
            or token in _TEACHABLE
            or token in _SHARED_HOSTS
            or token in _GENERIC_TERMS)

# Every student-facing HTML page, not just the scenario pages.
STUDENT_PAGES = {
    "index.html": os.path.join(TRAINING, "index.html"),
    "instructions.html": os.path.join(TRAINING, "instructions.html"),
}
STUDENT_PAGES.update({f"scenarios/{name}": os.path.join(SCENARIOS_DIR, name)
                      for name in SCENARIO_FILES.values()})


def test_every_student_page_is_covered_by_the_leak_scan():
    """The scan must actually read all student-facing pages."""
    for label, path in STUDENT_PAGES.items():
        assert os.path.isfile(path), f"missing student page: {label}"
    assert len(STUDENT_PAGES) == 2 + len(SCENARIO_FILES)


def test_no_student_page_exposes_a_value_students_must_derive(key):
    """An answer may appear only on the scenario page whose question it answers.

    Regression: the "How to Investigate" page used to print a real attacker IP, a
    destination IP, a username, a host and an exact event count in its example
    queries and prose, which handed students answers to Scenarios 1, 2 and 5.
    """
    page_text = {label: read(path).lower() for label, path in STUDENT_PAGES.items()}
    own_page = {scenario: read(os.path.join(SCENARIOS_DIR, name)).lower()
                for scenario, name in SCENARIO_FILES.items()}

    offenders = []
    for label, text in page_text.items():
        for scenario, spec in key["scenarios"].items():
            for qid, question in spec["questions"].items():
                for part in question.get("parts") or []:
                    for token in _answer_tokens(question):
                        if _skip_token(token):
                            continue
                        if not _appears(text, token):
                            continue
                        if _appears(own_page[scenario], token):
                            continue
                        offenders.append(
                            f"{label} reveals {token!r} (answer to {scenario}/{qid}, "
                            f"part {part.get('label')!r})")
    assert not offenders, "student-facing answer leaks:\n" + "\n".join(offenders)


def test_instructions_page_does_not_name_the_lab_addresses():
    """Targeted guard for the values the query examples used to carry."""
    text = read(os.path.join(TRAINING, "instructions.html"))
    for secret in ("203.0.113.45", "203.0.113.66", "198.51.100.25",
                   "198.51.100.77", "10.0.0.10", "svc_backup", "alice",
                   "web-01", "app-01", "app-02", "fw-01"):
        assert secret not in text, f"instructions.html exposes {secret!r}"


def test_instructions_page_does_not_give_away_the_scenario_one_window():
    """Scenario 1 Q3 asks for the failure count and the exact time window."""
    text = read(os.path.join(TRAINING, "instructions.html"))
    assert "07:25:55" not in text and "07:28:07" not in text
    assert "10 failed logons" not in text


# ------------------------------------------------------------- answer data

CORRECT_S1 = {
    "q1": "Attacker was 203.0.113.45 and the target was WEB-01",
    "q2": "root 5 times and admin 5 times",
    "q3": "10 failed logons spanning 132 seconds (2 min 12 s)",
    "q4": "rule brute_force; min_failures: 5 and time_window_minutes: 5",
    "q5": "No, there is no logon_success for that source IP",
    "q6": "Three events on fw-01: 203.0.113.45 -> 10.0.0.10 port 22",
    "q7": "svc_backup from 10.0.0.30 had 4 failures, below the threshold of 5",
}

WRONG_S1 = {
    "q1": "192.168.1.10 hit db-01",
    "q2": "only the admin account, 3 times",
    "q3": "7 failures over an hour",
    "q4": "a port scan rule with threshold 50",
    "q5": "Yes, it succeeded immediately",
    "q6": "there are no firewall records",
    "q7": "the guest account failed 9 times",
}

# Scenario 5, the capstone. q5 is answered in prose like a written finding, so it
# is phrased the way a student would actually phrase it rather than as a token.
CORRECT_S5 = {
    "q1": "4 alerts: 3 high, 1 critical, and 2 of them from suspicious_process_post_login",
    "q2": ("1) brute_force 203.0.113.45  2) successful_brute_force 203.0.113.66  "
           "3) suspicious_process_post_login 198.51.100.25  "
           "4) suspicious_process_post_login 198.51.100.77"),
    "q3": "4 distinct source IPs: 203.0.113.45, 203.0.113.66, 198.51.100.25, 198.51.100.77",
    "q4": "the attack ran for 146 seconds end to end",
    "q5": ("They are separate incidents: different source IPs, rules and accounts, "
           "and they ran in parallel"),
    "q6": "successful_brute_force, source 203.0.113.66, account alice - the attacker got in",
    "q7": "fw-01 holds the firewall records, blocked 10.0.0.10 port 22, 3 connections",
    "q8": ("svc_backup had 4 failures, below min_failures; app-02 ran powershell "
           "30 minutes later, outside the window"),
    "q9": "Routine logons and sudo by the service accounts, identical every day",
    "q10": ("Confirmed compromise of one account and an interactive shell elsewhere. "
            "Disable the accounts, rotate keys, block the source ranges, review all "
            "four hosts, and add rate limiting."),
}

WRONG_S5 = {
    "q1": "9 alerts, all of them low severity",
    "q2": "one single alert, a port scan",
    "q3": "just one source IP",
    "q4": "the whole thing took about an hour",
    "q5": "yes, it is one continuous incident",
    "q6": "brute_force, from an unknown address",
    "q7": "there are no firewall records at all",
    "q8": "both were blocked by the firewall",
    "q9": "I have no idea, maybe it is an attack",
    "q10": "nothing to report",
}
