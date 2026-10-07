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


def key_question_ids(html):
    """The question ids a page presents, read off its answer controls.

    Read from the controls rather than the question rows, because the controls
    are what the client submits: a row carrying no control would grade as blank.
    """
    return sorted(set(re.findall(r'data-question="(s\d(?:e\d+|f))"', html)))


def finding_id(scenario, loaded=None):
    """The final analyst finding id for a scenario."""
    loaded = loaded if loaded is not None else G.load_key()
    wanted = "s%sf" % scenario.split("-")[1]
    assert wanted in loaded["scenarios"][scenario]["questions"], scenario
    return wanted


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
    page_ids = set(re.findall(r'data-question="(s\d(?:e\d+|f))"', html))
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


@pytest.mark.parametrize("text", ["no idea", "I do not know", "I don't know",
                                  "not sure", "idk", "unknown", "unsure",
                                  "I cannot determine", ""])
def test_refusal_does_not_satisfy_a_yes_no_question(key, text):
    """A refusal must never be accepted as the answer "no".

    s2e7 and s5e4 are yes/no questions whose correct answer is the negative.
    Before Phase 6 the key carried the bare token "no" in an accept list for
    these, and containment matched it *inside* words such as "not" and "know",
    so "I do not know" graded correct. Every question is now checked.
    """
    for scenario, qid in (("scenario-2", "s2e7"), ("scenario-5", "s5e4")):
        result = G.grade(scenario, {qid: text}, key)
        entry = result["questions"][qid]
        assert entry["status"] == "incorrect", (scenario, qid, text, entry["status"])
        assert entry["answered"] is False, (scenario, qid, text)


@pytest.mark.parametrize("text", [
    "I do not know the source, but the host is web-01",
    "unknown user, but the destination port was 443",
])
def test_a_refusal_inside_a_real_answer_is_still_an_attempt(key, text):
    """The guard matches the whole stripped answer, not a fragment of it.

    "I do not know the source, but the host is web-01" contains a refusal phrase
    and is a genuine attempt. It names no source address, so it must grade as a
    real wrong answer rather than as "unanswered" - which would let a student
    blank out a question by writing prose around a refusal.
    """
    assert not G.is_refusal(text), text
    entry = G.grade("scenario-1", {"s1e1": text}, key)["questions"]["s1e1"]
    assert entry["answered"] is True, text
    assert entry["status"] == "incorrect", (text, entry["status"])


def test_an_answer_naming_the_right_value_is_graded_on_its_merits(key):
    """The other half of the same rule: a real answer inside a refusal phrase."""
    text = "unknown user, but the address was 203.0.113.45"
    assert not G.is_refusal(text), text
    entry = G.grade("scenario-1", {"s1e1": text}, key)["questions"]["s1e1"]
    assert entry["status"] == "correct", (text, entry["status"])


def test_refusal_everywhere_does_not_inflate_the_score(key):
    refusals = {qid: "no idea" for qid in key["scenarios"]["scenario-1"]["questions"]}
    result = G.grade("scenario-1", refusals, key)
    assert result["verdict"] == "unanswered"
    assert result["summary"]["required_correct"] == 0


def test_genuine_negative_answer_still_passes(key):
    """A real "no" must pass even though the refusal guard exists.

    s2e7 asks whether the two bursts share a source; they do not, so "no" is the
    right answer and must not be mistaken for a refusal.
    """
    result = G.grade("scenario-2", {"s2e7": CORRECT_S2["s2e7"]}, key)
    entry = result["questions"]["s2e7"]
    assert entry["status"] == "correct"
    assert entry["answered"] is True


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
    assert result["questions"]["s5e6"]["status"] == "correct"
    assert result["questions"]["s5f"]["status"] == "correct"


def test_scenario_five_requires_every_question_including_the_finding(key):
    """All eight Scenario 5 questions are required, the finding among them."""
    questions = key["scenarios"]["scenario-5"]["questions"]
    required = sorted(q for q, v in questions.items() if v.get("required"))
    assert required == ["s5e1", "s5e2", "s5e3", "s5e4", "s5e5", "s5e6", "s5e7", "s5f"]

    empty = G.grade("scenario-5", {}, key)
    assert empty["summary"]["required_total"] == 8
    assert empty["completed"] is False


def test_the_finding_alone_cannot_complete_a_scenario(key):
    """The Phase 6 completion gate: evidence alone is never enough."""
    for scenario in SCENARIO_FILES:
        evidence = [q for q in CORRECT_BY_SCENARIO[scenario] if not q.endswith("f")]
        finding = finding_id(scenario, key)
        without = dict(CORRECT_BY_SCENARIO[scenario])
        without[finding] = ""
        result = G.grade(scenario, without, key)
        assert result["questions"][finding]["status"] == "incorrect", scenario
        assert result["completed"] is False, (
            "%s completed with %d/%d evidence questions and no finding"
            % (scenario, result["summary"]["required_correct"],
               result["summary"]["required_total"]))
        assert evidence, scenario


@pytest.mark.parametrize("answer", [
    "They are separate incidents",
    "separate",
    "distinct",
    "different source IPs, so not the same incident",
    "Two unrelated incidents running in parallel",
])
def test_scenario_five_separate_activity_accepts_the_intended_answer(key, answer):
    """s5e4 asks whether the two same-host alerts share an actor. They do not."""
    assert G.grade("scenario-5", {"s5e4": answer}, key)["questions"]["s5e4"]["status"] == "correct"


@pytest.mark.parametrize("answer", [
    "yes, it is one continuous incident",
    "banana",
    "the answer is 42",
    "purple monkey dishwasher",
    "",
])
def test_scenario_five_separate_activity_rejects_an_obviously_wrong_answer(key, answer):
    result = G.grade("scenario-5", {"s5e4": answer}, key)
    assert result["questions"]["s5e4"]["status"] == "incorrect"
    assert result["completed"] is False


@pytest.mark.parametrize("answer", [
    "the authentication burst that succeeded - it left a valid session behind",
    "successful_brute_force, because it is the only alert with an accepted login",
    "the one that succeeded, which is why it escalated to critical",
])
def test_scenario_five_most_severe_accepts_the_intended_answer(key, answer):
    """s5e6 asks which alert is the most serious outcome, and why."""
    assert G.grade("scenario-5", {"s5e6": answer}, key)["questions"]["s5e6"]["status"] == "correct"


@pytest.mark.parametrize("answer", [
    "the failed-only burst, because it had more events",
    "whichever came first",
    "all of them are equally severe",
    "",
])
def test_scenario_five_most_severe_rejects_an_obviously_wrong_answer(key, answer):
    assert G.grade("scenario-5", {"s5e6": answer}, key)["questions"]["s5e6"]["status"] == "incorrect"


def test_scenario_five_wrong_answers_do_not_complete(key):
    result = G.grade("scenario-5", WRONG_S5, key)
    assert result["completed"] is False


def test_scenario_five_stays_incomplete_while_q5_is_left_blank(key):
    """q5 is graded by patterns rather than accept tokens, so an empty box fails.

    A build that filled a "perfect" submission from the accept lists alone would
    send nothing here and see 7 of 8 - the failure this test is written against.
    """
    answers = dict(CORRECT_S5)
    answers["s5e6"] = ""
    result = G.grade("scenario-5", answers, key)
    assert result["questions"]["s5e6"]["status"] == "incorrect"
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
    """Half a two-part question is partial, not wrong.

    s3e6 asks for the parent process *and* what it indicates. Naming only the
    process earns half the credit.
    """
    result = G.grade("scenario-3", {"s3e6": "winlogon.exe"}, key)
    entry = result["questions"]["s3e6"]
    assert entry["status"] == "partial"
    assert [p["ok"] for p in entry["parts"]] == [True, False]


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
    data = G.reveal("scenario-1", "s1e1", key)
    assert data["assisted"] is True
    assert "203.0.113.45" in data["solution"]


def test_the_finding_can_be_revealed_and_stays_safe(key):
    """The finding is revealable, and its rubric travels with the answer."""
    data = G.reveal("scenario-1", "s1f", key)
    assert data["assisted"] is True
    assert data["solution"]
    assert data["review_prompt"]


def test_reveal_requires_the_flag_when_grading(key):
    without = G.grade("scenario-1", CORRECT_S1, key, reveal_solution=False)
    for qid, entry in without["questions"].items():
        assert "solution" not in entry, qid
    with_flag = G.grade("scenario-1", CORRECT_S1, key, reveal_solution=True)
    for qid, entry in with_flag["questions"].items():
        assert entry["assisted"] is True, qid
        assert entry["solution"], qid


def test_unknown_scenario_and_question_are_rejected(key):
    with pytest.raises(G.GradingError):
        G.grade("scenario-99", {}, key)
    with pytest.raises(G.GradingError):
        G.reveal("scenario-1", "s1e99", key)


def test_the_finding_is_required_and_carries_its_rubric(key):
    """The finding replaced the unchecked self-review question.

    Under the worksheet model the written answers had no parts, so they graded
    as `self_review`, could never be correct, and were excluded from
    required_total - which let a scenario be completed without writing a
    finding at all. The finding is now graded against its rubric and is
    required.
    """
    for scenario in SCENARIO_FILES:
        question = key["scenarios"][scenario]["questions"][finding_id(scenario, key)]
        assert question.get("required") is True, scenario
        assert question.get("parts"), f"{scenario}: the finding needs rubric parts to be gradeable"
        assert question.get("review_prompt"), scenario
        empty = G.grade(scenario, {}, key)
        assert empty["questions"][question and finding_id(scenario, key)]["required"] is True, scenario


def test_oversized_answer_is_truncated_not_rejected(key):
    result = G.grade("scenario-1", {"s1e1": "x" * (G.MAX_ANSWER_CHARS + 500)}, key)
    assert result["questions"]["s1e1"]["answered"] is True


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
    """Reveal is no longer anonymous (security audit H-1).

    This file tests the grader, not authentication, and has no login helper, so
    it asserts the new refusal instead: an anonymous caller is turned away
    before the question id is ever validated. The authenticated path, including
    "an explicit question is required", is covered by
    tests/test_reveal_policy.py.
    """
    request = urllib.request.Request(
        server + "/api/reveal",
        data=json.dumps({"scenario": "scenario-1", "question": "s1e1"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status != 200, "anonymous reveal must not succeed"
            assert "solution" not in payload
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
        body = json.loads(exc.read().decode("utf-8"))
        assert "solution" not in body


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
    """Each question checks itself; there is no submit-everything button.

    The retirement of the single "Check answers" button is the point of the
    Phase 6 loop, so it is asserted rather than merely untested: a page that
    still submits everything would pass silently otherwise.
    """
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    ids = set(key_question_ids(html))
    assert ids, scenario
    for qid in ids:
        assert f'data-check="{qid}"' in html, f"{scenario}: {qid} has no Check answer button"
    assert 'id="check-answers"' not in html, f"{scenario}: the submit-all button is still present"
    assert 'id="check-result"' in html, scenario
    assert "lab-check.js" in html, scenario
    assert 'id="check-gate-note"' in html, scenario


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_question_row_is_tagged_with_feedback_hooks(scenario):
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    rows = set(re.findall(r'data-question-row="(s\d(?:e\d+|f))"', html))
    answers = set(key_question_ids(html))
    assert rows == answers, f"{scenario}: rows {rows} vs controls {answers}"
    for qid in sorted(rows):
        assert 'data-state-chip' in html, f"{scenario}/{qid} has no state chip"
        assert 'data-feedback' in html, f"{scenario}/{qid} has no feedback region"
        assert f'data-reveal="{qid}"' in html, f"{scenario}/{qid} missing reveal"
        assert f'data-hint="{qid}"' in html, f"{scenario}/{qid} missing hint"
        assert f'data-check="{qid}"' in html, f"{scenario}/{qid} missing Check answer"


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_mark_complete_starts_disabled(scenario):
    """Completion must not be one unverified click away."""
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    assert re.search(r'id="mark-done"[^>]*disabled', html), scenario


@pytest.mark.parametrize("scenario", sorted(SCENARIO_FILES))
def test_every_question_on_the_page_is_required_in_the_key(scenario, key):
    """No unchecked questions remain.

    Phase 6 retired the self-review checkbox: the graded finding replaced it, so
    nothing on the page may sit outside required_total any more.
    """
    html = read(os.path.join(SCENARIOS_DIR, SCENARIO_FILES[scenario]))
    assert 'data-self-review' not in html, scenario
    assert "analyst self-review" not in html, scenario
    not_required = {q for q, v in key["scenarios"][scenario]["questions"].items()
                    if not v.get("required")}
    assert not_required == set(), f"{scenario}: {not_required} are not required"
    assert set(key["scenarios"][scenario]["questions"]) == set(key_question_ids(html)), scenario


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
#
# Phase 6 ids: s<N>e<M> for evidence objectives, s<N>f for the final finding.
# Every question in a scenario is graded, including the finding, so a complete
# submission now carries one answer per question rather than leaving the written
# answers blank.

CORRECT_S1 = {
    "s1e1": "203.0.113.45",
    "s1e2": "web-01",
    "s1e3": "10 failed logons",
    "s1e4": "132 seconds (2 min 12 s)",
    "s1e5": "2 accounts: root and admin",
    "s1e6": "22 (SSH)",
    "s1e7": "3 blocked connections",
    "s1e8": "svc_backup had 4 failures, which is below min_failures of 5",
    "s1f": ("An external host ran an automated credential attack against SSH on web-01: "
            "source 203.0.113.45, ten failed authentications spread across multiple "
            "account names, all inside 132 seconds, with three blocked perimeter "
            "connections. No successful authentication followed, so nothing was obtained "
            "and no account was taken over. Block the source address at the firewall, "
            "confirm the perimeter rule held, and review the failure threshold."),
}

CORRECT_S2 = {
    "s2e1": "alice",
    "s2e2": "203.0.113.66",
    "s2e3": "5 failed authentications",
    "s2e4": "129 seconds (2 min 9 s)",
    "s2e5": ("Yes, the success fell inside the configured window, so the severity "
             "escalated to critical"),
    "s2e6": "the raw log line reports the authentication was accepted",
    "s2e7": "No, different source addresses, so they are separate activity",
    "s2f": ("alice on web-01 saw five failed SSH authentications from 203.0.113.66, and "
            "the raw log line then records an accepted password. Access was achieved and "
            "a valid session established, so an external party now holds access as alice. "
            "Block 203.0.113.66 at the firewall, rotate the credential and revoke sessions, "
            "and preserve the host for forensics."),
}

WRONG_S1 = {
    "s1e1": "192.168.1.10",
    "s1e2": "db-01",
    "s1e3": "7 failures",
    "s1e4": "an hour",
    "s1e5": "5 accounts",
    "s1e6": "443",
    "s1e7": "9 connections",
    "s1e8": "the rule was disabled for that host",
    "s1f": "Something bad happened to a web server. I would tell the team.",
}

# Scenario 5, the capstone.
CORRECT_S5 = {
    "s5e1": ("the failed-only authentication burst -> the authentication burst that "
             "succeeded -> the first post-authentication process -> the second "
             "post-authentication process"),
    "s5e2": "4 distinct source IPs",
    "s5e3": ("the failed-only authentication burst -> the authentication burst that "
             "succeeded"),
    "s5e4": ("No: different source addresses, so they are separate activity and must be "
             "tracked independently"),
    "s5e5": "the authentication burst that succeeded",
    "s5e6": ("The authentication burst that succeeded is most serious: its evidence "
             "contains an accepted authentication and a valid session, so it is achieved "
             "access rather than an attempt."),
    "s5e7": ("app-02 ran powershell 30 minutes after the logon, outside the rule's time "
             "window, so no alert fired"),
    "s5f": ("Timeline: first the failed-only authentication burst, second the burst that "
            "succeeded, then the two post-authentication processes. The confirmed "
            "compromise is the successful_brute_force alert - a valid session for alice on "
            "web-01. The two alerts on that host came from different sources so they are "
            "parallel and separate, and the powershell activity stayed quiet because it ran "
            "outside the rule's time window. Actions: block the confirmed source, contain "
            "the accessed account and host, and review the detection gap."),
}

# A correct answer set per scenario, for the tests that need "everything right"
# without caring which scenario.
CORRECT_BY_SCENARIO = {
    "scenario-1": CORRECT_S1,
    "scenario-2": CORRECT_S2,
    "scenario-5": CORRECT_S5,
}

WRONG_S5 = {
    "s5e1": ("the first post-authentication process -> the failed-only authentication burst "
             "-> the authentication burst that succeeded -> the second post-authentication "
             "process"),
    "s5e2": "231 source IPs",
    "s5e3": ("the first post-authentication process -> the second post-authentication "
             "process"),
    "s5e4": "Yes, the same actor ran both alerts on that host",
    "s5e5": "the failed-only authentication burst",
    "s5e6": "The failed-only burst is most serious because it had more events",
    "s5e7": "A scheduled task ran nightly on its own schedule",
    "s5f": "Four alerts happened. Investigate them.",
}


def _answers_for_the_rest():
    """Scenarios 3 and 4 correct answers, read from the key's own solutions."""
    loaded = G.load_key()
    out = {}
    for scenario in ("scenario-3", "scenario-4"):
        out[scenario] = {
            qid: question["solution"]
            for qid, question in loaded["scenarios"][scenario]["questions"].items()
        }
    return out


CORRECT_BY_SCENARIO.update(_answers_for_the_rest())
del _answers_for_the_rest
