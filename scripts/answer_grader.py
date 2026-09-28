"""Server-side grading for the BlueCloud SIEM lab scenarios.

Security model
--------------
The answer key is a local data file (``data/answer-key.json``) that is deliberately NOT
version controlled, because the repository is public and a committed key would
publish every scenario answer. It also lives outside the ``training/`` directory
served to students. This module is imported only by
``scripts/serve_training.py`` and runs exclusively on the server.

What the browser can learn per submission:

* which questions are correct, partially correct or incorrect;
* which *named parts* of a question were not matched (e.g. "target host");
* a hint for each unmatched part.

What the browser never receives unless the student explicitly asks: the
``solution`` text, or the accepted answer tokens. Grading is driven by the
supplied ``accept``/``patterns`` lists, which are compared on the server and
never echoed back.

Grading approach
----------------
Answers are free text written in a textarea, so grading is
containment-with-normalisation rather than exact equality: a part passes when
the student's answer contains one of its accepted tokens, or matches one of
its regular expressions. Normalisation folds case, unifies the several
characters people use for dashes/quotes, collapses whitespace, and treats
``_``, ``-``, ``.`` and whitespace as interchangeable inside identifiers, so
``brute_force``, ``brute force`` and ``Brute-Force`` are all accepted.

Values that change every lab session - absolute UTC timestamps and PIDs - are
deliberately absent from the key and therefore never graded. The key only
contains stable facts: addresses, account names, hosts, counts, durations,
rule names, thresholds, severities and command lines.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata

__all__ = [
    "ANSWER_KEY_PATH",
    "GradingError",
    "grade",
    "is_refusal",
    "load_key",
    "match_part",
    "normalize",
    "reveal",
    "scenario_overview",
    "question_count",
]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The answer key is deliberately NOT version controlled: the GitHub repository is
# public, and a committed key would hand the scenario answers to anyone who can
# read it. It lives under data/, which .gitignore already excludes.
#
# Resolution order:
#   1. $SIEM_ANSWER_KEY            - explicit override
#   2. data/answer-key.json        - the local, untracked copy
#   3. docs/answer-key.json        - legacy location, still honoured
ANSWER_KEY_RELATIVE = os.path.join("data", "answer-key.json")
ANSWER_KEY_LEGACY_RELATIVE = os.path.join("docs", "answer-key.json")


def _resolve_answer_key_path() -> str:
    """Locate the answer key, preferring the untracked data/ location."""
    override = os.environ.get("SIEM_ANSWER_KEY")
    if override:
        return os.path.abspath(override)
    for relative in (ANSWER_KEY_RELATIVE, ANSWER_KEY_LEGACY_RELATIVE):
        candidate = os.path.join(ROOT, relative)
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(ROOT, ANSWER_KEY_RELATIVE)


ANSWER_KEY_PATH = _resolve_answer_key_path()

# Bounded so a pasted document cannot make grading quadratic, and so the
# log/response surface stays small.
MAX_ANSWER_CHARS = 4000
MAX_PAYLOAD_BYTES = 64 * 1024

# Characters people substitute for '-' and quotes, folded before matching so
# that a pasted en-dash or a smart quote does not fail an otherwise correct answer.
_DASHES = {
    "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "―": "-", "−": "-",
}
_QUOTES = {
    "‘": "'", "’": "'", "‚": "'",
    "“": '"', "”": '"',
}

# A token boundary is anything that is not a letter, digit or
# underscore. This stops "root" matching "rootkit" and "5" matching "15".
_TOKEN_SPLIT = re.compile(r"[^a-z0-9_\\/-]+")
_BOUNDARY = re.compile(r"[a-z0-9_]")

# Answers that are a refusal rather than an attempt. Without this guard a box
# containing "no idea" would satisfy a yes/no question, because the word "no"
# matches the expected negative answer. Such a box counts as unanswered.
_REFUSAL_WORDS = frozenset({
    "noidea", "notsure", "idk", "dontknow", "unknown", "unclear", "noclue",
    "noclu", "nothing", "skip", "skipping", "tbd", "todo", "cannotfind",
    "cantfind", "couldnotfind", "notapplicable", "unsure", "unspecified",
    "pending", "guess", "maybe", "sorry", "stuck", "lost", "help", "erm",
})
_ANSWER_LETTERS = re.compile(r"[^a-z0-9]+")


def is_refusal(text: str) -> bool:
    """True when the answer is a refusal, or too short to be a real attempt.

    Guards against a near-empty box accidentally satisfying a low-specificity
    part, such as a yes/no question that is looking for the word "no".
    """
    if not text:
        return True
    letters = _ANSWER_LETTERS.sub("", normalize(text))
    if len(letters) <= 2:
        return True
    return letters in _REFUSAL_WORDS


class GradingError(Exception):
    """Raised for malformed or unsupported grading requests."""


def normalize(text: str) -> str:
    """Fold a raw answer into a comparable form."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", str(text))
    text = "".join(_DASHES.get(ch, ch) for ch in text)
    text = "".join(_QUOTES.get(ch, ch) for ch in text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _identifier_form(text: str) -> str:
    """Identifier form: ``brute_force`` -> ``bruteforce``, ``brute force`` too.

    Lets a rule name or a field name be written with any common separator.
    """
    return re.sub(r"[^a-z0-9]+", "", text)


def _bounded_find(needle: str, haystack: str) -> bool:
    """Substring search with token boundaries around short numeric tokens.

    Long literals (IPs, paths, commands) are matched literally: boundary rules
    would be wrong for them, because ``/app-01`` legitimately ends on a
    boundary character. Short all-numeric tokens are bounded so that a count of
    ``5`` cannot be satisfied by ``15``.
    """
    if not needle:
        return False
    idx = haystack.find(needle)
    if idx < 0:
        return False
    if not needle.replace(".", "").isdigit() or len(needle) > 6:
        return True
    end = idx + len(needle)
    before_ok = idx == 0 or not _BOUNDARY.match(haystack[idx - 1])
    after_ok = end >= len(haystack) or not _BOUNDARY.match(haystack[end])
    return before_ok and after_ok


def match_part(answer_norm: str, answer_ident: str, part: dict) -> bool:
    """True when the answer satisfies one part of a question.

    ``answer_ident`` is the pre-computed identifier form of the answer. It is
    derived here when not supplied, so the function is safe to call directly.
    """
    answer_norm = answer_norm or ""
    if not answer_ident:
        answer_ident = _identifier_form(answer_norm)
    for pattern in part.get("patterns") or []:
        try:
            if re.search(pattern, answer_norm, re.IGNORECASE):
                return True
        except re.error:
            # A malformed pattern must never silently pass a student.
            continue
    for token in part.get("accept") or []:
        token_norm = normalize(token)
        if not token_norm:
            continue
        if _bounded_find(token_norm, answer_norm):
            return True
        # Also allow the identifier form for rule names, field names and similar.
        ident = _identifier_form(token_norm)
        if ident and ident != token_norm and ident in answer_ident:
            return True
    return False


def load_key(path: str = None) -> dict:
    """Load and lightly validate the answer key."""
    path = path or ANSWER_KEY_PATH
    try:
        with open(path, "r", encoding="utf-8") as handle:
            key = json.load(handle)
    except FileNotFoundError as exc:
        raise GradingError(
            f"answer key not found at {path}. The key is intentionally not in "
            f"version control (this repository is public). Place your instructor "
            f"copy at data{os.sep}answer-key.json, or point $SIEM_ANSWER_KEY at it. "
            f"docs/INSTRUCTOR_GUIDE.md is the source of truth it is derived from."
        ) from exc
    except json.JSONDecodeError as exc:
        raise GradingError(f"answer key is not valid JSON: {exc}") from exc
    if not isinstance(key.get("scenarios"), dict) or not key["scenarios"]:
        raise GradingError("answer key contains no scenarios")
    return key


def _compile(patterns):
    out = []
    for pattern in patterns or []:
        try:
            out.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise GradingError(f"invalid pattern {pattern!r}: {exc}") from exc
    return out


def _iter_parts(question: dict):
    """Yield (part_label, part) pairs across every shape used by the key."""
    for part in question.get("parts") or []:
        yield part.get("label", "answer"), part
    for group in question.get("any_of") or []:
        for part in group:
            yield part.get("label", "answer"), part


def _question_status(parts, answered: bool) -> str:
    """Status for one question from its already-graded part results.

    ``parts`` is a list of ``{"label", "ok"}`` dicts built by :func:`grade`.
    """
    if not parts:
        return "self_review"
    if not answered:
        return "incorrect"
    flags = [bool(part.get("ok")) for part in parts]
    if all(flags):
        return "correct"
    if any(flags):
        return "partial"
    return "incorrect"


def grade(scenario: str, answers: dict, key: dict = None, reveal_solution: bool = False) -> dict:
    """Grade one submission.

    Returns a dict safe to send to the browser. When ``reveal_solution`` is
    true the ``solution`` string is included for the single requested question
    only, together with the ``assisted`` marker the UI uses to record that the
    student chose to see it.
    """
    key = key if key is not None else load_key()
    scenarios = key.get("scenarios", {})
    spec = scenarios.get(scenario)
    if spec is None:
        raise GradingError(f"unknown scenario {scenario!r}")

    questions = spec.get("questions", {})
    results = {}
    required_total = required_correct = 0
    answered_total = 0

    for qid, question in sorted(questions.items()):
        raw = answers.get(qid, "")
        raw = raw if isinstance(raw, str) else ""
        raw = raw[:MAX_ANSWER_CHARS]
        norm = normalize(raw)
        # A refusal ("no idea", "?", "idk") is not an attempt at the answer.
        answered = bool(norm) and not is_refusal(raw)
        ident = _identifier_form(norm)

        parts = []
        for label, part in _iter_parts(question):
            ok = match_part(norm, ident, part)
            entry = {"label": label, "ok": ok}
            if not ok:
                entry["hint"] = part.get("hint") or "Re-read the incident brief for this question."
            parts.append(entry)

        status = _question_status(parts, answered)
        if answered:
            answered_total += 1

        required = bool(question.get("required"))
        if required:
            required_total += 1
            if status == "correct":
                required_correct += 1

        entry = {
            "status": status,
            "parts": parts,
            "required": required,
            "answered": answered,
            "label": question.get("label", qid),
        }
        if question.get("review_prompt"):
            entry["review_prompt"] = question["review_prompt"]
        if reveal_solution:
            entry["solution"] = question.get("solution", "")
            entry["assisted"] = True
        results[qid] = entry

    correct = sum(1 for r in results.values() if r["status"] == "correct")
    partial = sum(1 for r in results.values() if r["status"] == "partial")
    incorrect = sum(1 for r in results.values() if r["status"] == "incorrect")
    self_review = sum(1 for r in results.values() if r["status"] == "self_review")

    completed = required_total > 0 and required_correct == required_total
    if not answered_total:
        verdict = "unanswered"
    elif completed:
        verdict = "complete"
    elif correct or partial:
        verdict = "in_progress"
    else:
        verdict = "incorrect"

    return {
        "scenario": scenario,
        "title": spec.get("title", scenario),
        "verdict": verdict,
        "completed": completed,
        "summary": {
            "correct": correct,
            "partial": partial,
            "incorrect": incorrect,
            "self_review": self_review,
            "answered": answered_total,
            "required_total": required_total,
            "required_correct": required_correct,
        },
        "questions": results,
    }


def reveal(scenario: str, question_id: str, key: dict = None) -> dict:
    """Return the model solution for one question, for 'Show Solution'."""
    key = key if key is not None else load_key()
    spec = (key.get("scenarios") or {}).get(scenario)
    if spec is None:
        raise GradingError(f"unknown scenario {scenario!r}")
    question = (spec.get("questions") or {}).get(question_id)
    if question is None:
        raise GradingError(f"unknown question {question_id!r}")
    return {
        "scenario": scenario,
        "question": question_id,
        "label": question.get("label", question_id),
        "solution": question.get("solution", ""),
        "review_prompt": question.get("review_prompt", ""),
        "assisted": True,
    }


def scenario_overview(key: dict = None) -> dict:
    """Question counts per scenario, for the client to lay out placeholders."""
    key = key if key is not None else load_key()
    out = {}
    for scenario, spec in (key.get("scenarios") or {}).items():
        out[scenario] = {
            "title": spec.get("title", scenario),
            "questions": len(spec.get("questions") or {}),
        }
    return out


def question_count(scenario: str, key: dict = None) -> int:
    key = key if key is not None else load_key()
    spec = (key.get("scenarios") or {}).get(scenario)
    if spec is None:
        raise GradingError(f"unknown scenario {scenario!r}")
    return len(spec.get("questions") or {})
