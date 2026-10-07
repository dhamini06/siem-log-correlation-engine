"""Server-side student progress: what a student has actually done, per scenario.

This is the layer that turns two events the server already sees - opening a
scenario, and submitting answers to ``/api/check`` - into durable progress. It
holds no HTTP and no grading rules of its own.

What it deliberately does not do
    It does not re-grade anything. :func:`record_check` is handed a result that
    ``answer_grader.grade`` has already produced and copies the counts out of
    it. The completion rule stays exactly where it was: the grader decides
    ``completed``, this module records it. Inventing a second definition of
    "finished" here is how a lab ends up disagreeing with itself.

    It does not store answers. No submitted text, no model solution, no
    accepted value and nothing from the answer key is ever written. The schema
    holds a question *id* and a verdict *label*, which is enough to answer
    "which questions has this student attempted, and how did they go" and not
    enough to reconstruct a single answer.

Identity
    Every function takes ``user_id`` as its first argument, and every caller
    resolves that from a session cookie through :func:`auth.resolve_session`.
    There is no code path in this module that reads a user id from a request,
    so a student cannot record progress against somebody else's account, and
    cannot read it either.

Counting, and why it is not simply "add the grader's numbers"
    ``attempts`` counts submissions, so re-checking the same answers increments
    it - that is what an attempt is.

    ``questions_attempted`` counts *distinct* question ids, so re-answering one
    question ten times still counts once. That needs per-question state to know
    whether a question is new, which is why ``student_progress_questions``
    exists alongside the roll-up.

    ``correct_answers`` and ``partial_answers`` are the *current* standing of
    the questions, not a lifetime tally. A student who gets three right, then
    breaks one by editing an answer, should show three correct and one
    incorrect - not four correct. So each submission replaces the verdict for
    the questions it answered, and the roll-up is recomputed from the
    per-question rows rather than incremented. Recomputing also means the
    counters cannot drift out of step with the detail they summarise.

    ``assisted_answers`` counts questions for which the student looked up the
    model answer. It is a floor, not a total: a question that was already
    assisted stays counted even if the student later answers it correctly, so
    an instructor can still see that help was used.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import labdb

__all__ = [
    "mark_assisted",
    "public_progress",
    "record_check",
    "record_start",
    "student_summary",
    "scenario_detail",
]

#: Verdicts the grader can return for one question. Anything else is stored
#: as-is rather than coerced, so a future status is visible rather than lost.
_KNOWN_STATUSES = ("correct", "partial", "incorrect", "self_review")


def _now(path: Optional[str] = None) -> str:
    return labdb.utc_now()


def record_start(user_id: int, scenario_id: str, *, path: Optional[str] = None) -> Dict[str, Any]:
    """Note that a student opened a scenario.

    Idempotent: the row is created once and ``started_at`` never moves, so
    reopening a scenario does not rewrite when the student first arrived.
    ``last_activity_at`` does move, because that is the "last seen" timestamp an
    instructor dashboard shows.

    Opening a scenario is emphatically not completing it. Only the grader can
    set ``completed``.
    """
    return labdb.record_progress(
        user_id, scenario_id, started=True, path=path
    ) or {}


def _upsert_question(
    user_id: int,
    scenario_id: str,
    question_id: str,
    *,
    status: Optional[str] = None,
    assisted: bool = False,
    at: str,
    path: Optional[str] = None,
) -> None:
    """Create or update the per-question row for one question.

    Two of the columns are merged rather than replaced, and both merges are
    load-bearing:

    ``last_status``
        Kept when this call supplies no status. A reveal knows that a question
        was looked up but not how it was last graded, and writing its ``None``
        over a recorded ``correct`` would silently lose the verdict - the
        roll-up, recomputed on the next check, would then under-count. Only a
        real grading result may move this column.

    ``assisted`` / ``assisted_at``
        Sticky, via ``MAX`` and ``COALESCE``. A student who used the model
        answer once has used it, whatever they type afterwards.
    """
    conn = labdb.get_connection(path)
    with conn:
        conn.execute(
            """
            INSERT INTO student_progress_questions
                (user_id, scenario_id, question_id, first_answered_at,
                 last_answered_at, last_status, assisted, assisted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (user_id, scenario_id, question_id) DO UPDATE SET
                last_answered_at = excluded.last_answered_at,
                last_status      = COALESCE(excluded.last_status,
                                            student_progress_questions.last_status),
                assisted          = MAX(student_progress_questions.assisted,
                                         excluded.assisted),
                assisted_at       = COALESCE(student_progress_questions.assisted_at,
                                              excluded.assisted_at)
            """,
            (
                user_id, scenario_id, question_id, at, at,
                status, 1 if assisted else 0, at if assisted else None,
            ),
        )


def _recompute_rollup(user_id: int, scenario_id: str, *, attempts: int,
                      completed: bool, at: str, path: Optional[str] = None) -> None:
    """Rewrite the roll-up from the per-question rows.

    Recomputed rather than incremented, so the summary can never disagree with
    the detail it summarises - see the module docstring.

    The read and the write share one transaction. That is not tidiness: the
    connection is thread-local and lives for the whole request, so an UPDATE
    left uncommitted here would hold SQLite's write lock until the thread
    finished and the *next* progress write would fail with "database is
    locked" after the busy timeout.
    """
    conn = labdb.get_connection(path)
    with conn:
        counts = conn.execute(
            """
            SELECT COUNT(*)                                            AS attempted,
                   SUM(CASE WHEN last_status = 'correct'  THEN 1 ELSE 0 END) AS correct,
                   SUM(CASE WHEN last_status = 'partial'  THEN 1 ELSE 0 END) AS partial,
                   SUM(assisted)                                        AS assisted
            FROM student_progress_questions
            WHERE user_id = ? AND scenario_id = ?
            """,
            (user_id, scenario_id),
        ).fetchone()

        # completed_at is stamped on the first completion and never moved, so a
        # scenario has one honest "finished at" rather than a moving target.
        conn.execute(
            """
            UPDATE student_progress
               SET attempts            = ?,
                   questions_attempted  = ?,
                   correct_answers      = ?,
                   partial_answers      = ?,
                   assisted_answers     = ?,
                   completed            = CASE
                                             WHEN ? IS NULL THEN completed
                                             ELSE ?
                                         END,
                   completed_at         = CASE
                                             WHEN completed = 1 THEN completed_at
                                             WHEN ? = 1 THEN ?
                                             ELSE completed_at
                                         END,
                   last_activity_at     = ?
             WHERE user_id = ? AND scenario_id = ?
            """,
            (
                attempts,
                int(counts["attempted"] or 0),
                int(counts["correct"] or 0),
                int(counts["partial"] or 0),
                int(counts["assisted"] or 0),
                None if completed is None else (1 if completed else 0),
                None if completed is None else (1 if completed else 0),
                1 if completed else 0, at,
                at,
                user_id, scenario_id,
            ),
        )


def record_check(
    user_id: int,
    scenario_id: str,
    result: Dict[str, Any],
    *,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Record one graded submission against a student's progress.

    ``result`` is the untouched dict from ``answer_grader.grade``. Nothing here
    re-grades and nothing here reads the answer key.

    Only questions the student actually answered are touched. A submission that
    omits a question leaves that question's previous verdict alone, so a student
    cannot lose credit by checking with a blank box, and cannot gain it either.

    A *scoped* result - the per-question check the investigation loop sends -
    touches only the question ids it returned, and leaves the scenario's
    completion flag untouched, because one graded question can neither establish
    nor disprove completion.
    """
    at = _now(path)
    # The row is created on first activity, and starting it here as well means a
    # student who answers without ever opening the page still gets a row.
    labdb.record_progress(user_id, scenario_id, started=True, activity_at=at, path=path)

    conn = labdb.get_connection(path)
    row = conn.execute(
        "SELECT attempts FROM student_progress WHERE user_id = ? AND scenario_id = ?",
        (user_id, scenario_id),
    ).fetchone()
    attempts = int((row["attempts"] if row else 0) or 0) + 1

    questions = result.get("questions") or {}
    for question_id, entry in questions.items():
        if not isinstance(entry, dict):
            continue
        # "answered" is the grader's own word for the student having put
        # something down. An unanswered question is not an attempt at it.
        if not entry.get("answered"):
            continue
        status = entry.get("status")
        _upsert_question(
            user_id, scenario_id, question_id,
            status=status if status in _KNOWN_STATUSES else (status or None),
            at=at, path=path,
        )

    # The grader owns completion. This module records it verbatim - except for a
    # scoped check, which graded one question and knows nothing about the rest,
    # so it leaves the flag alone rather than clearing a real completion.
    if result.get("scoped"):
        completed = None
    else:
        completed = bool(result.get("completed"))
    _recompute_rollup(user_id, scenario_id, attempts=attempts,
                      completed=completed, at=at, path=path)
    # The row was created above, so this is normally a hit; the fallback is
    # there so a caller can never crash on an empty read.
    rows = labdb.progress_for_user(user_id, scenario_id=scenario_id, path=path)
    return rows[0] if rows else {}


def mark_assisted(user_id: int, scenario_id: str, question_id: str,
                  *, path: Optional[str] = None) -> None:
    """Record that a student looked up one question's model answer.

    Called from the reveal handler, after the reveal policy has already
    authorised it. The solution text is not passed in and is not stored; only
    the fact that help was used.
    """
    at = _now(path)
    labdb.record_progress(user_id, scenario_id, started=True, activity_at=at, path=path)
    _upsert_question(user_id, scenario_id, question_id, assisted=True, at=at, path=path)

    conn = labdb.get_connection(path)
    with conn:
        conn.execute(
            """
            UPDATE student_progress
               SET assisted_answers = (
                     SELECT COUNT(*) FROM student_progress_questions
                      WHERE user_id = ? AND scenario_id = ? AND assisted = 1
                   ),
                   last_activity_at = ?
             WHERE user_id = ? AND scenario_id = ?
            """,
            (user_id, scenario_id, at, user_id, scenario_id),
        )


# --------------------------------------------------------------- read side

def public_progress(row: Dict[str, Any],
                     questions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Convert a stored row into the shape a client may see.

    An explicit field list again: this is the boundary where a column added to
    the schema later would otherwise start being sent to a browser.
    """
    out = {
        "scenario_id": row.get("scenario_id"),
        "started_at": row.get("started_at"),
        "last_activity_at": row.get("last_activity_at"),
        "attempts": int(row.get("attempts") or 0),
        "questions_attempted": int(row.get("questions_attempted") or 0),
        "correct_answers": int(row.get("correct_answers") or 0),
        "partial_answers": int(row.get("partial_answers") or 0),
        "assisted_answers": int(row.get("assisted_answers") or 0),
        "completed": bool(row.get("completed")),
        "completed_at": row.get("completed_at"),
    }
    if questions is not None:
        out["questions"] = questions
    return out


def _question_rows(user_id: int, scenario_id: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = labdb.get_connection(path).execute(
        """
        SELECT question_id, first_answered_at, last_answered_at, last_status, assisted
        FROM student_progress_questions
        WHERE user_id = ? AND scenario_id = ?
        ORDER BY question_id
        """,
        (user_id, scenario_id),
    ).fetchall()
    # No submitted text and no solution: only an id, two timestamps, a verdict
    # label and whether help was used.
    return [
        {
            "question_id": r["question_id"],
            "last_status": r["last_status"],
            "assisted": bool(r["assisted"]),
            "last_answered_at": r["last_answered_at"],
        }
        for r in rows
    ]


def student_summary(user_id: int, *, path: Optional[str] = None) -> Dict[str, Any]:
    """The signed-in student's own progress, with every scenario listed.

    All five known scenarios appear, so a student sees "not started" for work
    they have not touched rather than a short list that hides it. The state
    label is derived here for display; the underlying flags are the source of
    truth.
    """
    rows = {r["scenario_id"]: r for r in labdb.progress_for_user(user_id, path=path)}
    scenarios = []
    for scenario_id in labdb.SCENARIO_IDS:
        if scenario_id in rows:
            item = public_progress(rows[scenario_id])
            item["state"] = ("completed" if item["completed"]
                             else "in_progress")
        else:
            item = {
                "scenario_id": scenario_id, "started_at": None,
                "last_activity_at": None, "attempts": 0, "questions_attempted": 0,
                "correct_answers": 0, "partial_answers": 0, "assisted_answers": 0,
                "completed": False, "completed_at": None, "state": "not_started",
            }
        scenarios.append(item)

    return {
        "scenarios": scenarios,
        "scenarios_started": sum(1 for s in scenarios if s["state"] != "not_started"),
        "scenarios_completed": sum(1 for s in scenarios if s["completed"]),
        "attempts": sum(s["attempts"] for s in scenarios),
        "questions_attempted": sum(s["questions_attempted"] for s in scenarios),
        "correct_answers": sum(s["correct_answers"] for s in scenarios),
        "partial_answers": sum(s["partial_answers"] for s in scenarios),
        "assisted_answers": sum(s["assisted_answers"] for s in scenarios),
        "last_activity_at": max(
            (s["last_activity_at"] for s in scenarios if s["last_activity_at"]),
            default=None,
        ),
    }


def scenario_detail(user_id: int, scenario_id: str, *,
                    path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """One scenario's progress for this student, or ``None`` if untouched."""
    if scenario_id not in labdb.SCENARIO_IDS:
        return None
    rows = labdb.progress_for_user(user_id, scenario_id=scenario_id, path=path)
    if not rows:
        return public_progress({"scenario_id": scenario_id}, [])
    return public_progress(rows[0], _question_rows(user_id, scenario_id, path=path))
