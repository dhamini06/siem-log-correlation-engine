"""Read-only aggregates for the instructor dashboard.

Kept apart from :mod:`labdb` on purpose. That module is deliberately minimal
CRUD against one table at a time; this one answers questions that span
``users``, ``sessions`` and ``scenario_checks`` at once, which is a different
kind of work and a different risk profile.

Three rules govern everything here.

**Read only.** Every statement is a ``SELECT``. There is no function in this
module that changes a row, so the instructor dashboard cannot become a backdoor
for promoting a student, deactivating an account, or editing anyone's answers.
An administrator can look; they cannot change anything from here.

**No secrets, by construction.** The per-student record is built from an
explicit field list rather than by selecting a row and filtering it. A password
hash, a session token hash and any answer text are not merely omitted - they
are never read, so a later change that adds a column cannot accidentally start
leaking one. ``password_hash`` in particular is not selected anywhere in this
file.

**The role is never a parameter.** Callers are expected to have already
authorised the request; nothing here takes a role, a user id, or any other
caller-supplied selector, so it cannot be pointed at somebody else's data by a
request that was never authorised in the first place.

Honest numbers
    Progress persistence is a later phase, so ``scenario_checks`` currently
    holds only the rows written by an assisted reveal. That means "students who
    started a scenario" and "scenarios completed" will read 0 for a class that
    has merely signed in, and that is the truth rather than a bug. The
    aggregates report what is stored; they do not infer completion that was
    never recorded.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import labdb

__all__ = ["SCENARIO_LABELS", "scenario_rows", "student_rows", "summary"]


#: Display names for the five scenarios. Keyed by the same ids the training
#: pages and the answer key use, so the dashboard cannot drift out of step with
#: them. A scenario that is not listed here still appears, under its raw id.
SCENARIO_LABELS = {
    "scenario-1": "Scenario 01 - Brute force (SSH)",
    "scenario-2": "Scenario 02 - Successful login after brute force",
    "scenario-3": "Scenario 03 - Suspicious post-login process",
    "scenario-4": "Scenario 04 - Linux privilege escalation",
    "scenario-5": "Scenario 05 - Multi-event SOC investigation",
}

#: The only user fields this module will ever return. Anything not listed here
#: is not read from the database, so it cannot leak.
_PUBLIC_FIELDS = ("id", "username", "display_name", "created_at", "last_login_at", "is_active")


def _query(sql: str, params: tuple = (), path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run a read-only query through the shared labdb connection."""
    return labdb.get_connection(path).execute(sql, params).fetchall()


def summary(path: Optional[str] = None) -> Dict[str, Any]:
    """Headline counts for the dashboard.

    The per-scenario and per-student breakdowns live in their own functions; this
    one is the single cheap query pair an instructor sees first.
    """
    conn = labdb.get_connection(path)

    totals = conn.execute(
        """
        SELECT
          COUNT(*)                                                   AS total_accounts,
          SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END)         AS total_students,
          SUM(CASE WHEN role = 'admin'   THEN 1 ELSE 0 END)         AS total_admins,
          SUM(CASE WHEN role = 'student' AND is_active = 1
                   THEN 1 ELSE 0 END)                               AS active_students
        FROM users
        """
    ).fetchone()

    totals = dict(totals) if totals else {}

    # "Active" in the sense of a live session, which is a different and more
    # useful question than is_active. Only unexpired rows count.
    live_sessions = conn.execute(
        "SELECT COUNT(DISTINCT user_id) AS n FROM sessions WHERE expires_at > ?",
        (labdb.utc_now(),),
    ).fetchone()

    # A student "started" a scenario once a progress row exists. This reads
    # student_progress, which the server writes on every authenticated check
    # and scenario open. scenario_checks is not used here any more: it only
    # ever recorded assisted reveals, so it badly understated the class.
    progress = conn.execute(
        """
        SELECT COUNT(DISTINCT p.user_id) AS students_started,
               COUNT(*)                   AS scenarios_started,
               COALESCE(SUM(p.completed), 0) AS scenarios_completed,
               COALESCE(SUM(p.attempts), 0) AS attempts,
               COALESCE(SUM(p.questions_attempted), 0) AS questions_attempted,
               COALESCE(SUM(p.correct_answers), 0) AS correct,
               COALESCE(SUM(p.assisted_answers), 0) AS assisted,
               MAX(p.last_activity_at) AS last_activity
        FROM student_progress p
        JOIN users u ON u.id = p.user_id
        WHERE u.role = 'student'
        """
    ).fetchone()
    progress = dict(progress) if progress else {}

    return {
        "total_accounts": int(totals.get("total_accounts") or 0),
        "total_students": int(totals.get("total_students") or 0),
        "total_admins": int(totals.get("total_admins") or 0),
        "active_students": int(totals.get("active_students") or 0),
        "students_with_live_session": int(live_sessions["n"] or 0) if live_sessions else 0,
        "students_who_started": int(progress.get("students_started") or 0),
        "scenarios_started": int(progress.get("scenarios_started") or 0),
        "scenarios_completed": int(progress.get("scenarios_completed") or 0),
        "attempts": int(progress.get("attempts") or 0),
        "questions_attempted": int(progress.get("questions_attempted") or 0),
        "correct_answers": int(progress.get("correct") or 0),
        "assisted_answers": int(progress.get("assisted") or 0),
        "last_activity_at": progress.get("last_activity"),
        # total_checks is an alias for attempts, matching the student table's
        # column of the same name. It used to be a row count in
        # scenario_checks, which only ever held assisted reveals and so read
        # near zero on a busy class; leaving the two disagreeing would be worse
        # than either alone.
        "total_checks": int(progress.get("attempts") or 0),
        # path must be threaded through: without it this total would be read
        # from labdb's default database rather than the caller's.
        "total_sessions": int(_total("sessions", path=path) or 0),
    }


def _total(table: str, path: Optional[str] = None) -> Optional[int]:
    """Row count for one of the known tables. The name is never caller-supplied.

    Only ``sessions`` is still asked for. ``scenario_checks`` used to be here
    for the "recorded checks" figure; it now contributes nothing to the
    dashboard, because ``student_progress`` is the authoritative record and
    counting reveal rows would understate the class.
    """
    if table != "sessions":
        raise ValueError("unknown table")
    row = labdb.get_connection(path).execute(
        "SELECT COUNT(*) AS n FROM sessions"
    ).fetchone()
    return int(row["n"]) if row else 0


def scenario_rows(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per-scenario activity, including scenarios nobody has touched.

    Built from the known scenario list rather than from what happens to be in
    the database, so the dashboard shows five rows on day one instead of none.
    """
    rows = labdb.get_connection(path).execute(
        """
        SELECT scenario_id,
               COUNT(*)                             AS checks,
               COUNT(DISTINCT user_id)              AS students,
               COALESCE(SUM(attempts), 0)           AS attempts,
               COALESCE(SUM(completed), 0)          AS completions,
               COALESCE(SUM(questions_attempted), 0) AS questions_attempted,
               COALESCE(SUM(correct_answers), 0)    AS correct,
               COALESCE(SUM(assisted_answers), 0)   AS assisted
        FROM student_progress
        GROUP BY scenario_id
        """
    ).fetchall()
    found = {row["scenario_id"]: dict(row) for row in rows}
    counters = ("checks", "students", "attempts", "completions",
                "questions_attempted", "correct", "assisted")

    out: List[Dict[str, Any]] = []
    for scenario_id in labdb.SCENARIO_IDS:
        data = found.get(scenario_id, {})
        out.append({
            "scenario_id": scenario_id,
            "title": SCENARIO_LABELS.get(scenario_id, scenario_id),
            **{name: int(data.get(name) or 0) for name in counters},
        })

    # Anything recorded against an id we do not know about, rather than hiding
    # it. An unexpected scenario id is worth an instructor's attention.
    for scenario_id, data in sorted(found.items()):
        if scenario_id in labdb.SCENARIO_IDS:
            continue
        out.append({
            "scenario_id": scenario_id,
            "title": "%s (unrecognised)" % scenario_id,
            **{name: int(data.get(name) or 0) for name in counters},
        })
    return out


def student_rows(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """One row per student, safe to send to an instructor's browser.

    Assembled from an explicit column list: no ``password_hash``, no
    ``token_hash``, no answer text, and no per-session identifiers. An admin
    gets counts and timestamps, which is what a dashboard needs, and nothing
    that could be replayed or cracked.
    """
    conn = labdb.get_connection(path)

    # identity, without the secret columns
    people = conn.execute(
        """
        SELECT u.id, u.username, u.display_name, u.created_at,
               u.last_login_at, u.is_active,
               COALESCE(p.scenarios_started, 0)   AS scenarios_started,
               COALESCE(p.scenarios_completed, 0) AS scenarios_completed,
               COALESCE(p.attempts, 0)            AS attempts,
               COALESCE(p.questions_attempted, 0) AS questions_attempted,
               COALESCE(p.correct, 0)             AS correct,
               COALESCE(p.assisted, 0)           AS assisted,
               p.last_activity                    AS last_activity
        FROM users u
        LEFT JOIN (
            SELECT user_id,
                   COUNT(*) AS scenarios_started,
                   COALESCE(SUM(completed), 0) AS scenarios_completed,
                   COALESCE(SUM(attempts), 0) AS attempts,
                   COALESCE(SUM(questions_attempted), 0) AS questions_attempted,
                   COALESCE(SUM(correct_answers), 0) AS correct,
                   COALESCE(SUM(assisted_answers), 0) AS assisted,
                   MAX(last_activity_at) AS last_activity
            FROM student_progress
            GROUP BY user_id
        ) p ON p.user_id = u.id
        WHERE u.role = 'student'
        ORDER BY u.username COLLATE NOCASE
        """
    ).fetchall()

    # The per-student aggregates arrive joined into the projection above, so
    # there is no second query that could drift out of step with it.

    # last activity, preferring a real check and falling back to a sign-in
    activity = {}
    for row in conn.execute(
        """
        SELECT user_id, MAX(last_seen_at) AS last_seen
        FROM sessions
        WHERE expires_at > ?
        GROUP BY user_id
        """,
        (labdb.utc_now(),),
    ).fetchall():
        activity[row["user_id"]] = row["last_seen"]

    out: List[Dict[str, Any]] = []
    for person in people:
        user_id = person["id"]
        record = {field: person[field] for field in _PUBLIC_FIELDS}
        # The COALESCEs in the query above mean a student with no progress at
        # all still arrives as zeros, so these reads need no existence check.
        attempts = int(person["attempts"] or 0)
        record.update({
            # total_checks kept as an alias for attempts: the dashboard column
            # has always meant "submissions", and renaming it here would break
            # the page for no gain.
            "total_checks": attempts,
            "attempts": attempts,
            "scenarios_started": int(person["scenarios_started"] or 0),
            "scenarios_attempted": int(person["scenarios_started"] or 0),
            "scenarios_completed": int(person["scenarios_completed"] or 0),
            "questions_attempted": int(person["questions_attempted"] or 0),
            "assisted": int(person["assisted"] or 0),
            "correct": int(person["correct"] or 0),
            # "Last activity" is whichever is more recent: real work on a
            # scenario, or a live sign-in.
            "last_activity": max(
                filter(None, (person["last_activity"], activity.get(user_id))),
                default=None,
            ),
        })
        out.append(record)
    return out
