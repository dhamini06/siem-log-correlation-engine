"""SQLite storage foundation for the training platform.

Phase 1 only: this module is **storage**. It deliberately contains no password
hashing, no session-token generation, no role checks and no HTTP handling.
Those belong to a later phase; this file is the data layer they will sit on.

Why SQLite
    Python 3 ships ``sqlite3`` in the standard library, so this costs no new
    dependency, no service and no credentials. The workload is a classroom:
    a few dozen students, a handful of writes per minute, one server process.
    That is squarely SQLite's comfort zone.

Why this is separate from the SIEM
    Elasticsearch holds the *lab dataset* (``normalized-events-*`` and
    ``security-alerts-*``) - the shared puzzle every student investigates. It is
    regenerated wholesale by ``scripts/reset_lab_data.py`` and is identical for
    everybody. This database holds *per-student* state, which must **survive**
    that reset. Opposite lifecycles, so they must never share a store.

Safety properties
    * The database lives at ``data/training.db``, inside the directory that
      ``.gitignore`` already excludes, so no student data and no schema history
      can be committed by accident.
    * ``init_db()`` is idempotent and additive. It never drops, deletes or
      rewrites existing tables, so calling it on every server start is safe.
    * Connections are **per thread**. The training server is single-threaded
      today; when it becomes ``ThreadingMixIn`` in a later phase, each worker
      gets its own connection and SQLite's WAL mode lets readers and the writer
      coexist instead of blocking.
    * ``PRAGMA foreign_keys`` is enabled on every connection, because SQLite
      does not enforce foreign keys unless asked to do so per connection.
    * The ``sessions`` table stores only a *hash* of the session token. The raw
      token exists once, in the student's cookie, and is never persisted.
    * ``scenario_checks`` records outcomes and counts only. Raw student answer
      text, the answer key, accept tokens and model solutions are never stored.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

__all__ = [
    "DB_RELATIVE",
    "SCHEMA_VERSION",
    "ROLES",
    "SCENARIO_IDS",
    "close_connection",
    "create_session",
    "create_user",
    "db_path",
    "delete_expired_sessions",
    "delete_session",
    "get_connection",
    "get_latest_scenario_check",
    "get_scenario_checks",
    "get_schema_version",
    "get_session",
    "get_user_by_id",
    "get_user_by_username",
    "init_db",
    "progress_for_user",
    "record_progress",
    "record_scenario_check",
    "reset_connections",
    "utc_now",
]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_RELATIVE = os.path.join("data", "training.db")

#: Bumped by hand when the schema below changes. There is no migration
#: framework: ``init_db`` is additive and idempotent, so an existing version 1
#: database gains the new tables on the next start without a rebuild and
#: without losing users, sessions or history.
#:
#: 1 = users, sessions, scenario_checks
#: 2 = adds student_progress and student_progress_questions
SCHEMA_VERSION = 2

#: The only two roles the platform will ever hold.
ROLES = ("student", "admin")

#: The five scenarios the platform currently ships. Recorded as data rather
#: than a CHECK constraint so a scenario can be added later without a rebuild.
SCENARIO_IDS = (
    "scenario-1",
    "scenario-2",
    "scenario-3",
    "scenario-4",
    "scenario-5",
)

# Connection handles, keyed by resolved path, held per thread. A sqlite3
# connection must not be used from more than one thread, so each worker thread
# builds its own lazily and closes it on the way out.
_local = threading.local()


# --------------------------------------------------------------- timestamps

def utc_now() -> str:
    """Current time as a UTC ISO-8601 string, e.g. ``2026-09-29T10:41:00Z``.

    UTC only. Never the host's local timezone: a lab host may be moved or run
    in a different zone, and stored timestamps must stay comparable.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------- paths

def db_path(path: Optional[str] = None) -> str:
    """Absolute path of the database file, default ``data/training.db``."""
    if path is None:
        return os.path.join(ROOT, DB_RELATIVE)
    return os.path.abspath(path)


# ------------------------------------------------------------- connections

def get_connection(path: Optional[str] = None) -> sqlite3.Connection:
    """Return this thread's connection, opening it on first use.

    The database file and its parent directory are created if missing. The
    schema is *not* created here - call :func:`init_db` once at startup.
    """
    target = db_path(path)
    cache: Dict[str, sqlite3.Connection] = getattr(_local, "connections", None) or {}
    conn = cache.get(target)
    if conn is not None:
        return conn

    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(target, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # WAL lets the future threaded server read while another thread writes,
    # instead of every reader blocking on the single writer's lock.
    conn.execute("PRAGMA journal_mode=WAL")
    # sqlite3 is locked out per connection, so this must be set on each one.
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")

    cache[target] = conn
    _local.connections = cache
    return conn


def close_connection(path: Optional[str] = None) -> None:
    """Close this thread's connection for ``path`` (or all of them)."""
    cache: Dict[str, sqlite3.Connection] = getattr(_local, "connections", None) or {}
    targets = [db_path(path)] if path is not None else list(cache)
    for target in targets:
        conn = cache.pop(target, None)
        if conn is not None:
            conn.close()
    _local.connections = cache


def reset_connections() -> None:
    """Close every connection this thread holds. Intended for test teardown."""
    close_connection()


# ------------------------------------------------------------------ schema

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        version    INTEGER NOT NULL,
        updated_at TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY,
        username      TEXT    NOT NULL UNIQUE,
        email         TEXT    UNIQUE,
        display_name  TEXT    NOT NULL,
        -- Encoded hash produced elsewhere. This module never hashes and never
        -- stores a plaintext password.
        password_hash TEXT    NOT NULL,
        role          TEXT    NOT NULL CHECK (role IN ('student', 'admin')),
        is_active     INTEGER NOT NULL DEFAULT 1,
        created_at    TEXT    NOT NULL,
        last_login_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id           INTEGER PRIMARY KEY,
        -- SHA-256 (or similar) of the session token. The token itself is only
        -- ever held in the student's cookie and is never stored.
        token_hash   TEXT    NOT NULL UNIQUE,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at   TEXT    NOT NULL,
        expires_at   TEXT    NOT NULL,
        last_seen_at TEXT    NOT NULL,
        user_agent   TEXT,
        ip           TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scenario_checks (
        id              INTEGER PRIMARY KEY,
        user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        scenario_id     TEXT    NOT NULL,
        checked_at      TEXT    NOT NULL,
        verdict         TEXT,
        completed       INTEGER NOT NULL DEFAULT 0,
        correct         INTEGER NOT NULL DEFAULT 0,
        partial         INTEGER NOT NULL DEFAULT 0,
        incorrect       INTEGER NOT NULL DEFAULT 0,
        self_review     INTEGER NOT NULL DEFAULT 0,
        answered        INTEGER NOT NULL DEFAULT 0,
        required_correct INTEGER NOT NULL DEFAULT 0,
        required_total  INTEGER NOT NULL DEFAULT 0,
        -- 1 when this submission depended on a revealed solution. Cumulative
        -- per-scenario status is derived with MAX(assisted).
        assisted        INTEGER NOT NULL DEFAULT 0
    )
    """,
    # Per-scenario progress roll-up. One row per (student, scenario), so a
    # student's dashboard is a single indexed read and "which scenarios has
    # this student touched" needs no scan. A UNIQUE constraint is what stops a
    # duplicate row from ever being created, whichever code path gets there
    # first; the write path upserts on top of it.
    """
    CREATE TABLE IF NOT EXISTS student_progress (
        id                INTEGER PRIMARY KEY,
        user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        scenario_id       TEXT    NOT NULL,
        -- Set once, when the student first opens the scenario. Never moved.
        started_at        TEXT    NOT NULL,
        -- Moved forward by every check, so it answers "when was this student
        -- last seen on this scenario" without a second table.
        last_activity_at  TEXT    NOT NULL,
        -- Submissions, not questions: a student may check the same answers
        -- many times while iterating.
        attempts          INTEGER NOT NULL DEFAULT 0,
        -- Counts of questions, maintained by the roll-up in
        -- scripts/student_progress.py. questions_attempted counts distinct
        -- question ids, so re-answering does not inflate it.
        questions_attempted INTEGER NOT NULL DEFAULT 0,
        correct_answers   INTEGER NOT NULL DEFAULT 0,
        partial_answers   INTEGER NOT NULL DEFAULT 0,
        assisted_answers  INTEGER NOT NULL DEFAULT 0,
        -- 1 once the grader has said the scenario is complete. The definition
        -- is answer_grader's, not this column's: see student_progress.py.
        completed         INTEGER NOT NULL DEFAULT 0,
        -- Stamped only on the first completion and never cleared.
        completed_at      TEXT,
        UNIQUE (user_id, scenario_id)
    )
    """,
     # Per-question state. Needed rather than derived, because "questions
     # attempted" is a count of *distinct* question ids and "assisted" is a
     # per-question fact - neither can be computed from a per-submission total.
     # The question id is a label, not an answer: the submitted text is never
     # stored anywhere in this schema.
     """
     CREATE TABLE IF NOT EXISTS student_progress_questions (
         id              INTEGER PRIMARY KEY,
         user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
         scenario_id     TEXT    NOT NULL,
         question_id     TEXT    NOT NULL,
         first_answered_at TEXT  NOT NULL,
         last_answered_at  TEXT  NOT NULL,
         -- 1 once the student has looked up this question's model answer
         -- through the authenticated reveal endpoint.
         assisted        INTEGER NOT NULL DEFAULT 0,
         assisted_at     TEXT,
         -- Latest verdict for this question, from answer_grader: correct,
         -- partial, incorrect or self_review. A label, not content.
         last_status     TEXT,
         UNIQUE (user_id, scenario_id, question_id)
     )
     """,
     "CREATE INDEX IF NOT EXISTS idx_progress_user ON student_progress(user_id, scenario_id)",
     "CREATE INDEX IF NOT EXISTS idx_progress_activity ON student_progress(last_activity_at)",
     "CREATE INDEX IF NOT EXISTS idx_progress_questions ON student_progress_questions(user_id, scenario_id)",
     "CREATE INDEX IF NOT EXISTS idx_progress_questions_assisted ON student_progress_questions(user_id, assisted)",
     # Admin views are always "this student, this scenario, newest first".
     "CREATE INDEX IF NOT EXISTS idx_checks_user_scenario "
    "ON scenario_checks(user_id, scenario_id, checked_at)",
    "CREATE INDEX IF NOT EXISTS idx_checks_user ON scenario_checks(user_id, checked_at)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
)


def init_db(path: Optional[str] = None) -> str:
    """Create the database and schema if needed. Safe to call repeatedly.

    Additive only: every statement is ``CREATE ... IF NOT EXISTS``, and nothing
    here drops or rewrites a table, so existing users, sessions and history all
    survive. That is what lets one code path serve both a fresh checkout and a
    database created by an earlier version.

    The recorded version is advanced once the statements have run, so an
    existing version 1 database ends up stamped 2 and the server's startup
    check is satisfied. Leaving it at 1 would have made init_db add the tables
    and then still have the server refuse to start, which is the worst of both
    outcomes.

    A database stamped with a *newer* version than this code understands is
    left alone and is not stamped backwards: an older build must not silently
    claim compatibility with a newer schema.

    Returns the absolute path of the database.
    """
    conn = get_connection(path)
    with conn:
        for statement in _SCHEMA:
            conn.execute(statement)
        existing = conn.execute("SELECT version FROM schema_meta").fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO schema_meta (version, updated_at) VALUES (?, ?)",
                (SCHEMA_VERSION, utc_now()),
            )
        elif int(existing["version"]) < SCHEMA_VERSION:
            conn.execute(
                "UPDATE schema_meta SET version = ?, updated_at = ?",
                (SCHEMA_VERSION, utc_now()),
            )
    return db_path(path)


def get_schema_version(path: Optional[str] = None) -> Optional[int]:
    """Current schema version, or ``None`` if the database is not initialised."""
    conn = get_connection(path)
    try:
        row = conn.execute("SELECT version FROM schema_meta").fetchone()
    except sqlite3.OperationalError:
        return None
    return None if row is None else int(row["version"])


# ------------------------------------------------------------------- users

def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return None if row is None else {k: row[k] for k in row.keys()}


def create_user(
    username: str,
    password_hash: str,
    display_name: str,
    *,
    role: str = "student",
    email: Optional[str] = None,
    is_active: bool = True,
    path: Optional[str] = None,
    created_at: Optional[str] = None,
) -> int:
    """Insert a user and return the new id.

    ``password_hash`` must already be encoded by whatever hashes passwords;
    this module does no hashing. No default or seed account is created here.
    """
    if role not in ROLES:
        raise ValueError("role must be one of %s, got %r" % (ROLES, role))
    conn = get_connection(path)
    with conn:
        cur = conn.execute(
            """
            INSERT INTO users
                (username, email, display_name, password_hash, role,
                 is_active, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                username,
                email,
                display_name,
                password_hash,
                role,
                1 if is_active else 0,
                created_at or utc_now(),
            ),
        )
    return int(cur.lastrowid)


def get_user_by_username(
    username: str, path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Look a user up by username, or ``None``."""
    conn = get_connection(path)
    return _row_to_dict(
        conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    )


def record_progress(
    user_id: int,
    scenario_id: str,
    *,
    started: bool = False,
    activity_at: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create or touch the progress row for one student and one scenario.

    ``started=True`` creates the row if it is absent; ``started=False`` only
    moves ``last_activity_at`` on an existing row. That asymmetry is deliberate:
    opening a scenario is an event, but a check that arrives for a scenario
    never heard of should not silently invent one.

    The insert uses ``ON CONFLICT DO UPDATE`` rather than a read-then-write, so
    two concurrent requests for the same student and scenario cannot both
    decide the row is missing and create it twice. The UNIQUE constraint is the
    backstop underneath.

    Both branches commit before returning. The connection is thread-local and
    outlives the request, so an uncommitted write here would hold the database's
    write lock and make the next progress update fail with "database is locked".
    """
    now = activity_at or utc_now()
    conn = get_connection(path)
    with conn:
        if started:
            conn.execute(
                """
                INSERT INTO student_progress
                    (user_id, scenario_id, started_at, last_activity_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (user_id, scenario_id)
                DO UPDATE SET last_activity_at = excluded.last_activity_at
                """,
                (user_id, scenario_id, now, now),
            )
        else:
            conn.execute(
                """
                UPDATE student_progress SET last_activity_at = ?
                WHERE user_id = ? AND scenario_id = ?
                """,
                (now, user_id, scenario_id),
            )
    # One row, not the list. ``progress_for_user`` is a list because a student
    # has many scenarios; here the caller's own key narrows it to at most one,
    # and the empty case is the started=False path finding nothing to touch.
    rows = progress_for_user(user_id, scenario_id=scenario_id, path=path)
    return rows[0] if rows else {}


def progress_for_user(
    user_id: int,
    scenario_id: Optional[str] = None,
    path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Progress rows for one student, newest activity first.

    The ``user_id`` is always an argument resolved by the caller from a session
    row. There is no code path in this module that takes a user id from a
    request body, a query string or a header.
    """
    sql = "SELECT * FROM student_progress WHERE user_id = ?"
    params: List[Any] = [user_id]
    if scenario_id is not None:
        sql += " AND scenario_id = ?"
        params.append(scenario_id)
    sql += " ORDER BY last_activity_at DESC, scenario_id ASC"
    return [_row_to_dict(r) for r in get_connection(path).execute(sql, params).fetchall()]


def get_user_by_id(user_id: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Look a user up by primary key, or ``None``."""
    conn = get_connection(path)
    return _row_to_dict(
        conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    )


def touch_last_login(user_id: int, path: Optional[str] = None) -> None:
    """Record that a user just signed in."""
    conn = get_connection(path)
    with conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now(), user_id))


# ---------------------------------------------------------------- sessions

def create_session(
    user_id: int,
    token_hash: str,
    expires_at: str,
    *,
    user_agent: Optional[str] = None,
    ip: Optional[str] = None,
    path: Optional[str] = None,
    created_at: Optional[str] = None,
) -> int:
    """Store a session row and return its id.

    ``token_hash`` is the *hash* of the session token. The raw token is the
    caller's responsibility and is never written here, so a leaked database file
    cannot be replayed as a valid session.
    """
    conn = get_connection(path)
    now = created_at or utc_now()
    with conn:
        cur = conn.execute(
            """
            INSERT INTO sessions
                (token_hash, user_id, created_at, expires_at, last_seen_at,
                 user_agent, ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token_hash, user_id, now, expires_at, now, user_agent, ip),
        )
    return int(cur.lastrowid)


def get_session(
    token_hash: str, path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Fetch a session by token hash, or ``None``.

    Expiry is *not* evaluated here. Deciding whether a session is still valid
    is an authentication concern and belongs to the later auth phase; this
    function only reads storage.
    """
    conn = get_connection(path)
    return _row_to_dict(
        conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()
    )


def touch_session(token_hash: str, path: Optional[str] = None) -> None:
    """Move a session's idle clock forward."""
    conn = get_connection(path)
    with conn:
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
            (utc_now(), token_hash),
        )


def delete_session(token_hash: str, path: Optional[str] = None) -> bool:
    """Delete one session. Returns True if a row was removed.

    This is what makes logout real: the row is gone, so the token cannot be
    replayed even though it is stateless in the cookie.
    """
    conn = get_connection(path)
    with conn:
        cur = conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    return cur.rowcount > 0


def delete_expired_sessions(now: Optional[str] = None, path: Optional[str] = None) -> int:
    """Remove sessions whose ``expires_at`` has passed. Returns the count."""
    conn = get_connection(path)
    with conn:
        cur = conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (now or utc_now(),)
        )
    return int(cur.rowcount or 0)


# -------------------------------------------------------- scenario checks

def record_scenario_check(
    user_id: int,
    scenario_id: str,
    *,
    verdict: Optional[str] = None,
    completed: bool = False,
    correct: int = 0,
    partial: int = 0,
    incorrect: int = 0,
    self_review: int = 0,
    answered: int = 0,
    required_correct: int = 0,
    required_total: int = 0,
    assisted: bool = False,
    path: Optional[str] = None,
    checked_at: Optional[str] = None,
) -> int:
    """Append one immutable history row describing a graded submission.

    Counts and flags only. The student's raw answer text, the answer key, accept
    tokens and model solutions are intentionally not parameters: storing them
    would add a data-protection obligation and an answer-sharing surface for no
    instructional value, since ``answer_grader.grade()`` already returns every
    number recorded here.

    Returns the new row id.
    """
    conn = get_connection(path)
    with conn:
        cur = conn.execute(
            """
            INSERT INTO scenario_checks
                (user_id, scenario_id, checked_at, verdict, completed,
                 correct, partial, incorrect, self_review, answered,
                 required_correct, required_total, assisted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                scenario_id,
                checked_at or utc_now(),
                verdict,
                1 if completed else 0,
                int(correct),
                int(partial),
                int(incorrect),
                int(self_review),
                int(answered),
                int(required_correct),
                int(required_total),
                1 if assisted else 0,
            ),
        )
    return int(cur.lastrowid)


def get_latest_scenario_check(
    user_id: int, scenario_id: str, path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Most recent check for one student and one scenario, or ``None``."""
    conn = get_connection(path)
    return _row_to_dict(
        conn.execute(
            """
            SELECT * FROM scenario_checks
            WHERE user_id = ? AND scenario_id = ?
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
            """,
            (user_id, scenario_id),
        ).fetchone()
    )


def get_scenario_checks(
    user_id: int,
    scenario_id: Optional[str] = None,
    *,
    limit: Optional[int] = None,
    path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Check history for one student, newest first, optionally one scenario."""
    sql = "SELECT * FROM scenario_checks WHERE user_id = ?"
    params: List[Any] = [user_id]
    if scenario_id is not None:
        sql += " AND scenario_id = ?"
        params.append(scenario_id)
    sql += " ORDER BY checked_at DESC, id DESC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))
    return [_row_to_dict(r) for r in get_connection(path).execute(sql, params).fetchall()]


def get_scenario_summary(
    user_id: int, path: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """Per-scenario roll-up for one student, for a dashboard.

    Derived entirely from ``scenario_checks`` - there is deliberately no
    denormalised progress table to keep in sync.
    """
    conn = get_connection(path)
    rows = conn.execute(
        """
        SELECT scenario_id,
               COUNT(*)                AS check_count,
               MAX(checked_at)          AS last_checked_at,
               MAX(completed)           AS completed,
               MAX(assisted)            AS assisted
        FROM scenario_checks
        WHERE user_id = ?
        GROUP BY scenario_id
        """,
        (user_id,),
    ).fetchall()
    summary: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        latest = get_latest_scenario_check(user_id, row["scenario_id"], path=path)
        summary[row["scenario_id"]] = {
            "check_count": int(row["check_count"]),
            "last_checked_at": row["last_checked_at"],
            "completed": bool(row["completed"]),
            "assisted": bool(row["assisted"]),
            "required_correct": latest["required_correct"] if latest else 0,
            "required_total": latest["required_total"] if latest else 0,
        }
    return summary
