"""Phase 1 tests for the SQLite foundation (scripts/labdb.py).

Every test runs against a throwaway database in pytest's ``tmp_path``, so running
the suite can never touch student data. The real ``data/training.db`` is allowed
to exist - Phase 1 creates it deliberately - and the isolation tests below check
that it is left byte-identical rather than that it is absent.

These are storage tests. There is deliberately nothing here about password
hashing, login, cookies or role enforcement - those arrive in a later phase.
"""

import hashlib
import os
import sqlite3
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import labdb  # noqa: E402

FUTURE = "2099-01-01T00:00:00Z"


# ----------------------------------------------------------------- fixtures

@pytest.fixture()
def db(tmp_path):
    """A freshly initialised throwaway database, closed again on teardown.

    The path is threaded explicitly through every call below, so no test can
    accidentally fall back to the real ``data/training.db``.
    """
    path = str(tmp_path / "training.db")
    labdb.init_db(path)
    yield path
    labdb.close_connection(path)
    labdb.reset_connections()


# --------------------------------------------------------- path-carrying helpers

def add_user(db, username="student.one", role="student", **kw):
    return labdb.create_user(
        username=username,
        password_hash=kw.pop("password_hash", "encoded-hash-placeholder"),
        display_name=kw.pop("display_name", "Student One"),
        role=role,
        path=db,
        **kw,
    )


def add_session(db, user_id, token_hash, **kw):
    kw.setdefault("expires_at", FUTURE)
    return labdb.create_session(user_id, token_hash, path=db, **kw)


def add_check(db, user_id, scenario_id, **kw):
    return labdb.record_scenario_check(user_id, scenario_id, path=db, **kw)


def latest(db, user_id, scenario_id):
    return labdb.get_latest_scenario_check(user_id, scenario_id, db)


def history(db, user_id, scenario_id=None, **kw):
    return labdb.get_scenario_checks(user_id, scenario_id, path=db, **kw)


def tables(db):
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def columns(db, table):
    conn = sqlite3.connect(db)
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
    finally:
        conn.close()


# ------------------------------------------------- initialisation & schema

def test_init_db_creates_the_file_and_directory(tmp_path):
    target = str(tmp_path / "nested" / "deeper" / "training.db")
    labdb.init_db(target)
    try:
        assert os.path.isfile(target)
    finally:
        labdb.close_connection(target)
        labdb.reset_connections()


def test_init_db_creates_all_tables(db):
    assert {"schema_meta", "users", "sessions", "scenario_checks",
            "student_progress", "student_progress_questions"} <= tables(db)


def test_schema_version_matches_the_module(db):
    # Asserted against the constant, not a literal, on purpose: pinning the
    # number here meant every additive schema change broke this test for no
    # reason. What matters is that the stamped version and the code agree.
    assert labdb.get_schema_version(db) == labdb.SCHEMA_VERSION
    assert labdb.SCHEMA_VERSION >= 2, "student_progress arrived in version 2"


def test_schema_version_is_none_before_initialisation(tmp_path):
    path = str(tmp_path / "empty.db")
    assert labdb.get_schema_version(path) is None
    labdb.close_connection(path)
    labdb.reset_connections()


def test_repeated_init_is_idempotent_and_preserves_data(db):
    user_id = add_user(db, username="keeper")
    before = labdb.get_user_by_id(user_id, db)

    labdb.init_db(db)
    labdb.init_db(db)

    assert labdb.get_user_by_id(user_id, db) == before
    assert labdb.get_schema_version(db) == labdb.SCHEMA_VERSION
    assert len(history(db, user_id)) == 0


def test_repeated_init_does_not_duplicate_the_schema_version_row(db):
    labdb.init_db(db)
    labdb.init_db(db)
    conn = sqlite3.connect(db)
    try:
        count = conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_init_db_does_not_drop_or_rewrite_a_table(db):
    add_user(db, username="survivor", email="s@example.test")
    labdb.init_db(db)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT username, email FROM users").fetchall()
    finally:
        conn.close()
    assert [(r["username"], r["email"]) for r in rows] == [("survivor", "s@example.test")]


# ------------------------------------------------------------------ pragma

def test_wal_mode_is_enabled(db):
    mode = labdb.get_connection(db).execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"


def test_foreign_keys_are_enforced_on_the_connection(db):
    assert labdb.get_connection(db).execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_busy_timeout_is_configured(db):
    assert labdb.get_connection(db).execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_connection_is_reused_within_a_thread(db):
    assert labdb.get_connection(db) is labdb.get_connection(db)


# ------------------------------------------------------- foreign keys

def test_foreign_key_rejects_an_orphan_session(db):
    with pytest.raises(sqlite3.IntegrityError):
        add_session(db, 9999, "hash-orphan")


def test_foreign_key_rejects_an_orphan_scenario_check(db):
    with pytest.raises(sqlite3.IntegrityError):
        add_check(db, 9999, "scenario-1")


def test_deleting_a_user_cascades_to_its_sessions_and_checks(db):
    user_id = add_user(db, username="cascader")
    add_session(db, user_id, "hash-cascade")
    add_check(db, user_id, "scenario-1", correct=1)

    conn = labdb.get_connection(db)
    with conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    assert labdb.get_session("hash-cascade", db) is None
    assert history(db, user_id) == []


# ------------------------------------------------------------------- users

def test_create_and_read_user_by_username(db):
    user_id = add_user(db, username="alice.t", display_name="Alice T",
                       email="alice@example.test")
    found = labdb.get_user_by_username("alice.t", db)
    assert found is not None
    assert found["id"] == user_id
    assert found["display_name"] == "Alice T"
    assert found["email"] == "alice@example.test"
    assert found["role"] == "student"
    assert found["is_active"] == 1
    assert found["last_login_at"] is None
    assert found["created_at"].endswith("Z")


def test_get_user_by_id_and_missing_lookups(db):
    user_id = add_user(db, username="bob.t")
    assert labdb.get_user_by_id(user_id, db)["username"] == "bob.t"
    assert labdb.get_user_by_id(999999, db) is None
    assert labdb.get_user_by_username("nobody", db) is None


def test_username_uniqueness_is_enforced(db):
    add_user(db, username="dupe")
    with pytest.raises(sqlite3.IntegrityError):
        add_user(db, username="dupe", display_name="Someone Else")


def test_email_uniqueness_is_enforced_when_supplied(db):
    add_user(db, username="c1", email="shared@example.test")
    with pytest.raises(sqlite3.IntegrityError):
        add_user(db, username="c2", email="shared@example.test")


def test_multiple_users_may_have_no_email(db):
    add_user(db, username="noemail1")
    add_user(db, username="noemail2")
    assert labdb.get_user_by_username("noemail1", db)["email"] is None
    assert labdb.get_user_by_username("noemail2", db)["email"] is None


def test_role_is_restricted_to_student_or_admin(db):
    with pytest.raises(ValueError):
        add_user(db, username="bad.role", role="superuser")
    admin_id = add_user(db, username="adm", role="admin")
    assert labdb.get_user_by_id(admin_id, db)["role"] == "admin"


def test_no_account_is_seeded_by_initialisation(db):
    """init_db() must never create a default or demo account."""
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    finally:
        conn.close()


def test_is_active_can_be_false(db):
    user_id = add_user(db, username="disabled", is_active=False)
    assert labdb.get_user_by_id(user_id, db)["is_active"] == 0


def test_touch_last_login_records_a_utc_timestamp(db):
    user_id = add_user(db, username="login.user")
    labdb.touch_last_login(user_id, db)
    stamp = labdb.get_user_by_id(user_id, db)["last_login_at"]
    assert stamp is not None and stamp.endswith("Z")


# ----------------------------------------------------------------- sessions

def test_session_insert_read_and_delete(db):
    user_id = add_user(db, username="sess.user")
    session_id = add_session(db, user_id, "hash-abc123",
                             user_agent="pytest", ip="127.0.0.1")
    assert session_id > 0

    found = labdb.get_session("hash-abc123", db)
    assert found["user_id"] == user_id
    assert found["expires_at"] == FUTURE
    assert found["user_agent"] == "pytest"
    assert found["ip"] == "127.0.0.1"
    assert found["created_at"] == found["last_seen_at"]
    assert found["created_at"].endswith("Z")

    assert labdb.delete_session("hash-abc123", db) is True
    assert labdb.get_session("hash-abc123", db) is None
    assert labdb.delete_session("hash-abc123", db) is False


def test_session_token_hash_is_unique(db):
    user_id = add_user(db, username="dup.token")
    add_session(db, user_id, "hash-same")
    with pytest.raises(sqlite3.IntegrityError):
        add_session(db, user_id, "hash-same")


def test_sessions_table_has_no_raw_token_column(db):
    cols = columns(db, "sessions")
    assert "token_hash" in cols
    for forbidden in ("token", "raw_token", "session_token", "secret", "value"):
        assert forbidden not in cols


def test_raw_session_token_is_never_stored(db):
    """Only the hash reaches SQLite; the token exists solely in the cookie."""
    user_id = add_user(db, username="token.user")
    raw_token = "PLAINTEXT-SESSION-TOKEN-DO-NOT-STORE"
    add_session(db, user_id, "sha256-of-that-token")

    row = labdb.get_session("sha256-of-that-token", db)
    assert row["token_hash"] == "sha256-of-that-token"
    for value in row.values():
        assert value != raw_token
    assert raw_token not in " ".join(str(v) for v in row.values())


def test_touch_session_moves_the_idle_clock(db):
    user_id = add_user(db, username="idle.user")
    add_session(db, user_id, "hash-idle", created_at="2000-01-01T00:00:00Z")
    labdb.touch_session("hash-idle", db)
    found = labdb.get_session("hash-idle", db)
    assert found["created_at"] == "2000-01-01T00:00:00Z"
    assert found["last_seen_at"] != "2000-01-01T00:00:00Z"


def test_delete_expired_sessions_only_removes_past_ones(db):
    user_id = add_user(db, username="expiry.user")
    add_session(db, user_id, "hash-old", expires_at="2000-01-01T00:00:00Z")
    add_session(db, user_id, "hash-new")
    assert labdb.delete_expired_sessions(path=db) == 1
    assert labdb.get_session("hash-old", db) is None
    assert labdb.get_session("hash-new", db) is not None


# ---------------------------------------------------------- scenario checks

def test_record_and_read_a_scenario_check(db):
    user_id = add_user(db, username="checker")
    row_id = add_check(db, user_id, "scenario-1", verdict="in_progress",
                       completed=False, correct=3, partial=1, incorrect=3,
                       self_review=2, answered=7, required_correct=3,
                       required_total=7, assisted=False)
    assert row_id > 0
    latest_row = latest(db, user_id, "scenario-1")
    assert latest_row["scenario_id"] == "scenario-1"
    assert latest_row["verdict"] == "in_progress"
    assert latest_row["completed"] == 0
    assert latest_row["correct"] == 3
    assert latest_row["partial"] == 1
    assert latest_row["incorrect"] == 3
    assert latest_row["self_review"] == 2
    assert latest_row["answered"] == 7
    assert latest_row["required_correct"] == 3
    assert latest_row["required_total"] == 7
    assert latest_row["assisted"] == 0
    assert latest_row["checked_at"].endswith("Z")


def test_check_history_is_newest_first_and_filterable(db):
    user_id = add_user(db, username="historian")
    add_check(db, user_id, "scenario-1", correct=1, checked_at="2026-01-01T00:00:00Z")
    add_check(db, user_id, "scenario-1", correct=5, checked_at="2026-03-01T00:00:00Z")
    add_check(db, user_id, "scenario-2", correct=2, checked_at="2026-02-01T00:00:00Z")

    assert [r["correct"] for r in history(db, user_id, "scenario-1")] == [5, 1]
    assert history(db, user_id, "scenario-2")[0]["correct"] == 2
    assert len(history(db, user_id)) == 3
    assert len(history(db, user_id, limit=1)) == 1
    assert history(db, 424242) == []


def test_latest_check_per_scenario_is_independent(db):
    user_id = add_user(db, username="multi")
    add_check(db, user_id, "scenario-1", required_correct=7, required_total=7,
              completed=True)
    add_check(db, user_id, "scenario-2", required_correct=2, required_total=5)
    assert latest(db, user_id, "scenario-1")["completed"] == 1
    assert latest(db, user_id, "scenario-1")["required_correct"] == 7
    assert latest(db, user_id, "scenario-2")["completed"] == 0
    assert latest(db, user_id, "scenario-2")["required_correct"] == 2
    assert latest(db, user_id, "scenario-3") is None


def test_students_do_not_see_each_others_checks(db):
    a = add_user(db, username="student.a")
    b = add_user(db, username="student.b")
    add_check(db, a, "scenario-1", correct=7, required_total=7, completed=True)
    assert latest(db, a, "scenario-1")["completed"] == 1
    assert latest(db, b, "scenario-1") is None
    assert history(db, b) == []
    assert len(history(db, a)) == 1


def test_summary_rolls_up_per_scenario(db):
    user_id = add_user(db, username="rollup")
    add_check(db, user_id, "scenario-1", required_correct=2, required_total=7)
    add_check(db, user_id, "scenario-1", required_correct=7, required_total=7,
              completed=True)
    add_check(db, user_id, "scenario-2", required_correct=1, required_total=5,
              assisted=True)
    summary = labdb.get_scenario_summary(user_id, db)
    assert set(summary) == {"scenario-1", "scenario-2"}
    assert summary["scenario-1"]["check_count"] == 2
    assert summary["scenario-1"]["completed"] is True
    assert summary["scenario-1"]["required_correct"] == 7
    assert summary["scenario-2"]["assisted"] is True
    assert summary["scenario-2"]["completed"] is False


def test_scenario_checks_stores_no_answers_or_key_material(db):
    """Outcomes only: no answers, key material, solutions or question text."""
    assert columns(db, "scenario_checks") == {
        "id", "user_id", "scenario_id", "checked_at", "verdict", "completed",
        "correct", "partial", "incorrect", "self_review", "answered",
        "required_correct", "required_total", "assisted",
    }
    for forbidden in ("answer", "answers", "response", "text", "accept",
                      "pattern", "solution", "hint", "question", "raw"):
        assert forbidden not in columns(db, "scenario_checks")


def test_scenario_check_row_contains_no_answer_text(db):
    user_id = add_user(db, username="no.leak")
    add_check(db, user_id, "scenario-1", verdict="in_progress", correct=1,
              required_correct=1, required_total=7)
    blob = " ".join(str(v) for v in latest(db, user_id, "scenario-1").values())
    for secret in ("203.0.113.45", "svc_backup", "alice", "10 failed logons"):
        assert secret not in blob


def test_scenario_checks_survives_an_answer_key_change(db):
    """Storage is independent of data/answer-key.json - the module never reads it."""
    source = open(os.path.join(ROOT, "scripts", "labdb.py"), encoding="utf-8").read()
    assert "answer-key" not in source
    assert "answer_key" not in source
    user_id = add_user(db, username="independent")
    add_check(db, user_id, "scenario-1", correct=1)
    assert latest(db, user_id, "scenario-1")["correct"] == 1


# -------------------------------------------------------------- timestamps

def test_utc_now_is_iso_8601_utc():
    stamp = labdb.utc_now()
    assert stamp.endswith("Z")
    assert "T" in stamp
    assert len(stamp) == len("2026-09-29T10:41:00Z")


def test_utc_now_ignores_the_host_timezone(monkeypatch):
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    stamp = labdb.utc_now()
    assert stamp.endswith("Z")
    assert stamp[:10] == "2026-09-29" or stamp[:4] == "2026"


# ------------------------------------------------------------- concurrency

def test_connections_are_per_thread_not_shared(db):
    """Each thread gets its own handle; a shared connection would deadlock."""
    main_conn = labdb.get_connection(db)
    seen = {}

    def worker():
        seen["conn"] = labdb.get_connection(db)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert seen["conn"] is not main_conn
    assert labdb.get_connection(db) is main_conn


def test_a_worker_thread_can_write(db):
    user_id = add_user(db, username="thread.user")
    errors = []

    def worker():
        try:
            add_check(db, user_id, "scenario-3", correct=2, required_total=6)
        except Exception as exc:  # pragma: no cover - only reached on failure
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert errors == []
    assert len(history(db, user_id, "scenario-3")) == 1


# ---------------------------------------------- isolation from the real DB
#
# The real database is EXPECTED to exist: Phase 1 creates data/training.db on
# purpose. The contract is not "it must be absent", it is "the test suite must
# never write to it". An earlier version of this file asserted absence, which
# could never hold in real use and broke the suite as soon as the database was
# created. These tests state the real invariant instead.

REAL_DB = os.path.join(ROOT, "data", "training.db")


def _fingerprint(path):
    """(size, mtime_ns, sha256) for a file, or None when it does not exist.

    mtime is read at nanosecond resolution so a same-second write is still
    detected, and the digest catches any in-place modification.
    """
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


def test_using_labdb_leaves_the_real_database_byte_identical(tmp_path):
    """Exercise every table against a temp database; the real one must not move.

    Deterministic and self-contained: it compares a fingerprint taken either
    side of the workload, and passes whether or not data/training.db exists.
    """
    before = _fingerprint(REAL_DB)

    path = str(tmp_path / "isolation.db")
    labdb.init_db(path)
    try:
        user_id = add_user(path, username="isolation.probe")
        add_session(path, user_id, "hash-isolation")
        add_check(path, user_id, "scenario-1", verdict="complete", completed=True,
                  correct=7, required_correct=7, required_total=7)
        labdb.touch_last_login(user_id, path)
        labdb.get_scenario_summary(user_id, path)
        assert labdb.get_schema_version(path) == labdb.SCHEMA_VERSION
    finally:
        labdb.close_connection(path)
        labdb.reset_connections()

    assert _fingerprint(REAL_DB) == before


def test_the_db_fixture_never_hands_out_the_project_database(db):
    """The fixture path must be a temp file, never the project's own database."""
    used = os.path.abspath(db)
    assert used != os.path.abspath(REAL_DB)
    # tmp_path lives under the OS temp directory, so the repository is not on
    # the path at all and a write cannot land in the working tree.
    assert ROOT not in used
    assert os.path.isfile(used)


def test_creating_a_temp_database_does_not_create_the_real_one(tmp_path):
    """A fresh project checkout has no database; running the suite must not make one."""
    before = _fingerprint(REAL_DB)
    path = str(tmp_path / "fresh.db")
    labdb.init_db(path)
    try:
        assert os.path.isfile(path)
        add_user(path, username="fresh.probe")
    finally:
        labdb.close_connection(path)
        labdb.reset_connections()
    # Untouched either way: unchanged if it existed, still absent if it did not.
    assert _fingerprint(REAL_DB) == before


def test_default_database_path_is_data_training_db():
    assert labdb.db_path() == os.path.join(ROOT, "data", "training.db")
    assert labdb.db_path("relative.db") == os.path.abspath("relative.db")


# -------------------------------------------- reset script must not touch it

def test_reset_script_does_not_target_the_training_database():
    """The SIEM reset contract stays scoped to the two indices + dedup cache."""
    source = open(os.path.join(ROOT, "scripts", "reset_lab_data.py"), encoding="utf-8").read()
    assert "training.db" not in source
    # no directory enumeration, so a new file in data/ can never be swept up
    for sweep in ("iterdir", "listdir", "glob(", "rmtree", "walk("):
        assert sweep not in source, f"reset_lab_data.py must not enumerate: {sweep}"
    assert '"normalized-events-*"' in source
    assert '"security-alerts-*"' in source
