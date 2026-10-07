"""Tests for server-side student progress.

Progress is the first feature where a student could plausibly write to - or
read - somebody else's record, so most of what follows is about identity. The
recurring pattern is: attempt to nominate another user through a query string, a
body field or a header, and prove the stored owner does not change.

Every test uses a throwaway database in ``tmp_path``. The real
``data/training.db`` - which holds the instructor's admin account - is never
opened, and is fingerprinted at the end to prove it.
"""

import hashlib
import http.client
import json
import os
import sqlite3
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import admin_stats  # noqa: E402
import answer_grader  # noqa: E402
import auth  # noqa: E402
import labdb  # noqa: E402
import reveal_policy  # noqa: E402
import serve_training  # noqa: E402
import student_progress  # noqa: E402

TRAINING = os.path.join(ROOT, "training")
REAL_DB = os.path.join(ROOT, "data", "training.db")
STUDENT_A = "student.a"
STUDENT_B = "student.b"
PWD_A = "Student-A-pass-1a2b3c"
PWD_B = "Student-B-pass-4d5e6f"
ADMIN_PWD = "Instructor-Pass-4d7b2e"
S1 = "scenario-1"
# The verified-correct Scenario 01 answers, straight from the existing tests.
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


def _fingerprint(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


def _rows(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cookie = None

    def _do(self, method, path, body=None, headers=None, send_cookie=True):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=25)
        try:
            h = dict(headers or {})
            if send_cookie and self.cookie and "Cookie" not in h:
                h["Cookie"] = self.cookie
            payload = body if isinstance(body, (bytes, str)) else (
                json.dumps(body) if body is not None else None
            )
            conn.request(method, path, body=payload, headers=h)
            r = conn.getresponse()
            raw = r.read()
            out = dict(r.getheaders())
            setc = out.get("Set-Cookie")
            if setc:
                self.cookie = None if "Max-Age=0" in setc else setc.split(";")[0]
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                parsed = {"_text": raw[:200].decode("utf-8", "replace")}
            return r.status, parsed, out
        finally:
            conn.close()

    def get(self, path, **kw):
        return self._do("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self._do("POST", path, body=body, **kw)

    def sign_in(self, username, password):
        return self.post("/api/auth/login",
                         {"username": username, "password": password})


def make_server(db_path):
    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    server = serve_training.LabServer(("127.0.0.1", 0), handler)
    server.db_path = db_path
    server.force_secure_cookies = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, ("127.0.0.1", server.server_address[1])


@pytest.fixture()
def env(tmp_path):
    """A live server, two students, one admin, on a throwaway database."""
    db_path = str(tmp_path / "progress.db")
    labdb.init_db(db_path)
    auth.register_user(STUDENT_A, PWD_A, path=db_path)
    auth.register_user(STUDENT_B, PWD_B, path=db_path)
    import create_admin
    create_admin.create_admin("instructor", ADMIN_PWD, path=db_path)
    reveal_policy.reset()
    server, thread, addr = make_server(db_path)
    try:
        yield addr, db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        labdb.close_connection(db_path)
        labdb.reset_connections()
        reveal_policy.reset()


@pytest.fixture()
def a_student(env):
    addr, _db = env
    c = Client(*addr)
    c.sign_in(STUDENT_A, PWD_A)
    return c


@pytest.fixture()
def b_student(env):
    addr, _db = env
    c = Client(*addr)
    c.sign_in(STUDENT_B, PWD_B)
    return c


@pytest.fixture()
def an_admin(env):
    addr, _db = env
    c = Client(*addr)
    c.sign_in("instructor", ADMIN_PWD)
    return c


def user_id(db_path, username):
    return labdb.get_user_by_username(username, path=db_path)["id"]


# ================================================== 1-2. who records a start

def test_anonymous_scenario_visit_records_nothing(env):
    addr, db_path = env
    anon = Client(*addr)
    # The scenario page itself is gated, and the start call is refused.
    assert anon.get("/scenarios/scenario-1-brute-force.html")[0] == 302
    status, _b, _h = anon.post("/api/student/progress/start", {"scenario": S1})
    assert status == 401
    assert _rows(db_path, "SELECT * FROM student_progress") == []


def test_authenticated_visit_records_a_start(a_student, env):
    _addr, db_path = env
    status, body, _h = a_student.post("/api/student/progress/start", {"scenario": S1})
    assert status == 200
    assert body["started"] is True
    rows = _rows(db_path, "SELECT * FROM student_progress")
    assert len(rows) == 1
    assert rows[0]["scenario_id"] == S1
    assert rows[0]["user_id"] == user_id(db_path, STUDENT_A)
    assert rows[0]["started_at"]
    # Opening is not completing.
    assert rows[0]["completed"] == 0
    assert rows[0]["completed_at"] is None


def test_opening_a_scenario_twice_does_not_move_started_at(a_student, env):
    _addr, db_path = env
    a_student.post("/api/student/progress/start", {"scenario": S1})
    first = _rows(db_path, "SELECT started_at FROM student_progress")[0]["started_at"]
    a_student.post("/api/student/progress/start", {"scenario": S1})
    rows = _rows(db_path, "SELECT started_at FROM student_progress")
    assert len(rows) == 1, "the unique constraint should prevent a second row"
    assert rows[0]["started_at"] == first, "started_at must be the first arrival"


def test_an_unknown_scenario_is_refused(a_student, env):
    _addr, db_path = env
    for bad in ("scenario-99", "", "../../etc", "SCENARIO-1"):
        assert a_student.post("/api/student/progress/start", {"scenario": bad})[0] == 400, bad
    assert _rows(db_path, "SELECT * FROM student_progress") == []


# ============================================ 3-5. identity cannot be forged

def test_student_a_cannot_read_student_b_progress(a_student, b_student, env):
    _addr, db_path = env
    b_student.post("/api/student/progress/start", {"scenario": S1})
    b_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})

    status, body, _h = a_student.get("/api/student/progress")
    assert status == 200
    serialised = json.dumps(body)
    assert STUDENT_B not in serialised
    assert body["scenarios_started"] == 0, "A must not see B's activity"

    status, detail, _h = a_student.get("/api/student/progress/" + S1)
    assert detail["attempts"] == 0


@pytest.mark.parametrize("attempt", [
    "?user_id=2", "?user_id=1", "?id=2", "?username=student.b",
    "?user=student.b", "?user_id=0",
])
def test_a_user_id_in_the_query_string_is_ignored(a_student, env, attempt):
    _addr, db_path = env
    a_student.post("/api/student/progress/start", {"scenario": S1})
    status, body, _h = a_student.get("/api/student/progress" + attempt)
    assert status == 200
    assert body["scenarios_started"] == 1, "must stay the caller's own data"
    assert STUDENT_B not in json.dumps(body)


@pytest.mark.parametrize("header", ["X-User-Id", "X-User-ID", "X-Role", "X-Admin"])
def test_a_user_id_in_a_header_is_ignored(a_student, env, header):
    _addr, db_path = env
    other = user_id(db_path, STUDENT_B)
    status, body, _h = a_student.get("/api/student/progress", headers={header: str(other)})
    assert status == 200
    assert body["scenarios_started"] == 0


def test_a_student_cannot_submit_progress_for_another_user(a_student, env):
    _addr, db_path = env
    other = user_id(db_path, STUDENT_B)
    for body in ({"scenario": S1, "user_id": other},
                 {"scenario": S1, "userId": other},
                 {"scenario": S1, "id": other}):
        status, _b, _h = a_student.post("/api/student/progress/start", body)
        assert status == 200
    owners = {r["user_id"] for r in _rows(db_path, "SELECT user_id FROM student_progress")}
    assert owners == {user_id(db_path, STUDENT_A)}, "ownership must come from the session"


def test_check_records_progress_for_the_right_student(a_student, b_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    b_student.post("/api/check", {"scenario": "scenario-2", "answers": {"s1e1": "x"}})

    by_user = {r["user_id"]: r for r in _rows(db_path, "SELECT * FROM student_progress")}
    assert set(by_user) == {user_id(db_path, STUDENT_A), user_id(db_path, STUDENT_B)}
    assert by_user[user_id(db_path, STUDENT_A)]["scenario_id"] == S1
    assert by_user[user_id(db_path, STUDENT_B)]["scenario_id"] == "scenario-2"


# =========================================== 6-7. durability

def test_progress_survives_logout_and_login(a_student, env):
    addr, db_path = env
    a_student.post("/api/student/progress/start", {"scenario": S1})
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})

    a_student.post("/api/auth/logout")
    assert a_student.get("/")[0] == 302

    again = Client(*addr)
    again.sign_in(STUDENT_A, PWD_A)
    status, body, _h = again.get("/api/student/progress")
    assert status == 200
    assert body["scenarios_started"] == 1
    assert body["attempts"] == 1


def test_progress_survives_a_server_restart(env):
    addr, db_path = env
    c = Client(*addr)
    c.sign_in(STUDENT_A, PWD_A)
    c.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    before = _rows(db_path, "SELECT * FROM student_progress")

    # A brand new server process over the same file.
    labdb.reset_connections()
    server2, thread2, addr2 = make_server(db_path)
    try:
        c2 = Client(*addr2)
        c2.sign_in(STUDENT_A, PWD_A)
        status, body, _h = c2.get("/api/student/progress")
        assert status == 200
        assert body["attempts"] == 1
        assert _rows(db_path, "SELECT * FROM student_progress") == before
    finally:
        server2.shutdown()
        server2.server_close()
        thread2.join(timeout=10)


# ============================================ 8-9. /api/check integration

def test_check_updates_attempts_and_questions(a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    a_student.post("/api/check", {"scenario": S1,
                                  "answers": {"s1e1": "203.0.113.45", "s1e2": "root 5 and admin 5"}})

    row = _rows(db_path, "SELECT * FROM student_progress")[0]
    assert row["attempts"] == 3, "every submission is an attempt"
    assert row["questions_attempted"] == 2, "re-answering a question must not count twice"
    assert row["correct_answers"] == 1


def test_an_unanswered_question_is_not_an_attempt(a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    # Send an empty box: the grader reports it unanswered, so it must not count.
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45",
                                                              "s1e2": "   "}})
    row = _rows(db_path, "SELECT * FROM student_progress")[0]
    assert row["questions_attempted"] == 1
    assert row["attempts"] == 2


def test_anonymous_check_remains_stateless(env):
    addr, db_path = env
    anon = Client(*addr)
    status, body, _h = anon.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    assert status == 200
    assert body["verdict"] == "complete"
    assert _rows(db_path, "SELECT * FROM student_progress") == [], \
        "an anonymous check must write no progress"


def test_anonymous_check_response_is_unchanged(env):
    addr, _db = env
    _s, body, _h = Client(*addr).post("/api/check",
                                      {"scenario": S1, "answers": CORRECT_S1})
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_the_grader_still_decides_completion(a_student, env):
    _addr, db_path = env
    # Partial answers: graded, recorded, not completed.
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    row = _rows(db_path, "SELECT * FROM student_progress")[0]
    assert row["completed"] == 0
    assert row["completed_at"] is None

    # The full correct set, which is the grader's own completion rule.
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    row = _rows(db_path, "SELECT * FROM student_progress")[0]
    assert row["completed"] == 1
    assert row["completed_at"], "completion must be stamped"
    first_completion = row["completed_at"]


def test_completion_follows_the_grader_exactly(a_student, env):
    """If the grader says not complete, progress must not say complete."""
    _addr, db_path = env
    for answers in ({"s1e1": "x"}, {"s1e1": ""}, {}, {"s1e8": "free text"}):
        _s, body, _h = a_student.post("/api/check", {"scenario": S1, "answers": answers})
        stored = _rows(db_path, "SELECT completed FROM student_progress")[0]["completed"]
        assert stored == (1 if body["completed"] else 0), (answers, body["completed"])


def test_completion_is_stamped_once_and_not_rewritten(a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    first = _rows(db_path, "SELECT completed_at FROM student_progress")[0]["completed_at"]
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    assert _rows(db_path, "SELECT completed_at FROM student_progress")[0]["completed_at"] == first


def test_completion_tracks_the_latest_grader_verdict(a_student, env):
    """Correct is current standing, not a lifetime tally.

    The grader has no memory: it re-derives completion from the answers in
    front of it, every time. So a scenario the student has since broken is
    *currently* incomplete, and progress says so. Making completion sticky
    would be a second, invented definition of "finished" that disagrees with
    the one the scenario pages already use.

    ``completed_at`` is the part that is remembered. It is stamped the first
    time the grader reported completion and never moves, so an instructor can
    still see when a student first finished it.
    """
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    # All nine Scenario 1 questions, including the final finding, are correct.
    assert _rows(db_path, "SELECT correct_answers FROM student_progress")[0]["correct_answers"] == 9
    first_completion = _rows(db_path, "SELECT completed_at FROM student_progress")[0]["completed_at"]
    assert first_completion

    broken = dict(CORRECT_S1)
    broken["s1e1"] = "wrong"
    a_student.post("/api/check", {"scenario": S1, "answers": broken})

    row = _rows(db_path,
                "SELECT correct_answers, completed, completed_at FROM student_progress")[0]
    # One of the nine answers is wrong, so the standing falls by exactly one.
    assert row["correct_answers"] == 8, "standing falls when an answer breaks"
    assert row["completed"] == 0, "the grader no longer says complete, so neither do we"
    assert row["completed_at"] == first_completion, \
        "but the first completion time is remembered, not erased"


# ============================================ 11-12. reveal / no answers

def test_a_reveal_does_not_erase_a_recorded_verdict(a_student, env):
    """A reveal knows a question was looked up, not how it was last graded.

    Regression: marking assistance used to write a NULL last_status over the
    recorded verdict. The roll-up still looked right immediately after,
    because only the assisted counter is refreshed there - but the next check
    recomputes the roll-up from the per-question rows and the correct answer
    silently stopped counting.
    """
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    assert _rows(db_path,
                 "SELECT last_status FROM student_progress_questions "
                 "WHERE question_id = 's1e1'")[0]["last_status"] == "correct"

    assert a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})[0] == 200
    assert _rows(db_path,
                 "SELECT last_status, assisted FROM student_progress_questions "
                 "WHERE question_id = 's1e1'")[0] == {"last_status": "correct",
                                                    "assisted": 1}

    # And the verdict still counts after a later check recomputes the roll-up.
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    row = _rows(db_path, "SELECT correct_answers, assisted_answers FROM student_progress")[0]
    assert row["correct_answers"] == 9, "the verdict must survive the reveal"
    assert row["assisted_answers"] == 1


def test_assisted_is_recorded_when_a_reveal_is_granted(a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    # The policy requires an attempt, which the check above provided.
    status, body, _h = a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})
    assert status == 200
    row = _rows(db_path, "SELECT assisted_answers FROM student_progress")[0]
    assert row["assisted_answers"] == 1
    questions = _rows(db_path, "SELECT * FROM student_progress_questions")
    assisted = [q for q in questions if q["assisted"] == 1]
    assert len(assisted) == 1 and assisted[0]["question_id"] == "s1e1"


def test_assisted_is_a_floor_not_a_total(a_student, env):
    """Answering correctly afterwards must not erase the record of help."""
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    row = _rows(db_path, "SELECT assisted_answers, correct_answers FROM student_progress")[0]
    assert row["assisted_answers"] == 1
    assert row["correct_answers"] == 9


def test_the_reveal_policy_is_unchanged(a_student, env):
    _addr, _db = env
    # No attempt yet: refused.
    assert a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})[0] == 403
    a_student.post("/api/check", {"scenario": S1, "answers": {"s1e1": "203.0.113.45"}})
    # Attempt made: allowed, then throttled.
    assert a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})[0] == 200
    assert a_student.post("/api/reveal", {"scenario": S1, "question": "s1e2"})[0] == 429


def test_an_anonymous_reveal_records_nothing(env):
    addr, db_path = env
    anon = Client(*addr)
    assert anon.post("/api/reveal", {"scenario": S1, "question": "s1e1"})[0] == 401
    assert _rows(db_path, "SELECT * FROM student_progress") == []


def test_no_answer_or_key_material_is_ever_stored(a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})
    labdb.close_connection(db_path)
    labdb.reset_connections()
    with open(db_path, "rb") as handle:
        blob = handle.read()
    for secret in ("203.0.113.45 -> web-01", "svc_backup", "min_failures",
                   "time_window_minutes", "scrypt$", PWD_A):
        assert secret.encode() not in blob, secret
    for table in ("student_progress", "student_progress_questions"):
        for row in _rows(db_path, "SELECT * FROM " + table):
            for value in row.values():
                if isinstance(value, str):
                    assert "203.0.113.45" not in value, table


def test_the_progress_response_never_carries_an_answer(a_student, env):
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    a_student.post("/api/reveal", {"scenario": S1, "question": "s1e1"})
    _s, body, _h = a_student.get("/api/student/progress")
    _s, detail, _h = a_student.get("/api/student/progress/" + S1)
    for payload in (json.dumps(body), json.dumps(detail)):
        for secret in ("203.0.113.45", "min_failures", "accept", "patterns", "scrypt$"):
            assert secret not in payload, secret


# ================================================ 13-14. admin boundaries

def test_admin_apis_still_work_with_progress_present(an_admin, a_student, env):
    _addr, db_path = env
    a_student.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    for endpoint in ("/api/admin/summary", "/api/admin/students", "/api/admin/scenarios"):
        assert an_admin.get(endpoint)[0] == 200, endpoint

    _s, summary, _h = an_admin.get("/api/admin/summary")
    assert summary["total_students"] == 2
    assert summary["scenarios_started"] == 1
    assert summary["scenarios_completed"] == 1
    assert summary["attempts"] == 1
    assert summary["correct_answers"] == 9

    _s, students, _h = an_admin.get("/api/admin/students")
    names = {r["username"] for r in students["students"]}
    assert names == {STUDENT_A, STUDENT_B}
    a_row = next(r for r in students["students"] if r["username"] == STUDENT_A)
    assert a_row["scenarios_completed"] == 1
    assert a_row["attempts"] == 1


def test_an_admin_cannot_read_a_students_own_progress_endpoint(an_admin, env):
    """Instructors get the aggregate view, not the student endpoint."""
    assert an_admin.get("/api/student/progress")[0] == 403
    assert an_admin.get("/api/student/progress/" + S1)[0] == 403
    assert an_admin.post("/api/student/progress/start", {"scenario": S1})[0] == 403


def test_an_admin_does_not_accumulate_student_progress(an_admin, env):
    _addr, db_path = env
    an_admin.post("/api/check", {"scenario": S1, "answers": CORRECT_S1})
    owners = {r["user_id"] for r in _rows(db_path, "SELECT user_id FROM student_progress")}
    admin_id = user_id(db_path, "instructor")
    assert admin_id not in owners, "an instructor must not pollute the class statistics"


def test_a_student_still_cannot_reach_admin_apis(a_student, env):
    for endpoint in ("/api/admin/summary", "/api/admin/students", "/api/admin/scenarios"):
        assert a_student.get(endpoint)[0] == 403, endpoint
    assert a_student.get("/admin.html")[0] == 403


def test_the_admin_api_is_still_read_only(an_admin, env):
    _addr, db_path = env
    before = _rows(db_path, "SELECT * FROM student_progress")
    for endpoint in ("/api/admin/students", "/api/admin/summary"):
        assert an_admin.post(endpoint, {"username": STUDENT_A, "role": "admin"})[0] == 404
    assert _rows(db_path, "SELECT * FROM student_progress") == before


# ============================================= 15-17. nothing else broke

def test_the_student_portal_and_grading_are_unchanged(a_student, env):
    for path in ("/", "/index.html", "/instructions.html",
                 "/scenarios/scenario-1-brute-force.html"):
        assert a_student.get(path)[0] == 200, path
    status, body, _h = a_student.post("/api/check",
                                      {"scenario": S1, "answers": CORRECT_S1})
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_the_student_progress_page_is_public_to_be_styled(env):
    """The home page must not 404 on a fresh install that has no progress rows."""
    addr, _db = env
    c = Client(*addr)
    c.sign_in(STUDENT_A, PWD_A)
    _s, body, _h = c.get("/api/student/progress")
    assert len(body["scenarios"]) == len(labdb.SCENARIO_IDS)
    assert all(s["state"] == "not_started" for s in body["scenarios"])


def test_registration_is_still_student_only(env):
    addr, db_path = env
    c = Client(*addr)
    status, body, _h = c.post("/api/auth/register",
                              {"username": "newbie", "password": "Newbie-pass-9z8y7x",
                               "role": "admin"})
    assert status == 201
    assert body["user"]["role"] == "student"


# ==================================================== schema and migration

def test_the_schema_is_idempotent_and_versioned(tmp_path):
    path = str(tmp_path / "v.db")
    labdb.init_db(path)
    labdb.init_db(path)
    labdb.init_db(path)
    assert labdb.get_schema_version(path) == labdb.SCHEMA_VERSION >= 2
    tables = {r["name"] for r in _rows(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"student_progress", "student_progress_questions"} <= tables


def test_progress_cascades_when_a_student_is_deleted(tmp_path):
    path = str(tmp_path / "cascade.db")
    labdb.init_db(path)
    user = auth.register_user("doomed", "Doomed-pass-1a2b3c", path=path)
    student_progress.record_start(user["id"], S1, path=path)
    assert _rows(path, "SELECT * FROM student_progress")

    labdb.close_connection(path)
    labdb.reset_connections()
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    conn.close()
    assert _rows(path, "SELECT * FROM student_progress") == [], "ON DELETE CASCADE"
    assert _rows(path, "SELECT * FROM student_progress_questions") == []


def test_progress_holds_no_secret_columns():
    """Structural: the progress tables cannot hold a hash or a token."""
    import ast
    source = open(os.path.join(ROOT, "scripts", "student_progress.py"),
                  encoding="utf-8").read()
    statements = [
        n.args[0].value
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"
        and n.args and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
    ]
    assert statements
    for statement in statements:
        upper = statement.upper()
        for forbidden in ("PASSWORD", "TOKEN", "ANSWER_TEXT", "SOLUTION", "SECRET"):
            assert forbidden not in upper, (forbidden, statement[:70])


def test_the_real_database_is_untouched(tmp_path):
    before = _fingerprint(REAL_DB)
    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        user = auth.register_user("probe", "Probe-pass-1a2b3c", path=path)
        student_progress.record_start(user["id"], S1, path=path)
        result = answer_grader.grade(S1, {"s1e1": "203.0.113.45"})
        student_progress.record_check(user["id"], S1, result, path=path)
        student_progress.mark_assisted(user["id"], S1, "s1e1", path=path)
        student_progress.student_summary(user["id"], path=path)
        admin_stats.summary(path=path)
        labdb.close_connection(path)
        labdb.reset_connections()
    finally:
        pass
    assert _fingerprint(REAL_DB) == before
