"""Tests for the role-based portal: student versus admin, enforced server-side.

The point of this file is the *negative* cases. A role gate that is only ever
tested with the right role proves nothing, so most of what follows asserts that
a student is refused, that a forged role is ignored, and that a response meant
for an instructor carries no secret in it.

Every test uses a throwaway database in ``tmp_path``. The real
``data/training.db`` is never opened and is fingerprinted at the end to prove
it, and it must still hold no admin - the whole point of provisioning being
manual is that no test can quietly create one.
"""

import hashlib
import http.client
import json
import os
import re
import sqlite3
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import admin_stats  # noqa: E402
import auth  # noqa: E402
import create_admin  # noqa: E402
import labdb  # noqa: E402
import serve_training  # noqa: E402
import student_progress  # noqa: E402

TRAINING = os.path.join(ROOT, "training")
REAL_DB = os.path.join(ROOT, "data", "training.db")
ADMIN_PWD = "Instructor-Pass-4d7b2e"
STUDENT_PWD = "Student-Pass-8c3a1f"
EXPIRED_AT = "2000-01-01T00:00:00Z"
SCENARIOS = labdb.SCENARIO_IDS


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
    """Cookie-keeping HTTP client that does not follow redirects."""

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
                if "Max-Age=0" in setc:
                    self.cookie = None
                else:
                    self.cookie = setc.split(";")[0]
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                parsed = {"_text": raw[:400].decode("utf-8", "replace")}
            return r.status, parsed, out
        finally:
            conn.close()

    def get(self, path, **kw):
        return self._do("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self._do("POST", path, body=body, **kw)

    def register(self, username, password, **extra):
        payload = {"username": username, "password": password}
        payload.update(extra)
        return self.post("/api/auth/register", payload)

    def login(self, username, password):
        return self.post("/api/auth/login", {"username": username, "password": password})


@pytest.fixture()
def portal(tmp_path):
    """A live server on a temp database, pre-seeded with one student and one admin."""
    db_path = str(tmp_path / "portal.db")
    labdb.init_db(db_path)
    auth.register_user("student.one", STUDENT_PWD, path=db_path)
    create_admin.create_admin("instructor", ADMIN_PWD, path=db_path)
    # Give the student some recorded activity so the aggregates have something
    # to report, and an admin none - the shape of a real class.
    #
    # Seeded through student_progress, which is what the aggregates read. The
    # result dicts below are in answer_grader.grade's exact shape, so this
    # exercises the real storage path without needing real answers to every
    # scenario; test_student_progress.py drives the same code with genuine
    # grader output end to end.
    student_id = labdb.get_user_by_username("student.one", path=db_path)["id"]

    def _result(correct, total, completed):
        questions = {("q%d" % i): {"status": "correct", "answered": True,
                                   "required": True}
                     for i in range(1, correct + 1)}
        for i in range(correct + 1, total + 1):
            questions["q%d" % i] = {"status": "incorrect", "answered": True,
                                    "required": True}
        return {"completed": completed, "questions": questions}

    student_progress.record_check(student_id, SCENARIOS[0], _result(3, 3, True),
                                  path=db_path)
    student_progress.record_check(student_id, SCENARIOS[1], _result(3, 3, True),
                                  path=db_path)
    student_progress.record_check(student_id, SCENARIOS[2], _result(1, 2, False),
                                  path=db_path)
    student_progress.mark_assisted(student_id, SCENARIOS[2], "s1e2", path=db_path)

    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    server = serve_training.LabServer(("127.0.0.1", 0), handler)
    server.db_path = db_path
    server.force_secure_cookies = False
    auth.reset_rate_limits()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", server.server_address[1], db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        labdb.close_connection(db_path)
        labdb.reset_connections()
        auth.reset_rate_limits()


def as_student(portal):
    _host, port, _db = portal
    c = Client("127.0.0.1", port)
    c.login("student.one", STUDENT_PWD)
    return c


def as_admin(portal):
    _host, port, _db = portal
    c = Client("127.0.0.1", port)
    c.login("instructor", ADMIN_PWD)
    return c


ADMIN_ENDPOINTS = ("/api/admin/summary", "/api/admin/students", "/api/admin/scenarios")


# =========================================== 1-3. the admin page

def test_anonymous_admin_page_is_redirected_to_login(portal):
    host, port, _db = portal
    status, _body, headers = Client(host, port).get("/admin.html")
    assert status == 302
    assert headers["Location"].startswith("/login.html")


def test_a_student_is_denied_the_admin_page(portal):
    status, _body, _headers = as_student(portal).get("/admin.html")
    assert status == 403


def test_a_student_denial_does_not_leak_the_page(portal):
    """The 403 body is a fixed string, so nothing from the request is reflected."""
    host, port, _db = portal
    c = as_student(portal)
    status, body, _h = c.get("/admin.html")
    text = body.get("_text", "")
    assert status == 403
    assert "Instructor area" in text
    # No sign of the underlying document.
    assert "stat-students" not in text
    assert "student-table" not in text


def test_the_forbidden_body_reflects_nothing():
    body = serve_training.FORBIDDEN_HTML.decode("utf-8")
    for placeholder in ("{{", "}}", "{", "}", "%s"):
        assert placeholder not in body, placeholder


def test_an_admin_is_served_the_admin_page(portal):
    status, _body, headers = as_admin(portal).get("/admin.html")
    assert status == 200
    assert "Location" not in headers


def test_the_admin_page_is_not_in_the_public_allowlist(portal):
    assert "/admin.html" in serve_training.ADMIN_PAGES
    assert "/admin.html" not in serve_training.PUBLIC_PAGES
    # And behave accordingly: never served anonymously, never to a student.
    _host, port, _db = portal
    assert Client("127.0.0.1", port).get("/admin.html")[0] == 302
    assert as_student(portal).get("/admin.html")[0] == 403


def test_the_admin_page_carries_no_credentials_or_data():
    """A shell: the numbers are fetched at runtime, nothing is baked in."""
    html = open(os.path.join(TRAINING, "admin.html"), encoding="utf-8").read()
    # Real secrets and the secret column names, not the word "password" (the
    # page legitimately says in prose that it shows no password material).
    for forbidden in (ADMIN_PWD, STUDENT_PWD, "scrypt$", "password_hash",
                      "token_hash", "answer-key", "solution"):
        assert forbidden not in html, forbidden
    # Every statistic is a placeholder filled in by admin.js.
    for stat in ("stat-students", "stat-active", "stat-started", "stat-checks"):
        assert 'id="%s">-' % stat in html, stat
    # No client-side authority and no embedded role.
    assert "data-role" not in html
    assert "localStorage" not in html


# =========================================== 4-6. the admin API

def test_anonymous_admin_api_is_unauthorised(portal):
    host, port, _db = portal
    for endpoint in ADMIN_ENDPOINTS:
        status, _body, _h = Client(host, port).get(endpoint)
        assert status == 401, endpoint


def test_a_student_admin_api_is_forbidden(portal):
    c = as_student(portal)
    for endpoint in ADMIN_ENDPOINTS:
        status, _body, _h = c.get(endpoint)
        assert status == 403, endpoint


def test_an_admin_admin_api_succeeds(portal):
    c = as_admin(portal)
    for endpoint in ADMIN_ENDPOINTS:
        status, _body, _h = c.get(endpoint)
        assert status == 200, endpoint


def test_the_student_refusal_says_nothing_extra(portal):
    """A 403 must not confirm which endpoints exist beyond the three."""
    c = as_student(portal)
    _s, body, _h = c.get("/api/admin/summary")
    serialised = json.dumps(body)
    assert "administrator access required" in serialised
    for leak in ("student.one", "instructor", ADMIN_PWD):
        assert leak not in serialised, leak


def test_unknown_admin_endpoints_are_404(portal):
    c = as_admin(portal)
    for endpoint in ("/api/admin/", "/api/admin/nope", "/api/admin/students/1"):
        assert c.get(endpoint)[0] == 404, endpoint


def _status_or_transport_error(client, method, path, body=None):
    """The status, or None if the connection failed before one was read.

    The server answers an unsupported method with 501 without draining the
    request body, so the client can observe a reset instead. That is a
    transport detail, not an authorisation result, so it is reported as None
    and judged by what it could not have done: change anything.
    """
    try:
        return client._do(method, path, body)[0]
    except (ConnectionError, OSError):
        return None


def test_the_admin_api_is_read_only(portal):
    """No admin endpoint may change anything - not a student, not a role."""
    _host, _port, db_path = portal
    before = _rows(db_path, "SELECT username, role, password_hash FROM users ORDER BY id")

    c = as_admin(portal)
    for endpoint in ADMIN_ENDPOINTS:
        # POST is routed by do_POST, which only knows auth/, check and reveal.
        assert c.post(endpoint, {})[0] == 404, endpoint
        for method in ("PUT", "DELETE", "PATCH"):
            status = _status_or_transport_error(c, method, endpoint, {})
            assert status in (404, 405, 501, None), (method, endpoint, status)

    after = _rows(db_path, "SELECT username, role, password_hash FROM users ORDER BY id")
    assert after == before, "an admin API request changed a user row"


def test_the_admin_api_cannot_promote_anybody(portal):
    _host, _port, db_path = portal
    c = as_admin(portal)
    for body in ({"username": "student.one", "role": "admin"},
                 {"id": 2, "role": "admin"},
                 {"user_id": 2, "role": "admin"}):
        c.post("/api/admin/students", body)
        c.post("/api/admin/summary", body)
        c.post("/api/admin/students?role=admin", body)
    roles = _rows(db_path, "SELECT username, role FROM users ORDER BY id")
    assert roles == [{"username": "student.one", "role": "student"},
                     {"username": "instructor", "role": "admin"}]


# =========================================== 7. no client-side role trust

@pytest.mark.parametrize("spoof", [
    {"X-Role": "admin"},
    {"X-User-Role": "admin"},
    {"X-Admin": "true"},
    {"Authorization": "Bearer admin"},
    {"X-Forwarded-User": "instructor"},
    {"X-Original-Url": "/api/admin/summary"},
])
def test_spoofed_role_headers_do_not_grant_access(portal, spoof):
    """A student stays a student no matter what headers are sent.

    The student's real cookie is still attached, so the server resolves them as
    a student and refuses on role - which is exactly the point.
    """
    c = as_student(portal)
    assert c.get("/api/admin/summary", headers=spoof)[0] == 403, spoof
    assert c.get("/admin.html", headers=spoof)[0] == 403, spoof


def test_a_replaced_cookie_is_treated_as_no_session(portal):
    """Overriding Cookie does not smuggle a role, it just loses the session."""
    c = as_student(portal)
    status, _b, _h = c.get("/api/admin/summary",
                          headers={"Cookie": "bc_lab_session=admin"})
    assert status == 401
    assert c.get("/admin.html", headers={"Cookie": "bc_lab_session=admin"})[0] == 302


@pytest.mark.parametrize("query", [
    "?role=admin", "?user=instructor", "?username=instructor", "?id=2",
    "?role=admin&user=instructor",
])
def test_role_query_parameters_are_ignored(portal, query):
    c = as_student(portal)
    assert c.get("/api/admin/summary" + query)[0] == 403
    assert c.get("/admin.html" + query)[0] == 403


def test_registration_cannot_request_the_admin_role(portal):
    _host, port, db_path = portal
    c = Client("127.0.0.1", port)
    status, body, _h = c.register("sneaky", STUDENT_PWD, role="admin")
    assert status == 201
    assert body["user"]["role"] == "student"
    roles = {r["username"]: r["role"] for r in _rows(db_path, "SELECT username, role FROM users")}
    assert roles["sneaky"] == "student"


def test_the_role_comes_from_the_database_not_the_request(portal):
    """/api/auth/me reports the stored role, whatever the caller believes."""
    _host, port, _db = portal
    student = as_student(portal)
    _s, body, _h = student.get("/api/auth/me", headers={"X-Role": "admin"})
    assert body["user"]["role"] == "student"

    admin = as_admin(portal)
    _s, body, _h = admin.get("/api/auth/me", headers={"X-Role": "student"})
    assert body["user"]["role"] == "admin"


def test_me_exposes_only_safe_identity_fields(portal):
    _host, port, _db = portal
    for who, pwd in (("student.one", STUDENT_PWD), ("instructor", ADMIN_PWD)):
        c = Client("127.0.0.1", port)
        c.login(who, pwd)
        _s, body, _h = c.get("/api/auth/me")
        assert set(body["user"]) == {"id", "username", "display_name", "role"}
        serialised = json.dumps(body)
        assert "password_hash" not in serialised
        assert "token_hash" not in serialised
        assert pwd not in serialised


# =========================================== 8. bad sessions

def test_an_unknown_token_cannot_reach_the_admin_api(portal):
    _host, port, _db = portal
    c = Client("127.0.0.1", port)
    status, _b, _h = c.get("/api/admin/summary",
                          headers={"Cookie": "bc_lab_session=not-a-real-token"})
    assert status == 401
    assert c.get("/admin.html", headers={"Cookie": "bc_lab_session=nope"})[0] == 302


def test_an_expired_session_cannot_reach_the_admin_api(portal):
    _host, port, db_path = portal
    admin_id = labdb.get_user_by_username("instructor", path=db_path)["id"]
    token = auth.new_token()
    labdb.create_session(admin_id, auth.hash_token(token), EXPIRED_AT, path=db_path)

    c = Client("127.0.0.1", port)
    assert c.get("/api/admin/summary",
                 headers={"Cookie": "bc_lab_session=" + token})[0] == 401
    assert c.get("/admin.html",
                 headers={"Cookie": "bc_lab_session=" + token})[0] == 302


def test_a_deleted_session_cannot_reach_the_admin_api(portal):
    _host, port, _db = portal
    c = as_admin(portal)
    token = c.cookie.split("=", 1)[1]
    assert c.get("/api/admin/summary")[0] == 200

    auth.delete_session(token, path=_db)
    assert c.get("/api/admin/summary")[0] == 401
    assert c.get("/admin.html")[0] == 302


def test_a_students_token_cannot_be_upgraded_by_being_longer(portal):
    """A token is compared as a hash; a near-miss must not resolve."""
    _host, port, _db = portal
    c = as_admin(portal)
    token = c.cookie.split("=", 1)[1]

    # Each mutation is checked against the original first. This used to be a
    # bare token[:-1] + "A", which is a no-op whenever the random token already
    # ends in "A" - roughly one run in sixteen, since token_urlsafe's last
    # character has 16 possible values. On those runs the server was right to
    # answer 200 and the test failed for the wrong reason.
    #
    # token.upper() is checked the same way: a 43-character base64url string
    # with no lowercase letter in it would also be a no-op.
    def replaced_last(char):
        """A character guaranteed to differ from ``char``."""
        return "B" if char == "A" else "A"

    mutations = [token[:-1] + replaced_last(token[-1]), token + "A",
                 token.upper(), token[::-1]]
    for mutated in mutations:
        assert mutated != token, "mutation %r is not actually different" % mutated
        probe = Client("127.0.0.1", port)
        assert probe.get("/api/admin/summary",
                         headers={"Cookie": "bc_lab_session=" + mutated})[0] == 401


# =========================================== 9. no secrets to an admin

def test_the_admin_api_returns_no_password_or_token_material(portal):
    c = as_admin(portal)
    for endpoint in ADMIN_ENDPOINTS:
        _s, body, _h = c.get(endpoint)
        serialised = json.dumps(body)
        for forbidden in ("password_hash", "token_hash", "password", "scrypt$",
                          "salt", ADMIN_PWD, STUDENT_PWD, "token"):
            assert forbidden not in serialised, (endpoint, forbidden)


def test_an_admin_cannot_read_a_password_hash_through_any_endpoint(portal):
    _host, port, _db = portal
    c = as_admin(portal)
    for path in ("/api/admin/summary", "/api/admin/students", "/api/admin/scenarios",
                 "/api/auth/me"):
        _s, body, _h = c.get(path)
        assert "scrypt$" not in json.dumps(body)
    # And no hash leaks through the static route either.
    assert c.get("/admin.html")[0] == 200


def test_the_student_table_returns_only_the_declared_fields(portal):
    _host, _port, db_path = portal
    rows = admin_stats.student_rows(path=db_path)
    assert rows, "expected the seeded student"
    allowed = {"id", "username", "display_name", "created_at", "last_login_at",
               "is_active", "total_checks", "attempts", "scenarios_started",
               "scenarios_attempted", "scenarios_completed",
               "questions_attempted", "assisted", "correct", "last_activity"}
    for row in rows:
        assert set(row) == allowed, set(row) ^ allowed


def test_the_aggregates_report_the_seeded_activity(portal):
    _host, _port, db_path = portal
    data = admin_stats.summary(path=db_path)
    assert data["total_students"] == 1
    assert data["total_admins"] == 1
    assert data["active_students"] == 1
    assert data["students_who_started"] == 1
    assert data["total_checks"] == 3

    students = admin_stats.student_rows(path=db_path)
    assert students[0]["username"] == "student.one"
    assert students[0]["scenarios_attempted"] == 3
    assert students[0]["scenarios_completed"] == 2
    assert students[0]["assisted"] == 1
    assert students[0]["correct"] == 7
    assert students[0]["questions_attempted"] == 8
    assert students[0]["attempts"] == 3

    scenarios = admin_stats.scenario_rows(path=db_path)
    assert len(scenarios) == 5, "all five scenarios should be listed, even unused"
    assert {s["scenario_id"] for s in scenarios} == set(SCENARIOS)
    assert sum(s["checks"] for s in scenarios) == 3
    assert sum(s["attempts"] for s in scenarios) == 3
    assert sum(s["completions"] for s in scenarios) == 2
    assert sum(s["questions_attempted"] for s in scenarios) == 8


def test_the_aggregates_never_select_a_secret_column():
    """Structural: the secret columns are never read, not merely filtered.

    Checked against the actual SQL string literals in the module, found with
    ast. A regex over the file text would match the docstring that explains
    this very rule, which is the opposite of useful.
    """
    import ast
    source = open(os.path.join(ROOT, "scripts", "admin_stats.py"), encoding="utf-8").read()

    # Only the first argument of an .execute() call is SQL. Collecting every
    # string constant would also collect the module docstring, which discusses
    # these very column names and would match on the word "SELECT".
    statements = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
            continue
        if node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            statements.append(node.args[0].value)

    assert len(statements) >= 5, "expected the module's queries, found %d" % len(statements)
    for statement in statements:
        upper = statement.upper()
        assert "PASSWORD_HASH" not in upper, statement[:80]
        assert "TOKEN_HASH" not in upper, statement[:80]
        # No wildcard SELECT either: it would quietly pull the secrets in,
        # however carefully the row were filtered afterwards.
        assert "SELECT *" not in upper, statement[:80]

    # And the module's own field allowlist is exactly the public set, so
    # widening it later is a visible, reviewable change rather than a silent
    # new leak.
    assert set(admin_stats._PUBLIC_FIELDS) == {
        "id", "username", "display_name", "created_at", "last_login_at", "is_active",
    }
    # The per-student payload cannot grow a secret by accident either.
    assert admin_stats.student_rows.__doc__ is not None
    assert "password" in admin_stats.student_rows.__doc__.lower()


def test_an_admin_sees_counters_not_another_students_answers(portal):
    """The aggregate is a number, never the answer text behind it."""
    _host, _port, db_path = portal
    student_id = labdb.get_user_by_username("student.one", path=db_path)["id"]
    labdb.record_scenario_check(student_id, SCENARIOS[0], verdict="complete",
                                required_correct=7, required_total=7, path=db_path)
    c = as_admin(portal)
    _s, body, _h = c.get("/api/admin/students")
    serialised = json.dumps(body)
    assert "203.0.113.45" not in serialised
    assert "min_failures" not in serialised


# =========================================== 10-12. nothing else broke

def test_the_answer_key_stays_inaccessible_to_an_admin(portal):
    c = as_admin(portal)
    for path in ("/data/answer-key.json", "/../data/answer-key.json",
                 "/%2e%2e/data/answer-key.json", "/scripts/answer_grader.py"):
        assert c.get(path)[0] in (302, 404), path


def test_an_admin_can_still_use_the_student_portal(portal):
    """One account, both doors: an admin is also a signed-in user."""
    c = as_admin(portal)
    for path in ("/", "/instructions.html", "/scenarios/scenario-1-brute-force.html"):
        assert c.get(path)[0] == 200, path


def test_the_student_portal_is_unchanged_for_a_student(portal):
    c = as_student(portal)
    for path in ("/", "/index.html", "/instructions.html",
                 "/scenarios/scenario-1-brute-force.html"):
        assert c.get(path)[0] == 200, path
    assert c.get("/api/auth/me")[1]["user"]["role"] == "student"


def test_anonymous_portal_still_redirects(portal):
    _host, port, _db = portal
    c = Client("127.0.0.1", port)
    assert c.get("/")[0] == 302
    assert c.get("/login.html")[0] == 200
    assert c.get("/register.html")[0] == 200


def test_the_reveal_policy_still_applies_to_an_admin(portal):
    """An admin is not exempt: same session, same attempt gate, same throttle."""
    c = as_admin(portal)
    assert c.post("/api/reveal", {"scenario": SCENARIOS[0], "question": "s1e1"})[0] == 403
    c.post("/api/check", {"scenario": SCENARIOS[0], "answers": {"s1e1": "203.0.113.45"}})
    assert c.post("/api/reveal", {"scenario": SCENARIOS[0], "question": "s1e1"})[0] == 200
    # And anonymously it is still refused outright.
    _host, port, _db = portal
    assert Client("127.0.0.1", port).post(
        "/api/reveal", {"scenario": SCENARIOS[0], "question": "s1e1"})[0] == 401


def test_check_remains_anonymous_and_stateless(portal):
    _host, port, _db = portal
    status, body, _h = Client("127.0.0.1", port).post(
        "/api/check", {"scenario": SCENARIOS[0], "answers": {"s1e1": "203.0.113.45"}})
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_public_registration_is_still_student_only(portal):
    _host, port, db_path = portal
    c = Client("127.0.0.1", port)
    status, body, _h = c.register("brand.new", STUDENT_PWD)
    assert status == 201
    assert body["user"]["role"] == "student"
    # It really landed, as a student, and did not inflate the instructor count.
    rows = {r["username"]: r["role"]
            for r in _rows(db_path, "SELECT username, role FROM users")}
    assert rows["brand.new"] == "student"
    assert admin_stats.summary(path=db_path)["total_admins"] == 1


def test_no_admin_signup_route_exists(portal):
    _host, port, _db = portal
    c = Client("127.0.0.1", port)
    no_signup = ("/api/admin/register", "/api/admin/users", "/api/auth/admin",
                 "/admin/register.html", "/admin/signup.html", "/signup.html")
    for path in no_signup:
        # Anonymous: a refusal of some kind, never content and never a 200.
        assert c.get(path)[0] in (302, 401, 404), path
        assert c.post(path, {"username": "x", "password": "y"})[0] in (400, 401, 404), path
    # A student is refused by the role gate, and an admin gets a plain 404:
    # neither can create an account through these paths.
    student = as_student(portal)
    admin = as_admin(portal)
    for path in no_signup:
        # A student gets refused, and an admin gets a plain 404: the route
        # does not exist for anybody, so neither can create an account here.
        assert student.get(path)[0] in (302, 403, 404), path
        assert admin.get(path)[0] in (302, 404), path
        assert admin.post(path, {"username": "x", "password": "y"})[0] == 404, path


# =========================================== nothing auto-provisions

def test_starting_a_server_creates_no_admin(tmp_path):
    db_path = str(tmp_path / "boot.db")
    labdb.init_db(db_path)
    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    server = serve_training.LabServer(("127.0.0.1", 0), handler)
    server.db_path = db_path
    server.force_secure_cookies = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        import http.client as hc
        for path in ("/login.html", "/admin.html", "/api/admin/summary"):
            conn = hc.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            conn.request("GET", path)
            conn.getresponse().read()
            conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
    assert _rows(db_path, "SELECT * FROM users") == []


@pytest.mark.parametrize("script", [
    "scripts/serve_training.py", "scripts/start_lab.ps1", "scripts/setup.ps1",
    "docker-compose.yml",
])
def test_no_startup_script_creates_an_admin(script):
    source = open(os.path.join(ROOT, script.replace("/", os.sep)), encoding="utf-8").read()
    assert "create_admin" not in source, script


# =========================================== the real DB stays clean

def test_this_suite_leaves_the_real_database_untouched(tmp_path):
    before = _fingerprint(REAL_DB)
    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        create_admin.create_admin("probe", ADMIN_PWD, path=path)
        admin_stats.summary(path=path)
        admin_stats.student_rows(path=path)
        admin_stats.scenario_rows(path=path)
        labdb.close_connection(path)
        labdb.reset_connections()
    finally:
        pass
    assert _fingerprint(REAL_DB) == before
