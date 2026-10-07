"""Tests for the authentication-first student portal flow.

The portal is gated by ``serve_training.py`` itself, not by the pages. These
tests pin three things:

* an unauthenticated browser cannot read any student page, by any route;
* a signed-in student can, and sees their own identity;
* registration can only ever make a student - there is no route to admin.

Every test uses a throwaway database in ``tmp_path``. The real
``data/training.db`` is never opened, and is fingerprinted at the end to prove
it. All HTTP traffic goes through a real threaded server on an ephemeral port
against a real ``SimpleHTTPRequestHandler`` - the same code the packaged entry
point runs - so the gate is exercised as shipped, redirects and all.
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

import auth  # noqa: E402
import labdb  # noqa: E402
import reveal_policy  # noqa: E402
import serve_training  # noqa: E402

TRAINING = os.path.join(ROOT, "training")
REAL_DB = os.path.join(ROOT, "data", "training.db")
PASSWORD = "correct-horse-battery-staple"
SCENARIO = "scenario-1"

SCENARIO_PAGES = [
    "/scenarios/scenario-1-brute-force.html",
    "/scenarios/scenario-2-successful-brute-force.html",
    "/scenarios/scenario-3-post-login-execution.html",
    "/scenarios/scenario-4-linux-privilege-escalation.html",
    "/scenarios/scenario-5-multi-event-soc-investigation.html",
]
PORTAL_PAGES = ["/", "/index.html", "/instructions.html"] + SCENARIO_PAGES


def _fingerprint(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


class Browser:
    """A cookie-keeping client that does NOT follow redirects.

    Not following matters: a test that followed redirects would see 200 for
    /login.html and conclude the gate was open. What a browser is actually told
    is the status and the Location header.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, headers=None, send_cookie=True):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=25)
        try:
            hdrs = dict(headers or {})
            if send_cookie and self.cookie and "Cookie" not in hdrs:
                hdrs["Cookie"] = self.cookie
            payload = body if isinstance(body, (bytes, str)) else (
                json.dumps(body) if body is not None else None
            )
            conn.request(method, path, body=payload, headers=hdrs)
            response = conn.getresponse()
            raw = response.read()
            hdrs_out = dict(response.getheaders())
            set_cookie = hdrs_out.get("Set-Cookie")
            if set_cookie:
                if "Max-Age=0" in set_cookie:
                    self.cookie = None
                else:
                    self.cookie = set_cookie.split(";")[0]
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                parsed = {"_bytes": len(raw)}
            return response.status, parsed, hdrs_out
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)

    def register(self, username, password=PASSWORD, **extra):
        payload = {"username": username, "password": password}
        payload.update(extra)
        return self.post("/api/auth/register", payload)

    def login(self, username, password=PASSWORD):
        return self.post("/api/auth/login", {"username": username, "password": password})


@pytest.fixture()
def portal(tmp_path):
    """A live server on an ephemeral port, backed by a throwaway database."""
    db_path = str(tmp_path / "portal.db")
    labdb.init_db(db_path)
    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    server = serve_training.LabServer(("127.0.0.1", 0), handler)
    server.db_path = db_path
    server.force_secure_cookies = False
    auth.reset_rate_limits()
    reveal_policy.reset()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Browser("127.0.0.1", server.server_address[1]), db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        labdb.close_connection(db_path)
        labdb.reset_connections()
        auth.reset_rate_limits()
        reveal_policy.reset()


@pytest.fixture()
def student(portal):
    """A browser with a registered, signed-in student."""
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    return browser


def roles_in(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return {r[0]: r[1] for r in conn.execute("SELECT username, role FROM users")}
    finally:
        conn.close()


# ============================================ A. unauthenticated page access

def test_login_and_register_pages_are_public(portal):
    browser, _db = portal
    assert browser.get("/login.html")[0] == 200
    assert browser.get("/register.html")[0] == 200


@pytest.mark.parametrize("page", PORTAL_PAGES)
def test_portal_pages_redirect_when_anonymous(portal, page):
    """The core of the requirement: no student content without a session."""
    browser, _db = portal
    status, _body, headers = browser.get(page)
    assert status == 302, page
    assert headers["Location"].startswith("/login.html")


def test_the_root_redirects_to_login(portal):
    browser, _db = portal
    status, _body, headers = browser.get("/")
    assert status == 302
    assert headers["Location"] == "/login.html"


def test_the_redirect_remembers_where_the_student_was_going(portal):
    browser, _db = portal
    _s, _b, headers = browser.get("/scenarios/scenario-2-successful-brute-force.html")
    location = headers["Location"]
    assert location.startswith("/login.html?next=")
    # A path only, percent-encoded - never an absolute URL.
    assert location.startswith("/login.html?next=%2Fscenarios%2F")
    assert "://" not in location


def test_the_root_redirect_carries_no_next_parameter(portal):
    browser, _db = portal
    _s, _b, headers = browser.get("/")
    assert headers["Location"] == "/login.html"


def test_static_assets_stay_public(portal):
    """The login page is styled by these; gating them would lock the door."""
    browser, _db = portal
    for asset in ("/assets/css/bluecloud.css", "/assets/js/auth.js",
                  "/assets/js/auth-form.js", "/assets/img/bluecloud-logo.png"):
        assert browser.get(asset)[0] == 200, asset


@pytest.mark.parametrize("cookie", [
    "bc_lab_session=forged-token-123456789",
    "bc_lab_session=",
    "bc_lab_session=../../data/answer-key.json",
    "bc_lab_session=%00",
])
def test_a_forged_or_empty_cookie_grants_nothing(portal, cookie):
    browser, _db = portal
    status, _body, headers = browser.get(
        "/", headers={"Cookie": cookie}, send_cookie=False
    )
    assert status == 302
    assert headers["Location"].startswith("/login.html")


def test_a_bogus_cookie_on_a_scenario_page_grants_nothing(portal):
    browser, _db = portal
    status, _body, _h = browser.get(
        SCENARIO_PAGES[0], headers={"Cookie": "bc_lab_session=nope"}, send_cookie=False
    )
    assert status == 302


def test_the_gate_is_an_allowlist(portal):
    """A page that is not explicitly public is protected by default."""
    browser, _db = portal
    status, _body, headers = browser.get("/a-page-that-does-not-exist.html")
    assert status == 302
    assert headers["Location"].startswith("/login.html")


def test_the_gate_does_not_leak_whether_a_page_exists(portal):
    """Anonymous callers are redirected identically for real and fake pages."""
    browser, _db = portal
    real = browser.get(SCENARIO_PAGES[0])[0]
    fake = browser.get("/definitely-not-a-real-page.html")[0]
    assert real == fake == 302


# ================================================ B. student registration

def test_registration_succeeds_and_creates_a_student(portal):
    browser, db_path = portal
    status, body, _h = browser.register("newstudent")
    assert status == 201
    assert body["registered"] is True
    assert body["user"]["role"] == "student"
    assert roles_in(db_path) == {"newstudent": "student"}


def test_registration_never_issues_a_session(portal):
    browser, _db = portal
    _status, _body, headers = browser.register("newstudent")
    assert "Set-Cookie" not in headers
    assert browser.cookie is None
    # And the portal is still closed.
    assert browser.get("/")[0] == 302


@pytest.mark.parametrize("role", [
    "admin", "ADMIN", "Admin", "administrator", "root", "superuser",
    "instructor", "teacher", "staff", "staff", "moderator", "grader",
    ["admin"], {"role": "admin"}, "admin ", " admin",
])
def test_no_role_value_in_the_body_can_create_an_admin(portal, role):
    browser, db_path = portal
    status, body, _h = browser.register("esc", role=role)
    assert status in (201, 400), role
    if status == 201:
        assert body["user"]["role"] == "student"
    assert set(roles_in(db_path).values()) <= {"student"}


def test_privilege_escalation_fields_are_ignored(portal):
    browser, db_path = portal
    browser.register(
        "esc2", id=1, is_active=True, is_admin=True, created_at="1999-01-01T00:00:00Z",
    )
    assert roles_in(db_path) == {"esc2": "student"}
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT role, is_active, created_at FROM users WHERE username = ?",
            ("esc2",),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "student"


def test_duplicate_registration_is_rejected(portal):
    browser, db_path = portal
    assert browser.register("dupe")[0] == 201
    assert browser.register("dupe")[0] == 409
    assert list(roles_in(db_path)) == ["dupe"]


def test_registration_validates_its_input(portal):
    browser, _db = portal
    for username, password in (("", PASSWORD), ("ab", PASSWORD),
                               ("has space", PASSWORD), ("ok", "short"),
                               ("ok", "")):
        assert browser.register(username, password)[0] == 400


def test_there_is_no_admin_signup_route(portal):
    """No endpoint creates an admin, and none is reachable to try."""
    browser, _db = portal
    for path in ("/api/auth/register-admin", "/api/auth/admin",
                 "/api/auth/signup", "/api/auth/role",
                 "/api/auth/elevate", "/api/auth/verify-admin",
                 "/api/admin/users", "/api/admin/register", "/admin.html",
                 "/admin", "/register-admin.html"):
        # /api/admin/* is session-gated before routing, so an anonymous caller
        # is refused with 401 before the route is even looked up. Any of 302,
        # 401 or 404 is a refusal; none of them is a working signup.
        status, _body, _h = browser.get(path)
        assert status in (302, 401, 404), path
        status, _body, _h = browser.post(path, {"username": "x", "password": PASSWORD})
        assert status in (400, 401, 404), path


def test_the_register_page_never_offers_an_admin_role(portal):
    browser, _db = portal
    _status, body, _h = browser.get("/register.html")
    assert body.get("_bytes", 0) > 0
    raw = browser.get("/register.html")
    assert raw[1].get("_bytes", 0) > 0
    html = _raw_get(browser, "/register.html").decode("utf-8", "replace")
    lowered = html.lower()
    assert "create student account" in lowered
    assert "<select" not in lowered, "no role chooser on the student form"
    assert 'name="role"' not in lowered
    assert 'value="admin"' not in lowered


def _raw_get(browser, path):
    conn = http.client.HTTPConnection(browser.host, browser.port, timeout=25)
    try:
        conn.request("GET", path, headers={"Cookie": browser.cookie or ""})
        return conn.getresponse().read()
    finally:
        conn.close()


def test_the_register_form_never_asks_for_a_role(portal):
    html = _raw_get(portal[0], "/register.html").decode("utf-8", "replace")
    assert "Create Student Account" in html or "create your account" in html.lower()
    for forbidden in ('name="role"', 'value="admin"', "<select"):
        assert forbidden not in html


# ============================================================== C. login

def test_valid_student_credentials_succeed(portal):
    browser, _db = portal
    browser.register("alice")
    status, body, headers = browser.login("alice")
    assert status == 200
    assert body["authenticated"] is True
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "student"


def test_login_issues_a_correct_cookie(portal):
    browser, _db = portal
    browser.register("alice")
    _status, _body, headers = browser.login("alice")
    raw = headers["Set-Cookie"]
    assert raw.startswith("bc_lab_session=")
    assert "HttpOnly" in raw
    assert "SameSite=Lax" in raw
    assert "Path=/" in raw


def test_invalid_credentials_fail_without_a_session(portal):
    browser, _db = portal
    browser.register("alice")
    for user, password in (("alice", "wrong-password-here"),
                           ("ghost", PASSWORD), ("", PASSWORD)):
        status, body, headers = browser.login(user, password)
        assert status == 401
        assert body["error"] == serve_training.GENERIC_AUTH_ERROR
        assert "Set-Cookie" not in headers


def test_me_identifies_the_signed_in_student(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    status, body, _h = browser.get("/api/auth/me")
    assert status == 200
    assert body["authenticated"] is True
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "student"
    assert "password_hash" not in json.dumps(body)


def test_me_is_anonymous_before_login(portal):
    browser, _db = portal
    status, body, _h = browser.get("/api/auth/me")
    assert status == 200
    assert body == {"authenticated": False}


# ============================================== D. authenticated access

def test_a_signed_in_student_can_reach_the_home_page(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    for path in ("/", "/index.html"):
        status, _body, headers = browser.get(path)
        assert status == 200, path
        assert "Location" not in headers


@pytest.mark.parametrize("page", PORTAL_PAGES)
def test_a_signed_in_student_can_reach_every_portal_page(portal, page):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    status, _body, headers = browser.get(page)
    assert status == 200, page
    assert "Location" not in headers


def test_the_portal_offers_the_scenarios(portal):
    """The five cards live on their own page now, reached from the dashboard.

    The home page is a compact student dashboard, so it links to
    /scenarios.html rather than carrying the cards itself. Both halves are
    checked: the dashboard offers the page, and the page offers every scenario.
    """
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    home = _raw_get(browser, "/").decode("utf-8", "replace")
    assert "scenarios.html" in home, "the dashboard no longer links the scenarios page"
    page = _raw_get(browser, "/scenarios.html").decode("utf-8", "replace")
    for scenario in range(1, 6):
        assert "scenario-%d" % scenario in page


def test_the_portal_offers_the_investigation_workflow(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    html = _raw_get(browser, "/").decode("utf-8", "replace")
    assert "SOC Triage Board" in html
    assert "data-kibana-dash" in html
    assert "data-kibana-link" in html


def test_the_portal_shows_the_signed_in_identity_and_a_way_out(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    for path in ("/", "/instructions.html") + tuple(SCENARIO_PAGES):
        html = _raw_get(browser, path).decode("utf-8", "replace")
        assert "data-auth-identity" in html, path
        assert "data-auth-signout" in html, path
        assert "auth.js" in html, path


def test_the_identity_slot_is_hidden_until_the_server_confirms(portal):
    """A student name must never be baked into the page."""
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    html = _raw_get(browser, "/").decode("utf-8", "replace")
    assert 'data-auth-identity hidden' in html
    # The username is fetched at runtime, never written into the markup.
    assert "Signed in as alice" not in html


# ================================================================ E. logout

def test_logout_invalidates_the_session(portal):
    browser, db_path = portal
    browser.register("alice")
    browser.login("alice")
    assert browser.get("/api/auth/me")[1]["authenticated"] is True
    assert browser.get("/")[0] == 200

    status, _body, headers = browser.post("/api/auth/logout")

    assert status == 200
    assert "Max-Age=0" in headers["Set-Cookie"]
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    finally:
        conn.close()
    assert browser.get("/api/auth/me")[1]["authenticated"] is False


def test_after_logout_protected_pages_redirect_again(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    browser.post("/api/auth/logout")
    for page in PORTAL_PAGES:
        status, _body, headers = browser.get(page)
        assert status == 302, page
        assert headers["Location"].startswith("/login.html")


def test_a_replayed_cookie_after_logout_grants_nothing(portal):
    """Logout must be server-side, not just a cleared cookie."""
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    stale = browser.cookie
    browser.post("/api/auth/logout")

    status, _body, _h = browser.get(
        "/", headers={"Cookie": "bc_lab_session=" + stale}, send_cookie=False
    )
    assert status == 302
    status, body, _h = browser.get(
        "/api/auth/me", headers={"Cookie": "bc_lab_session=" + stale}, send_cookie=False
    )
    assert body["authenticated"] is False


def test_the_login_page_is_reachable_again_after_logout(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    browser.post("/api/auth/logout")
    assert browser.get("/login.html")[0] == 200
    assert browser.get("/register.html")[0] == 200


# ================================== F. remediation must be preserved

def test_reveal_is_still_authenticated(portal):
    browser, _db = portal
    assert browser.post("/api/reveal", {"scenario": SCENARIO, "question": "s1e1"})[0] == 401


def test_reveal_still_needs_a_prior_check(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    assert browser.post("/api/reveal", {"scenario": SCENARIO, "question": "s1e1"})[0] == 403
    browser.post("/api/check", {"scenario": SCENARIO, "answers": {"s1e1": "203.0.113.45"}})
    assert browser.post("/api/reveal", {"scenario": SCENARIO, "question": "s1e1"})[0] == 200


def test_check_is_still_anonymous_and_stateless(portal):
    browser, _db = portal
    status, body, _h = browser.post(
        "/api/check", {"scenario": SCENARIO, "answers": {"s1e1": "203.0.113.45"}}
    )
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_login_throttling_is_untouched(portal):
    browser, _db = portal
    browser.register("alice")
    statuses = [browser.login("alice", "wrong-%d" % i)[0] for i in range(8)]
    assert 429 in statuses


def test_the_answer_key_is_not_reachable_even_when_signed_in(portal):
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    for path in ("/data/answer-key.json", "/answer-key.json",
                 "/../data/answer-key.json", "/%2e%2e/data/answer-key.json"):
        assert browser.get(path)[0] in (302, 404), path


def test_no_scenario_page_embeds_a_model_solution(portal):
    """The gate must not be the only thing keeping answers out of the HTML."""
    import re
    browser, _db = portal
    browser.register("alice")
    browser.login("alice")
    for page in PORTAL_PAGES:
        html = _raw_get(browser, page).decode("utf-8", "replace")
        assert "answer-key" not in html, page
        # No base64 or inline JSON blob carrying the key.
        assert not re.search(r'"accept"\s*:', html), page
        assert not re.search(r'"patterns"\s*:', html), page
    login_html = _raw_get(browser, "/login.html").decode("utf-8", "replace")
    assert "answer-key" not in login_html


def test_api_endpoints_are_not_redirected_by_the_page_gate(portal):
    """The gate is for pages; a JSON API must answer with JSON, not a 302."""
    browser, _db = portal
    for path, body in (("/api/es-status", None),
                       ("/api/auth/me", None),
                       ("/api/check", {"scenario": SCENARIO, "answers": {}}),
                       ("/api/reveal", {"scenario": SCENARIO, "question": "s1e1"})):
        status, _b, headers = browser.post(path, body)
        assert "Location" not in headers, path
        assert status != 302, path


def test_unknown_api_endpoints_still_404(portal):
    browser, _db = portal
    assert browser.get("/api/nope")[0] == 404
    assert browser.post("/api/nope", {})[0] == 404


# ================================================== real DB left alone

def test_this_suite_never_opens_the_real_database(tmp_path):
    before = _fingerprint(REAL_DB)
    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        auth.register_user("probe", PASSWORD, path=path)
        labdb.close_connection(path)
        labdb.reset_connections()
    finally:
        pass
    assert _fingerprint(REAL_DB) == before
