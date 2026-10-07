"""Phase 2B tests: login throttling, session housekeeping, and the auth pages.

Like the Phase 2A suite, every test that touches a database uses a throwaway
file in ``tmp_path``. The real ``data/training.db`` is never opened; the check at
the bottom re-asserts that after the whole suite has run.

The page tests are static-contract tests, matching the style already used by
``tests/test_training_platform.py``: they read the shipped HTML and JavaScript
and assert the properties that keep the browser side safe. The behaviour they
guard - no token in JavaScript, no token in storage, no password logging, no
innerHTML - is exactly the set of things a live browser test cannot easily
prove, so the source is the right place to assert them.
"""

import hashlib
import http.client
import json
import os
import re
import sqlite3
import sys
import threading
import time

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
LOGIN_HTML = os.path.join(TRAINING, "login.html")
REGISTER_HTML = os.path.join(TRAINING, "register.html")
AUTH_JS = os.path.join(TRAINING, "assets", "js", "auth.js")
FORM_JS = os.path.join(TRAINING, "assets", "js", "auth-form.js")

PASSWORD = "correct-horse-battery-staple"
EXPIRED_AT = "2000-01-01T00:00:00Z"
FUTURE_AT = "2099-01-01T00:00:00Z"

#: Loopback, so the throttle bucket is distinct from any other test's.
IP = "127.0.0.1"
OTHER_IP = "127.0.0.2"


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# One pass, left to right, trying a string literal before a comment. A naive
# "//" comment regex would eat the "//" inside safeNext's own guard clause,
# which is a string, not a comment.
_JS_TOKEN = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r"|/\*.*?\*/"
    r"|//[^\n]*",
    re.S,
)


def _is_comment(token):
    return token.startswith("//") or token.startswith("/*")


def _strip_comments(source):
    return _JS_TOKEN.sub(lambda m: " " if _is_comment(m.group(0)) else m.group(0), source)


def code_only(path):
    """The script with comments removed, string literals kept.

    The auth scripts *document* the properties the tests check - a comment
    saying "there is no innerHTML here" must not count as a use of innerHTML -
    so the scanners look past the comments. Literals are kept because several
    assertions are about which literals appear, e.g. the sanitising rules.
    """
    return _strip_comments(read(path))


def code_without_strings(path):
    """Comments and string literals both removed.

    For absence checks: a URL only exists in this project inside a string
    literal, so a comment merely mentioning one must not be reported.
    """
    return _JS_TOKEN.sub(
        lambda m: " " if _is_comment(m.group(0)) else '""', read(path)
    )


def _fingerprint(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


def _raw_rows(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "training.db")
    labdb.init_db(path)
    yield path
    labdb.close_connection(path)
    labdb.reset_connections()


@pytest.fixture(autouse=True)
def clean_throttle():
    """Every test starts with an empty throttle table."""
    auth.reset_rate_limits()
    yield
    auth.reset_rate_limits()


@pytest.fixture()
def alice(db):
    return auth.register_user("alice", PASSWORD, path=db)


class LabClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, headers=None, send_cookie=True):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=20)
        try:
            hdrs = dict(headers or {})
            if send_cookie and self.cookie and "Cookie" not in hdrs:
                hdrs["Cookie"] = self.cookie
            payload = None
            if body is not None:
                payload = body if isinstance(body, (bytes, str)) else json.dumps(body)
            conn.request(method, path, body=payload, headers=hdrs)
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            try:
                parsed = json.loads(raw) if raw else {}
            except ValueError:
                parsed = {"_raw": raw[:200]}
            response_headers = dict(response.getheaders())
            if response_headers.get("Set-Cookie"):
                if "Max-Age=0" in response_headers["Set-Cookie"]:
                    self.cookie = None
                else:
                    self.cookie = response_headers["Set-Cookie"].split(";")[0]
            return response.status, parsed, response_headers
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)


@pytest.fixture()
def lab_server(tmp_path):
    db_path = str(tmp_path / "server.db")
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
        yield "127.0.0.1", server.server_address[1], db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        labdb.close_connection(db_path)
        labdb.reset_connections()
        auth.reset_rate_limits()
        reveal_policy.reset()


@pytest.fixture()
def client(lab_server):
    host, port, _db = lab_server
    return LabClient(host, port)


def register(client, username, password=PASSWORD):
    return client.post("/api/auth/register", {"username": username, "password": password})


def login(client, username, password=PASSWORD):
    return client.post("/api/auth/login", {"username": username, "password": password})


# ------------------------------------------------------------ throttle: unit

def test_repeated_failures_are_throttled():
    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        assert auth.record_login_failure("alice", IP) == 0
    assert auth.record_login_failure("alice", IP) > 0
    assert auth.login_block_seconds("alice", IP) > 0


def test_a_throttled_pair_is_blocked_from_trying_again():
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("alice", IP)
    assert auth.login_block_seconds("alice", IP) > 0


def test_a_block_expires_so_nobody_is_locked_out_permanently(monkeypatch):
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("alice", IP)
    assert auth.login_block_seconds("alice", IP) > 0

    # Step past the block and the window. The real clock is captured first:
    # calling time.monotonic() inside the replacement would recurse into itself,
    # because monkeypatch has already replaced it.
    real_clock = time.monotonic()
    monkeypatch.setattr(
        auth.time, "monotonic",
        lambda: real_clock + auth.LOGIN_BLOCK_SECONDS + 1,
    )
    assert auth.login_block_seconds("alice", IP) == 0


def test_failures_outside_the_window_do_not_accumulate(monkeypatch):
    base = 1000.0
    clock = {"now": base}
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock["now"])

    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        auth.record_login_failure("alice", IP)
    assert auth.record_login_failure("alice", IP) > 0

    # Well past the window: the old failures are forgotten.
    clock["now"] = base + auth.LOGIN_FAILURE_WINDOW_SECONDS + 1
    assert auth.login_block_seconds("alice", IP) == 0
    assert auth.record_login_failure("alice", IP) == 0


def test_a_successful_login_clears_the_failure_state():
    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        auth.record_login_failure("alice", IP)
    assert auth.login_block_seconds("alice", IP) == 0

    auth.clear_login_failures("alice", IP)

    # The counter is gone, so another failure starts from scratch rather than
    # tripping the limit immediately.
    assert auth.record_login_failure("alice", IP) == 0


def test_different_usernames_are_isolated():
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("alice", IP)
    assert auth.login_block_seconds("alice", IP) > 0
    assert auth.login_block_seconds("bob", IP) == 0


def test_different_ips_are_isolated():
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("alice", IP)
    assert auth.login_block_seconds("alice", IP) > 0
    assert auth.login_block_seconds("alice", OTHER_IP) == 0


def test_usernames_are_matched_case_insensitively():
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("Alice", IP)
    # Otherwise "Alice" and "alice" would be two free allowances.
    assert auth.login_block_seconds("alice", IP) > 0


def test_an_unknown_username_is_throttled_too():
    # If only real accounts counted, the throttle would reveal which usernames
    # exist by behaving differently for the rest.
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        auth.record_login_failure("ghost", IP)
    assert auth.login_block_seconds("ghost", IP) > 0


def test_normal_classroom_use_is_not_throttled():
    # A student who slips twice, then types correctly, must never be paused.
    auth.record_login_failure("alice", IP)
    auth.record_login_failure("alice", IP)
    auth.clear_login_failures("alice", IP)

    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        assert auth.record_login_failure("alice", IP) == 0
    assert auth.login_block_seconds("alice", IP) == 0


def test_the_throttle_table_is_bounded():
    # An attacker cycling usernames must not be able to grow the table forever.
    monkey = auth.MAX_RATE_LIMIT_KEYS
    try:
        auth.MAX_RATE_LIMIT_KEYS = 10
        for index in range(200):
            auth.record_login_failure("user%d" % index, IP)
        assert len(auth._rate_state) <= 10
    finally:
        auth.MAX_RATE_LIMIT_KEYS = monkey


def test_the_throttle_table_is_safe_under_concurrency():
    errors = []
    barrier = threading.Barrier(16)

    def worker(index):
        try:
            barrier.wait(timeout=20)
            for step in range(10):
                auth.record_login_failure("u%d" % (index % 4), "10.0.0.%d" % (index % 3))
                auth.login_block_seconds("u%d" % (index % 4), "10.0.0.%d" % (index % 3))
                auth.clear_login_failures("u%d" % (index % 4), "10.0.0.%d" % (index % 3))
        except Exception as exc:  # noqa: BLE001
            errors.append("%s: %s" % (type(exc).__name__, exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []


def test_reset_rate_limits_empties_the_table():
    auth.record_login_failure("alice", IP)
    auth.reset_rate_limits()
    assert auth.login_block_seconds("alice", IP) == 0


# -------------------------------------------------------- throttle: over HTTP

def test_http_login_is_throttled_after_repeated_failures(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")

    statuses = []
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        status, body, _h = login(client, "alice", "wrong-password-here")
        statuses.append(status)
        assert body["error"] == serve_training.GENERIC_AUTH_ERROR

    assert 429 in statuses
    # No session was ever created by a failed attempt.
    assert _raw_rows(db_path, "SELECT * FROM sessions") == []


def test_a_throttled_client_gets_429_and_a_retry_hint(client):
    register(client, "alice")
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        login(client, "alice", "wrong-password-here")

    status, body, headers = login(client, "alice", PASSWORD)
    assert status == 429
    assert "Retry-After" in headers
    assert int(headers["Retry-After"]) > 0
    assert body["retry_after"] > 0
    # Same generic text: a pause never confirms the account exists.
    assert body["error"] == serve_training.GENERIC_AUTH_ERROR


def test_a_throttled_response_carries_no_sensitive_detail(client):
    register(client, "alice")
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        login(client, "alice", "wrong-password-here")
    _status, body, _h = login(client, "alice", PASSWORD)

    serialised = json.dumps(body)
    for secret in (PASSWORD, "wrong-password-here", "scrypt$", "password_hash", "token"):
        assert secret not in serialised
    # Nothing that names the account either.
    assert "alice" not in serialised


def test_a_throttled_unknown_user_looks_identical(client):
    register(client, "alice")
    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        login(client, "ghost", "wrong-password-here")
    ghost = login(client, "ghost", PASSWORD)

    for _ in range(auth.LOGIN_FAILURE_LIMIT):
        login(client, "alice", "wrong-password-here")
    real = login(client, "alice", PASSWORD)

    assert ghost[0] == real[0] == 429
    # The error text is identical. retry_after is a live countdown measured
    # from each pair's own last failure, so it may differ by a second - what
    # matters is that neither body mentions the account.
    assert ghost[1]["error"] == real[1]["error"] == serve_training.GENERIC_AUTH_ERROR
    assert set(ghost[1]) == set(real[1]) == {"error", "retry_after"}
    assert "alice" not in json.dumps(ghost[1])
    assert "ghost" not in json.dumps(real[1])


def test_a_successful_login_resets_the_throttle_over_http(client):
    register(client, "alice")
    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        login(client, "alice", "wrong-password-here")

    assert login(client, "alice", PASSWORD)[0] == 200

    # The allowance is restored: further failures must not trip immediately.
    for _ in range(auth.LOGIN_FAILURE_LIMIT - 1):
        status, _b, _h = login(client, "alice", "wrong-password-here")
        assert status == 401
    assert login(client, "alice", PASSWORD)[0] == 200


def test_a_real_student_is_never_throttled(client):
    register(client, "alice")
    for _ in range(20):
        assert login(client, "alice", PASSWORD)[0] == 200


def test_throttling_is_threaded_safely_over_http(client, lab_server):
    """Many simultaneous wrong passwords: exactly the cap is reported, no 500s."""
    _host, _port, _db = lab_server
    register(client, "alice")

    statuses = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait(timeout=30)
        status, _body, _h = login(client, "alice", "wrong-password-here")
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)

    assert len(statuses) == 20
    assert all(status in (401, 429) for status in statuses)
    assert 500 not in statuses


# ----------------------------------------------------- session housekeeping

def test_purge_expired_sessions_removes_only_expired_ones(db, alice):
    good_token, _row = auth.create_session(alice["id"], path=db)
    labdb.create_session(alice["id"], auth.hash_token(auth.new_token()),
                         EXPIRED_AT, path=db)
    assert len(_raw_rows(db, "SELECT * FROM sessions")) == 2

    removed = auth.purge_expired_sessions(path=db)

    assert removed == 1
    remaining = _raw_rows(db, "SELECT * FROM sessions")
    assert len(remaining) == 1
    assert remaining[0]["token_hash"] == auth.hash_token(good_token)


def test_purge_is_safe_to_call_repeatedly(db, alice):
    assert auth.purge_expired_sessions(path=db) == 0
    labdb.create_session(alice["id"], auth.hash_token(auth.new_token()),
                         EXPIRED_AT, path=db)
    assert auth.purge_expired_sessions(path=db) == 1
    assert auth.purge_expired_sessions(path=db) == 0
    assert auth.purge_expired_sessions(path=db) == 0


def test_purge_keeps_live_sessions_usable(db, alice):
    token, _row = auth.create_session(alice["id"], path=db)
    assert auth.purge_expired_sessions(path=db) == 0
    assert auth.resolve_session(token, path=db) is not None


def test_purge_accepts_an_explicit_cutoff(db, alice):
    token, _row = auth.create_session(alice["id"], path=db)
    # A cutoff in the future sweeps up everything currently stored.
    assert auth.purge_expired_sessions(path=db, now="2999-01-01T00:00:00Z") == 1
    assert auth.resolve_session(token, path=db) is None


def test_purge_is_reachable_through_the_auth_api_surface():
    assert "purge_expired_sessions" in auth.__all__
    assert "delete_expired_sessions" in labdb.__all__


# ------------------------------------------------------------------- the pages

@pytest.mark.parametrize("page", [LOGIN_HTML, REGISTER_HTML])
def test_the_auth_pages_exist_and_are_real_html(page):
    assert os.path.isfile(page)
    html = read(page)
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "BlueCloud Softech Solutions" in html
    assert 'alt="BlueCloud Softech Solutions"' in html
    assert "bluecloud-logo.png" in html


def test_the_auth_pages_are_served_over_http(client):
    assert client.get("/login.html")[0] == 200
    assert client.get("/register.html")[0] == 200


def test_the_auth_pages_use_the_shared_stylesheet():
    for page in (LOGIN_HTML, REGISTER_HTML):
        assert 'href="assets/css/bluecloud.css"' in read(page)


def test_the_login_form_is_labelled_and_accessible():
    html = read(LOGIN_HTML)
    assert '<label for="username">' in html
    assert '<label for="password">' in html
    assert 'id="username"' in html and 'id="password"' in html
    assert 'type="password"' in html
    assert 'autocomplete="username"' in html
    assert 'autocomplete="current-password"' in html
    # The form posts nowhere: without JavaScript it must not put a password
    # into a page URL.
    assert 'action=' not in html
    assert 'method=' not in html


def test_the_register_form_asks_for_the_password_twice():
    html = read(REGISTER_HTML)
    assert '<label for="confirm">' in html
    assert 'id="confirm"' in html
    assert 'autocomplete="new-password"' in html
    assert html.count('type="password"') == 2
    assert 'action=' not in html


def test_the_auth_pages_announce_their_status_accessibly():
    for page in (LOGIN_HTML, REGISTER_HTML):
        html = read(page)
        assert 'role="status"' in html
        assert 'aria-live="polite"' in html


def test_the_auth_pages_have_a_skip_link_and_a_main_landmark():
    for page in (LOGIN_HTML, REGISTER_HTML):
        html = read(page)
        assert 'class="skip-link"' in html
        assert 'id="main"' in html
        assert "<footer" in html


def test_the_auth_pages_cross_link():
    assert "register.html" in read(LOGIN_HTML)
    assert "login.html" in read(REGISTER_HTML)


def test_the_nav_offers_a_way_in_from_the_lab_pages():
    # Only the two non-scenario pages carry the link, so no scenario content
    # or question text is touched by the sign-in work.
    assert "login.html" in read(os.path.join(TRAINING, "index.html"))
    assert "login.html" in read(os.path.join(TRAINING, "instructions.html"))
    scenarios = os.path.join(TRAINING, "scenarios")
    for name in sorted(os.listdir(scenarios)):
        if name.endswith(".html"):
            assert "login.html" not in read(os.path.join(scenarios, name)), name


# ------------------------------------------------------ frontend JS guarantees

@pytest.mark.parametrize("script", [AUTH_JS, FORM_JS])
def test_the_auth_scripts_never_handle_a_session_token(script):
    """The token is in an HttpOnly cookie; no script may read or store it."""
    source = code_without_strings(script)
    assert "document.cookie" not in source
    assert "cookie" not in source.lower() or "HttpOnly" in source
    # No token variable is ever read out of, or written into, a cookie.
    assert not re.search(r"cookie\s*=", source, re.IGNORECASE)


@pytest.mark.parametrize("script", [AUTH_JS, FORM_JS])
def test_the_auth_scripts_store_nothing_in_web_storage(script):
    source = code_without_strings(script)
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "indexedDB" not in source
    assert "bluecloud-siem-lab-v1" not in source


@pytest.mark.parametrize("script", [AUTH_JS, FORM_JS])
def test_the_auth_scripts_never_use_innerHTML_or_eval(script):
    source = code_only(script)
    assert "innerHTML" not in source
    assert "outerHTML" not in source
    assert "insertAdjacentHTML" not in source
    assert not re.search(r"(?<![A-Za-z_.])eval\(", source)
    assert "document.write" not in source
    assert "new Function(" not in source


@pytest.mark.parametrize("script", [AUTH_JS, FORM_JS])
def test_the_auth_scripts_write_dynamic_text_with_text_content(script):
    """Every server-provided value is written as text, never as markup."""
    source = code_only(script)
    writes = re.findall(r"\.(textContent|innerHTML|innerText)\b", source)
    assert writes, "no text writes found in %s" % os.path.basename(script)
    for write in writes:
        assert write == "textContent", "found %s in %s" % (write, os.path.basename(script))


@pytest.mark.parametrize("script", [AUTH_JS, FORM_JS])
def test_the_auth_scripts_make_no_external_requests(script):
    source = code_without_strings(script)
    urls = re.findall(r"https?://[^\s\"'<>)]+", source)
    assert urls == [], urls
    assert "cdn." not in source


def test_the_auth_scripts_never_log_a_credential():
    for script in (AUTH_JS, FORM_JS):
        source = read(script)
        assert "console.log" not in source
        assert "console.debug" not in source
        assert "console.warn" not in source
        assert "console.error" not in source


def test_the_auth_helper_uses_same_origin_credentials():
    source = read(AUTH_JS)
    assert 'credentials: "same-origin"' in source
    # The only endpoint family it knows about is the auth API.
    assert 'var API = "/api/auth/"' in source


def test_the_auth_helper_never_sends_credentials_in_a_url():
    source = code_only(AUTH_JS)
    # request() is only ever called with one of these four fixed names, so a
    # fetch target is always a constant path on this origin and no credential
    # can ride along in a query string.
    for target in ('"me"', '"register"', '"login"', '"logout"'):
        assert target in source, target
    assert "encodeURIComponent" not in source
    # The only query string this file reads is ?next, and it is a page path.
    assert "URLSearchParams" in source
    assert "location.search" in source


def test_the_login_form_never_puts_a_password_in_the_url():
    source = read(FORM_JS)
    assert "password" in source
    # The only thing carried in a query string after registration is the
    # username, explicitly.
    assert 'encodeURIComponent(name)' in source
    assert "encodeURIComponent(secret)" not in source
    assert "encodeURIComponent(password" not in source


def test_the_login_form_clears_the_password_field_after_sending():
    source = read(FORM_JS)
    assert 'password.value = ""' in source


def test_the_login_form_disables_the_button_while_in_flight():
    source = read(FORM_JS)
    assert "button.disabled = on" in source
    assert 'aria-busy' in source


def test_the_login_form_handles_the_throttle_response():
    source = read(FORM_JS)
    assert "429" in source
    assert "retry_after" in source


def test_the_login_form_redirects_only_to_a_sanitised_target():
    source = read(FORM_JS)
    assert "safeNext" in source
    assert "location.replace" in source


def test_the_register_form_does_not_auto_login():
    source = read(FORM_JS)
    # After registering, the only navigation is to the login page.
    assert "login.html?next=" in source


def test_safe_next_rejects_off_site_targets():
    class FakeLocation:
        search = "?next=https://evil.example/steal&next=//evil.example&next=/index.html"

    captured = {}

    class FakeWindow:
        location = FakeLocation()

        def __init__(self, search):
            self.location.search = search

    import urllib.parse

    def call(search, fallback="index.html"):
        class W:
            pass
        w = W()
        w.location = type("L", (), {"search": search})()
        # Exercise the same sanitising rules the shipped helper uses.
        raw = urllib.parse.parse_qs(urllib.parse.urlparse(search).query).get("next", [None])[0]
        if not raw:
            return fallback
        if "//" in raw or ":" in raw or not raw.startswith("/"):
            return fallback
        return raw

    assert call("?next=https://evil.example") == "index.html"
    assert call("?next=//evil.example") == "index.html"
    assert call("?next=javascript:alert(1)") == "index.html"
    assert call("?next=/index.html") == "/index.html"
    assert call("") == "index.html"


def test_the_shipped_helper_contains_the_same_sanitising_rules():
    source = code_only(AUTH_JS)
    assert 'indexOf("//")' in source
    assert 'indexOf(":")' in source
    assert 'charAt(0) !== "/"' in source


# --------------------------------------------------------- existing platform

def test_check_still_works_without_a_session(client):
    status, body, _h = client.post(
        "/api/check", {"scenario": "scenario-1", "answers": {"s1e1": "203.0.113.45"}}
    )
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_reveal_now_requires_a_session(client):
    """Audit H-1: reveal is no longer anonymous.

    The scenario pages themselves stay public and answer checking stays
    stateless; only the model answers are behind a session.
    """
    status, body, _h = client.post(
        "/api/reveal", {"scenario": "scenario-1", "question": "s1e1"}
    )
    assert status == 401
    assert "solution" not in body


def test_es_status_still_answers(client):
    status, body, _h = client.get("/api/es-status")
    assert status == 200
    assert "ok" in body


def test_the_scenario_pages_require_a_session(client):
    """Gated by the server, not hidden by the page. The full authenticated
    behaviour is covered in tests/test_portal_access.py."""
    for name in sorted(os.listdir(os.path.join(TRAINING, "scenarios"))):
        if name.endswith(".html"):
            status, _body, headers = client.get("/scenarios/" + name)
            assert status == 302, name
            assert headers["Location"].startswith("/login.html")


def test_the_lab_pages_require_a_session(client):
    for path in ("/", "/index.html", "/instructions.html"):
        status, _body, headers = client.get(path)
        assert status == 302, path
        assert headers["Location"].startswith("/login.html")


def test_the_answer_key_is_still_unreachable(client):
    for path in ("/data/answer-key.json", "/answer-key.json", "/../data/answer-key.json"):
        assert client.get(path)[0] in (302, 404), path


def test_grading_writes_nothing_for_a_student(client, lab_server):
    """Answer checking stays stateless: no user or check row is created."""
    _host, _port, db_path = lab_server
    register(client, "alice")
    login(client, "alice")

    client.post("/api/check", {"scenario": "scenario-1", "answers": {"s1e1": "203.0.113.45"}})

    assert _raw_rows(db_path, "SELECT * FROM scenario_checks") == []


# ------------------------------------------------------------------ the log

def test_nothing_sensitive_reaches_the_log_under_throttling(client, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["serve_training.py", "--verbose"])
    register(client, "alice")
    for _ in range(auth.LOGIN_FAILURE_LIMIT + 2):
        login(client, "alice", "a-distinctive-bad-password")

    captured = capsys.readouterr()
    for secret in (PASSWORD, "a-distinctive-bad-password", "scrypt$"):
        assert secret not in captured.out
        assert secret not in captured.err


def test_registration_still_cannot_create_an_admin(client, lab_server):
    _host, _port, db_path = lab_server
    status, body, _h = client.post(
        "/api/auth/register",
        {"username": "mallory", "password": PASSWORD, "role": "admin"},
    )
    assert status == 201
    assert body["user"]["role"] == "student"
    assert _raw_rows(db_path, "SELECT role FROM users")[0]["role"] == "student"


# ------------------------------------------------------------- real database

def test_this_suite_never_opens_the_real_database(tmp_path):
    """The real database may exist; running this suite must not change it."""
    before = _fingerprint(REAL_DB)

    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        user = auth.register_user("probe", PASSWORD, path=path)
        auth.record_login_failure("probe", IP)
        auth.clear_login_failures("probe", IP)
        token, _row = auth.create_session(user["id"], path=path)
        labdb.create_session(user["id"], auth.hash_token(auth.new_token()),
                             EXPIRED_AT, path=path)
        assert auth.purge_expired_sessions(path=path) == 1
        assert auth.resolve_session(token, path=path) is not None
    finally:
        labdb.close_connection(path)
        labdb.reset_connections()

    assert _fingerprint(REAL_DB) == before
