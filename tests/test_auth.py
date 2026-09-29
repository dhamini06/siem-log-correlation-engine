"""Phase 2A tests: password hashing, sessions, and the auth HTTP endpoints.

Every test that touches a database uses a throwaway file in ``tmp_path``. The
real ``data/training.db`` is never opened. ``scripts/labdb.py`` is not modified
by this phase, so the Phase 1 isolation guarantee still holds; the check at the
bottom of this file re-asserts it after the whole suite has run.

No test starts the packaged server. ``lab_server`` starts the *same*
``LabRequestHandler`` and ``LabServer`` the real entry point uses, on an
ephemeral port, against a temporary database - so the HTTP layer is exercised
for real without depending on a running lab.
"""

import hashlib
import http.client
import json
import os
import socket
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
import serve_training  # noqa: E402

REAL_DB = os.path.join(ROOT, "data", "training.db")
TRAINING_DIR = os.path.join(ROOT, "training")

PASSWORD = "correct-horse-battery-staple"
OTHER_PASSWORD = "a-different-password"

# A timestamp comfortably in the past, used to forge an already-expired session.
EXPIRED_AT = "2000-01-01T00:00:00Z"
FUTURE_AT = "2099-01-01T00:00:00Z"

#: The server's cookie name, imported so a rename breaks these tests loudly.
_SESSION_COOKIE_NAME = serve_training.SESSION_COOKIE


# ----------------------------------------------------------------- fixtures

@pytest.fixture()
def db(tmp_path):
    """A throwaway initialised database, closed again on teardown."""
    path = str(tmp_path / "training.db")
    labdb.init_db(path)
    yield path
    labdb.close_connection(path)
    labdb.reset_connections()


def _fingerprint(path):
    """(size, mtime_ns, sha256) for a file, or None when it does not exist."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


def _raw_rows(db_path, sql, params=()):
    """Read rows with a private connection, so no test touches the pool."""
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


class LabClient:
    """Minimal HTTP client that keeps one cookie, like a browser would."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cookie = None

    def _connect(self):
        return http.client.HTTPConnection(self.host, self.port, timeout=15)

    def request(self, method, path, body=None, headers=None, send_cookie=True):
        conn = self._connect()
        try:
            hdrs = dict(headers or {})
            # An explicitly supplied Cookie header wins, so a test can pretend
            # to be a browser that ignored the expiry.
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
            except json.JSONDecodeError:
                parsed = {"_raw": raw}
            response_headers = dict(response.getheaders())
            self._adopt_cookie(response_headers)
            return response.status, parsed, response_headers
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)

    def _adopt_cookie(self, headers):
        """Store Set-Cookie automatically, as a browser does.

        An expired cookie (Max-Age=0) is discarded rather than kept, so a
        logout genuinely leaves the client anonymous.
        """
        raw = headers.get("Set-Cookie")
        if not raw:
            return
        for attribute in raw.split(";"):
            name, _, value = attribute.strip().partition("=")
            if name.lower() == "max-age":
                try:
                    if int(value) <= 0:
                        self.cookie = None
                        return
                except ValueError:
                    pass
        self.cookie = raw.split(";")[0]

    def set_cookie_from(self, headers):
        """Adopt the Set-Cookie value explicitly, as a browser would."""
        self._adopt_cookie(headers)
        raw = headers.get("Set-Cookie")
        return raw or ""


@pytest.fixture()
def lab_server(tmp_path):
    """A real threaded server on an ephemeral port, over a temporary database."""
    db_path = str(tmp_path / "server.db")
    labdb.init_db(db_path)

    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING_DIR, **kw
    )
    server = serve_training.LabServer(("127.0.0.1", 0), handler)
    server.db_path = db_path
    server.force_secure_cookies = False

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


@pytest.fixture()
def client(lab_server):
    host, port, _db = lab_server
    return LabClient(host, port)


def register(client, username, password=PASSWORD):
    return client.post(
        "/api/auth/register", {"username": username, "password": password}
    )


def login(client, username, password=PASSWORD):
    return client.post(
        "/api/auth/login", {"username": username, "password": password}
    )


# ------------------------------------------------------------------ database

def test_registration_creates_a_student_row(db):
    user = auth.register_user("alice", PASSWORD, path=db)

    assert user["username"] == "alice"
    assert user["role"] == "student"
    rows = _raw_rows(db, "SELECT * FROM users WHERE username = ?", ("alice",))
    assert len(rows) == 1
    assert rows[0]["role"] == "student"
    assert rows[0]["is_active"] == 1


def test_registration_rejects_a_duplicate_username(db):
    auth.register_user("alice", PASSWORD, path=db)
    with pytest.raises(auth.DuplicateUsername):
        auth.register_user("alice", PASSWORD, path=db)

    # The second attempt must not have created or changed a second row.
    assert len(_raw_rows(db, "SELECT * FROM users")) == 1


def test_duplicate_registration_cannot_overwrite_the_first_account(db):
    auth.register_user("alice", PASSWORD, path=db)
    before = _raw_rows(db, "SELECT * FROM users WHERE username = ?", ("alice",))[0]

    with pytest.raises(auth.DuplicateUsername):
        auth.register_user("alice", OTHER_PASSWORD, path=db)

    after = _raw_rows(db, "SELECT * FROM users WHERE username = ?", ("alice",))[0]
    assert after["id"] == before["id"]
    assert after["password_hash"] == before["password_hash"]


def test_no_plaintext_password_is_ever_stored(db):
    auth.register_user("alice", PASSWORD, path=db)
    stored = _raw_rows(db, "SELECT password_hash FROM users")[0]["password_hash"]

    assert PASSWORD not in stored
    assert "correct-horse" not in stored
    assert stored.startswith("scrypt$")


def test_a_user_cannot_self_register_as_admin(db):
    # register_user has no role parameter at all, so there is nothing to pass.
    with pytest.raises(TypeError):
        auth.register_user("mallory", PASSWORD, path=db, role="admin")

    user = auth.register_user("mallory", PASSWORD, path=db)
    assert user["role"] == "student"
    assert _raw_rows(db, "SELECT role FROM users")[0]["role"] == "student"


def test_admin_role_is_not_accepted_by_the_role_validator(db):
    # Defence in depth: even if a role were passed, labdb rejects it.
    with pytest.raises(ValueError):
        labdb.create_user(
            username="mallory",
            password_hash=auth.hash_password(PASSWORD),
            display_name="Mallory",
            role="superuser",
            path=db,
        )


def test_schema_initialisation_stays_idempotent(db):
    auth.register_user("alice", PASSWORD, path=db)
    before = len(_raw_rows(db, "SELECT * FROM users"))

    labdb.init_db(db)
    labdb.init_db(db)

    assert len(_raw_rows(db, "SELECT * FROM users")) == before
    assert labdb.get_schema_version(db) == labdb.SCHEMA_VERSION == 1


# ----------------------------------------------------------------- passwords

def test_the_correct_password_verifies():
    stored = auth.hash_password(PASSWORD)
    assert auth.verify_password(PASSWORD, stored) is True


def test_a_wrong_password_fails():
    stored = auth.hash_password(PASSWORD)
    assert auth.verify_password(OTHER_PASSWORD, stored) is False
    assert auth.verify_password("", stored) is False
    assert auth.verify_password(PASSWORD + "x", stored) is False


def test_two_hashes_of_one_password_use_different_salts():
    first = auth.hash_password(PASSWORD)
    second = auth.hash_password(PASSWORD)

    assert first != second
    assert first.split("$")[4] != second.split("$")[4]
    # ...and both still verify, which is the point of a per-password salt.
    assert auth.verify_password(PASSWORD, first)
    assert auth.verify_password(PASSWORD, second)


def test_a_malformed_stored_hash_fails_safely():
    for bad in (
        "",
        "not-a-hash",
        "scrypt$16384$8$1$only-four-parts",
        "scrypt$a$b$c$d$e",
        "bcrypt$16384$8$1$AAAA$AAAA",
        "scrypt$16384$8$1$!!!not-base64!!!$AAAA",
        "scrypt$0$0$0$AAAA$AAAA",
        "scrypt$99999999$8$1$AAAA$AAAA",
        None,
        123,
        b"bytes",
    ):
        assert auth.verify_password(PASSWORD, bad) is False


def test_verify_password_rejects_non_string_input():
    stored = auth.hash_password(PASSWORD)
    assert auth.verify_password(None, stored) is False
    assert auth.verify_password(PASSWORD, None) is False
    assert auth.verify_password(b"bytes", stored) is False


def test_hash_password_encodes_its_own_parameters():
    stored = auth.hash_password(PASSWORD)
    scheme, n, r, p, salt, key = stored.split("$")

    assert scheme == "scrypt"
    assert int(n) == auth.SCRYPT_N and int(r) == auth.SCRYPT_R and int(p) == auth.SCRYPT_P
    # Enough information is stored to verify the password later, with no
    # dependency on the module's current constants.
    assert salt and key


def test_hash_password_rejects_non_strings():
    with pytest.raises(TypeError):
        auth.hash_password(None)


def test_password_hashing_survives_a_unicode_password():
    stored = auth.hash_password("pässwörd-Ünïcode-123")
    assert auth.verify_password("pässwörd-Ünïcode-123", stored)
    assert not auth.verify_password("password-unicode-123", stored)


# ------------------------------------------------------------------ sessions

def test_a_session_stores_only_the_token_hash(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token, _row = auth.create_session(user["id"], path=db)

    rows = _raw_rows(db, "SELECT * FROM sessions")
    assert len(rows) == 1
    stored = rows[0]
    assert token not in stored["token_hash"]
    assert stored["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert stored["user_id"] == user["id"]


def test_a_raw_token_is_never_stored_anywhere_in_the_row(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token, _row = auth.create_session(user["id"], path=db)

    rows = _raw_rows(db, "SELECT * FROM sessions")
    for key, value in rows[0].items():
        if isinstance(value, str):
            assert token not in value, f"raw token leaked into sessions.{key}"


def test_tokens_are_unique_per_session(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    tokens = {auth.create_session(user["id"], path=db)[0] for _ in range(5)}
    assert len(tokens) == 5


def test_resolve_session_returns_the_user(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token, _row = auth.create_session(user["id"], path=db)

    resolved = auth.resolve_session(token, path=db)
    assert resolved["id"] == user["id"]
    assert resolved["username"] == "alice"
    assert resolved["role"] == "student"


def test_resolve_session_rejects_an_unknown_token(db):
    assert auth.resolve_session("not-a-real-token", path=db) is None
    assert auth.resolve_session("", path=db) is None
    assert auth.resolve_session(None, path=db) is None


def test_an_expired_session_is_treated_as_absent_and_removed(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token = auth.new_token()
    labdb.create_session(user["id"], auth.hash_token(token), EXPIRED_AT, path=db)

    assert auth.resolve_session(token, path=db) is None
    # The row is deleted, so a stale cookie cannot be revived later.
    assert _raw_rows(db, "SELECT * FROM sessions") == []


def test_delete_session_invalidates_it_server_side(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token, _row = auth.create_session(user["id"], path=db)

    assert auth.resolve_session(token, path=db) is not None
    assert auth.delete_session(token, path=db) is True
    assert auth.resolve_session(token, path=db) is None
    assert _raw_rows(db, "SELECT * FROM sessions") == []
    # Deleting twice is harmless.
    assert auth.delete_session(token, path=db) is False


def test_a_deactivated_user_cannot_use_an_existing_session(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    token, _row = auth.create_session(user["id"], path=db)

    labdb.get_connection(db).execute(
        "UPDATE users SET is_active = 0 WHERE id = ?", (user["id"],)
    )
    labdb.get_connection(db).commit()

    assert auth.resolve_session(token, path=db) is None


def test_public_user_never_exposes_the_hash(db):
    user = auth.register_user("alice", PASSWORD, path=db)
    row = labdb.get_user_by_id(user["id"], path=db)

    public = auth.public_user(row)
    assert "password_hash" not in public
    assert set(public) == {"id", "username", "display_name", "role"}


# --------------------------------------------------------------------- login

def test_authenticate_returns_the_user_for_correct_credentials(db):
    auth.register_user("alice", PASSWORD, path=db)
    user = auth.authenticate("alice", PASSWORD, path=db)
    assert user["username"] == "alice"
    assert "password_hash" not in user


def test_authenticate_fails_for_a_wrong_password(db):
    auth.register_user("alice", PASSWORD, path=db)
    with pytest.raises(auth.InvalidCredentials):
        auth.authenticate("alice", OTHER_PASSWORD, path=db)


def test_authenticate_gives_one_generic_error_for_every_failure(db):
    auth.register_user("alice", PASSWORD, path=db)

    messages = set()
    for username, password in (
        ("alice", OTHER_PASSWORD),      # right user, wrong password
        ("nobody", PASSWORD),           # no such user
        ("nobody", OTHER_PASSWORD),     # no such user, wrong password
    ):
        with pytest.raises(auth.InvalidCredentials) as excinfo:
            auth.authenticate(username, password, path=db)
        messages.add(str(excinfo.value))

    assert len(messages) == 1
    assert messages.pop() == "invalid username or password"


def test_authenticate_rejects_empty_and_non_string_input(db):
    for username, password in (("", PASSWORD), (None, PASSWORD), ("alice", ""), ("alice", None)):
        with pytest.raises(auth.InvalidCredentials):
            auth.authenticate(username, password, path=db)


# ---------------------------------------------------------------- validation

def test_username_validation(db):
    for bad in (None, "", "   ", "a", "x" * 33, "has space", "quote\"inject", "semi;colon"):
        with pytest.raises(auth.AuthenticationError):
            auth.register_user(bad, PASSWORD, path=db)

    assert _raw_rows(db, "SELECT * FROM users") == []


def test_password_validation(db):
    for bad in (None, "", "short", "x" * 201):
        with pytest.raises(auth.AuthenticationError):
            auth.register_user("alice", bad, path=db)

    assert _raw_rows(db, "SELECT * FROM users") == []


def test_validation_errors_never_echo_the_password():
    try:
        auth.register_user("alice", "a-very-distinctive-secret-value", path="/nonexistent")
    except Exception as exc:
        # The failure may be anything; what matters is that the submitted
        # password is not in the message.
        assert "a-very-distinctive-secret-value" not in str(exc)


# ------------------------------------------------------------- register API

def test_registration_api_succeeds(client):
    status, body, _h = register(client, "alice")
    assert status == 201
    assert body["registered"] is True
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "student"


def test_registration_api_rejects_a_duplicate(client):
    register(client, "alice")
    status, body, _h = register(client, "alice")
    assert status == 409
    assert "error" in body


def test_registration_api_rejects_malformed_json(client):
    status, body, _h = client.post("/api/auth/register", "{not json")
    assert status == 400
    assert "error" in body


def test_registration_api_rejects_a_non_object_body(client):
    status, _body, _h = client.post("/api/auth/register", "[1, 2, 3]")
    assert status == 400


def test_registration_api_rejects_missing_fields(client):
    assert register(client, "")[0] == 400
    assert register(client, "alice", "")[0] == 400
    assert client.post("/api/auth/register", {})[0] == 400
    assert client.post("/api/auth/register", {"username": "alice"})[0] == 400
    assert client.post("/api/auth/register", {"password": PASSWORD})[0] == 400


def test_registration_api_rejects_invalid_lengths(client):
    assert register(client, "a")[0] == 400
    assert register(client, "x" * 33)[0] == 400
    assert register(client, "alice", "short")[0] == 400
    assert register(client, "alice", "x" * 201)[0] == 400


def test_registration_api_never_returns_the_password_or_hash(client, lab_server):
    _host, _port, db_path = lab_server
    status, body, _h = register(client, "alice")

    serialised = json.dumps(body)
    assert status == 201
    assert PASSWORD not in serialised
    assert "password_hash" not in serialised
    assert "scrypt$" not in serialised
    assert set(body["user"]) == {"id", "username", "display_name", "role"}

    # And nothing was written to disk that contains the plaintext.
    assert PASSWORD not in _raw_rows(db_path, "SELECT password_hash FROM users")[0]["password_hash"]


def test_a_role_in_the_request_body_is_ignored(client, lab_server):
    _host, _port, db_path = lab_server
    status, body, _h = client.post(
        "/api/auth/register",
        {"username": "mallory", "password": PASSWORD, "role": "admin"},
    )

    assert status == 201
    assert body["user"]["role"] == "student"
    assert _raw_rows(db_path, "SELECT role FROM users")[0]["role"] == "student"


def test_registration_does_not_set_a_session_cookie(client):
    _status, _body, headers = register(client, "alice")
    assert "Set-Cookie" not in headers


# ------------------------------------------------------------------ login API

def test_login_api_succeeds_and_sets_a_cookie(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")

    status, body, headers = login(client, "alice")
    raw_cookie = client.set_cookie_from(headers)

    assert status == 200
    assert body["authenticated"] is True
    assert body["user"]["username"] == "alice"
    assert "password_hash" not in json.dumps(body)
    assert _SESSION_COOKIE_NAME in raw_cookie


def test_login_cookie_has_the_right_attributes(client):
    register(client, "alice")
    _status, _body, headers = login(client, "alice")
    raw = headers["Set-Cookie"]

    assert "HttpOnly" in raw
    assert "SameSite=Lax" in raw
    assert "Path=/" in raw
    assert f"Max-Age={auth.SESSION_TTL_SECONDS}" in raw
    # Plain HTTP lab: Secure would be ignored, so it must not be set.
    assert "Secure" not in raw


def test_login_cookie_is_secure_over_https(client):
    register(client, "alice")
    _status, _body, headers = client.post(
        "/api/auth/login",
        {"username": "alice", "password": PASSWORD},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert "Secure" in headers["Set-Cookie"]


def test_login_does_not_write_the_raw_token_to_the_database(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")
    _status, _body, headers = login(client, "alice")
    token = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]

    rows = _raw_rows(db_path, "SELECT * FROM sessions")
    assert len(rows) == 1
    for key, value in rows[0].items():
        if isinstance(value, str):
            assert token not in value, f"raw token leaked into sessions.{key}"
    assert rows[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()


def test_login_updates_last_login(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")
    assert _raw_rows(db_path, "SELECT last_login_at FROM users")[0]["last_login_at"] is None

    login(client, "alice")
    assert _raw_rows(db_path, "SELECT last_login_at FROM users")[0]["last_login_at"] is not None


def test_login_fails_for_a_wrong_password_without_creating_a_session(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")

    status, body, headers = login(client, "alice", OTHER_PASSWORD)

    assert status == 401
    assert body["error"] == serve_training.GENERIC_AUTH_ERROR
    assert "Set-Cookie" not in headers
    assert _raw_rows(db_path, "SELECT * FROM sessions") == []


def test_login_failure_is_identical_for_an_unknown_user(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")
    wrong_password = login(client, "alice", OTHER_PASSWORD)
    no_such_user = login(client, "nobody", PASSWORD)

    assert wrong_password[0] == no_such_user[0] == 401
    assert wrong_password[1] == no_such_user[1]
    assert _raw_rows(db_path, "SELECT * FROM sessions") == []


def test_login_rejects_a_malformed_body(client):
    assert client.post("/api/auth/login", "{not json")[0] == 400
    assert client.post("/api/auth/login", {})[0] == 401


def test_login_does_not_echo_the_password(client):
    register(client, "alice")
    _status, body, _h = login(client, "alice", "a-distinctive-wrong-secret")
    assert "a-distinctive-wrong-secret" not in json.dumps(body)


# ---------------------------------------------------------------------- me

def test_me_is_unauthenticated_without_a_cookie(client):
    status, body, _h = client.get("/api/auth/me")
    assert status == 200
    assert body == {"authenticated": False}


def test_me_is_unauthenticated_with_a_bogus_cookie(client):
    status, body, _h = client.get("/api/auth/me", headers={"Cookie": f"{_SESSION_COOKIE_NAME}=nope"})
    assert status == 200
    assert body["authenticated"] is False


def test_me_reports_the_authenticated_user(client):
    register(client, "alice")
    login(client, "alice")

    status, body, _h = client.get("/api/auth/me")

    assert status == 200
    assert body["authenticated"] is True
    assert body["user"]["username"] == "alice"
    assert body["user"]["role"] == "student"
    assert isinstance(body["user"]["id"], int)


def test_me_never_returns_secrets(client):
    register(client, "alice")
    login(client, "alice")
    _status, body, _h = client.get("/api/auth/me")

    serialised = json.dumps(body)
    assert "password_hash" not in serialised
    assert "token_hash" not in serialised
    assert PASSWORD not in serialised
    assert set(body["user"]) == {"id", "username", "display_name", "role"}


def test_me_does_not_return_the_session_token(client):
    register(client, "alice")
    _s, _b, headers = login(client, "alice")
    token = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]

    _status, body, _h = client.get("/api/auth/me")
    assert token not in json.dumps(body)


def test_me_rejects_an_expired_session(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")
    token, _row = auth.create_session(
        labdb.get_user_by_username("alice", path=db_path)["id"],
        path=db_path,
        created_at="2000-01-01T00:00:00Z",
    )
    # Force the stored expiry into the past.
    labdb.get_connection(db_path).execute(
        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
        (EXPIRED_AT, auth.hash_token(token)),
    )
    labdb.get_connection(db_path).commit()

    status, body, _h = client.get(
        "/api/auth/me", headers={"Cookie": f"{_SESSION_COOKIE_NAME}={token}"}
    )
    assert status == 200
    assert body["authenticated"] is False
    assert _raw_rows(db_path, "SELECT * FROM sessions") == []


def test_a_malformed_cookie_header_is_ignored(client):
    register(client, "alice")
    login(client, "alice")
    status, body, _h = client.get(
        "/api/auth/me", headers={"Cookie": "garbage;;;=;;;not-a-cookie"}
    )
    assert status == 200
    assert body["authenticated"] is False


# ------------------------------------------------------------------- logout

def test_logout_clears_the_session_server_side(client, lab_server):
    _host, _port, db_path = lab_server
    register(client, "alice")
    login(client, "alice")
    assert len(_raw_rows(db_path, "SELECT * FROM sessions")) == 1

    status, _body, _h = client.post("/api/auth/logout")

    assert status == 200
    assert _raw_rows(db_path, "SELECT * FROM sessions") == []


def test_logout_expires_the_cookie(client):
    register(client, "alice")
    login(client, "alice")
    _status, _body, headers = client.post("/api/auth/logout")

    raw = headers["Set-Cookie"]
    assert "Max-Age=0" in raw
    assert "HttpOnly" in raw
    assert "SameSite=Lax" in raw


def test_me_is_unauthenticated_after_logout(client):
    register(client, "alice")
    login(client, "alice")
    assert client.get("/api/auth/me")[1]["authenticated"] is True

    client.post("/api/auth/logout")

    assert client.get("/api/auth/me")[1]["authenticated"] is False


def test_logout_works_even_when_the_browser_keeps_the_cookie(client):
    register(client, "alice")
    _s, _b, headers = login(client, "alice")
    stale = headers["Set-Cookie"].split(";")[0]

    client.post("/api/auth/logout")

    # The browser still presents the old cookie; the server must refuse it.
    status, body, _h = client.get("/api/auth/me", headers={"Cookie": stale})
    assert status == 200
    assert body["authenticated"] is False


def test_logout_without_a_session_is_harmless(client):
    status, body, _h = client.post("/api/auth/logout")
    assert status == 200
    assert body["authenticated"] is False


# ------------------------------------------------------------------ routing

def test_unknown_auth_endpoints_are_404(client):
    assert client.post("/api/auth/nope", {})[0] == 404
    assert client.get("/api/auth/nope")[0] == 404
    assert client.get("/api/auth/register")[0] == 404


def test_the_server_is_threaded():
    assert issubclass(serve_training.LabServer, __import__("socketserver").ThreadingMixIn)
    assert serve_training.LabServer.daemon_threads is True


# ---------------------------------------------------------- existing platform

def test_existing_answer_endpoints_still_work(client):
    status, body, _h = client.post(
        "/api/check",
        {
            "scenario": "scenario-1",
            "answers": {
                "q1": "203.0.113.45 and web-01",
                "q2": "root 5 times and admin 5 times",
                "q3": "10 failed logons spanning 132 seconds",
                "q4": "brute_force; min_failures: 5 and time_window_minutes: 5",
                "q5": "No, there is no logon_success for that source IP",
                "q6": "Three events on fw-01: 203.0.113.45 to 10.0.0.10 port 22",
                "q7": "svc_backup from 10.0.0.30 had 4 failures, below the threshold of 5",
            },
        },
    )
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions"}
    assert body["verdict"] == "complete"
    assert body["completed"] is True


def test_reveal_endpoint_still_works(client):
    status, body, _h = client.post(
        "/api/reveal", {"scenario": "scenario-1", "question": "q1"}
    )
    assert status == 200
    assert set(body) == {
        "scenario", "question", "label", "solution", "review_prompt", "assisted",
    }
    assert body["assisted"] is True


def test_check_endpoint_needs_no_authentication(client):
    # No cookie was ever set in this test, yet grading works.
    status, _body, _h = client.post(
        "/api/check", {"scenario": "scenario-1", "answers": {"q1": "203.0.113.45"}}
    )
    assert status == 200


def test_es_status_endpoint_still_answers(client):
    status, body, _h = client.get("/api/es-status")
    assert status == 200
    assert "ok" in body


def test_unknown_api_endpoint_is_still_404(client):
    status, body, _h = client.get("/api/nope")
    assert status == 404
    assert "error" in body


def test_training_pages_are_still_served(client):
    for path in ("/", "/instructions.html", "/scenarios/scenario-1-brute-force.html"):
        status, _body, _h = client.get(path)
        assert status == 200, path


# ----------------------------------------------------------------- concurrency

def test_concurrent_registrations_all_succeed(lab_server):
    host, port, db_path = lab_server
    names = [f"student{i:02d}" for i in range(12)]
    results = {}
    errors = []
    barrier = threading.Barrier(len(names))

    def worker(name):
        c = LabClient(host, port)
        try:
            barrier.wait(timeout=20)
            status, body, _h = register(c, name)
            results[name] = (status, body)
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
        finally:
            c.set_cookie_from({})

    threads = [threading.Thread(target=worker, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == []
    assert all(status == 201 for status, _b in results.values())
    assert len(results) == len(names)

    rows = _raw_rows(db_path, "SELECT username FROM users")
    assert len(rows) == len(names)
    assert {r["username"] for r in rows} == set(names)
    # Distinct primary keys: no lost update or reused id.
    ids = [r["id"] for r in _raw_rows(db_path, "SELECT id FROM users")]
    assert len(set(ids)) == len(names)


def test_concurrent_registration_of_one_name_creates_exactly_one_account(lab_server):
    host, port, db_path = lab_server
    statuses = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        c = LabClient(host, port)
        barrier.wait(timeout=20)
        status, _body, _h = register(c, "contested")
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert len(statuses) == 8
    assert statuses.count(201) == 1
    assert statuses.count(409) == 7
    assert "database is locked" not in "".join(map(str, statuses))
    assert len(_raw_rows(db_path, "SELECT * FROM users")) == 1


def test_concurrent_logins_keep_sessions_separate(lab_server):
    """No student may ever see another student's identity."""
    host, port, db_path = lab_server
    names = [f"student{i:02d}" for i in range(8)]

    for name in names:
        register(LabClient(host, port), name)

    observed = {}
    errors = []
    barrier = threading.Barrier(len(names))

    def worker(name):
        c = LabClient(host, port)
        try:
            barrier.wait(timeout=30)
            status, _body, headers = login(c, name)
            c.set_cookie_from(headers)
            me_status, me_body, _h = c.get("/api/auth/me")
            observed[name] = (status, me_status, me_body.get("user", {}).get("username"))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)

    assert errors == []
    for name in names:
        assert observed[name] == (200, 200, name), f"session crossed users for {name}"

    # Every session row belongs to a distinct user.
    rows = _raw_rows(db_path, "SELECT user_id FROM sessions")
    assert len(rows) == len(names)
    assert len({r["user_id"] for r in rows}) == len(names)


def test_concurrent_mixed_traffic_does_not_lock_the_database(lab_server):
    """Registrations, logins and identity checks all at once."""
    host, port, db_path = lab_server
    names = [f"student{i:02d}" for i in range(10)]
    for name in names:
        register(LabClient(host, port), name)

    outcomes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(len(names) * 3)

    def work(kind, name):
        c = LabClient(host, port)
        try:
            barrier.wait(timeout=30)
            if kind == "login":
                status, _b, headers = login(c, name)
                c.set_cookie_from(headers)
                c.get("/api/auth/me")
            elif kind == "register":
                status, _b, _h = register(c, f"{name}-extra")
            else:  # read-only grading, unchanged and still stateless
                status, _b, _h = c.post(
                    "/api/check", {"scenario": "scenario-1", "answers": {"q1": "x"}}
                )
            with lock:
                outcomes.append(status)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{kind}/{name}: {type(exc).__name__}: {exc}")

    threads = []
    for name in names:
        for kind in ("login", "register", "check"):
            threads.append(threading.Thread(target=work, args=(kind, name)))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    assert errors == [], errors
    assert all(status < 500 for status in outcomes)
    assert outcomes.count(201) == len(names)          # every "*-extra" registered
    assert outcomes.count(200) == len(names) * 2      # logins and checks
    assert len(outcomes) == len(names) * 3
    # 10 original + 10 extra accounts, and no database was locked out.
    assert len(_raw_rows(db_path, "SELECT * FROM users")) == len(names) * 2


def test_a_burst_of_simultaneous_connections_is_served(lab_server):
    """Each connection gets its own thread; none is refused or dropped."""
    host, port, _db = lab_server
    count = 24
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(count)

    def worker():
        barrier.wait(timeout=30)
        c = LabClient(host, port)
        status, _body, _h = c.get("/api/auth/me")
        with lock:
            results.append(status)

    threads = [threading.Thread(target=worker) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert results == [200] * count


# ------------------------------------------------------------------ log hygiene

def test_nothing_sensitive_is_written_to_the_log_stream(client, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["serve_training.py", "--verbose"])
    register(client, "alice")
    _s, _b, headers = login(client, "alice")
    token = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
    client.get("/api/auth/me")

    captured = capsys.readouterr()
    for secret in (PASSWORD, token, auth.hash_token(token)):
        assert secret not in captured.out
        assert secret not in captured.err


def test_the_session_token_is_never_carried_in_a_url(client):
    register(client, "alice")
    _s, _b, headers = login(client, "alice")
    token = headers["Set-Cookie"].split(";")[0].split("=", 1)[1]

    # No auth endpoint accepts a token, and none reflects it back.
    for path in ("/api/auth/me", "/api/auth/logout"):
        status, body, _h = client.get(path)
        assert token not in json.dumps(body)
        assert status in (200, 404)
    status, body, _h = client.post("/api/auth/login", {"token": token})
    assert token not in json.dumps(body)


def test_the_answer_key_is_not_readable_through_the_server(client):
    for path in (
        "/data/answer-key.json",
        "/answer-key.json",
        "/../data/answer-key.json",
        "/scripts/answer_grader.py",
    ):
        status, _body, _h = client.get(path)
        assert status == 404, path


# ------------------------------------------------------------ real database

def test_this_suite_never_opens_the_real_database(tmp_path):
    """The real database may exist; running this suite must not change it."""
    before = _fingerprint(REAL_DB)

    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        user = auth.register_user("isolation.probe", PASSWORD, path=path)
        auth.authenticate("isolation.probe", PASSWORD, path=path)
        token, _row = auth.create_session(user["id"], path=path)
        assert auth.resolve_session(token, path=path) is not None
        auth.delete_session(token, path=path)
    finally:
        labdb.close_connection(path)
        labdb.reset_connections()

    assert _fingerprint(REAL_DB) == before
