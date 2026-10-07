"""Tests for instructor/admin provisioning (scripts/create_admin.py).

The point of these tests is that the admin account is *hard to create by
accident*. The command is the only route to ``role='admin'``, it is interactive,
and the public registration endpoint must stay incapable of producing an admin
no matter what a caller sends.

Every test uses a throwaway database in ``tmp_path``. The real
``data/training.db`` is never opened and is fingerprinted at the end to prove
it - and it must still contain no admin afterwards, because nothing in the test
suite may provision one.
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
import create_admin  # noqa: E402
import labdb  # noqa: E402
import serve_training  # noqa: E402

TRAINING = os.path.join(ROOT, "training")
REAL_DB = os.path.join(ROOT, "data", "training.db")
PASSWORD = "Instructor-Pass-4d7b2e"
OTHER_PASSWORD = "a-different-instructor-pass"


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


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "admin.db")
    labdb.init_db(path)
    yield path
    labdb.close_connection(path)
    labdb.reset_connections()


@pytest.fixture()
def server(tmp_path):
    """A live server on a throwaway database, for the public-route tests."""
    db_path = str(tmp_path / "server.db")
    labdb.init_db(db_path)
    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    srv = serve_training.LabServer(("127.0.0.1", 0), handler)
    srv.db_path = db_path
    srv.force_secure_cookies = False
    auth.reset_rate_limits()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", srv.server_address[1], db_path
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=10)
        labdb.close_connection(db_path)
        labdb.reset_connections()
        auth.reset_rate_limits()


def post(host, port, path, body, cookie=None):
    import json
    conn = http.client.HTTPConnection(host, port, timeout=20)
    try:
        h = {"Content-Type": "application/json"}
        if cookie:
            h["Cookie"] = cookie
        conn.request("POST", path, body=json.dumps(body), headers=h)
        r = conn.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw.decode("utf-8")), r.getheader("Set-Cookie")
        except ValueError:
            return r.status, {"_raw": raw[:120].decode("utf-8", "replace")}, r.getheader("Set-Cookie")
    finally:
        conn.close()


def get(host, port, path):
    conn = http.client.HTTPConnection(host, port, timeout=20)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        return r.status, r.getheader("Location")
    finally:
        conn.close()


# ============================================ provisioning creates an admin

def test_provisioning_creates_exactly_one_admin(db):
    user = create_admin.create_admin("instructor", PASSWORD, path=db)

    assert user["username"] == "instructor"
    assert user["role"] == "admin"
    rows = _rows(db, "SELECT username, role FROM users")
    assert rows == [{"username": "instructor", "role": "admin"}]
    assert len([r for r in rows if r["role"] == "admin"]) == 1


def test_provisioning_creates_no_student(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    roles = [r["role"] for r in _rows(db, "SELECT role FROM users")]
    assert "student" not in roles


def test_the_password_is_stored_hashed(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    stored = _rows(db, "SELECT password_hash FROM users")[0]["password_hash"]

    assert stored.startswith("scrypt$")
    assert "password" not in stored.lower()
    # The hash came from the shared helper, so it verifies there and nowhere
    # else - there is no second implementation to drift.
    assert auth.verify_password(PASSWORD, stored) is True


def test_the_plaintext_password_is_never_stored(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    stored = _rows(db, "SELECT password_hash FROM users")[0]["password_hash"]

    assert PASSWORD not in stored
    assert "Instructor-Pass" not in stored
    # And nowhere in the file itself.
    with open(db, "rb") as handle:
        assert PASSWORD.encode() not in handle.read()


def test_duplicate_admin_username_is_rejected(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    before = _rows(db, "SELECT * FROM users")

    with pytest.raises(create_admin.DuplicateAdmin):
        create_admin.create_admin("instructor", OTHER_PASSWORD, path=db)

    after = _rows(db, "SELECT * FROM users")
    assert len(after) == len(before) == 1
    # The first account must be untouched, not re-hashed.
    assert after[0]["password_hash"] == before[0]["password_hash"]
    assert auth.verify_password(PASSWORD, after[0]["password_hash"])


def test_an_admin_cannot_shadow_an_existing_student(db):
    """A duplicate is refused even when the existing row is a student."""
    auth.register_user("instructor", PASSWORD, path=db)
    with pytest.raises(create_admin.DuplicateAdmin):
        create_admin.create_admin("instructor", OTHER_PASSWORD, path=db)
    roles = [r["role"] for r in _rows(db, "SELECT role FROM users")]
    assert roles == ["student"], "an existing student must not be promoted"


def test_provisioning_validates_username(db):
    for bad in ("", "  ", "ab", "x" * 33, "has space", 'quote"inject'):
        with pytest.raises(auth.AuthenticationError):
            create_admin.create_admin(bad, PASSWORD, path=db)
    assert _rows(db, "SELECT * FROM users") == []


def test_provisioning_validates_password(db):
    for bad in ("", "short", "x" * 201):
        with pytest.raises(auth.AuthenticationError):
            create_admin.create_admin("instructor", bad, path=db)
    assert _rows(db, "SELECT * FROM users") == []


def test_validation_errors_never_echo_the_password(db):
    try:
        create_admin.create_admin("instructor", "a-very-distinctive-secret", path=db)
    except Exception as exc:
        assert "a-very-distinctive-secret" not in str(exc)


# ============================================== admin authenticates normally

def test_an_admin_can_authenticate_through_the_existing_login(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)

    user = auth.authenticate("instructor", PASSWORD, path=db)

    assert user["username"] == "instructor"
    assert user["role"] == "admin"
    assert "password_hash" not in user


def test_an_invalid_password_cannot_authenticate(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)

    with pytest.raises(auth.InvalidCredentials):
        auth.authenticate("instructor", OTHER_PASSWORD, path=db)
    with pytest.raises(auth.InvalidCredentials):
        auth.authenticate("instructor", "", path=db)
    with pytest.raises(auth.InvalidCredentials):
        auth.authenticate("instructor", PASSWORD + "x", path=db)


def test_an_admin_gets_a_session_just_like_a_student(db):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    user = auth.authenticate("instructor", PASSWORD, path=db)

    token, _row = auth.create_session(user["id"], path=db)

    resolved = auth.resolve_session(token, path=db)
    assert resolved["role"] == "admin"
    assert resolved["username"] == "instructor"


# ================================= public registration cannot create admin

def test_public_registration_cannot_create_an_admin(server):
    host, port, _db = server
    status, body, _c = post(host, port, "/api/auth/register",
                            {"username": "sneaky", "password": PASSWORD,
                             "role": "admin"})
    assert status == 201
    assert body["user"]["role"] == "student"
    # Nothing leaked in the response either.
    assert "admin" not in json.dumps(body) or body["user"]["role"] == "student"


@pytest.mark.parametrize("role", [
    "admin", "ADMIN", "Admin", "administrator", "root", "superuser",
    "instructor", "staff", ["admin"], {"role": "admin"},
])
def test_no_role_value_in_a_registration_body_escalates(server, role):
    host, port, db_path = server
    post(host, port, "/api/auth/register",
         {"username": "sneaky", "password": PASSWORD, "role": role})
    roles = [r["role"] for r in _rows(db_path, "SELECT role FROM users")]
    assert set(roles) <= {"student"}


def test_student_registration_still_creates_a_student(server):
    host, port, db_path = server
    status, body, _c = post(host, port, "/api/auth/register",
                            {"username": "a.student", "password": PASSWORD})
    assert status == 201
    assert body["user"]["role"] == "student"
    assert _rows(db_path, "SELECT role FROM users") == [{"role": "student"}]


def test_register_user_has_no_role_parameter_to_set():
    """The structural reason the endpoint cannot make an admin."""
    import inspect
    params = inspect.signature(auth.register_user).parameters
    assert "role" not in params


def test_there_is_no_admin_registration_route(server):
    host, port, _db = server
    for path in ("/api/auth/register-admin", "/api/auth/admin",
                 "/api/auth/signup", "/api/admin/register",
                 "/api/admin/users", "/admin.html", "/admin",
                 "/register-admin.html", "/signup.html"):
        # /api/admin/* is session-gated before routing, so an anonymous caller
        # is refused with 401 before the route is even looked up. Any of 302,
        # 401 or 404 is a refusal; none of them is a working signup.
        status, _location = get(host, port, path)
        assert status in (302, 401, 404), path


def test_an_admin_cannot_be_created_over_http_after_provisioning(server):
    """Even with a real admin present, the public route still makes students."""
    host, port, db_path = server
    create_admin.create_admin("instructor", PASSWORD, path=db_path)

    post(host, port, "/api/auth/register",
         {"username": "second", "password": OTHER_PASSWORD, "role": "admin"})

    roles = {r["username"]: r["role"]
             for r in _rows(db_path, "SELECT username, role FROM users")}
    assert roles == {"instructor": "admin", "second": "student"}


# ======================================== nothing auto-provisions an admin

def test_init_db_does_not_create_an_account(db):
    labdb.init_db(db)
    labdb.init_db(db)
    assert _rows(db, "SELECT * FROM users") == []


def test_starting_a_server_creates_no_admin(tmp_path):
    db_path = str(tmp_path / "boot.db")
    labdb.init_db(db_path)
    handler = lambda *a, **kw: serve_training.LabRequestHandler(
        *a, directory=TRAINING, **kw
    )
    srv = serve_training.LabServer(("127.0.0.1", 0), handler)
    srv.db_path = db_path
    srv.force_secure_cookies = False
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = "127.0.0.1", srv.server_address[1]
        get(host, port, "/login.html")
        get(host, port, "/")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=10)
    assert _rows(db_path, "SELECT * FROM users") == []


@pytest.mark.parametrize("script", [
    "scripts/serve_training.py", "scripts/start_lab.ps1", "scripts/setup.ps1",
    "docker-compose.yml", "docker-compose.prod.yml",
])
def test_no_startup_script_provisions_an_admin(script):
    """A silent admin created at boot would be a backdoor, not a convenience."""
    source = open(os.path.join(ROOT, script.replace("/", os.sep)), encoding="utf-8").read()
    assert "create_admin" not in source, script


def test_the_test_suite_never_provisions_into_the_real_database():
    """Belt and braces: every provisioning call in this file must name a database.

    Parsed rather than grepped. A line-based scan cannot tell a real call from
    the scan's own pattern string, so it would always match itself; the AST can.
    A future test that forgets ``path=`` and falls back to the real
    data/training.db is caught here, instead of by an account mysteriously
    appearing in the lab database.
    """
    import ast
    tree = ast.parse(open(os.path.abspath(__file__), encoding="utf-8").read())

    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "create_admin":
            calls.append(node)

    assert calls, "expected at least one provisioning call to inspect"
    for call in calls:
        keywords = {kw.arg for kw in call.keywords if kw.arg}
        assert "path" in keywords, (
            "create_admin() called without path= (line %d); it would default "
            "to the real data/training.db" % call.lineno
        )


# ============================================== the interactive command

def test_the_prompt_creates_an_admin_and_never_echoes_the_password(db, monkeypatch, capsys):
    answers = iter(["instructor", PASSWORD, PASSWORD])
    asked = []

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(create_admin.getpass, "getpass",
                        lambda _prompt="": (asked.append(_prompt), next(answers))[1])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    user = create_admin.prompt_for_admin(path=db)
    out = capsys.readouterr()

    assert user["role"] == "admin"
    # It asked for the password twice, and used getpass (which does not echo).
    assert asked == ["Password: ", "Confirm password: "]
    # Nothing on either stream contains the secret.
    assert PASSWORD not in out.out
    assert PASSWORD not in out.err
    assert "scrypt$" not in out.out
    # The username is safe and useful to echo.
    assert "instructor" in out.out


def test_a_mismatched_confirmation_is_refused_then_retried(db, monkeypatch, capsys):
    # username, then a mismatched pair, then a matching one: two confirmations.
    answers = iter(["instructor", PASSWORD, OTHER_PASSWORD,
                    OTHER_PASSWORD, OTHER_PASSWORD])
    asked = []

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(create_admin.getpass, "getpass",
                        lambda _prompt="": (asked.append(_prompt), next(answers))[1])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    user = create_admin.prompt_for_admin(path=db)
    out = capsys.readouterr()

    assert user["role"] == "admin"
    assert "did not match" in out.out
    assert asked.count("Confirm password: ") == 2
    assert asked.count("Password: ") == 2
    assert PASSWORD not in out.out and OTHER_PASSWORD not in out.out
    # Only the final, confirmed password was stored.
    stored = _rows(db, "SELECT password_hash FROM users")[0]["password_hash"]
    assert auth.verify_password(OTHER_PASSWORD, stored)
    assert not auth.verify_password(PASSWORD, stored)


def test_an_invalid_password_is_refused_then_retried(db, monkeypatch, capsys):
    # "short" twice, so the pair matches and the length rule is what rejects it.
    answers = iter(["instructor", "short", "short", PASSWORD, PASSWORD])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(create_admin.getpass, "getpass", lambda _prompt="": next(answers))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    user = create_admin.prompt_for_admin(path=db)
    out = capsys.readouterr()

    assert user["role"] == "admin"
    assert "at least 8 characters" in out.out
    assert "short" not in out.out


def test_the_command_refuses_to_run_without_a_terminal(db, monkeypatch, capsys):
    """A pipe would put the password into a script or CI log."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)

    with pytest.raises(SystemExit) as excinfo:
        create_admin.prompt_for_admin(path=db)

    assert excinfo.value.code == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert _rows(db, "SELECT * FROM users") == []


def test_a_refused_duplicate_creates_nothing(db, monkeypatch, capsys):
    create_admin.create_admin("instructor", PASSWORD, path=db)
    answers = iter(["instructor", OTHER_PASSWORD, OTHER_PASSWORD])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(create_admin.getpass, "getpass", lambda _prompt="": next(answers))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)

    result = create_admin.prompt_for_admin(path=db)
    out = capsys.readouterr()

    assert result == {}
    assert "already taken" in out.err
    assert PASSWORD not in out.err and OTHER_PASSWORD not in out.err
    assert len(_rows(db, "SELECT * FROM users")) == 1


def test_main_refuses_and_exits_nonzero_without_a_terminal(tmp_path, monkeypatch, capsys):
    """main() bails out before prompting when there is no terminal."""
    target = str(tmp_path / "cli.db")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        create_admin.main(["--database", target])
    assert excinfo.value.code == 2
    assert "interactive terminal" in capsys.readouterr().err
    # And it created no account in the database it was pointed at.
    assert _rows(target, "SELECT * FROM users") == []


def test_there_is_no_password_command_line_flag():
    """A --password flag would leak through the process list and shell history.

    Only real parser arguments are inspected; the surrounding comments
    deliberately mention the flag to explain why it is absent.
    """
    import inspect
    import re
    source = inspect.getsource(create_admin.main)
    declared = re.findall(r'add_argument\(\s*"([^"]+)"', source)
    assert "--database" in declared
    for forbidden in ("--password", "--username", "--role", "--admin"):
        assert forbidden not in declared, forbidden


def test_no_admin_username_or_password_is_hard_coded_in_the_source():
    """The failure mode is a default admin name or password baked into code."""
    import inspect
    import re
    source = open(os.path.join(ROOT, "scripts", "create_admin.py"), encoding="utf-8").read()

    # No function may carry a default that looks like a credential.
    for name in ("create_admin", "prompt_for_admin", "main"):
        sig = inspect.signature(getattr(create_admin, name))
        for parameter in sig.parameters.values():
            value = parameter.default
            if isinstance(value, str) and value.strip():
                assert "admin" not in value.lower() or parameter.name == "path", (name, value)
                assert "pass" not in value.lower(), (name, value)

    # No call passes a literal password into either entry point.
    calls = re.findall(r"create_admin(?:\.create_admin)?\(\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"", source)
    for username, password in calls:
        assert not password.strip(), (username, password)

    # And the familiar weak-credential shapes are absent outright.
    for weak in ("admin123", "changeme", "letmein", "password123", "admin:admin"):
        assert weak not in source.lower(), weak


# ================================================= the real DB stays clean

def test_this_suite_leaves_the_real_database_without_an_admin(tmp_path):
    before = _fingerprint(REAL_DB)
    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        create_admin.create_admin("probe", PASSWORD, path=path)
        labdb.close_connection(path)
        labdb.reset_connections()
    finally:
        pass
    assert _fingerprint(REAL_DB) == before
