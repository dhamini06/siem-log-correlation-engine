"""Tests for the reveal policy that closes audit finding H-1.

Before this, ``POST /api/reveal`` was anonymous and unthrottled: 46 of 46 model
solutions came back in about half a second. These tests pin the three
properties that fix that - a session is required, the student must have tried
the scenario first, and reveals are throttled per user - and pin the things
that must not have changed while fixing it.

Every test uses a throwaway database in ``tmp_path``. The real
``data/training.db`` is never opened.
"""

import hashlib
import http.client
import json
import os
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
REAL_DB = os.path.join(ROOT, "data", "answer-key.json")  # never read
REAL_STUDENT_DB = os.path.join(ROOT, "data", "training.db")

PASSWORD = "correct-horse-battery-staple"
SCENARIO = "scenario-1"


def _fingerprint(path):
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    info = os.stat(path)
    return (info.st_size, info.st_mtime_ns, digest)


def _raw_rows(db_path, sql, params=()):
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


class LabClient:
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
            raw = response.read().decode("utf-8", "replace")
            response_headers = dict(response.getheaders())
            set_cookie = response_headers.get("Set-Cookie")
            if set_cookie:
                if "Max-Age=0" in set_cookie:
                    self.cookie = None
                else:
                    self.cookie = set_cookie.split(";")[0]
            try:
                parsed = json.loads(raw) if raw else {}
            except ValueError:
                parsed = {"_raw": raw[:200]}
            return response.status, parsed, response_headers
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "training.db")
    labdb.init_db(path)
    yield path
    labdb.close_connection(path)
    labdb.reset_connections()


@pytest.fixture(autouse=True)
def clean_policy():
    reveal_policy.reset()
    yield
    reveal_policy.reset()


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


def sign_in(client, username="alice", password=PASSWORD):
    client.post("/api/auth/register", {"username": username, "password": password})
    return client.post("/api/auth/login", {"username": username, "password": password})


def check(client, scenario=SCENARIO, question="s1e1", answer="203.0.113.45 -> web-01"):
    return client.post(
        "/api/check", {"scenario": scenario, "answers": {question: answer}}
    )


def reveal(client, scenario=SCENARIO, question="s1e1"):
    return client.post("/api/reveal", {"scenario": scenario, "question": question})


# ------------------------------------------------- 1. anonymous is refused

def test_anonymous_reveal_is_rejected(client):
    """The core of H-1: no session, no model answer."""
    status, body, headers = reveal(client)
    assert status == 401
    assert "error" in body
    assert "solution" not in body
    # The stale cookie is cleared so the page stops presenting it.
    assert "Max-Age=0" in headers.get("Set-Cookie", "")


def test_anonymous_reveal_cannot_enumerate_the_whole_key(client):
    """The exact harvest from the audit must now return nothing."""
    harvested = []
    for scenario in ("scenario-1", "scenario-2", "scenario-3",
                     "scenario-4", "scenario-5"):
        for question in range(1, 12):
            status, body, _h = reveal(client, scenario, "q%d" % question)
            if status == 200 and body.get("solution"):
                harvested.append((scenario, question))
    assert harvested == []


def test_anonymous_cannot_reveal_with_a_forged_cookie(client):
    status, body, _h = client.post(
        "/api/reveal", {"scenario": SCENARIO, "question": "s1e1"},
        headers={"Cookie": "bc_lab_session=made-up-token"},
    )
    assert status == 401
    assert "solution" not in body


def test_logged_out_student_loses_reveal_access(client):
    sign_in(client)
    check(client)
    assert reveal(client)[0] == 200
    client.post("/api/auth/logout")
    assert reveal(client)[0] == 401


# -------------------------------------------- 2. the policy gate and happy path

def test_reveal_before_any_check_is_refused(client):
    """Investigate, answer, check - and only then consult the model answer."""
    sign_in(client)
    status, body, _h = reveal(client)
    assert status == 403
    assert "solution" not in body


def test_reveal_after_a_check_is_allowed(client):
    sign_in(client)
    check(client)
    status, body, _h = reveal(client)
    assert status == 200
    assert body["scenario"] == SCENARIO
    assert body["question"] == "s1e1"
    assert body["assisted"] is True
    assert body["solution"]  # the training feature still works


def test_a_check_of_a_different_scenario_does_not_unlock_this_one(client):
    sign_in(client)
    check(client, scenario="scenario-2")
    assert reveal(client, scenario=SCENARIO)[0] == 403


def test_an_anonymous_check_does_not_unlock_a_student(client):
    """A check only counts when it comes from a session - otherwise the gate
    would be free to walk around."""
    sign_in(client, "alice")
    other = LabClient(client.host, client.port)   # no cookie
    other.post("/api/check", {"scenario": SCENARIO, "answers": {"s1e1": "x"}})
    assert reveal(client)[0] == 403


def test_the_show_hide_ui_contract_is_preserved(client):
    """The frontend needs the same fields it always read."""
    sign_in(client)
    check(client)
    _status, body, _h = reveal(client)
    assert set(body) == {
        "scenario", "question", "label", "solution", "review_prompt", "assisted",
    }
    assert isinstance(body["label"], str) and body["label"]


# ------------------------------------------------------ 3. malformed input

def test_malformed_scenario_is_rejected_the_same_way_as_before(client):
    sign_in(client)
    check(client)
    for bad in ("nope", "../../data/answer-key.json", "SCENARIO-1",
                "scenario-1; DROP TABLE users", ""):
        status, body, _h = reveal(client, bad, "s1e1")
        assert status == 400, bad
        assert "solution" not in body


def test_malformed_question_is_rejected(client):
    sign_in(client)
    check(client)
    for bad in ("s9e9", "../q1", "*", ""):
        status, body, _h = reveal(client, SCENARIO, bad)
        assert status == 400, bad
        assert "solution" not in body


def test_malformed_json_is_rejected(client):
    sign_in(client)
    status, body, _h = client.post("/api/reveal", "{not json")
    assert status == 400
    assert "solution" not in body


def test_path_traversal_in_scenario_is_rejected(client):
    sign_in(client)
    check(client)
    for bad in ("../../../etc/passwd", "/data/answer-key.json",
                "..\\..\\data\\answer-key.json", "%2e%2e/data/answer-key.json"):
        status, body, _h = reveal(client, bad, "s1e1")
        assert status in (400, 403), bad
        assert "solution" not in body


# ------------------------------------------------------------ 4. throttling

def test_repeated_reveals_are_throttled(client):
    sign_in(client)
    check(client)
    statuses = []
    # Distinct questions, spaced past the cooldown so only the window limit bites.
    for index in range(reveal_policy.REVEAL_RATE_LIMIT + 4):
        reveal_policy.note_check(1, SCENARIO)
        # Neutralise the per-user cooldown so this test measures the window
        # limit alone; the cooldown is covered separately.
        if 1 in reveal_policy._reveals:
            window_start, count, _last = reveal_policy._reveals[1]
            reveal_policy._reveals[1] = (window_start, count, 0.0)
        status, body, _h = reveal(client, SCENARIO, "s1e%d" % (index % 8 + 1))
        statuses.append(status)
    assert 429 in statuses


def test_a_throttled_reveal_returns_retry_after(client):
    sign_in(client)
    check(client)
    reveal_policy.note_check(1, SCENARIO)
    _status, _body, _h = reveal(client, SCENARIO, "s1e1")
    immediate = reveal(client, SCENARIO, "s1e2")
    assert immediate[0] == 429
    assert "Retry-After" in immediate[2]
    assert int(immediate[2]["Retry-After"]) >= 1
    assert "solution" not in immediate[1]


def test_concurrent_reveals_cannot_bypass_the_throttle(client, lab_server):
    """A burst from many threads must not hand out more than the policy allows."""
    sign_in(client)
    check(client)
    allowed, refused = [], []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def worker(index):
        local = LabClient(client.host, client.port)
        local.cookie = client.cookie
        try:
            barrier.wait(timeout=30)
            status, body, _h = reveal(local, SCENARIO, "q%d" % (index % 9 + 1))
            with lock:
                (allowed if status == 200 else refused).append(status)
        except Exception:  # noqa: BLE001
            with lock:
                refused.append(None)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)

    assert len(allowed) + len(refused) == 16
    # The cooldown alone caps this well below 16.
    assert len(allowed) <= 4, "cooldown did not hold under concurrency"
    assert refused


def test_two_students_have_independent_allowances(client, lab_server):
    _host, _port, _db = lab_server
    sign_in(client, "alice")
    check(client)
    reveal(client, SCENARIO, "s1e1")          # alice uses one
    second = LabClient(client.host, client.port)
    sign_in(second, "bob")
    check(second)
    # Bob is not affected by Alice's usage.
    assert reveal(second, SCENARIO, "s1e1")[0] == 200


def test_the_throttle_is_keyed_on_identity_not_on_a_spoofable_header(client):
    sign_in(client)
    check(client)
    reveal(client, SCENARIO, "s1e1")
    status, _body, _h = client.post(
        "/api/reveal", {"scenario": SCENARIO, "question": "s1e2"},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert status == 429  # the header did not buy a fresh allowance


# ---------------------------------------------- 5. no key metadata leaked

def test_no_answer_key_metadata_is_returned(client):
    sign_in(client)
    check(client)
    _status, body, _h = reveal(client)
    serialised = json.dumps(body)
    for forbidden in ("accept", "patterns", "required", "parts", "scrypt$",
                      "answer-key", "password_hash"):
        assert forbidden not in serialised


def test_a_refused_reveal_never_leaks_a_solution(client):
    sign_in(client)
    no_attempt = reveal(client)                                   # 403
    check(client)
    bad_scenario = client.post(                                   # 400
        "/api/reveal", {"scenario": "bogus", "question": "s1e1"}
    )
    for _status, body, _h in (no_attempt, bad_scenario):
        assert "solution" not in json.dumps(body)
        assert "accept" not in json.dumps(body)


def test_revealing_does_not_write_answer_text_to_the_database(client, lab_server):
    _host, _port, db_path = lab_server
    sign_in(client)
    check(client)
    reveal(client)
    rows = _raw_rows(db_path, "SELECT * FROM scenario_checks")
    assert rows, "an assisted record should exist"
    for row in rows:
        for value in row.values():
            if isinstance(value, str):
                assert "203.0.113.45" not in value, "answer text was persisted"


def test_the_assisted_flag_is_recorded(client, lab_server):
    _host, _port, db_path = lab_server
    sign_in(client)
    check(client)
    reveal(client)
    rows = _raw_rows(db_path, "SELECT assisted FROM scenario_checks")
    assert any(row["assisted"] == 1 for row in rows)


# --------------------------------- 6. /api/check must be unchanged by this

def test_check_still_works_anonymously(client):
    status, body, _h = client.post(
        "/api/check", {"scenario": SCENARIO, "answers": {"s1e1": "203.0.113.45 and web-01"}}
    )
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_check_response_shape_is_unchanged_for_a_signed_in_student(client):
    sign_in(client)
    status, body, _h = check(client)
    assert status == 200
    assert set(body) == {"scenario", "title", "verdict", "completed", "summary", "questions",
                "scoped", "checked"}


def test_a_signed_in_check_writes_no_progress_row(client, lab_server):
    """A check must not become progress persistence - that is a later phase."""
    _host, _port, db_path = lab_server
    sign_in(client)
    check(client)
    assert _raw_rows(db_path, "SELECT * FROM scenario_checks") == []


def test_reveal_unknown_endpoint_still_404s(client):
    assert client.get("/api/reveal")[0] == 404
    assert client.post("/api/reveal2", {})[0] == 404


# ------------------------------------------- 7. policy unit-level behaviour

def test_policy_refuses_an_anonymous_user_id():
    with pytest.raises(reveal_policy.RevealNotPermitted):
        reveal_policy.evaluate(None, SCENARIO, "s1e1")


def test_policy_requires_an_attempt():
    with pytest.raises(reveal_policy.RevealNotPermitted):
        reveal_policy.evaluate(7, SCENARIO, "s1e1")
    reveal_policy.note_check(7, SCENARIO)
    reveal_policy.evaluate(7, SCENARIO, "s1e1")   # now permitted


def test_the_attempt_window_expires():
    reveal_policy.note_check(7, SCENARIO)
    assert reveal_policy.has_attempt(7, SCENARIO) is True
    record = reveal_policy._attempts[7][SCENARIO]
    reveal_policy._attempts[7][SCENARIO] = record - reveal_policy.ATTEMPT_WINDOW_SECONDS - 1
    assert reveal_policy.has_attempt(7, SCENARIO) is False


def test_the_per_question_cap_backstops_a_single_question_script():
    reveal_policy.note_check(7, SCENARIO)
    for _ in range(reveal_policy.REVEAL_PER_QUESTION_CAP):
        reveal_policy.note_check(7, SCENARIO)
        reveal_policy._reveals[7] = (0.0, 0, 0.0)   # ignore cooldown/window
        reveal_policy.evaluate(7, SCENARIO, "s1e1")
    # Neutralise the cooldown and window so the *cap* is what fails, not the
    # rate limiter - otherwise this test would pass for the wrong reason.
    reveal_policy.note_check(7, SCENARIO)
    reveal_policy._reveals[7] = (0.0, 0, 0.0)
    with pytest.raises(reveal_policy.RevealNotPermitted):
        reveal_policy.evaluate(7, SCENARIO, "s1e1")


def test_the_policy_tables_are_bounded():
    original = reveal_policy.MAX_TRACKED_USERS
    try:
        reveal_policy.MAX_TRACKED_USERS = 8
        for index in range(500):
            reveal_policy.note_check(index, SCENARIO)
        assert len(reveal_policy._attempts) <= 8
    finally:
        reveal_policy.MAX_TRACKED_USERS = original


def test_the_policy_is_thread_safe():
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=20)
            for step in range(25):
                reveal_policy.note_check(index, SCENARIO)
                try:
                    reveal_policy.evaluate(index, SCENARIO, "q%d" % (step % 9 + 1))
                except (reveal_policy.RevealNotPermitted, reveal_policy.RevealThrottled):
                    pass
        except Exception as exc:  # noqa: BLE001
            errors.append("%s: %s" % (type(exc).__name__, exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []


# ------------------------------------------------------- 8. real DB untouched

def test_this_suite_never_opens_the_real_student_database(tmp_path):
    before = _fingerprint(REAL_STUDENT_DB)
    path = str(tmp_path / "probe.db")
    labdb.init_db(path)
    try:
        user = auth.register_user("probe", PASSWORD, path=path)
        reveal_policy.note_check(user["id"], SCENARIO)
        reveal_policy.evaluate(user["id"], SCENARIO, "s1e1")
        labdb.record_scenario_check(user["id"], SCENARIO, assisted=True, path=path)
    finally:
        labdb.close_connection(path)
        labdb.reset_connections()
    assert _fingerprint(REAL_STUDENT_DB) == before
