"""Serve the BlueCloud training platform locally (no dependencies).

Uses the Python standard library only, so it runs identically on Windows and
Ubuntu and needs nothing installed beyond the interpreter already required by
the SIEM engine.

    python scripts/serve_training.py

Then open http://localhost:8080

Two POST endpoints back the student answer checker. Both run on the server, so
the answer key never reaches the browser:

    POST /api/check    {"scenario": "...", "answers": {"q1": "..."}}
        -> per-question verdict and, for anything unmatched, a hint.

    POST /api/reveal   {"scenario": "...", "question": "q1"}
        -> the model solution for one question, marked as assisted.
        Requires a signed-in student who has already submitted a check for
        that scenario, and is throttled per user. See scripts/reveal_policy.py
        for why: an anonymous, unthrottled reveal handed out the whole key.

Three more endpoints back student accounts. They are optional: the lab works
exactly as before if nobody ever calls them.

    POST /api/auth/register  {"username": "...", "password": "..."}
    POST /api/auth/login     {"username": "...", "password": "..."}
    GET  /api/auth/me
    POST /api/auth/logout

Authentication gates the student portal. An unauthenticated request for /,
/index.html, /instructions.html or any /scenarios/* page is redirected to
/login.html by this server, not hidden by the page: a client-side gate would
still leave the content readable in "view source". /login.html, /register.html
and the static assets stay public so a visitor can actually sign in.

Neither answer endpoint requires a session. POST /api/check stays stateless and
anonymous so answer checking never depends on an account, and POST /api/reveal
carries its own authentication, attempt gate and throttling (see
scripts/reveal_policy.py).

The key itself lives at ``data/answer-key.json`` — untracked, and outside the
directory served here. It is read only by ``scripts/answer_grader.py``.

Concurrency
    The server is threaded (one thread per request), so a slow Elasticsearch
    health probe cannot block a student's login. SQLite is reached only through
    ``labdb``, which keeps one connection per thread; WAL plus a busy timeout
    then let readers and the writer coexist. Each connection is closed when its
    request thread finishes, so a long-running server does not accumulate them.

For a production-style deployment on Ubuntu, put the `training/` directory
behind nginx or any static web server instead. Note that a purely static
deployment has no answer checking: route /api to this script, or validate
answers offline with the instructor guide.
"""

import argparse
import functools
import http.server
import json
import os
import socket
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.cookies import SimpleCookie

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_stats  # noqa: E402
import answer_grader  # noqa: E402
import auth  # noqa: E402
import labdb  # noqa: E402
import reveal_policy  # noqa: E402
import student_progress  # noqa: E402

TRAINING_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "training")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

DIRECTORY_INDEX = "index.html"
API_PREFIX = "/api/"
AUTH_PREFIX = "/api/auth/"

#: Name of the session cookie. Deliberately not a __Host- prefix, because that
#: would require Secure, which cannot be set on a plain-HTTP lab host. It is
#: HttpOnly and SameSite=Lax, which is what stops script access and cross-site
#: submission.
SESSION_COOKIE = "bc_lab_session"

#: Generic login/register failure text. One message for every cause, so the
#: endpoints cannot be used to discover which usernames exist.
GENERIC_AUTH_ERROR = "invalid username or password"

# --------------------------------------------------------------- portal gate
#
# The student portal is served only to a signed-in student. This is enforced
# here, in the HTTP server, and not in JavaScript: a page that merely hides
# content is still fully readable in "view source", so a client-side gate would
# be theatre. The check runs before the file is opened, so an anonymous request
# never learns whether a page exists, let alone what is in it.
#
# Two things stay public. The sign-in and registration pages have to be
# reachable or nobody can start. Static assets stay reachable because the login
# page is styled by them - gating /assets/ would lock everyone out of the front
# door. Neither carries student content: the stylesheet and scripts are
# presentation and behaviour, and the answer key lives in data/, which is
# outside the served directory entirely.
#
# This is an allowlist. Anything not named is student content, so a page added
# later is protected by default rather than silently becoming public.

#: Exact paths an anonymous visitor may fetch.
PUBLIC_PAGES = frozenset({"/login.html", "/register.html"})

#: Prefixes an anonymous visitor may fetch. Presentational assets only.
PUBLIC_PREFIXES = ("/assets/",)

#: Pages an *administrator* may fetch and a student may not. Kept as its own
#: list rather than folded into PUBLIC_PAGES, because the two need opposite
#: defaults: a student is redirected to sign in, an admin is served. Anything
#: not named here is student content and needs only a session.
ADMIN_PAGES = frozenset({"/admin.html"})

#: API namespaces that require the admin role. Matched by prefix.
ADMIN_API_PREFIX = "admin/"

#: API namespace for a student's own progress. Separate from the admin one
#: because the rules are opposite: a student may read their own, and an admin
#: may not read it here. Instructors get the aggregate and per-student view
#: through /api/admin/* instead, which is the only place another person's
#: progress is exposed.
STUDENT_API_PREFIX = "student/"

#: Where an anonymous browser request is sent. A path, never an absolute URL,
#: so this cannot become an open redirect.
LOGIN_PATH = "/login.html"

#: Body for an admin page a student asked for. Deliberately a constant with no
#: placeholders: the request path and any other input are never reflected into
#: it, so this cannot become a reflection point.
FORBIDDEN_HTML = (
    b'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    b'<title>Instructor area - BlueCloud Softech Solutions</title>'
    b'<link rel="stylesheet" href="/assets/css/bluecloud.css"></head>'
    b'<body data-page="forbidden"><main id="main"><section class="section">'
    b'<div class="wrap"><h1>Instructor area</h1>'
    b'<p class="lede">This page is for instructor accounts only. '
    b'Your account is signed in as a student, so it does not have access.</p>'
    b'<p><a class="btn btn-primary" href="/index.html">Back to the lab</a></p>'
    b'</div></section></main></body></html>'
)
# Where the training platform looks for Elasticsearch. Kept in step with the
# SIEM engine's ES_HOST / ES_PORT environment variables so one setting moves
# both. This is the address the *server* dials, never a Docker-internal name.
ES_HOST = os.environ.get("ES_HOST", "localhost")
ES_PORT = os.environ.get("ES_PORT", "9200")
ES_HEALTH_URL = f"http://{ES_HOST}:{ES_PORT}/_cluster/health"
ES_HEALTH_TIMEOUT = 2.0

# Magic-byte signatures. Brand assets are sometimes supplied with an extension
# that does not match the real format (the BlueCloud logo is a JPEG named .png),
# so the content type is sniffed from the file itself rather than the extension.
IMAGE_SIGNATURES = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


class LabRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Static file handler that serves index.html for directory paths.

    Also implements the two JSON endpoints used by the answer checker.
    """

    def send_head(self):
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            self.path = self.path.rstrip("/") + "/" + DIRECTORY_INDEX
        return super().send_head()

    def end_headers(self):
        # Lab content is edited often; never let a browser cache a stale page.
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def guess_type(self, path):
        """Report the real content type, sniffed from the file's magic bytes.

        Needed because the BlueCloud logo is a JPEG carrying a .png extension.
        Sniffing keeps the image rendering even when a reverse proxy in front of
        this server sets X-Content-Type-Options: nosniff.
        """
        try:
            with open(path, "rb") as handle:
                head = handle.read(16)
        except OSError:
            return super().guess_type(path)
        for signature, mime in IMAGE_SIGNATURES:
            if head.startswith(signature):
                return mime
        if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            return "image/webp"
        if b"<svg" in head:
            return "image/svg+xml"
        return super().guess_type(path)

    def _api_endpoint(self) -> str:
        """The API endpoint name for this request, e.g. ``auth/login``."""
        return self.path.split("?", 1)[0].strip("/")[len("api/"):]

    # ------------------------------------------------------------ portal gate
    def _requested_path(self) -> str:
        """The request path with query and fragment removed, always starting /."""
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/"):
            path = "/" + path
        # A directory request and its index are the same page to a browser.
        if len(path) > 1 and path.endswith("/"):
            path += DIRECTORY_INDEX
        return path

    def _is_public_path(self, path: str) -> bool:
        """Whether this path may be fetched without a session.

        An allowlist, not a denylist: a page added later is protected by
        default instead of silently becoming public.
        """
        if path in PUBLIC_PAGES:
            return True
        return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)

    def _send_login_redirect(self) -> None:
        """Send an anonymous browser to sign in, remembering where it was going.

        Only the path is carried, and the login page re-validates it before
        using it, so this cannot be steered at another origin.
        """
        target = self._requested_path()
        if target in ("/", "/index.html"):
            target = ""            # the home page needs no next
        location = LOGIN_PATH
        if target and target not in PUBLIC_PAGES:
            location += "?next=" + urllib.parse.quote(target, safe="")
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        # Never cacheable, or a browser could be pinned to the redirect.
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()

    def _has_session(self) -> bool:
        """Whether this request carries a valid, unexpired session."""
        return auth.resolve_session(self._cookie_token(), path=self._db_path()) is not None

    # ------------------------------------------------------------- role gate
    def _current_user(self):
        """The signed-in user, or ``None``.

        Always resolved from the session cookie through the database row. No
        request header, query parameter, JSON field or stored value is ever
        consulted, so a client cannot claim a role it does not hold.
        """
        return auth.resolve_session(self._cookie_token(), path=self._db_path())

    def _progress_user(self):
        """The signed-in user id for progress writes, or ``None``.

        Resolved from the session cookie and the database row. There is no
        branch that reads a user id from a query string, a request body or a
        header, so a caller cannot nominate somebody else's account.
        """
        user = self._current_user()
        return user["id"] if user else None

    def _is_student(self, user) -> bool:
        """Whether this resolved user is a student.

        An admin is *not* a student for progress purposes. Instructors have the
        admin dashboard; letting them silently accumulate their own progress
        rows would put instructor activity into the class statistics.
        """
        return bool(user) and user.get("role") == "student"

    def _is_admin(self, user) -> bool:
        """Whether this resolved user holds the admin role."""
        return bool(user) and user.get("role") == "admin"

    def _send_admin_page_refused(self, user) -> None:
        """A signed-in student asking for an admin page gets a flat refusal.

        A redirect to the student portal would be friendlier, but it would also
        quietly imply the admin page does not exist, and it would make a
        misdirected bookmark look like it worked. A 403 says what happened.
        The body is a fixed string: nothing from the request is interpolated,
        so there is nothing here to inject into.
        """
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(FORBIDDEN_HTML)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        try:
            self.wfile.write(FORBIDDEN_HTML)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_admin_api_refused(self) -> None:
        """403 for an admin API. The body says nothing about who is allowed."""
        self._send_json(
            {"error": "administrator access required",
             "authenticated": bool(self._current_user())},
            403,
        )

    def _serve_admin_page(self, path: str) -> bool:
        """Authorise an admin page. True means the caller may serve it.

        Anonymous first, and the answer is the same login redirect the rest of
        the portal uses, so an unauthenticated visitor has one consistent
        behaviour. Only a *signed-in non-admin* reaches the 403.
        """
        user = self._current_user()
        if user is None:
            self._send_login_redirect()
            return False
        if not self._is_admin(user):
            self._send_admin_page_refused(user)
            return False
        return True

    def _db_path(self) -> str:
        """Database this request should use.

        Taken from the server rather than a module global so that tests can run
        a real server against a throwaway database.
        """
        return getattr(self.server, "db_path", None) or labdb.db_path()

    # ------------------------------------------------------------ lab API
    def do_GET(self):
        """Serve /api/* as JSON, and everything else as a gated static page."""
        if self.path.startswith(API_PREFIX):
            endpoint = self._api_endpoint()
            if endpoint == "es-status":
                self._send_json(es_health())
            elif endpoint == "auth/me":
                self._handle_auth_me()
            elif endpoint.startswith(ADMIN_API_PREFIX):
                self._handle_admin_get(endpoint)
            elif endpoint.startswith(STUDENT_API_PREFIX):
                self._handle_student_get(endpoint)
            else:
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
            return

        requested = self._requested_path()
        if requested in ADMIN_PAGES:
            if not self._serve_admin_page(requested):
                return
            super().do_GET()
            return

        # Student content. The gate runs before the file is touched, so an
        # anonymous request cannot probe which pages exist.
        if not self._is_public_path(requested) and not self._has_session():
            self._send_login_redirect()
            return
        super().do_GET()

    # ----------------------------------------------------------- answer API
    def _send_json(
        self, payload: dict, status: int = 200, cookies: list = None, headers: list = None
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers or []:
            self.send_header(name, value)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _session_cookie(
        self, token: str, *, max_age: int, secure: bool = False
    ) -> str:
        """Build the ``Set-Cookie`` value carrying a session token.

        HttpOnly keeps it away from JavaScript, SameSite=Lax keeps it off
        cross-site POSTs, and Max-Age makes it expire on the client too even if
        logout never runs. Secure is only safe to add over HTTPS, so it is
        conditional rather than always on.
        """
        parts = [
            f"{SESSION_COOKIE}={token}",
            "Path=/",
            f"Max-Age={max_age}",
            "HttpOnly",
            "SameSite=Lax",
        ]
        if secure:
            parts.append("Secure")
        return "; ".join(parts)

    def _drain_body(self) -> None:
        """Read and discard a request body we are not going to parse.

        Bounded, so a declared-but-unsent gigabyte cannot be turned into a
        wait. Anything unread stays in the socket buffer and is closed with the
        connection, which is the correct outcome for a body we discard.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        remaining = min(length, 1024 * 1024)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > answer_grader.MAX_PAYLOAD_BYTES:
            raise answer_grader.GradingError("request body too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise answer_grader.GradingError(f"invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise answer_grader.GradingError("body must be a JSON object")
        return data

    def do_POST(self):
        if not self.path.startswith(API_PREFIX):
            # Drain the body before answering. Replying and closing while the
            # client is still writing makes it see a connection error instead
            # of the status, which is confusing and looks like an outage.
            self._drain_body()
            self._send_json({"error": "not found"}, 404)
            return
        endpoint = self._api_endpoint()
        if endpoint.startswith("auth/"):
            self._handle_auth_post(endpoint)
            return
        if endpoint.startswith(STUDENT_API_PREFIX):
            try:
                data = self._read_json()
            except answer_grader.GradingError as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            self._handle_student_post(endpoint, data)
            return
        try:
            data = self._read_json()
            if endpoint == "reveal":
                # Authenticated and throttled; see _reveal.
                self._reveal(data)
                return
            if endpoint == "check":
                scenario = data.get("scenario") or ""
                answers = data.get("answers") or {}
                if not isinstance(answers, dict):
                    raise answer_grader.GradingError("answers must be an object")
                reveal_solution = data.get("reveal") is True
                # Optional: grade only the questions the student just answered.
                # The investigation loop checks one objective at a time, so it
                # sends {"questions": ["s1e3"]}. Omitting the field keeps the
                # original whole-scenario behaviour for any other caller.
                selected = data.get("questions")
                if selected is not None:
                    if not isinstance(selected, list) or not all(
                            isinstance(q, str) for q in selected):
                        raise answer_grader.GradingError(
                            "questions must be a list of question ids")
                result = answer_grader.grade(
                    scenario, answers, reveal_solution=reveal_solution,
                    questions=selected,
                )
                # Side effect only, and only for a caller who already has a
                # session: tells reveal_policy this student engaged with the
                # scenario. The check itself stays stateless and anonymous -
                # the response is not touched and an anonymous caller records
                # nothing.
                # Server-side progress, for signed-in students only. The id
                # comes from the session; an anonymous caller is graded exactly
                # as before and nothing is written, so stateless checking is
                # preserved.
                student_id = self._progress_user()
                if self._is_student(self._current_user()):
                    try:
                        student_progress.record_check(
                            student_id, scenario, result, path=self._db_path()
                        )
                    except sqlite3.Error as exc:  # grading must not fail on bookkeeping
                        print(f"progress update failed: {exc}", file=sys.stderr)

                # Feeds the reveal policy's attempt gate. Recorded for any
                # signed-in user, so an admin hitting the gate behaves the same
                # as a student.
                reveal_policy.note_check(self._optional_user_id(), scenario)
            else:
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
                return
        except answer_grader.GradingError as exc:
            self._send_json({"error": str(exc)}, 400)
            return
        except Exception as exc:  # never leak a traceback to a student's browser
            print(f"answer API error: {exc}", file=sys.stderr)
            self._send_json({"error": "grading failed"}, 500)
            return
        self._send_json(result)

    def _optional_user_id(self):
        """The signed-in user's id, or ``None`` for an anonymous caller.

        Deliberately forgiving: a missing or broken cookie is simply nobody. It
        is used where a session is a *benefit* rather than a requirement, such
        as noting that a check was attempted.
        """
        user = auth.resolve_session(self._cookie_token(), path=self._db_path())
        return user["id"] if user else None

    def _reveal(self, data: dict) -> None:
        """Serve one model answer, under the reveal policy.

        The gate order matters, and it is deliberate:

        1. **Session required.** This is the fix for audit finding H-1 - an
           anonymous caller used to be able to walk the whole key.
        2. **Validate first.** ``answer_grader`` still owns scenario and
           question validation, so a malformed request gets the same 400 it
           always did. Doing this before the rate limit means a typo does not
           burn one of the student's reveals.
        3. **Attempt gate.** No submitted check for this scenario, no model
           answer. The training loop is investigate, answer, check, then consult.
        4. **Rate limit.** Per user, bounded and thread-safe. The slot is
           reserved inside the policy's lock, so concurrent requests cannot both
           slip through.
        5. **Bookkeeping**, then the one place a solution reaches the wire.
        """
        token = self._cookie_token()
        user = auth.resolve_session(token, path=self._db_path())

        if user is None:
            self._send_json(
                {"error": "sign in to view model answers"}, 401,
                cookies=[self._session_cookie(token, max_age=0)],
            )
            return

        scenario = data.get("scenario") or ""
        question = data.get("question") or ""

        # 2. Existing validation and response shape, unchanged. Raises
        #    GradingError -> 400 for an unknown scenario or question.
        result = answer_grader.reveal(scenario, question)

        # 3. Must have engaged with this scenario first.
        if not reveal_policy.has_attempt(user["id"], scenario):
            self._send_json(
                {"error": "check your answers before viewing the model answer"}, 403
            )
            return

        # 4. Throttling. evaluate() also reserves the slot, atomically.
        try:
            reveal_policy.evaluate(user["id"], scenario, question)
        except reveal_policy.RevealNotPermitted as exc:
            self._send_json({"error": str(exc)}, 403)
            return
        except reveal_policy.RevealThrottled as exc:
            wait = int(exc.retry_after)
            self._send_json(
                {"error": "too many model answers requested; wait a moment",
                 "retry_after": wait},
                429,
                headers=[("Retry-After", str(wait))],
            )
            return

        # 5. Opening a model answer is itself engagement, so the attempt window
        #    is refreshed, and the assisted flag is recorded. Counts and flags
        #    only - no answer text, and nothing that reads as analytics.
        reveal_policy.note_reveal(user["id"], scenario, question)
        try:
            labdb.record_scenario_check(
                user["id"], scenario, assisted=True, path=self._db_path()
            )
            if self._is_student(user):
                student_progress.mark_assisted(
                    user["id"], scenario, question, path=self._db_path()
                )
        except sqlite3.Error as exc:  # never fail a reveal over bookkeeping
            print(f"could not record assisted reveal: {exc}", file=sys.stderr)

        # 6. The only place a solution is written to the wire.
        self._send_json(result)

    # ----------------------------------------------------- student progress
    def _student_api_refused(self, user):
        """401 for anonymous, 403 for a signed-in non-student."""
        if user is None:
            self._send_json({"error": "authentication required"}, 401)
            return True
        if not self._is_student(user):
            self._send_json(
                {"error": "student access required",
                 "authenticated": True}, 403,
            )
            return True
        return False

    def _handle_student_get(self, endpoint: str) -> None:
        """Serve one student's own progress.

        ``user_id`` is taken from the session and used for every query. A
        ``?user_id=`` in the request is not read, so there is nothing to spoof.
        """
        user = self._current_user()
        if self._student_api_refused(user):
            return

        try:
            if endpoint == "student/progress":
                payload = student_progress.student_summary(
                    user["id"], path=self._db_path()
                )
            elif endpoint.startswith("student/progress/"):
                scenario_id = endpoint[len("student/progress/"):].strip("/")
                detail = student_progress.scenario_detail(
                    user["id"], scenario_id, path=self._db_path()
                )
                if detail is None:
                    self._send_json({"error": "unknown scenario"}, 404)
                    return
                payload = detail
            else:
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
                return
        except Exception as exc:  # never leak a traceback to a browser
            print(f"student progress error: {exc}", file=sys.stderr)
            self._send_json({"error": "could not read progress"}, 500)
            return
        self._send_json(payload)

    def _handle_student_post(self, endpoint: str, data: dict) -> None:
        """Mark a scenario started. The only progress write a client can cause."""
        user = self._current_user()
        if self._student_api_refused(user):
            return
        if endpoint != "student/progress/start":
            self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
            return
        scenario = data.get("scenario") or ""
        if scenario not in labdb.SCENARIO_IDS:
            self._send_json({"error": "unknown scenario"}, 400)
            return
        try:
            record = student_progress.record_start(
                user["id"], scenario, path=self._db_path()
            )
        except Exception as exc:
            print(f"progress start failed: {exc}", file=sys.stderr)
            self._send_json({"error": "could not record progress"}, 500)
            return
        self._send_json({"started": True, "scenario": scenario,
                         "progress": student_progress.public_progress(record)})

    # ----------------------------------------------------------- admin API
    def _handle_admin_get(self, endpoint: str) -> None:
        """Serve an admin API read.

        Three outcomes, and the order matters. No session at all is 401, so a
        client can tell "log in" from "not allowed" without the two being
        confused. A session that is not an admin is 403. Only then is the
        aggregate read and only then is anything returned.
        """
        user = self._current_user()
        if user is None:
            self._send_json({"error": "authentication required"}, 401)
            return
        if not self._is_admin(user):
            self._send_admin_api_refused()
            return

        db = self._db_path()
        try:
            if endpoint == "admin/summary":
                payload = admin_stats.summary(path=db)
            elif endpoint == "admin/students":
                payload = {"students": admin_stats.student_rows(path=db)}
            elif endpoint == "admin/scenarios":
                payload = {"scenarios": admin_stats.scenario_rows(path=db)}
            else:
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
                return
        except Exception as exc:  # never leak a traceback to a browser
            print(f"admin API error: {exc}", file=sys.stderr)
            self._send_json({"error": "could not read the dashboard data"}, 500)
            return
        self._send_json(payload)

    # ------------------------------------------------------------ auth API
    def _cookie_token(self) -> str:
        """The raw session token from the request cookie, or ``""``.

        Read through SimpleCookie so a malformed Cookie header is ignored
        rather than raising inside a request thread.
        """
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except Exception:
            return ""
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _request_is_secure(self) -> bool:
        """Whether this request arrived over HTTPS.

        The lab itself is plain HTTP, so Secure would be ignored by the browser
        there; it matters only behind a TLS-terminating proxy, which announces
        itself with X-Forwarded-Proto.
        """
        forwarded = (self.headers.get("X-Forwarded-Proto") or "").strip().lower()
        if forwarded:
            return forwarded == "https"
        return bool(getattr(self.server, "force_secure_cookies", False))

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else None

    def _handle_auth_me(self) -> None:
        """Report who the caller is, or that they are nobody.

        200 either way: an anonymous visitor is a normal state, not an error,
        and a 401 would force the page to treat "not logged in" as a failure.
        """
        token = self._cookie_token()
        user = auth.resolve_session(token, path=self._db_path())
        if user is None:
            self._send_json({"authenticated": False})
            return
        auth.touch_session(token, path=self._db_path())
        self._send_json({"authenticated": True, "user": user})

    def _handle_auth_post(self, endpoint: str) -> None:
        try:
            data = self._read_json()
        except answer_grader.GradingError as exc:
            self._send_json({"error": str(exc)}, 400)
            return

        db = self._db_path()
        if endpoint == "auth/register":
            self._auth_register(data, db)
        elif endpoint == "auth/login":
            self._auth_login(data, db)
        elif endpoint == "auth/logout":
            self._auth_logout(db)
        else:
            self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)

    def _auth_register(self, data: dict, db: str) -> None:
        # 'role' in the body is ignored on purpose: Phase 2A issues students
        # only. See auth.register_user, which has no role parameter to set.
        try:
            user = auth.register_user(
                data.get("username"), data.get("password"), path=db
            )
        except auth.DuplicateUsername as exc:
            self._send_json({"error": str(exc)}, 409)
            return
        except auth.AuthenticationError as exc:
            self._send_json({"error": str(exc)}, 400)
            return
        # Registration does not log the student in. Issuing a cookie here would
        # silently couple the two flows; login is a separate, explicit step.
        self._send_json({"registered": True, "user": user}, 201)

    def _auth_login(self, data: dict, db: str) -> None:
        username = data.get("username")
        password = data.get("password")
        ip = self._client_ip()

        # Throttle first, and answer with the same generic body as a wrong
        # password, so a pause never confirms whether an account exists.
        wait = auth.login_block_seconds(username if isinstance(username, str) else None, ip)
        if wait:
            self._send_json(
                {"error": GENERIC_AUTH_ERROR, "retry_after": wait},
                429,
                headers=[("Retry-After", str(wait))],
            )
            return

        try:
            user = auth.authenticate(username, password, path=db)
        except auth.AuthenticationError:
            # Counted for every rejection, real account or not.
            wait = auth.record_login_failure(
                username if isinstance(username, str) else None, ip
            )
            if wait:
                self._send_json(
                    {"error": GENERIC_AUTH_ERROR, "retry_after": wait},
                    429,
                    headers=[("Retry-After", str(wait))],
                )
            else:
                # One message for every failure mode, including a valid
                # username with a wrong password and one that does not exist.
                self._send_json({"error": GENERIC_AUTH_ERROR}, 401)
            return

        # A real login clears the slate, so a student who mistyped a few
        # times is never punished for it.
        auth.clear_login_failures(username if isinstance(username, str) else None, ip)

        token, _row = auth.create_session(
            user["id"],
            path=db,
            ip=ip,
            user_agent=(self.headers.get("User-Agent") or None),
        )
        labdb.touch_last_login(user["id"], path=db)
        cookie = self._session_cookie(
            token,
            max_age=auth.SESSION_TTL_SECONDS,
            secure=self._request_is_secure(),
        )
        self._send_json({"authenticated": True, "user": user}, 200, cookies=[cookie])

    def _auth_logout(self, db: str) -> None:
        token = self._cookie_token()
        auth.delete_session(token, path=db)
        # The row is gone, so the token is dead even if the browser kept it.
        # The expired cookie is belt and braces.
        cookie = self._session_cookie(token, max_age=0, secure=self._request_is_secure())
        self._send_json({"authenticated": False}, 200, cookies=[cookie])

    def log_message(self, fmt, *args):
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)

    def finish_request(self, request, client_address):
        # This thread's SQLite connection is about to become unreachable with
        # its thread-local storage. Close it explicitly rather than waiting for
        # the garbage collector, so a long-running server does not accumulate
        # connections, each holding its own WAL read lock.
        try:
            super().finish_request(request, client_address)
        finally:
            labdb.close_connection(self._db_path())


class LabServer(http.server.ThreadingHTTPServer):
    """Threaded so one slow request cannot block every other student.

    ``ThreadingHTTPServer`` is the stdlib's ``ThreadingMixIn`` + ``HTTPServer``
    combination: one thread per request, which is what a handful of students
    doing separate logins needs. Threads are daemonic, so Ctrl+C stops the
    server without waiting for a request in flight.

    Each request thread opens its own SQLite connection through ``labdb`` and
    closes it again on the way out, so connections do not accumulate.
    """

    allow_reuse_address = True
    daemon_threads = True


def es_health(url: str = None, timeout: float = None) -> dict:
    """Query Elasticsearch's cluster health from the server side.

    The browser cannot make this call itself. The lab platform is served on
    port 8080 and Elasticsearch on 9200, which are different origins, and
    Elasticsearch returns no ``Access-Control-Allow-Origin`` header. A direct
    ``fetch()`` is therefore blocked by CORS even when the cluster is perfectly
    healthy, which is what made the homepage report "not reachable" against a
    green cluster. Proxying this single read through this same-origin server
    keeps the status honest without loosening the Elasticsearch configuration.

    One request, no retries: it runs once per page load with a short timeout, so
    a dead cluster cannot stall the page.
    """
    url = url or ES_HEALTH_URL
    timeout = ES_HEALTH_TIMEOUT if timeout is None else timeout
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}
    return {
        "ok": True,
        "status": body.get("status"),
        "cluster_name": body.get("cluster_name"),
        "number_of_nodes": body.get("number_of_nodes"),
    }


def _port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
            return True
        except OSError:
            return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the BlueCloud SIEM training platform")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--db", default=None, help="Path to the student database (default: data/training.db)")
    parser.add_argument(
        "--secure-cookies",
        action="store_true",
        help="Add Secure to the session cookie (only useful behind HTTPS)",
    )
    parser.add_argument("--open", action="store_true", help="Open the browser automatically")
    parser.add_argument("--verbose", action="store_true", help="Log every HTTP request")
    args = parser.parse_args()

    if not os.path.isdir(TRAINING_DIR):
        print(f"Training directory not found: {TRAINING_DIR}", file=sys.stderr)
        return 1

    index = os.path.join(TRAINING_DIR, DIRECTORY_INDEX)
    if not os.path.isfile(index):
        print(f"Landing page not found: {index}", file=sys.stderr)
        return 1

    # Create the schema once, here, before any request can arrive. init_db is
    # additive and idempotent, so a restart against an existing database is a
    # no-op, and an empty users table is a perfectly valid starting state:
    # there is no default account and no default password anywhere.
    db_path = labdb.init_db(args.db)
    version = labdb.get_schema_version(db_path)
    if version != labdb.SCHEMA_VERSION:
        print(
            f"Student database schema is version {version}, expected "
            f"{labdb.SCHEMA_VERSION}: {db_path}",
            file=sys.stderr,
        )
        return 1

    # Housekeeping, once, at startup. There is no background scheduler yet;
    # a later phase can call auth.purge_expired_sessions on a timer.
    try:
        removed = auth.purge_expired_sessions(path=db_path)
    except Exception:
        removed = 0
    if removed:
        print(f"  Removed {removed} expired session(s).")

    # Port selection is explicit, or startup fails. An earlier revision, when the
    # requested port was busy, walked forward to port+1..port+19 and started on
    # whichever it found, printing one line to stdout. That is acceptable on a
    # dedicated workstation and wrong on a shared server, for three reasons:
    #
    #   1. It is silent about the one thing an operator needs to know. The process
    #      ends up listening somewhere other than where its documentation, its
    #      systemd unit and its reverse proxy all say it is listening, so the
    #      failure surfaces later as a refused connection somewhere else entirely.
    #   2. On a host running several labs, port+1 is a port another lab may own,
    #      or one that is firewalled. "Found a free port" is a different question
    #      from "found the port you were told to use".
    #   3. It converts a configuration error into a success, which is backwards:
    #      being asked to serve on an occupied port should stop the launch.
    #
    # The requested port is used or the process exits non-zero. Local development
    # is unaffected whenever the port is free, which is the normal case there.
    port = args.port
    if not _port_is_free(args.host, port):
        print(
            f"Cannot start: {args.host}:{port} is already in use.\n"
            f"\n"
            f"  This server does not pick a different port automatically. On a shared\n"
            f"  host, silently relocating a service that a reverse proxy, a systemd\n"
            f"  unit or a bookmark already points at a specific port turns a clear\n"
            f"  configuration error into a confusing connection failure later.\n"
            f"\n"
            f"  Do one of these:\n"
            f"    * stop whatever is holding the port, then start again\n"
            f"        ss -lntp | grep {port}\n"
            f"    * choose a different port explicitly, and update whatever else\n"
            f"      refers to it:\n"
            f"        python scripts/serve_training.py --port <free-port>\n",
            file=sys.stderr,
        )
        return 1

    handler = functools.partial(LabRequestHandler, directory=TRAINING_DIR)
    try:
        with LabServer((args.host, port), handler) as httpd:
            # Handed to every request thread so auth reads the same database
            # this startup opened, and so tests can point a live server at a
            # throwaway one.
            httpd.db_path = db_path
            httpd.force_secure_cookies = bool(args.secure_cookies)
            url = f"http://localhost:{port}"
            print("=" * 66)
            print("  BlueCloud Softech Solutions - Cybersecurity Training Lab")
            print("  SIEM Log Correlation Engine")
            print("=" * 66)
            print(f"  Training platform : {url}")
            print(f"  Serving directory : {TRAINING_DIR}")
            print(f"  Student database  : {db_path}")
            print(f"  Stop with         : Ctrl+C")
            print("=" * 66)
            print("  Companion services (start separately):")
            print("    SOC Triage Board : http://localhost:5601/app/dashboards#/view/siem-soc-triage-board")
            print("    Kibana           : http://localhost:5601")
            print("    Elasticsearch    : http://localhost:9200")
            print()
            if args.open:
                webbrowser.open(url)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nTraining platform stopped.")
    except OSError as exc:
        print(f"Could not start the training platform server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
