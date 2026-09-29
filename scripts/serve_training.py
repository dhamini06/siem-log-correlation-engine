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

Three more endpoints back student accounts. They are optional: the lab works
exactly as before if nobody ever calls them.

    POST /api/auth/register  {"username": "...", "password": "..."}
    POST /api/auth/login     {"username": "...", "password": "..."}
    GET  /api/auth/me
    POST /api/auth/logout

Authentication is a foundation for a later phase. No scenario page and neither
answer endpoint requires it, so adding accounts can never break the lab.

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
import sys
import urllib.error
import urllib.request
import webbrowser
from http.cookies import SimpleCookie

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import answer_grader  # noqa: E402
import auth  # noqa: E402
import labdb  # noqa: E402

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

    def _db_path(self) -> str:
        """Database this request should use.

        Taken from the server rather than a module global so that tests can run
        a real server against a throwaway database.
        """
        return getattr(self.server, "db_path", None) or labdb.db_path()

    # ------------------------------------------------------------ lab API
    def do_GET(self):
        """Serve /api/* here, everything else as a static file."""
        if self.path.startswith(API_PREFIX):
            endpoint = self._api_endpoint()
            if endpoint == "es-status":
                self._send_json(es_health())
            elif endpoint == "auth/me":
                self._handle_auth_me()
            elif endpoint.startswith("auth/"):
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
            else:
                self._send_json({"error": f"unknown endpoint {endpoint!r}"}, 404)
            return
        super().do_GET()

    # ----------------------------------------------------------- answer API
    def _send_json(self, payload: dict, status: int = 200, cookies: list = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
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
            self._send_json({"error": "not found"}, 404)
            return
        endpoint = self._api_endpoint()
        if endpoint.startswith("auth/"):
            self._handle_auth_post(endpoint)
            return
        try:
            data = self._read_json()
            if endpoint == "check":
                scenario = data.get("scenario") or ""
                answers = data.get("answers") or {}
                if not isinstance(answers, dict):
                    raise answer_grader.GradingError("answers must be an object")
                reveal_solution = data.get("reveal") is True
                result = answer_grader.grade(
                    scenario, answers, reveal_solution=reveal_solution
                )
            elif endpoint == "reveal":
                result = answer_grader.reveal(
                    data.get("scenario") or "", data.get("question") or ""
                )
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
        try:
            user = auth.authenticate(
                data.get("username"), data.get("password"), path=db
            )
        except auth.AuthenticationError:
            # One message for every failure mode, including a valid username
            # with a wrong password and a username that does not exist.
            self._send_json({"error": GENERIC_AUTH_ERROR}, 401)
            return

        token, _row = auth.create_session(
            user["id"],
            path=db,
            ip=self._client_ip(),
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

    port = args.port
    if not _port_is_free(args.host, port):
        for candidate in range(port + 1, port + 20):
            if _port_is_free(args.host, candidate):
                print(f"Port {port} is in use; using {candidate} instead.")
                port = candidate
                break
        else:
            print(f"No free port found in {port}-{port + 19}.", file=sys.stderr)
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
