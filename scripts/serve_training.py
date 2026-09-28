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

The key itself lives in ``docs/answer-key.json``, outside the directory served
here, and is read only by ``scripts/answer_grader.py``.

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
import socketserver
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import answer_grader  # noqa: E402

TRAINING_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "training")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080

DIRECTORY_INDEX = "index.html"
API_PREFIX = "/api/"

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

    # ----------------------------------------------------------- answer API
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

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
        endpoint = self.path[len(API_PREFIX):].split("?", 1)[0].strip("/")
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

    def log_message(self, fmt, *args):
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)


class LabServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


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
            url = f"http://localhost:{port}"
            print("=" * 66)
            print("  BlueCloud Softech Solutions - Cybersecurity Training Lab")
            print("  SIEM Log Correlation Engine")
            print("=" * 66)
            print(f"  Training platform : {url}")
            print(f"  Serving directory : {TRAINING_DIR}")
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
