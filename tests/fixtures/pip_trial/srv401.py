"""Tiny HTTP server on 127.0.0.1:8401 that answers every request with 401 (the 401 fixtures)."""
import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def _respond(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        sys.stderr.write(f"REQ {self.command} {self.path}\n")
        sys.stderr.flush()

    do_GET = do_HEAD = do_POST = _respond

    def log_message(self, format: str, *args: object) -> None:
        pass


http.server.HTTPServer(("127.0.0.1", 8401), Handler).serve_forever()
