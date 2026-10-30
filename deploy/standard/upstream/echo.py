"""Tiny echo upstream used only by the standard deployment smoke test."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {key: value for key, value in self.headers.items()},
                "client": self.client_address[0],
            },
            ensure_ascii=True,
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Echo-Server", "highwall-standard-upstream")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_HEAD = _reply
    do_POST = _reply

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 18080), EchoHandler).serve_forever()
