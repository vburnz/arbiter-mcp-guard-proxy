#!/usr/bin/env python3
"""Minimal MCP echo server for docker-compose quickstart.

Responds to all requests with a JSON-RPC response echoing the method
and params it received. Non-JSON bodies get a simple echo.
"""

import json
import http.server
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        try:
            req = json.loads(body)
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {
                    "echo": True,
                    "method": req.get("method"),
                    "params": req.get("params"),
                },
            }
        except (json.JSONDecodeError, AttributeError):
            resp = {"echo": True, "body": body.decode("utf-8", errors="replace")}

        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        resp = json.dumps({"status": "ok", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, fmt, *args):
        print(f"[echo-server] {fmt % args}", flush=True)


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), EchoHandler)
    print(f"[echo-server] listening on :{PORT}", flush=True)
    server.serve_forever()
