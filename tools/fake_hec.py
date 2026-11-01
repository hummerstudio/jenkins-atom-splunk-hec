#!/usr/bin/env python3
"""A Splunk HEC endpoint that judges the envelope: token, JSON shape, required keys.

    fake_hec.py <port> <log> <token> [--reject-events] [--deny-token]
"""
import http.server
import json
import sys

port, log_path, token = int(sys.argv[1]), sys.argv[2], sys.argv[3]
flags = sys.argv[4:]
reject_events = "--reject-events" in flags
deny_token = "--deny-token" in flags


class Handler(http.server.BaseHTTPRequestHandler):
    def _answer(self, status, doc):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        auth = self.headers.get("Authorization", "")
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps({"path": self.path, "auth": auth,
                                  "body": raw.decode("utf-8", "replace")}) + "\n")

        if deny_token or auth != "Splunk " + token:
            self._answer(403, {"text": "Invalid token", "code": 4})
            return
        if self.path not in ("/services/collector/event", "/services/collector/raw"):
            self._answer(404, {"text": "no such endpoint", "code": 7})
            return
        if self.path.endswith("/raw"):
            self._answer(200, {"text": "Success", "code": 0})
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            self._answer(400, {"text": "Invalid data format", "code": 6})
            return
        if "event" not in doc or "sourcetype" not in doc:
            self._answer(200, {"text": "Event field is required", "code": 12})
            return
        if reject_events:
            # 200 with a non-zero code: exactly the answer a status-code-only sender misreads as success
            self._answer(200, {"text": "incorrect index", "code": 7})
            return
        self._answer(200, {"text": "Success", "code": 0})

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
