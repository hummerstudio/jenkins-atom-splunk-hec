#!/usr/bin/env bash
# The fake HEC judges the envelope itself: token, path, JSON shape, required keys, and 200-with-code-4.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

log="$(mktemp)"; port=$((33000 + RANDOM % 900)); token="hec-token-1"
start() { python3 tools/fake_hec.py "$port" "$log" "$token" "$@" & server=$!
  for _ in $(seq 1 40); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.1; done; }
stop() { kill $server 2>/dev/null; wait $server 2>/dev/null; }
start; trap 'stop' EXIT

ws="$(mktemp -d)"
write_input() { printf '%s' "$1" >"$ws/input.json"; }
write_secret() { printf '{"token": "%s"}' "$1" >"$ws/.secrets.json"; }

# --- the default event is built from the runner's build facts
write_secret "$token"
write_input "{\"url\": \"http://127.0.0.1:$port\", \"sourcetype\": \"jenkins\", \"source\": \"acme/api\"}"
# the runner hands the build facts in through atom_build_json; the harness passes it the same way
write_secret "$token"
run "$ws" atom_build_json='{"jobName":"acme/api","number":"42","result":"SUCCESS","duration":"1200"}' \
  >"$ws/atom.log" 2>&1 || fail "send: $(cat "$ws/output.json") $(tail -3 "$ws/atom.log")"
[ "$(output "$ws" code)" = "0" ] || fail "code: $(cat "$ws/output.json")"

python3 - "$log" <<'PY' || fail "the envelope is not what HEC expects"
import json, sys
entry = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
assert entry["path"] == "/services/collector/event", entry["path"]
assert entry["auth"] == "Splunk hec-token-1", entry["auth"]
body = json.loads(entry["body"])
assert body["sourcetype"] == "jenkins", body
assert body["source"] == "acme/api", body
event = body["event"]
assert event["job"] == "acme/api", event
assert event["build"] == "42", event
assert event["result"] == "SUCCESS", event
assert event["atom"], event          # the runner names it; the harness does not, so only presence is checked
assert body["time"].isdigit(), body
PY

# --- an explicit event wins, and key=value becomes an object
: >"$log"
write_secret "$token"
write_input "{\"url\": \"http://127.0.0.1:$port\", \"event\": \"deploy=prod,commit=abc123\"}"
write_secret "$token"
run "$ws" >"$ws/atom.log" 2>&1 || fail "explicit event: $(cat "$ws/output.json")"
python3 - "$log" <<'PY' || fail "key=value should become an object"
import json, sys
body = json.loads(json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])["body"])
assert body["event"] == {"deploy": "prod", "commit": "abc123"}, body["event"]
PY

# --- a wrong token is a USER problem, with Splunk's own words
write_secret "wrong-token"
write_input "{\"url\": \"http://127.0.0.1:$port\"}"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a bad token must fail"
grep -q "Splunk refused the token" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"
grep -q "Invalid token" "$ws/output.json" || fail "Splunk's text should be quoted: $(cat "$ws/output.json")"
grep -q '"errorType":1' "$ws/output.json" || fail "a refused token is USER(1)"

# --- 200 with code 4 is a rejection: this is the case a status-code-only sender reports as success
stop; start --reject-events
write_secret "$token"
write_input "{\"url\": \"http://127.0.0.1:$port\"}"
write_secret "$token"
run "$ws" >"$ws/atom.log" 2>&1 && fail "HTTP 200 with a non-zero code must fail the step"
grep -q "Splunk rejected the event: code 7" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"
grep -q "incorrect index" "$ws/output.json" || fail "the reason should be quoted: $(cat "$ws/output.json")"

# --- raw mode posts text, not JSON
stop; start
: >"$log"
write_secret "$token"
write_input "{\"url\": \"http://127.0.0.1:$port\", \"mode\": \"raw\", \"event\": \"build 42 finished\"}"
write_secret "$token"
run "$ws" >"$ws/atom.log" 2>&1 || fail "raw: $(cat "$ws/output.json")"
python3 - "$log" <<'PY' || fail "raw mode should post the text"
import json, sys
entry = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
assert entry["path"] == "/services/collector/raw", entry["path"]
assert "build%2042%20finished" in entry["body"], entry["body"]
PY
[ "$(output "$ws" endpoint)" = "http://127.0.0.1:$port/services/collector/raw" ] || fail "endpoint output: $(cat "$ws/output.json")"

# --- bad input
write_secret "$token"
write_input '{"url": ""}'
write_secret "$token"
run "$ws" >"$ws/atom.log" 2>&1 && fail "a missing url must be refused"
grep -q "url is required" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"
write_input "{\"url\": \"http://127.0.0.1:$port\", \"mode\": \"raw\"}"
write_secret "$token"
run "$ws" >"$ws/atom.log" 2>&1 && fail "raw without event must be refused"
grep -q "mode=raw needs event" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

echo "smoke ok: build-fact event, explicit key=value event, refused token, 200-with-code-4 rejection, raw mode, bad input"
