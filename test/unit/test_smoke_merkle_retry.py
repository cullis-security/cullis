"""Exercise the smoke GET helper over HTTP, including its negative assertions."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread

import pytest


LIB = Path(__file__).resolve().parents[1] / "smoke" / "lib"
SHED = json.dumps({"error": "db_latency_circuit_breaker_open"})


@pytest.fixture
def request_get(tmp_path):
    replies = []
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("X-Admin-Secret")))
            reply = replies[min(len(requests) - 1, len(replies) - 1)]
            if reply is None:
                self.close_connection = True
                return
            status, body, retry_after = reply
            self.send_response(status)
            if retry_after is not None:
                self.send_header("rEtRy-AfTeR", retry_after)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def run(sequence, expected=200, secret="test-secret"):
        replies.extend(sequence)
        # Advance Bash's clock instead of waiting; curl and HTTP are real.
        script = '''
set -euo pipefail
source "$1/_common.sh"
source "$1/_merkle.sh"
NGINX_URL="$2"
sleep() { printf 'WAIT %s\n' "$1" >&2; SECONDS=$(( SECONDS + $1 )); }
merkle_get '/v1/admin/audit/merkle/anchors?limit=5' "$3" "$4"
'''
        env = dict(os.environ, TMPDIR=str(tmp_path))
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
        result = subprocess.run(
            ["bash", "-c", script, "merkle-test", str(LIB),
             f"http://127.0.0.1:{server.server_port}", str(expected), secret],
            env=env, capture_output=True, text=True, timeout=10,
        )
        assert list(tmp_path.iterdir()) == [], "temporary response files leaked"
        return result, requests

    try:
        yield run
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("expected,secret", [(200, "test-secret"), (403, "wrong-secret"), (404, "test-secret")])
def test_shed_then_expected_status_preserves_body_and_credentials(request_get, expected, secret):
    body = '{"result": "unchanged"}'
    result, requests = request_get([(503, SHED, "5"), (expected, body, None)], expected, secret)
    assert result.returncode == 0, result.stderr
    assert result.stdout == body
    assert result.stderr.count("WAIT 5\n") == 1
    assert requests == [("/v1/admin/audit/merkle/anchors?limit=5", secret)] * 2


@pytest.mark.parametrize("actual,expected", [(403, 200), (404, 200), (200, 403), (200, 404), (500, 200)])
def test_unexpected_status_fails_without_retry(request_get, actual, expected):
    result, requests = request_get([(actual, "{}", None)], expected)
    assert result.returncode != 0
    assert f"HTTP {actual}, expected {expected}" in result.stderr
    assert len(requests) == 1
    assert "WAIT" not in result.stderr


@pytest.mark.parametrize("body", ['{"error":"other_outage"}', '{}', 'not json', '[]'])
def test_unrelated_or_invalid_503_never_retries(request_get, body):
    result, requests = request_get([(503, body, "5")])
    assert result.returncode != 0
    assert len(requests) == 1
    assert "WAIT" not in result.stderr


@pytest.mark.parametrize("retry_after", [None, "0", "-1", "soon", "5 junk", "30", "9999999999"])
def test_invalid_or_excessive_retry_after_fails_without_retry(request_get, retry_after):
    result, requests = request_get([(503, SHED, retry_after)])
    assert result.returncode != 0
    assert "Retry-After" in result.stderr
    assert len(requests) == 1
    assert "WAIT" not in result.stderr


def test_persistent_shedding_exhausts_budget(request_get):
    result, requests = request_get([(503, SHED, "5")])
    assert result.returncode != 0
    assert "recovery budget" in result.stderr
    assert 1 < len(requests) <= 6
    assert result.stderr.count("WAIT 5\n") == len(requests) - 1


def test_transport_failure_is_not_retried(request_get):
    result, requests = request_get([None])
    assert result.returncode != 0
    assert "transport failure" in result.stderr
    assert len(requests) == 1
    assert "WAIT" not in result.stderr
