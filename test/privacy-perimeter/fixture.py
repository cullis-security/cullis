"""Synthetic read-only MCP or external connectivity control; never real records."""
import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

INPUT_MARKER = "SYNTHETIC-CASE-PRIVATE-6729"
OUTPUT_MARKER = "SYNTHETIC-RESULT-PRIVATE-4831"
STATE = {"calls": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(STATE)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = body.get("method")
        if method == "tools/list":
            result = {"tools": [{"name": "read_case", "description": "Read a synthetic case.",
                       "inputSchema": {"type": "object", "properties": {
                           "reference": {"type": "string"}}, "required": ["reference"]}}]}
        elif method == "tools/call" and body["params"]["name"] == "read_case":
            if body["params"]["arguments"] != {"reference": INPUT_MARKER}:
                self.reply({"error": "Unexpected synthetic case"}, 400)
                return
            STATE["calls"] += 1
            result = {"content": [{"type": "text", "text": OUTPUT_MARKER + ": review pending"}],
                      "isError": False}
        else:
            self.reply({"error": "Unsupported operation"}, 400)
            return
        self.reply({"jsonrpc": "2.0", "id": body.get("id"), "result": result})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    server = HTTPServer(("0.0.0.0", 8443 if args.tls else 8080), Handler)
    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/tls/server.pem", "/tls/server.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
