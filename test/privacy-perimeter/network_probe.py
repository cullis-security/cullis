"""Probe an explicitly supplied, controlled destination without sending payloads."""
import argparse
import json
import socket

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("port", type=int)
parser.add_argument("--expect", choices=["allow", "deny"], required=True)
args = parser.parse_args()
try:
    with socket.create_connection((args.host, args.port), timeout=2):
        connected = True
except OSError:
    connected = False
print(json.dumps({"host": args.host, "port": args.port, "connected": connected, "expected": args.expect}))
if connected != (args.expect == "allow"):
    raise SystemExit(1)
