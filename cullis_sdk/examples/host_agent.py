"""Host-agent example — send a one-shot using the Connector identity.

After enrolling an agent through the Connector Desktop (ADR-009 sandbox
Step 3 of GUIDE.md), run this script from any shell:

    CULLIS_TARGET_AGENT=orgb::agent-b python cullis_sdk/examples/host_agent.py

The script loads the enrolled identity from ``~/.cullis/identity/``,
authenticates through the local Mastio via ``login_via_proxy`` (which
the SDK auto-counter-signs, see ADR-009 Phase 2), and sends a single
one-shot envelope to the target.

Env:
    CULLIS_TARGET_AGENT    recipient (e.g. ``orgb::agent-b``)
    CULLIS_CONFIG_DIR      override ``~/.cullis`` (optional)
"""
from __future__ import annotations

import os
import sys
import time
import uuid

from cullis_sdk import CullisClient


def main() -> int:
    target = os.environ.get("CULLIS_TARGET_AGENT")
    if not target:
        print("set CULLIS_TARGET_AGENT (e.g. orgb::agent-b)", file=sys.stderr)
        return 2

    config_dir = os.environ.get("CULLIS_CONFIG_DIR")
    client = CullisClient.from_connector(config_dir=config_dir)
    print(f"loaded identity from disk: agent_id={client._proxy_agent_id}")

    client.login_via_proxy()
    print("authenticated via local Mastio — broker token issued")

    nonce = uuid.uuid4().hex[:12]
    resp = client.send_oneshot(
        recipient_id=target,
        payload={
            "hello": "from a host-side agent",
            "nonce": nonce,
            "sent_at": time.time(),
        },
        ttl_seconds=300,
    )
    print(
        f"\u2713 one-shot sent to {target}  "
        f"msg_id={resp.get('msg_id')}  nonce={nonce}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
