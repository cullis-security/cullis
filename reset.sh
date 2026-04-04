#!/usr/bin/env bash
# Reset the environment for a clean demo:
#   - drop and recreate Postgres tables (via broker init_db)
#   - delete SQLite files if present
#   - delete generated certificates
#
# Usage: ./reset.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
LIBSTDCXX=$(find /nix/store -maxdepth 3 -name "libstdc++.so.6" 2>/dev/null | head -1 | xargs dirname)

export LD_LIBRARY_PATH="$LIBSTDCXX:$LD_LIBRARY_PATH"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

echo "Resetting Agent Trust Network..."

# Postgres — drop all tables then recreate
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q agent-trust-db; then
    echo "  → Dropping Postgres tables..."
    "$VENV/bin/python" - <<'EOF'
import asyncio
from app.db.database import engine, Base
import app.auth.jti_blacklist       # noqa
import app.broker.db_models         # noqa
import app.registry.store           # noqa
import app.registry.org_store       # noqa
import app.registry.binding_store   # noqa
import app.policy.store             # noqa
import app.db.audit                 # noqa

async def reset():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("  ✓ Postgres reset complete")

asyncio.run(reset())
EOF
else
    echo "  ! Container agent-trust-db non trovato — skip Postgres reset"
fi

# SQLite (legacy)
for db in "$SCRIPT_DIR/agent_trust.db" "$SCRIPT_DIR/test_agent_trust.db"; do
    if [ -f "$db" ]; then
        rm "$db"
        echo "  ✓ $(basename $db) removed"
    fi
done

# Certificates
if [ -d "$SCRIPT_DIR/certs" ]; then
    rm -rf "$SCRIPT_DIR/certs"
    echo "  ✓ certs/ removed"
fi

echo ""
echo "Reset complete. Now run:"
echo "  python generate_certs.py"
echo "  ./run.sh &"
echo "  sleep 2 && python bootstrap.py"
