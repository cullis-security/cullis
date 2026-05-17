"""Lifespan helpers shared across boot-time setup and background tasks.

Currently houses :mod:`leader_election` (Cluster A, Wave 2b): the
helper that elects exactly one uvicorn worker as owner of a named
background loop or one-shot startup step, so multi-worker deployments
don't run the same poller / sweeper / migration N times.
"""
from __future__ import annotations

from mcp_proxy.lifespan.leader_election import (
    LeaderElection,
    NoopLeader,
    PostgresAdvisoryLeader,
    SQLiteFlockLeader,
    get_leader,
)

__all__ = [
    "LeaderElection",
    "NoopLeader",
    "PostgresAdvisoryLeader",
    "SQLiteFlockLeader",
    "get_leader",
]
