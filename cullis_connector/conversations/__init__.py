"""Connector-local chat conversation history (Sprint 1 Step 6 PR-A).

Until now the SPA's left sidebar showed an editorial empty state
("Conversation history lands in v0.5"). This module is the v0.5
backing store: an async SQLite database living next to ``users.db``
under the Connector ``config_dir``, exposing the CRUD primitives the
ambassador's REST router consumes.

Design notes mirror the users.db module (``cullis_connector.identity.users_db``):

- Per-(config_dir, event_loop_id) engine cache.
- WAL journaling + ``synchronous = NORMAL`` for the same reasons.
- ``chmod 0600`` on the file because conversation contents include
  user-typed text that may be PII; we treat them like credentials.
- Schema is intentionally minimal for v0.5: ``conversations`` (title,
  principal, timestamps, soft delete) and ``messages`` (role + content
  + tool calls JSON + trace_id). Phase D-3 will add a richer
  attribution column once the per-tool PDP audit row format settles.
"""
