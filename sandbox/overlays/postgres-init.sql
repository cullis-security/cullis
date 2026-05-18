-- Postgres initdb seed for the sandbox Postgres overlay.
-- Runs once on first boot (Postgres image semantics: any *.sql under
-- /docker-entrypoint-initdb.d/ executes against the default database
-- when the data directory is empty). On subsequent boots the data
-- directory is non-empty so this file is ignored.
--
-- Two per-Mastio databases owned by the same role. The Mastio
-- alembic chain runs against each one independently.
CREATE DATABASE mastio_a OWNER cullis;
CREATE DATABASE mastio_b OWNER cullis;
