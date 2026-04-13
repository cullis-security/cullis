#!/bin/sh
# Create the multiple databases listed in POSTGRES_MULTIPLE_DATABASES.
# The official postgres image only creates one DB at startup; this hook
# expands that to N for the smoke variant which runs two proxies.
set -e

if [ -z "${POSTGRES_MULTIPLE_DATABASES:-}" ]; then
    exit 0
fi

for db in $(echo "$POSTGRES_MULTIPLE_DATABASES" | tr ',' ' '); do
    [ "$db" = "$POSTGRES_DB" ] && continue   # already created by entrypoint
    echo "Creating database '$db'..."
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        CREATE DATABASE "$db";
        GRANT ALL PRIVILEGES ON DATABASE "$db" TO "$POSTGRES_USER";
EOSQL
done
