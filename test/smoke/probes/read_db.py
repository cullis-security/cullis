"""Read-only smoke queries using the database drivers shipped with Mastio."""
import asyncio
import os
import sqlite3


def query(sql, params=()):
    url = os.environ["MCP_PROXY_DATABASE_URL"]
    if url.startswith("postgresql"):
        import asyncpg

        async def fetch():
            connection = await asyncpg.connect(url.replace("postgresql+asyncpg://", "postgresql://"))
            try:
                # Smoke SQL uses positional DB-API placeholders on both backends.
                statement = sql
                for index in range(len(params)):
                    statement = statement.replace("?", "$" + str(index + 1), 1)
                return [tuple(row) for row in await connection.fetch(statement, *params)]
            finally:
                await connection.close()
        return asyncio.run(fetch())
    path = url.replace("sqlite+aiosqlite:////", "/").replace("sqlite+aiosqlite:///", "/")
    with sqlite3.connect(path) as connection:
        return connection.execute(sql, params).fetchall()
