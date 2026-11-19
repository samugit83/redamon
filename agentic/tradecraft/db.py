"""The page store's Postgres pool (master plan TD-5).

The agent writes ingestion output itself, over the ``DATABASE_URL`` it already holds
(R-004): one ``AsyncConnectionPool`` of at most ``constants.dbPoolSize`` connections per
agent copy, so tradecraft takes about 5 of Postgres's 100 and fails its own job, not the
rest of the stack, when the limit is near (EX-5). With ``net.py`` this is the only module
of the package that imports a database driver (``test_tradecraft_fetcher_contract.py``).

The pool opens on first use, inside the event loop that uses it. A pool belongs to the
loop it was opened in, so a call from another loop (each test's own ``asyncio.run``) gets
a pool of its own; the agent has one loop and so one pool.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import Any, AsyncIterator, Optional

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from tradecraft import settings as _settings

MAX_SIZE = _settings.constant("dbPoolSize")
# Seconds a caller waits for a free connection before its job fails: a full pool means the
# store is busy or Postgres is near its connection limit, and waiting longer would only
# stall the job queue behind it.
ACQUIRE_TIMEOUT_SEC = 10.0
# A statement that runs longer is cancelled by Postgres; the purge and the bulk writes are
# split so that none comes near it.
STATEMENT_TIMEOUT_MS = 120_000
# Prisma's DateTime columns are `timestamp(3)` without a time zone holding UTC: a session in
# UTC stores the agent's aware datetimes and compares them with now() the way the webapp does.
SESSION_OPTIONS = f"-c statement_timeout={STATEMENT_TIMEOUT_MS} -c TimeZone=UTC"


ForeignKeyViolation = psycopg.errors.ForeignKeyViolation


class StoreUnavailable(RuntimeError):
    """No ``DATABASE_URL``: the agent was started without the database the store needs."""


_pool: Optional[AsyncConnectionPool] = None
_pool_loop: Optional[asyncio.AbstractEventLoop] = None


def dsn() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise StoreUnavailable("DATABASE_URL is not set")
    return url


def pool() -> AsyncConnectionPool:
    """The pool of the running event loop, created closed on first call (``connection``
    opens it)."""
    global _pool, _pool_loop
    loop = asyncio.get_running_loop()
    if _pool is None or _pool_loop is not loop:
        _pool = AsyncConnectionPool(
            conninfo=dsn(),
            min_size=0,
            max_size=MAX_SIZE,
            timeout=ACQUIRE_TIMEOUT_SEC,
            kwargs={
                "autocommit": False,
                "row_factory": dict_row,
                "options": SESSION_OPTIONS,
            },
            open=False,
        )
        _pool_loop = loop
    return _pool


async def _opened() -> AsyncConnectionPool:
    p = pool()
    if p.closed:
        await p.open()
    return p


@contextlib.asynccontextmanager
async def connection() -> AsyncIterator[Any]:
    """A connection in a transaction that commits when the block ends and rolls back
    when it raises (psycopg's pool does both)."""
    p = await _opened()
    async with p.connection() as conn:
        yield conn


async def close() -> None:
    """Close the pool of this loop (shutdown, and between tests)."""
    global _pool, _pool_loop
    p, _pool, _pool_loop = _pool, None, None
    if p is not None and not p.closed:
        await p.close()


def reset() -> None:
    """Forget the pool without closing it: for a test that changed ``DATABASE_URL`` from a
    loop that is already gone."""
    global _pool, _pool_loop
    _pool, _pool_loop = None, None
