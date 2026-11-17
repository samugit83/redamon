"""The Tradecraft binding of one chat run (master plan TD-9, TD-10).

At run start the orchestrator hands ``bind_run_catalog`` the catalog the webapp answered for
this run. It is bound to the run's task, in this module's own context variable and nowhere
else, together with the run's registry entries; no catalog (or one that does not parse)
clears both, and the run has no tradecraft tool.

The catalog carries secrets (a GitHub token, and the owner's logins in the owner's own run),
so every tradecraft module reads it only through ``bound_catalog()``: never through
``get_setting``, whose fallback outside a run's task is the module-global settings of
whichever project loaded last (``project_settings.get_settings``). A call from outside the
run's task finds nothing bound and makes no request.
"""

from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Iterator, Optional

from pydantic import ValidationError

from logging_config import get_logger
from tradecraft.contract import V2Catalog

logger = get_logger(__name__)

_catalog: contextvars.ContextVar[Optional[V2Catalog]] = contextvars.ContextVar("tradecraft_v2_catalog", default=None)
_store: contextvars.ContextVar[Any] = contextvars.ContextVar("tradecraft_v2_store", default=None)
_index: contextvars.ContextVar[Any] = contextvars.ContextVar("tradecraft_v2_index", default=None)
_coverage: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar("tradecraft_v2_coverage", default=None)


def bind_run_catalog(catalog: Any) -> bool:
    """Binds the run's catalog, its coverage counts (Q5, when ``prompt.coverageMap`` is on) and
    its registry entries to the current task; True when bound. None, a payload that is no
    catalog, or a catalog that does not parse clears the binding (False)."""
    from prompts.tool_registry import swap_tradecraft_v2_entries
    from tradecraft import overlay

    parsed: Optional[V2Catalog] = None
    if isinstance(catalog, dict) and catalog.get("v2") is True:
        try:
            parsed = V2Catalog.model_validate(catalog)
        except ValidationError as exc:
            logger.warning(f"[tradecraft] run catalog refused code=internal_error errors={len(exc.errors())}")
    _catalog.set(parsed)
    coverage = _coverage_of(parsed) if parsed is not None else None
    _coverage.set(coverage)
    swap_tradecraft_v2_entries(overlay.build_entries(parsed, coverage) if parsed is not None else None)
    if parsed is not None:
        _bind_browser_fetcher()
        logger.info(f"[tradecraft] run catalog bound resources={len(parsed.resources)}")
    return parsed is not None


def _coverage_of(catalog: V2Catalog) -> Optional[dict]:
    """The coverage counts of the run's resources (one bounded query), or None when the map is
    off, the run has no active resource (it then sees no Tradecraft at all), or the counts cannot
    be read: the run then goes on without one."""
    from tradecraft.library import coverage
    from tradecraft.settings import EffectiveSettings

    if not catalog.resources or not EffectiveSettings(catalog.search or {}, scope="search").bool("prompt.coverageMap"):
        return None
    return coverage.coverage_for(catalog)


def bound_coverage() -> Optional[dict]:
    """The run's coverage counts, or None outside a 2.0 run's task or without a map."""
    return _coverage.get()


def _bind_browser_fetcher() -> None:
    """The run's reads reach the sandbox browser for a thin page, as 1.x did: the module's
    default fetcher has no MCP manager. A fetcher a caller bound already (a test's) stays."""
    from tradecraft import net
    from tradecraft.jobs import _agent_mcp_manager

    if net.get_fetcher() is net._DEFAULT:
        net._current.set(net.GuardedFetcher(_agent_mcp_manager()))


def bound_catalog() -> Optional[V2Catalog]:
    """The run's catalog, or None outside a run's task."""
    return _catalog.get()


def run_github_token() -> str:
    """The GitHub token of the account whose run this is (its project's owner: the run's
    ``USER_SETTINGS``), read from the settings bound to the run's task only, as 1.x read it
    (``tools.run_user_settings``, RBAC T17): never another run's, never the module-global
    snapshot of whichever project loaded last. "" outside a run or when the account has none."""
    import project_settings as _ps

    user_settings = (_ps._settings_ctx.get() or {}).get("USER_SETTINGS") or {}
    return str(user_settings.get("githubAccessToken") or "")


def v2_active() -> bool:
    return _catalog.get() is not None


def v2_tool_for(name: str) -> Any:
    """The tool ``name`` as this run reads it when a catalog is bound, else None (the executor's
    stand-in answers "not available" then)."""
    if not v2_active():
        return None
    from tradecraft.agent_tools import V2_TOOLS
    return V2_TOOLS.get(name)


def catalog_query(project_id: str) -> dict:
    """The query of the catalog route: the project, and the person and the acting administrator
    of the run (``current_run_actor``). Without a run actor (a request outside a socket's run)
    only the project goes, and the webapp leaves out every resource with a login (R-155). The
    owner is never sent: the webapp reads it from the project row."""
    from decision_check import current_run_actor

    query = {"projectId": project_id}
    actor = current_run_actor.get()
    if actor is not None and actor.user_id:
        query["personId"] = actor.user_id
        if actor.actor_id:
            query["actorId"] = actor.actor_id
    return query


def run_store() -> Any:
    """The page store the run reads (a test binds its own with ``use_store``)."""
    store = _store.get()
    if store is None:
        from tradecraft.store import Store
        store = Store()
    return store


@contextlib.contextmanager
def use_store(store: Any) -> Iterator[Any]:
    token = _store.set(store)
    try:
        yield store
    finally:
        _store.reset(token)


def run_index() -> Any:
    """The search index the run reads (``library.search.LibraryIndex`` on the page store's
    database), or None when a caller bound a store of its own and no index with it (a test's
    in-memory store has no full-text search; its reads keep today's title match)."""
    index = _index.get()
    if index is not None:
        return index
    if _store.get() is not None:
        return None
    from tradecraft.library.search import LibraryIndex
    return LibraryIndex()


@contextlib.contextmanager
def use_index(index: Any) -> Iterator[Any]:
    token = _index.set(index)
    try:
        yield index
    finally:
        _index.reset(token)
