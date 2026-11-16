"""The Tradecraft 2.0 binding of one chat run (master plan TD-9, TD-10).

At run start the orchestrator hands ``bind_run_catalog`` the catalog the webapp answered for
this run. A 2.0 catalog is bound to the run's task, in this module's own context variable and
nowhere else, together with the run's registry entries; a 1.x payload (or none) clears both,
and the 1.x manager serves the run as before.

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
    """Binds a 2.0 catalog, its coverage counts (Q5, when ``prompt.coverageMap`` is on) and its
    registry entries to the current task; True when bound. A 1.x payload, None, or a catalog that
    does not parse clears the 2.0 binding (False)."""
    from prompts.tool_registry import pop_tradecraft_entry, swap_tradecraft_v2_entries
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
        # A 1.x entry left in this task (an earlier run of the session) must not show beside
        # the 2.0 entries, nor in their place when the 2.0 list is empty.
        pop_tradecraft_entry()
        _bind_browser_fetcher()
        logger.info(f"[tradecraft] run catalog bound resources={len(parsed.resources)}")
    return parsed is not None


def _coverage_of(catalog: V2Catalog) -> Optional[dict]:
    """The coverage counts of the run's resources (one bounded query), or None when the map is
    off or cannot be read: the run then goes on without one."""
    from tradecraft.library import coverage
    from tradecraft.settings import EffectiveSettings

    if not EffectiveSettings(catalog.search or {}, scope="search").bool("prompt.coverageMap"):
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
    """The run's 2.0 catalog, or None outside a 2.0 run's task."""
    return _catalog.get()


def v2_active() -> bool:
    return _catalog.get() is not None


def v2_tool_for(name: str) -> Any:
    """The 2.0 implementation of tool ``name`` when this run is a 2.0 run, else None."""
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


def section_picker() -> Any:
    """The owner's "Tradecraft section picker" model for this run, or None (text match).

    Read from the settings bound to the run's task only, as 1.x builds it; a loop model is
    refused by the builder."""
    import project_settings as _ps

    settings = _ps._settings_ctx.get() or {}
    user_settings = settings.get("USER_SETTINGS") or {}
    try:
        from feature_models import feature_model
        model = feature_model(user_settings, "tradecraft_section_picker")
        if not model:
            return None
        from llm_builder import build_llm_from_providers
        return build_llm_from_providers(model, settings.get("USER_LLM_PROVIDERS") or [])
    except Exception as exc:
        logger.warning(f"[tradecraft] section picker unavailable error={type(exc).__name__}")
        return None
