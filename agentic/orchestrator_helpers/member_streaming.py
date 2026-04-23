"""Member-scoped streaming callback proxy.

When a fireteam member runs inside ``fireteam_deploy_node._run_one``, its
execute_tool_node / execute_plan_node / fireteam_member_think_node calls
resolve the streaming callback via ``streaming_callbacks.get(session_id)``.
That returns the ROOT callback, which fires generic ``TOOL_START`` /
``TOOL_COMPLETE`` / ``THINKING`` events — the frontend routes those as
root-level items, bypassing the FireteamMemberCard panel.

This module defines a thin proxy that, when active, rewrites the on_*
methods so events go out as ``FIRETEAM_TOOL_START`` / ``FIRETEAM_TOOL_COMPLETE``
/ ``FIRETEAM_THINKING`` etc., scoped to the member panel in the UI.

The proxy is activated via a ContextVar that the deploy node sets before
creating each member's task. ``asyncio`` copies ContextVar values at
``create_task`` time, so each member task has its own view.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ContextVar: when non-None inside a member's task, signals "we are inside
# a fireteam member run; rewrite streaming events to fireteam-scoped ones."
_member_streaming_ctx: ContextVar[Optional["MemberScopedCallback"]] = ContextVar(
    "_member_streaming_ctx", default=None,
)


def get_member_streaming() -> Optional["MemberScopedCallback"]:
    """Return the active MemberScopedCallback, or None if not inside a member."""
    return _member_streaming_ctx.get()


def resolve_streaming_callback(streaming_callbacks: dict, session_id: str):
    """Returns the member-scoped proxy if set, else the root callback.

    Used by execute_tool_node / execute_plan_node as a drop-in replacement
    for ``streaming_callbacks.get(session_id)``.
    """
    member = _member_streaming_ctx.get()
    if member is not None:
        return member
    return streaming_callbacks.get(session_id) if streaming_callbacks else None


class MemberScopedCallback:
    """Wraps a real StreamingCallback, rewriting events to fireteam-scoped ones.

    Forwards every method the real callback exposes, but the
    *tool lifecycle* methods are overridden to emit the fireteam-scoped
    variant with ``fireteam_id`` and ``member_id`` attached. Unknown methods
    are forwarded via ``__getattr__`` so database persistence, connection
    lookup, and any future streaming callback additions keep working.
    """

    def __init__(self, real_callback: Any, *, fireteam_id: str, member_id: str, member_name: str):
        self._real = real_callback
        self._fireteam_id = fireteam_id
        self._member_id = member_id
        self._member_name = member_name
        # Per-member dedup sets: emit_streaming_events reads these attributes
        # to avoid duplicate events when the same state yields multiple times.
        # MUST be separate from the root callback's sets so members don't
        # collide with root emissions.
        self._emitted_tool_start_ids: set = set()
        self._emitted_tool_complete_ids: set = set()
        self._emitted_tool_output_ids: set = set()
        self._emitted_thinking_ids: set = set()
        self._emitted_approval_key: str = ""
        self._emitted_question_key: str = ""

    # ----- Identity passthrough so log/debug code that reads these keeps working -----

    def __getattr__(self, name: str):
        # Delegate anything we don't explicitly override to the real callback.
        return getattr(self._real, name)

    # ----- Thinking (the member is reasoning) -----

    async def on_thinking(self, iteration: int, phase: str, thought: str, reasoning: str,
                          action: Optional[str] = None,
                          input_tokens: int = 0,
                          output_tokens: int = 0):
        # `action` is root-side only: fireteam_thinking has its own payload
        # shape and doesn't carry it. Accept and drop.
        try:
            await self._real.on_fireteam_thinking(
                fireteam_id=self._fireteam_id,
                member_id=self._member_id,
                name=self._member_name,
                iteration=iteration,
                phase=phase,
                thought=thought,
                reasoning=reasoning,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        except AttributeError:
            # Older callback without fireteam_thinking: fall back to generic.
            await self._real.on_thinking(
                iteration, phase, thought, reasoning, action=action,
                input_tokens=input_tokens, output_tokens=output_tokens,
            )

    async def on_thinking_chunk(self, chunk: str):
        # No fireteam-scoped streaming chunk yet; swallow to avoid mixing with root.
        # Frontend shows thinking when the final thought arrives via on_thinking.
        return

    # ----- Tool lifecycle -----

    async def on_tool_start(self, tool_name: str, tool_args: dict,
                            wave_id: Optional[str] = None, step_index: Optional[int] = None):
        await self._real.on_fireteam_tool_start(
            fireteam_id=self._fireteam_id,
            member_id=self._member_id,
            tool_name=tool_name,
            tool_args=tool_args,
            wave_id=wave_id,
            step_index=step_index,
        )

    async def on_tool_output_chunk(self, tool_name: str, chunk: str, is_final: bool = False,
                                   wave_id: Optional[str] = None, step_index: Optional[int] = None):
        # Emit FIRETEAM_TOOL_OUTPUT_CHUNK so the UI can append to the
        # correct member's tool card instead of showing silence during
        # long-running tools. Persistence is handled by the callback itself.
        await self._real.on_fireteam_tool_output_chunk(
            fireteam_id=self._fireteam_id,
            member_id=self._member_id,
            tool_name=tool_name,
            chunk=chunk,
            is_final=is_final,
            wave_id=wave_id,
            step_index=step_index,
        )

    async def on_tool_complete(self, tool_name: str, success: bool, output: str,
                               duration_ms: Optional[int] = None,
                               wave_id: Optional[str] = None, step_index: Optional[int] = None,
                               **kwargs):
        await self._real.on_fireteam_tool_complete(
            fireteam_id=self._fireteam_id,
            member_id=self._member_id,
            tool_name=tool_name,
            success=success,
            duration_ms=duration_ms or 0,
            output_excerpt=(output or "")[:500],
            wave_id=wave_id,
            step_index=step_index,
        )

    # ----- Plan wave (plan_tools fired inside the member) -----

    async def on_plan_start(self, wave_id: str, plan_rationale: str, tools: list):
        await self._real.on_fireteam_plan_start(
            fireteam_id=self._fireteam_id,
            member_id=self._member_id,
            wave_id=wave_id,
            plan_rationale=plan_rationale,
            tools=tools,
        )

    async def on_plan_complete(self, wave_id: str, total: int, successful: int, failed: int):
        await self._real.on_fireteam_plan_complete(
            fireteam_id=self._fireteam_id,
            member_id=self._member_id,
            wave_id=wave_id,
            total=total,
            successful=successful,
            failed=failed,
        )

    async def on_plan_analysis(self, *args, **kwargs):
        # Analysis happens at root only; swallow for members to keep UI focused
        # on per-member tool cards inside their panel.
        return

    async def on_phase_update(self, *args, **kwargs):
        # Swallow. `emit_streaming_events` fires on_phase_update after every
        # astream yield using `state.get("current_iteration", 0)` — which, on
        # a member state, is the MEMBER's sub-step number, not the root's.
        # Without this override the UI header's "Step N" climbs every time
        # a member iterates and overwrites the real root iteration count.
        # Root-level phase updates are emitted by the parent's own
        # emit_streaming_events with the real callback (not this proxy).
        return

    async def on_todo_update(self, *args, **kwargs):
        # Members don't own the root todo list; only the root's think_node
        # should ever emit TODO_UPDATE. Same rationale as on_phase_update.
        return


# Helper to set the context for a member task
class _MemberStreamingContext:
    """Context manager to scope a MemberScopedCallback for the duration of a
    member's astream invocation. Use with:

        async with scoped_member_streaming(real_cb, fireteam_id=..., member_id=..., member_name=...):
            async for event in member_graph.astream(...):
                ...
    """

    def __init__(self, real_callback, fireteam_id: str, member_id: str, member_name: str):
        self._proxy = MemberScopedCallback(
            real_callback,
            fireteam_id=fireteam_id,
            member_id=member_id,
            member_name=member_name,
        )
        self._token = None

    def __enter__(self):
        self._token = _member_streaming_ctx.set(self._proxy)
        return self._proxy

    def __exit__(self, *exc):
        if self._token is not None:
            _member_streaming_ctx.reset(self._token)
        return False


def scoped_member_streaming(real_callback, *, fireteam_id: str, member_id: str, member_name: str):
    """Context manager factory. See :class:`_MemberStreamingContext`."""
    if real_callback is None:
        # No root callback (headless); return a no-op context.
        class _Noop:
            def __enter__(self): return None
            def __exit__(self, *exc): return False
        return _Noop()
    return _MemberStreamingContext(real_callback, fireteam_id, member_id, member_name)
