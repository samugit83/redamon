"""PDF text for a readable mirror, extracted in a short-lived child process.

A hostile PDF can make pypdf spin for minutes. A thread cannot be killed and
would pin one of the import pool's two workers; a process can be (SEC-8). One
conversion runs at a time, each with a deadline.

The child loads web_sources.py by its path. Importing it as
orchestrator_helpers.web_sources would first run that package's __init__,
which imports most of the agent (over 5,000 modules, about 6 s) in every child.

Stdlib only at import time: the spawned child imports this module.
"""
from __future__ import annotations

import asyncio
import importlib.util
import multiprocessing
import os
import weakref
from typing import Callable, Tuple

TIMEOUT_SEC = 60.0

_WEB_SOURCES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "orchestrator_helpers", "web_sources.py")
# One lock per event loop: an asyncio.Lock is bound to the loop it first waits on.
_locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


def _extract_pdf_pages():
    spec = importlib.util.spec_from_file_location("_workspace_import_web_sources", _WEB_SOURCES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.extract_pdf_pages


def child_main(path: str, conn) -> None:
    """Runs in the child: send ("ok", text) or ("error", "")."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        _meta, texts, _err = _extract_pdf_pages()(raw)
        conn.send(("ok", "\n\n".join(t for t in texts if t)))
    except Exception:
        conn.send(("error", ""))
    finally:
        conn.close()


async def pdf_to_text(path, *, timeout: float = TIMEOUT_SEC,
                      target: Callable = child_main) -> Tuple[str, str]:
    """("ok", text), ("timeout", "") after the child was killed at the
    deadline, or ("error", "") when it failed or died."""
    loop = asyncio.get_running_loop()
    lock = _locks.setdefault(loop, asyncio.Lock())
    async with lock:
        ctx = multiprocessing.get_context("spawn")
        reader, writer = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=target, args=(str(path), writer), daemon=True)
        ready = asyncio.Event()
        try:
            proc.start()
            writer.close()
            # Wait on the pipe from the event loop itself: no thread is held
            # while a slow PDF is parsed.
            loop.add_reader(reader.fileno(), ready.set)
            try:
                await asyncio.wait_for(ready.wait(), timeout)
            except asyncio.TimeoutError:
                return "timeout", ""
            finally:
                loop.remove_reader(reader.fileno())
            try:
                status, text = reader.recv()
            except (EOFError, OSError, ValueError, TypeError):
                return "error", ""
            return ("ok", text) if status == "ok" and isinstance(text, str) else ("error", "")
        finally:
            writer.close()
            reader.close()
            if proc.is_alive():
                proc.kill()
            # A killed or finished child is reaped at once; never block the loop on a live one.
            proc.join(0.5)
