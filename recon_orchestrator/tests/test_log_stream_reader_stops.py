"""A log stream's reader thread ends when its client goes away (L-14).

Every SSE log stream (full and partial recon, AI attack surface, GVM, GitHub
hunt, TruffleHog, supply chain) followed the container's logs on a worker of
the shared 64-thread log pool and pushed each line into an unbounded queue.
Nothing told that worker the client had left, so it went on reading, and
queueing, until the container exited, hours later for a long scan. Enough
reconnects exhausted the pool and no project got a log stream any more.

Now one reader serves them all: a bounded buffer, a stop flag set when the
consumer goes away, and the Docker log stream closed so a reader blocked on a
quiet container wakes at once.
"""
import asyncio
import threading
from unittest.mock import MagicMock, patch

import pytest

import container_manager as cm
from container_manager import ContainerManager
from models import (
    AiAttackSurfaceState, AiAttackSurfaceStatus, GithubHuntState, GithubHuntStatus,
    GvmState, GvmStatus, PartialReconState, PartialReconStatus, ReconState, ReconStatus,
    SupplyChainState, SupplyChainStatus, TrufflehogState, TrufflehogStatus,
)

STAMP = "2026-11-10T10:00:00.000000000Z"
# Long enough that a reader nobody stops is plainly still there when the test
# looks, short enough that a failing run still ends.
GIVE_UP_S = 5.0


class BlockingLogStream:
    """docker-py's follow=True log stream: its lines, then a wait for the next
    one, as on a live but quiet container. close() is the socket shutdown
    docker-py's CancellableStream does, and ends the iteration."""

    def __init__(self, lines=(f"{STAMP} [*] first line".encode(),)):
        self.lines = list(lines)
        self.closed = threading.Event()
        self.ended = threading.Event()

    def __iter__(self):
        return self

    def __next__(self):
        if self.lines and not self.closed.is_set():
            return self.lines.pop(0)
        self.closed.wait(GIVE_UP_S)
        self.ended.set()
        raise StopIteration

    def close(self):
        self.closed.set()


class EndlessLogStream:
    """A scan writing faster than the client reads."""

    def __init__(self):
        self.pulled = 0
        self.closed = threading.Event()

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed.is_set() or self.pulled >= 200_000:
            raise StopIteration
        self.pulled += 1
        return f"{STAMP} [*] line {self.pulled}".encode()

    def close(self):
        self.closed.set()


def _manager(stream_factory, log_workers=64):
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = ContainerManager()
    mgr.client = MagicMock()
    mgr.local_llm_manager = MagicMock()
    mgr._log_stream_executor = cm.ThreadPoolExecutor(
        max_workers=log_workers, thread_name_prefix="log-stream")
    container = MagicMock()
    container.id = "c1"
    container.status = "running"
    container.attrs = {"State": {"ExitCode": 0}}
    mgr.streams = []

    def _logs(**kwargs):
        # The status poll reads a running scan's recent lines without `stream`.
        if not kwargs.get("stream"):
            return b""
        stream = stream_factory()
        mgr.streams.append(stream)
        return stream

    container.logs.side_effect = _logs
    mgr.client.containers.get.return_value = container
    return mgr


def _open(kind, m):
    if kind == "recon":
        m.running_states["p"] = ReconState(project_id="p", status=ReconStatus.RUNNING,
                                           container_id="c1")
        return m.stream_logs("p")
    if kind == "partial_recon":
        m.partial_recon_states["p"] = {"r": PartialReconState(
            project_id="p", run_id="r", tool_id="Httpx",
            status=PartialReconStatus.RUNNING, container_id="c1")}
        return m.stream_partial_logs("p", "r")
    if kind == "ai_attack":
        m.ai_attack_states["p"] = {"r": AiAttackSurfaceState(
            project_id="p", run_id="r", status=AiAttackSurfaceStatus.RUNNING,
            container_id="c1")}
        return m.stream_ai_attack_surface_logs("p", "r")
    if kind == "gvm":
        m.gvm_states["p"] = GvmState(project_id="p", status=GvmStatus.RUNNING,
                                     container_id="c1")
        return m.stream_gvm_logs("p")
    if kind == "github_hunt":
        m.github_hunt_states["p"] = GithubHuntState(project_id="p", status=GithubHuntStatus.RUNNING,
                                                    container_id="c1")
        return m.stream_github_hunt_logs("p")
    if kind == "trufflehog":
        m.trufflehog_states["p"] = {"git": TrufflehogState(
            project_id="p", source="git", run_id="git", status=TrufflehogStatus.RUNNING,
            container_id="c1")}
        return m.stream_trufflehog_logs("p", "git")
    if kind == "supply_chain":
        m.supply_chain_states["p"] = SupplyChainState(project_id="p", status=SupplyChainStatus.RUNNING,
                                                      container_id="c1")
        return m.stream_supply_chain_logs("p")
    raise AssertionError(kind)


KINDS = ["recon", "partial_recon", "ai_attack", "gvm", "github_hunt", "trufflehog", "supply_chain"]


async def _ended(event: threading.Event, timeout: float = 1.0) -> bool:
    return await asyncio.to_thread(event.wait, timeout)


@pytest.mark.parametrize("kind", KINDS)
async def test_closing_the_stream_ends_its_reader(kind):
    m = _manager(BlockingLogStream)
    agen = _open(kind, m)
    try:
        first = await asyncio.wait_for(agen.__anext__(), timeout=2.0)
        assert "first line" in first.log
        await agen.aclose()
        stream = m.streams[0]
        assert stream.closed.is_set(), "the Docker log stream was left open"
        assert await _ended(stream.ended), "the reader is still following the logs"
    finally:
        for s in m.streams:
            s.close()


@pytest.mark.parametrize("kind", ["recon", "partial_recon", "supply_chain"])
async def test_a_cancelled_client_ends_its_reader(kind):
    """sse-starlette cancels the response task when the browser goes away."""
    m = _manager(BlockingLogStream)
    agen = _open(kind, m)
    got_first = asyncio.Event()

    async def _consume():
        async for _ in agen:
            got_first.set()

    task = asyncio.create_task(_consume())
    try:
        await asyncio.wait_for(got_first.wait(), timeout=2.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await _ended(m.streams[0].ended), "the reader outlived its cancelled client"
    finally:
        for s in m.streams:
            s.close()


async def test_a_client_gone_before_docker_answered_still_closes_the_stream():
    """The client leaves while the reader is still waiting for container.logs()
    to answer: the reader must notice once it has the stream, and close it."""
    asked, answer = threading.Event(), threading.Event()
    stream = BlockingLogStream()

    def _slow_open():
        asked.set()
        answer.wait(GIVE_UP_S)
        return stream

    m = _manager(_slow_open)
    agen = _open("recon", m)
    task = asyncio.create_task(agen.__anext__())
    try:
        assert await asyncio.to_thread(asked.wait, 2.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        answer.set()
        assert await _ended(stream.closed), "a stream opened after the client left stayed open"
        assert not stream.ended.is_set(), "the reader followed logs nobody reads"
    finally:
        answer.set()
        stream.close()


async def test_dropped_streams_give_their_worker_back():
    """The E2E symptom: with every log worker held by a reader nobody reads,
    a new stream never starts. One worker, three dropped streams, then a fourth
    must still deliver its first line."""
    m = _manager(BlockingLogStream, log_workers=1)
    try:
        for _ in range(3):
            agen = _open("recon", m)
            await asyncio.wait_for(agen.__anext__(), timeout=2.0)
            await agen.aclose()
        agen = _open("recon", m)
        first = await asyncio.wait_for(agen.__anext__(), timeout=2.0)
        assert "first line" in first.log
        await agen.aclose()
    finally:
        for s in m.streams:
            s.close()


async def test_a_slow_client_holds_a_bounded_backlog(monkeypatch):
    monkeypatch.setattr(cm, "LOG_STREAM_BUFFER_LINES", 20, raising=False)
    m = _manager(EndlessLogStream)
    agen = _open("recon", m)
    try:
        await asyncio.wait_for(agen.__anext__(), timeout=2.0)
        await asyncio.sleep(0.5)
        stream = m.streams[0]
        # The buffer, the line handed over, and the one the reader holds.
        assert stream.pulled <= 22, f"the reader ran {stream.pulled} lines ahead"
        await agen.aclose()
        assert stream.closed.is_set()
    finally:
        for s in m.streams:
            s.close()


async def test_back_pressure_loses_no_line(monkeypatch):
    monkeypatch.setattr(cm, "LOG_STREAM_BUFFER_LINES", 5, raising=False)
    lines = [f"{STAMP} [*] line {i}".encode() for i in range(200)]

    class Finite(BlockingLogStream):
        def __next__(self):
            if self.lines:
                return self.lines.pop(0)
            self.ended.set()
            raise StopIteration

    m = _manager(lambda: Finite(lines))
    m.partial_recon_states["p"] = {"r": PartialReconState(
        project_id="p", run_id="r", tool_id="Httpx",
        status=PartialReconStatus.RUNNING, container_id="c1")}
    seen = []
    async for event in m.stream_partial_logs("p", "r"):
        seen.append(event.log)
        if len(seen) % 50 == 0:
            await asyncio.sleep(0.05)
    assert seen == [f"[*] line {i}" for i in range(200)]


async def test_a_container_that_exits_ends_the_stream():
    """A quiet stream whose container is gone still ends, as before."""
    m = _manager(BlockingLogStream)
    container = m.client.containers.get.return_value
    agen = _open("recon", m)
    try:
        await asyncio.wait_for(agen.__anext__(), timeout=2.0)
        container.status = "exited"
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(agen.__anext__(), timeout=5.0)
        assert await _ended(m.streams[0].ended)
    finally:
        for s in m.streams:
            s.close()
