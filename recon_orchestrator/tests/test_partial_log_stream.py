"""A partial recon's log stream: one phase named after its tool, and no blank
line shown as its own Docker timestamp.

The stream used the full pipeline's tool-name patterns, which never move the
phase backwards, so one line mentioning "nuclei" or "vuln…scan" labelled an
Httpx run "Vulnerability Scanning" until it ended. And a blank print() arrives
from Docker as the stamp alone, exactly 30 characters once its trailing space is
stripped, which a `len(line) > 30` check let through as the line's text in
every log stream.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import container_manager as cm
from container_manager import ContainerManager
from models import PartialReconState, PartialReconStatus, ReconState, ReconStatus

STAMP = "2026-11-06T12:37:26.665584924Z"

HTTPX_RUN = [
    "2026-11-06T12:36:00.000000000Z [*][Partial Recon] HTTP Probing (Httpx)",
    "2026-11-06T12:36:01.000000000Z [*][httpx] HTTPX HTTP PROBER",
    "2026-11-06T12:36:02.000000000Z [*][Nuclei-AI] Loaded 40 candidate tags",
    "2026-11-06T12:36:03.000000000Z [+][PageType-Jev] vulnerability disclosure page, scanned",
    "2026-11-06T12:36:04.000000000Z",
    "2026-11-06T12:36:05.000000000Z [+][Partial Recon] HTTP probing completed successfully",
]


def _manager(lines, tool_id="Httpx"):
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = ContainerManager()
    mgr.client = MagicMock()
    container = MagicMock()
    container.status = "running"
    container.logs.return_value = iter([line.encode() for line in lines])
    mgr.client.containers.get.return_value = container
    mgr.partial_recon_states = {"p": {"r": PartialReconState(
        project_id="p", run_id="r", tool_id=tool_id,
        status=PartialReconStatus.RUNNING, container_id="c0ffee")}}
    return mgr


class TestSplitDockerStamp:
    def test_a_stamped_line_splits_into_time_and_text(self):
        at, text = cm._split_docker_stamp(f"{STAMP} [+][httpx] Banner grab complete")
        assert at == datetime(2026, 11, 6, 12, 37, 26, 665584, tzinfo=timezone.utc)
        assert text == "[+][httpx] Banner grab complete"

    def test_a_blank_line_is_its_stamp_alone_and_has_no_text(self):
        assert len(STAMP) == 30
        at, text = cm._split_docker_stamp(STAMP)
        assert at == datetime(2026, 11, 6, 12, 37, 26, 665584, tzinfo=timezone.utc)
        assert text == ""

    def test_a_fraction_docker_trimmed_still_parses_and_indentation_is_kept(self):
        at, text = cm._split_docker_stamp("2026-11-06T12:37:26.2912Z   [+] indented")
        assert at == datetime(2026, 11, 6, 12, 37, 26, 291200, tzinfo=timezone.utc)
        assert text == "  [+] indented"

    def test_a_line_without_a_stamp_is_kept_whole(self):
        assert cm._split_docker_stamp("plain output line") == (None, "plain output line")


def test_the_pipeline_patterns_name_this_httpx_run_vulnerability_scanning():
    """The premise: the patterns the partial stream no longer uses."""
    tracker = cm.PhaseTracker("Partial Recon", 1)
    for raw in HTTPX_RUN:
        tracker.feed(cm._split_docker_stamp(raw)[1])
    assert tracker.phase == "Vulnerability Scanning"


class TestPartialStream:
    async def test_every_line_is_in_the_tools_one_phase(self):
        mgr = _manager(HTTPX_RUN)
        events = [e async for e in mgr.stream_partial_logs("p", "r")]
        assert len(events) == len(HTTPX_RUN) - 1
        assert {e.phase for e in events} == {"Httpx"}
        assert {e.phase_number for e in events} == {cm.PARTIAL_RECON_PHASE_NUMBER}
        assert [e.is_phase_start for e in events] == [True] + [False] * (len(events) - 1)

    async def test_a_blank_line_is_not_shown_as_its_stamp(self):
        mgr = _manager(HTTPX_RUN)
        events = [e async for e in mgr.stream_partial_logs("p", "r")]
        assert not any(e.log.startswith("2026-") or not e.log for e in events)
        assert events[-1].timestamp == datetime(2026, 11, 6, 12, 36, 5, tzinfo=timezone.utc)
        assert mgr.partial_recon_states["p"]["r"].last_log_timestamp == events[-1].timestamp

    async def test_a_run_with_no_tool_id_is_named_partial_recon(self):
        mgr = _manager(HTTPX_RUN[:2], tool_id="")
        events = [e async for e in mgr.stream_partial_logs("p", "r")]
        assert {e.phase for e in events} == {"Partial Recon"}


async def test_the_full_recon_stream_drops_a_blank_line_too():
    mgr = _manager([
        "2026-11-06T12:36:00.000000000Z [*][Pipeline] GROUP 4: HTTP Probing",
        "2026-11-06T12:36:01.000000000Z",
        "2026-11-06T12:36:02.000000000Z [+][httpx] done",
    ])
    mgr.running_states["p"] = ReconState(project_id="p", status=ReconStatus.RUNNING,
                                         container_id="c0ffee")
    events = [e async for e in mgr.stream_logs("p")]
    assert [e.log for e in events] == ["[*][Pipeline] GROUP 4: HTTP Probing", "[+][httpx] done"]
    assert events[0].phase == "HTTP Probing"
