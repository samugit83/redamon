"""The progress label comes from the pipeline's own headers (plan 12.8).

The first tool-name pattern a line matched set the phase, so the label rewound
all the time: the background graph writer's `[graph-db] update_graph_from_…`
lines, IP mode's `PHASE n:` prelude, the two end-of-run summaries, and
parallel fan-outs interleaving lines all moved it, and Nmap's banner jumped it
ahead to Vulnerability Scanning. And only a log stream parsed it, so with
nobody watching, get_recon_status (UI and MCP) showed no phase or an old one.

Once a log has shown one of recon/main.py's `[*][Pipeline] GROUP …` headers,
only headers move the phase; the old patterns serve a log with no header yet
(a container from before the headers) and never move it backwards. A per-project cursor parses each
line once, from the stream or from a status poll.
"""
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm  # noqa: E402
from models import ReconState, ReconStatus  # noqa: E402


def _walk(lines, tracker=None):
    tracker = tracker or cm.PhaseTracker()
    seen = []
    for line in lines:
        tracker.feed(line)
        seen.append(tracker.phase_number)
    return tracker, seen


DOMAIN_RUN = [
    "  [*][Pipeline] SCAN_MODULES:      domain_discovery,port_scan,http_probe,resource_enum,vuln_scan",
    "[*][Pipeline] GROUP 1: WHOIS + Subdomain Discovery + URLScan (parallel fan-out)",
    "[*][WHOIS] WHOIS Lookup for example.com",
    "[graph-db] update_graph_from_domain_discovery complete",
    "[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)",
    "[*][Naabu] NAABU PORT SCANNER",
    "[+][graph-db] Domain discovery written",
    "[*][Pipeline] GROUP 3.5: Nmap Service Detection + NSE Vuln Scripts",
    "[*][Nmap] SERVICE & VULNERABILITY SCANNER",
    "[*][Pipeline] GROUP 3.6: TLS Certificate Grab",
    "[*][Pipeline] GROUP 3b: OSINT Enrichment (censys, otx) — parallel",
    "[!][graph-db] Background graph update (update_graph_from_port_scan) failed: boom",
    "[*][Pipeline] GROUP 4: HTTP Probing",
    "[*][Httpx] HTTPX HTTP PROBER",
    "[graph-db] update_graph_from_http_probe complete",
    "[*][Pipeline] GROUP 5: Resource Enumeration",
    "[*][Katana] Katana + GAU crawl",
    "[*][Pipeline] GROUP 4.5: AI Surface Recon",
    "[*][Pipeline] GROUP 5b: JS Recon",
    "[graph-db] update_graph_from_resource_enum complete",
    "[*][Pipeline] GROUP 5.5: Supply-Chain Recon",
    "[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning (fan-out: vuln_scan)",
    "[*][Nuclei] NUCLEI scan running",
    "[*][CVE] CVE LOOKUP for nginx",
    "[*][Pipeline] GROUP 6 Phase B: MITRE CVE Enrichment",
    "[*][MITRE] MITRE CWE/CAPEC enrichment",
    "[graph-db] update_graph_from_vuln_scan complete",
    "[✓][Pipeline] DOMAIN RECON COMPLETE",
    "[+][ResourceEnum] Endpoints: 12",
    "[+][Nuclei] Vuln findings: 3 (2 vulnerabilities)",
    "  [✓][Pipeline] RECON PIPELINE COMPLETE",
    "  [+][Naabu] Port Scan: 2 hosts, 4 ports",
    "  [+][Httpx] HTTP Probe: 3 live URLs, 5 technologies",
]


class TestADomainRun:
    def test_the_phase_never_moves_backwards(self):
        _, seen = _walk(DOMAIN_RUN)
        numbers = [n for n in seen if n is not None]
        assert numbers == sorted(numbers)

    def test_each_header_sets_its_phase(self):
        tracker = cm.PhaseTracker()
        expect = {
            "GROUP 1:": 1, "GROUP 3:": 2, "GROUP 3.5:": 2, "GROUP 3.6:": 2, "GROUP 3b:": 2,
            "GROUP 4:": 3, "GROUP 5:": 4, "GROUP 4.5:": 4.5, "GROUP 5b:": 4.5, "GROUP 5.5:": 4.5,
            "GROUP 6 Phase A:": 5, "GROUP 6 Phase B:": 6,
        }
        for line in DOMAIN_RUN:
            tracker.feed(line)
            for marker, number in expect.items():
                if f"[Pipeline] {marker}" in line:
                    assert tracker.phase_number == number, line

    def test_no_graph_db_line_moves_it(self):
        tracker = cm.PhaseTracker()
        tracker.feed("[*][Pipeline] GROUP 5: Resource Enumeration")
        for line in ("[graph-db] update_graph_from_domain_discovery complete",
                     "[!][graph-db] Neo4j not reachable — skipped update_graph_from_port_scan",
                     "[!][graph-db] Background graph update (update_graph_from_vuln_scan) failed: x",
                     "[+][graph-db] Graph database updated with http probe data",
                     "[*][graph-db] GRAPH UPDATE: MitreData"):
            assert tracker.feed(line) is False
            assert tracker.phase_number == 4

    def test_nmaps_banner_does_not_jump_ahead(self):
        tracker, _ = _walk(DOMAIN_RUN[:9])
        assert tracker.phase_number == 2
        assert tracker.phase == "Port Scanning"

    def test_neither_summary_rewinds_it(self):
        tracker, _ = _walk(DOMAIN_RUN)
        assert tracker.phase_number == 6
        assert tracker.phase == "CVE & MITRE"


IP_RUN = [
    "[*][Pipeline] GROUP 1: Reverse DNS + DNS + IP WHOIS (IP mode)",
    "[*][DNS] IP STEP 1: Reverse DNS Lookup",
    "[*][DNS] IP STEP 2: DNS Resolution for Discovered Hosts",
    "[*][WHOIS] IP STEP 3: IP WHOIS Lookup",
    "[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)",
    "[*][Pipeline] GROUP 6: Vulnerability Scanning (Nuclei, then MITRE)",
    "[*][MITRE] MITRE CWE/CAPEC enrichment",
    "[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning (fan-out: graphql_scan)",
    "[✓][Pipeline] IP RECON COMPLETE",
]


class TestAnIpRun:
    def test_the_prelude_does_not_map_to_pipeline_phases(self):
        tracker, seen = _walk(IP_RUN[:4])
        assert seen == [1, 1, 1, 1]
        assert tracker.phase == "Domain Discovery"

    def test_the_prelude_lines_match_no_pattern_without_a_header_either(self):
        for line in IP_RUN[1:4]:
            assert cm.PhaseTracker().feed(line) is False

    def test_it_never_moves_backwards(self):
        _, seen = _walk(IP_RUN)
        assert seen == [1, 1, 1, 1, 2, 5, 5, 5, 5]


class TestABatch:
    def test_the_phase_resets_at_each_group_marker(self):
        tracker = cm.PhaseTracker()
        for line in ["[Batch] Group 1/2: a.example.com", *DOMAIN_RUN,
                     "[Batch] Group 2/2: b.example.com"]:
            tracker.feed(line)
        assert tracker.phase_number is None
        tracker.feed("[*][Pipeline] GROUP 1: WHOIS + Subdomain Discovery + URLScan (parallel fan-out)")
        assert tracker.phase_number == 1
        tracker.feed("[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)")
        assert tracker.phase_number == 2


class TestALogWithNoHeader:
    def test_the_old_patterns_still_report_progress(self):
        tracker = cm.PhaseTracker()
        assert tracker.feed("[*][Httpx] HTTPX HTTP PROBER") is True
        assert tracker.phase_number == 3

    def test_but_never_backwards(self):
        tracker = cm.PhaseTracker()
        tracker.feed("[*][Nuclei] NUCLEI scan running")
        assert tracker.feed("[*][Naabu] NAABU PORT SCANNER") is False
        assert tracker.phase_number == 5

    def test_the_legacy_parse_entry_point_still_reports_a_phase(self):
        manager = cm.ContainerManager.__new__(cm.ContainerManager)
        event = cm.ContainerManager._parse_log_line(manager, "[Phase 2] NAABU PORT SCANNER", None, None)
        assert event.is_phase_start is True and event.phase_number == 2


def test_the_highest_header_phase_is_the_total():
    assert max(n for _, _, n in cm.PIPELINE_HEADER_PHASES) == ReconState.model_fields["total_phases"].default


# --- the per-project cursor --------------------------------------------------

def _ts(seconds):
    return (datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds))


def _docker_line(seconds, text):
    stamp = _ts(seconds).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"
    return f"{stamp} {text}".encode()


class LoggingContainer:
    status = "running"

    def __init__(self, lines):
        self.lines = lines
        self.calls = []

    def logs(self, since=None, timestamps=False, stream=False, follow=False, **_):
        self.calls.append(since)
        out = [raw for seconds, raw in self.lines if since is None or _ts(seconds) >= since]
        return b"\n".join(out)


def _manager(container):
    m = cm.ContainerManager.__new__(cm.ContainerManager)
    m.client = type("C", (), {})()
    m.client.containers = type("Cs", (), {"get": staticmethod(lambda cid: container)})()
    m.running_states = {"p1": ReconState(project_id="p1", status=ReconStatus.RUNNING,
                                         container_id="c1")}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=1)
    return m


class TestTheCursor:
    LINES = [
        (1, _docker_line(1, "[*][Pipeline] GROUP 1: WHOIS + Subdomain Discovery + URLScan")),
        (2, _docker_line(2, "[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)")),
        (3, _docker_line(3, "[graph-db] update_graph_from_domain_discovery complete")),
    ]

    def test_a_status_poll_with_no_stream_reports_the_phase(self):
        container = LoggingContainer(list(self.LINES))
        m = _manager(container)
        state = m._get_status_sync("p1")
        assert (state.current_phase, state.phase_number) == ("Port Scanning", 2)

    def test_each_line_is_parsed_once_and_polls_are_throttled(self, monkeypatch):
        container = LoggingContainer(list(self.LINES))
        m = _manager(container)
        fed = []
        original = cm.PhaseTracker.feed
        monkeypatch.setattr(cm.PhaseTracker, "feed", lambda self, line: fed.append(line) or original(self, line))
        m._get_status_sync("p1")
        m._get_status_sync("p1")                    # inside the 10 s throttle: no read
        assert len(container.calls) == 1
        cursor = m._phase_cursors["p1"]
        cursor.next_poll = 0                        # throttle elapsed
        container.lines.append((5, _docker_line(5, "[*][Pipeline] GROUP 4: HTTP Probing")))
        state = m._get_status_sync("p1")
        assert state.phase_number == 3
        assert len(fed) == 4                        # every line once, the re-read second skipped

    def test_nothing_new_keeps_the_previous_phase(self):
        container = LoggingContainer(list(self.LINES))
        m = _manager(container)
        m._get_status_sync("p1")
        m._phase_cursors["p1"].next_poll = 0
        container.lines = []
        assert m._get_status_sync("p1").phase_number == 2

    def test_a_stream_attached_later_does_not_rewind_it(self):
        container = LoggingContainer(list(self.LINES))
        m = _manager(container)
        m._get_status_sync("p1")
        cursor = m._phase_cursors["p1"]
        # A late stream replays the whole log from the start.
        for _seconds, raw in self.LINES:
            m._feed_phase_cursor("p1", raw.decode())
        assert m.running_states["p1"].phase_number == 2
        assert cursor.tracker.phase_number == 2

    def test_no_poll_while_a_stream_is_parsing(self):
        container = LoggingContainer(list(self.LINES))
        m = _manager(container)
        m._phase_streams = {"p1": 1}
        m._get_status_sync("p1")
        assert container.calls == []
