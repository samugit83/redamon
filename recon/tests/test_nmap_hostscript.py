"""R-30: nmap's host-rule NSE results become findings.

`--script vuln` runs host-rule scripts too (smb-vuln-ms17-010, smb-vuln-ms10-054,
smb-double-pulsar-backdoor...). nmap reports them under the host's
<hostscript>, not under a <port>, so a parser reading only port scripts dropped
every one of them.

A host-level finding is about the host, not one port: it carries
``host_level: true`` and the host-level port key 0 (the writer's MERGE key needs
a non-null port), and the writer links it from its IP with HAS_VULNERABILITY
instead of AFFECTS a Port.

The XML is synthetic (RFC 5737 addresses); nmap and Neo4j are fakes.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins.recon.port_mixin import PortMixin  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402
from recon.main_recon_modules.nmap_scan import parse_nmap_xml  # noqa: E402

IP = "192.0.2.20"
IP_2 = "198.51.100.7"

MS17_010_OUTPUT = (
    "&#xa;  VULNERABLE:&#xa;"
    "  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)&#xa;"
    "    State: VULNERABLE&#xa;"
    "    IDs:  CVE:CVE-2017-0143&#xa;"
    "    Risk factor: HIGH&#xa;"
)

FTP_BACKDOOR_OUTPUT = (
    "VULNERABLE: vsFTPd version 2.3.4 backdoor. State: VULNERABLE (Exploitable). "
    "IDs: CVE:CVE-2011-2523"
)

PORTS = (
    '<ports>'
    '<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/>'
    '<service name="ftp" product="vsftpd" version="2.3.4"/>'
    f'<script id="ftp-vsftpd-backdoor" output="{FTP_BACKDOOR_OUTPUT}"/>'
    '</port>'
    '<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>'
    '<service name="microsoft-ds" product="Microsoft Windows 7 - 10 microsoft-ds"/>'
    '</port>'
    '</ports>'
)

# The shape nmap 7.9x writes: the vulns library's table beside the flat output,
# a script that answered "false", and one that could not connect.
HOSTSCRIPT = (
    '<hostscript>'
    f'<script id="smb-vuln-ms17-010" output="{MS17_010_OUTPUT}">'
    '<table key="CVE-2017-0143">'
    '<elem key="title">Remote Code Execution vulnerability in Microsoft SMBv1 servers'
    ' (ms17-010)</elem>'
    '<elem key="state">VULNERABLE</elem>'
    '</table></script>'
    '<script id="smb-vuln-ms10-054" output="false">false</script>'
    '<script id="smb-vuln-ms10-061" output="Could not negotiate a connection:SMB: '
    'Failed to receive bytes: ERROR"/>'
    '</hostscript>'
)


def _xml(*hosts: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<nmaprun scanner="nmap" args="nmap -sV --script vuln" version="7.94SVN">'
            + "".join(hosts) + '</nmaprun>')


def _host(ip: str, body: str) -> str:
    return (f'<host starttime="1" endtime="2"><status state="up" reason="syn-ack"/>'
            f'<address addr="{ip}" addrtype="ipv4"/>{body}</host>')


def _parse(xml: str, ip_to_hostnames=None) -> dict:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as f:
        f.write(xml)
    try:
        return parse_nmap_xml(path, ip_to_hostnames or {})
    finally:
        os.unlink(path)


def _host_level(result: dict) -> list:
    return [v for v in result["nse_vulns"] if v.get("host_level")]


# ─── the parser ──────────────────────────────────────────────────────────────

class TestParserReadsHostScripts:
    def test_a_vulnerable_hostscript_becomes_one_host_level_finding(self):
        result = _parse(_xml(_host(IP, PORTS + HOSTSCRIPT)))

        assert _host_level(result) == [{
            "host": IP,
            "ip": IP,
            "port": 0,
            "host_level": True,
            "script_id": "smb-vuln-ms17-010",
            "state": "VULNERABLE",
            "output": MS17_010_OUTPUT.replace("&#xa;", "\n").strip(),
            "cve": "CVE-2017-0143",
        }]

    def test_the_port_finding_beside_it_is_unchanged(self):
        result = _parse(_xml(_host(IP, PORTS + HOSTSCRIPT)))

        port_level = [v for v in result["nse_vulns"] if not v.get("host_level")]
        assert port_level == [{
            "host": IP, "ip": IP, "port": 21, "script_id": "ftp-vsftpd-backdoor",
            "state": "VULNERABLE", "output": FTP_BACKDOOR_OUTPUT, "cve": "CVE-2011-2523",
        }]

    def test_an_xml_without_a_hostscript_gives_todays_output(self):
        with_hs = _parse(_xml(_host(IP, PORTS + HOSTSCRIPT)), {IP: ["smb.example.com"]})
        without = _parse(_xml(_host(IP, PORTS)), {IP: ["smb.example.com"]})

        assert without["nse_vulns"] == [{
            "host": IP, "ip": IP, "port": 21, "script_id": "ftp-vsftpd-backdoor",
            "state": "VULNERABLE", "output": FTP_BACKDOOR_OUTPUT, "cve": "CVE-2011-2523",
        }]
        # The host scripts add findings only: ports, services and the host
        # entry are what they were.
        assert with_hs["by_host"] == without["by_host"]
        assert with_hs["services_detected"] == without["services_detected"]
        assert list(without["by_host"]) == ["smb.example.com"]
        assert without["by_host"]["smb.example.com"]["ports"] == [21, 445]

    def test_not_vulnerable_false_and_failed_host_scripts_write_nothing(self):
        quiet = (
            '<hostscript>'
            '<script id="smb-vuln-ms10-054" output="false"/>'
            '<script id="smb-vuln-cve2009-3103" output="&#xa;  NOT VULNERABLE:&#xa;'
            '    State: NOT VULNERABLE&#xa;"/>'
            '<script id="smb-vuln-ms10-061" output="ERROR: Script execution failed"/>'
            '</hostscript>'
        )
        result = _parse(_xml(_host(IP, PORTS + quiet)))

        assert _host_level(result) == []
        assert [v["script_id"] for v in result["nse_vulns"]] == ["ftp-vsftpd-backdoor"]

    def test_likely_vulnerable_keeps_its_state(self):
        likely = ('<hostscript><script id="smb-double-pulsar-backdoor" output="'
                  'LIKELY VULNERABLE: Double Pulsar SMB backdoor"/></hostscript>')
        result = _parse(_xml(_host(IP, PORTS + likely)))

        [finding] = _host_level(result)
        assert finding["state"] == "LIKELY VULNERABLE"
        assert finding["cve"] == ""
        assert finding["port"] == 0

    def test_a_host_without_ports_still_reports_its_hostscript(self):
        result = _parse(_xml(_host(IP, HOSTSCRIPT)))

        assert [(v["script_id"], v["ip"], v["port"]) for v in _host_level(result)] == [
            ("smb-vuln-ms17-010", IP, 0)]
        # No port data, so no host entry: the same as before.
        assert result["by_host"] == {}
        assert result["services_detected"] == []

    def test_each_host_keeps_its_own_ip(self):
        result = _parse(_xml(_host(IP, PORTS + HOSTSCRIPT), _host(IP_2, PORTS)))

        assert [v["ip"] for v in _host_level(result)] == [IP]
        assert sorted(v["ip"] for v in result["nse_vulns"]) == [IP, IP, IP_2]


# ─── the module: nmap's command and the host-level finding in its output ─────

class _Proc:
    returncode = 0

    def communicate(self, timeout=None):
        return "", ""


class _FakeNmap:
    def __init__(self, xml_by_ip):
        self.xml_by_ip = xml_by_ip
        self.commands = []

    def __call__(self, cmd, **_kw):
        self.commands.append(cmd)
        Path(cmd[cmd.index("-oX") + 1]).write_text(self.xml_by_ip[cmd[-1]])
        return _Proc()


class TestRunNmapScanKeepsHostLevelFindings:
    def test_the_host_level_finding_reaches_nmap_scan(self, monkeypatch):
        fake = _FakeNmap({IP: _xml(_host(IP, PORTS + HOSTSCRIPT))})
        monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
        monkeypatch.setattr(nmap_scan.subprocess, "Popen", fake)
        recon = {"port_scan": {"by_ip": {IP: {"ip": IP, "hostnames": [], "ports": [21, 445]}},
                               "by_host": {}, "ip_to_hostnames": {}}}

        out = nmap_scan.run_nmap_scan(recon, settings={"NMAP_PARALLELISM": 1})

        [cmd] = fake.commands
        assert cmd[cmd.index("--script") + 1] == "vuln"
        assert cmd[cmd.index("-p") + 1] == "21,445"
        assert cmd[-1] == IP
        vulns = out["nmap_scan"]["nse_vulns"]
        assert sorted((v["script_id"], v["port"], bool(v.get("host_level"))) for v in vulns) == [
            ("ftp-vsftpd-backdoor", 21, False), ("smb-vuln-ms17-010", 0, True)]
        assert out["nmap_scan"]["summary"]["nse_vulns_found"] == 2


# ─── the writer ──────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, record=None):
        self._record = record

    def single(self):
        return self._record

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        flat = " ".join(query.split())
        self.calls.append((flat, params))
        if "AS matched" in flat:
            return _Result({"matched": 1})
        return _Result()

    def queries(self, needle):
        return [(q, p) for q, p in self.calls if needle in q]


class _Graph(PortMixin):
    def __init__(self, session):
        self.driver = mock.MagicMock()
        self.driver.session.return_value = session


HOST_LEVEL = {"host": IP, "ip": IP, "port": 0, "host_level": True,
              "script_id": "smb-vuln-ms17-010", "state": "VULNERABLE",
              "output": "VULNERABLE: ms17-010", "cve": "CVE-2017-0143"}
PORT_LEVEL = {"host": IP, "ip": IP, "port": 21, "script_id": "ftp-vsftpd-backdoor",
              "state": "VULNERABLE", "output": "VULNERABLE: backdoor", "cve": "CVE-2011-2523"}
SERVICES = [{"product": "vsftpd", "version": "2.3.4", "port": 21, "host": IP, "ip": IP,
             "cpe": ""}]


def _write(*vulns):
    session = _Session()
    stats = _Graph(session).update_graph_from_nmap(
        {"nmap_scan": {"by_host": {}, "services_detected": SERVICES, "nse_vulns": list(vulns)}},
        "u1", "p1")
    return session, stats


def _vuln_merge(session, name):
    [(q, p)] = [(q, p) for q, p in session.queries("MERGE (v:Vulnerability")
                if p["name"] == name]
    return q, p


class TestWriterLinksHostLevelFindingsToTheirIp:
    def test_a_host_level_finding_is_merged_on_port_zero_and_flagged(self):
        session, stats = _write(HOST_LEVEL)

        q, p = _vuln_merge(session, "smb-vuln-ms17-010")
        assert "port_number: $port_number" in q
        assert p["port_number"] == 0
        assert "v.host_level = $host_level" in q
        assert p["host_level"] is True
        # The id hashes the MERGE key, as every nmap_nse id does.
        assert p["nse_id"] == "nse-bcc84f33b47500ef"
        assert stats["errors"] == []

    def test_it_is_linked_from_its_ip_with_has_vulnerability(self):
        session, stats = _write(HOST_LEVEL)

        [(q, p)] = session.queries("-[:HAS_VULNERABILITY]->(v)")
        assert "MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})" in q
        assert "port_number: $port_number" in q
        assert (p["ip_addr"], p["port_number"], p["user_id"], p["project_id"]) == (
            IP, 0, "u1", "p1")
        assert stats["host_level_links"] == 1

    def test_nmap_never_creates_the_ip(self):
        session, _ = _write(HOST_LEVEL)

        assert session.queries("MERGE (i:IP") == []

    def test_no_port_or_technology_link_and_the_cve_still_links(self):
        session, _ = _write(HOST_LEVEL)

        assert session.queries("-[:AFFECTS]->") == []
        assert session.queries("-[:FOUND_ON]->") == []
        [(_, p)] = session.queries("MERGE (v)-[:HAS_CVE]->(c)")
        assert (p["cve_id"], p["port_number"]) == ("CVE-2017-0143", 0)

    def test_a_host_level_entry_without_a_port_still_has_a_merge_key(self):
        entry = {k: v for k, v in HOST_LEVEL.items() if k != "port"}
        session, stats = _write(entry)

        _, p = _vuln_merge(session, "smb-vuln-ms17-010")
        assert p["port_number"] == 0
        assert p["nse_id"] == "nse-bcc84f33b47500ef"
        assert len(session.queries("-[:HAS_VULNERABILITY]->(v)")) == 1

    def test_a_port_finding_keeps_its_port_link_and_its_id(self):
        session, stats = _write(PORT_LEVEL)

        _, p = _vuln_merge(session, "ftp-vsftpd-backdoor")
        assert p["port_number"] == 21
        assert not p["host_level"]
        assert p["nse_id"] == "nse-20eae671b571ed95"
        [(_, ap)] = session.queries("MERGE (v)-[:AFFECTS]->(p)")
        assert (ap["ip_addr"], ap["port_number"]) == (IP, 21)
        assert len(session.queries("MERGE (v)-[:FOUND_ON]->(t)")) == 1
        assert session.queries("-[:HAS_VULNERABILITY]->(v)") == []
        assert stats.get("host_level_links", 0) == 0
