"""
L-17: Katana's crawl scope is fqdn, fixed, and that is why `katanaScope` is gone.

The form offered "dn" / "rdn", the column defaulted to "dn", and the command
always ran `-fs fqdn`. Wiring the setting would have been worse than leaving it
dead: run_katana_crawler keeps only URLs on `allowed_hosts`, which both callers
build from the seed URLs, so a wider field scope adds requests to hosts no scan
admitted and then discards what they return. These tests pin the command and
that filter together.

Run: python -m pytest tests/test_katana_field_scope.py -v
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from recon.helpers.resource_enum import katana_helpers


def _run(lines: list[str]):
    captured = {}

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        proc = MagicMock()
        proc.stdout.readline.side_effect = [l + "\n" for l in lines] + [""]
        proc.stderr.read.return_value = ""
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.wait.return_value = 0
        return proc

    with patch.object(katana_helpers.subprocess, "Popen", side_effect=fake_popen), \
         patch.object(katana_helpers.select, "select", side_effect=lambda r, w, x, t: (r, [], [])), \
         patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None), create=True):
        urls, meta = katana_helpers.run_katana_crawler(
            target_urls=["https://www.example.com"],
            docker_image="projectdiscovery/katana:latest",
            depth=2, max_urls=100, rate_limit=10, timeout=30,
            js_crawl=False, params_only=False,
            allowed_hosts={"www.example.com"},
            custom_headers=[], exclude_patterns=[],
        )
    return captured["cmd"], urls, meta


def test_the_command_crawls_with_fqdn_scope_once():
    cmd, _, _ = _run([])
    assert cmd.count("-fs") == 1
    assert cmd[cmd.index("-fs") + 1] == "fqdn"


def test_the_whole_command_is_unchanged_by_the_retired_setting():
    """Retiring katanaScope removed a control nothing read: the argv katana
    receives is the one it received before, flag for flag."""
    with patch.object(katana_helpers, "resolver_args", return_value=["-r", "192.0.2.53"]), \
         patch.object(katana_helpers.uuid, "uuid4", return_value=MagicMock(hex="deadbeefcafe")):
        cmd, _, _ = _run([])
    # The name a stop kills the container by (R-9) differs per run; the rest is flag for flag.
    i = cmd.index("--name")
    assert cmd[i + 1].startswith("katana-")
    del cmd[i:i + 2]
    assert cmd == [
        "docker", "run", "--rm", "--net=host", "-v", "/tmp/redamon:/tmp/redamon",
        "projectdiscovery/katana:latest",
        "-list", "/tmp/redamon/katana_targets_deadbeef.txt",
        "-d", "2", "-silent", "-nc", "-rl", "10", "-p", "5", "-c", "10",
        "-timeout", "30", "-crawl-duration", "30s", "-fs", "fqdn",
        "-r", "192.0.2.53",
    ]


def test_a_url_on_another_host_is_discarded_whatever_katana_returns():
    """What a wider scope would add is exactly what the filter drops."""
    cmd, urls, meta = _run([
        "https://www.example.com/login?next=/",
        "https://shop.example.com/cart",
        "https://example.org/landing",
    ])
    assert urls == ["https://www.example.com/login?next=/"]
    assert {e["domain"] for e in meta["external_domains"]} == {"shop.example.com", "example.org"}
