"""Partial Hakrawler never crawls subdomains on an EXACT group (S-9).

Hakrawler's ``-subs`` follows links into any subdomain of a seed's host (every
sibling when the scan root is a seed), so it sends traffic to hosts an EXACT
group never listed. The full pipeline turns ``-subs`` off on an EXACT group
(``run_resource_enum``); partial Hakrawler must apply the same rule, read from
the run's scope groups. An ENUMERATE group keeps the operator's setting.

Only the graph (Neo4j), the Docker pull and the hakrawler process are mocked;
the assertion reads the real command ``_crawl_single_url`` built.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

import recon.helpers.resource_enum as resource_enum  # noqa: E402
from recon.helpers.resource_enum import hakrawler_helpers  # noqa: E402
from recon.partial_recon_modules import web_crawling  # noqa: E402

ROOT = "example.com"
HOST = "app.example.com"
OTHER_ROOT = "example.org"


def _group(root, mode, hosts=(), include_root=False):
    prefixes = (["*"] if mode == "enumerate" else []) + (["."] if include_root else [])
    prefixes += [f"{h[:-len(root) - 1]}." for h in hosts]
    return {"rootDomain": root, "prefixes": prefixes, "batch": False, "scanRoot": root,
            "orgDomain": root, "mode": mode, "includeRoot": include_root,
            "exactHosts": list(hosts)}


EXACT = _group(ROOT, "exact", hosts=[HOST], include_root=True)
ENUMERATE = _group(ROOT, "enumerate")
ENUMERATE_OTHER = _group(OTHER_ROOT, "enumerate")


@pytest.fixture
def crawl(monkeypatch):
    """Run partial Hakrawler on graph-built seeds; return every command built."""
    commands = []

    def fake_popen(cmd, **_kw):
        commands.append(list(cmd))
        proc = MagicMock()
        proc.stdout.readline.return_value = ""
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.returncode = 0
        return proc

    client = MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.update_graph_from_resource_enum.return_value = {}
    graph_db = MagicMock()
    graph_db.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", graph_db)
    monkeypatch.setattr(hakrawler_helpers.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(resource_enum, "pull_hakrawler_docker_image", lambda *_a, **_k: True)

    def run(groups, roots=(ROOT,), seeds=(f"https://{HOST}",), **settings):
        def graph_seeds(roots_, *_a, **_k):
            return {"domain": roots_[0], "domains": list(roots_), "subdomains": [],
                    "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in seeds}}}

        monkeypatch.setattr(web_crawling, "_build_http_probe_data_from_graph", graph_seeds)
        web_crawling.run_hakrawler({
            "_settings": {"HAKRAWLER_PARALLELISM": 1, **settings},
            "domains": list(roots), "domain": roots[0], "domain_groups": groups,
        })
        assert commands, "hakrawler never ran"
        return commands

    return run


class TestPartialHakrawlerSubs:
    def test_an_exact_group_never_gets_subs(self, crawl):
        commands = crawl([EXACT], seeds=(f"https://{HOST}", f"https://{ROOT}"),
                         HAKRAWLER_INCLUDE_SUBS=True)
        assert len(commands) == 2
        assert all("-subs" not in cmd for cmd in commands)

    def test_an_enumerate_group_keeps_subs_when_on(self, crawl):
        commands = crawl([ENUMERATE], HAKRAWLER_INCLUDE_SUBS=True)
        assert all("-subs" in cmd for cmd in commands)

    def test_an_enumerate_group_keeps_subs_off_when_off(self, crawl):
        commands = crawl([ENUMERATE], HAKRAWLER_INCLUDE_SUBS=False)
        assert all("-subs" not in cmd for cmd in commands)

    def test_a_batch_with_an_exact_group_gets_no_subs(self, crawl):
        # One hakrawler flag serves every seed of the run, so one EXACT group
        # turns it off for the whole run.
        commands = crawl([ENUMERATE_OTHER, EXACT], roots=(OTHER_ROOT, ROOT),
                         seeds=(f"https://{HOST}", f"https://www.{OTHER_ROOT}"),
                         HAKRAWLER_INCLUDE_SUBS=True)
        assert len(commands) == 2
        assert all("-subs" not in cmd for cmd in commands)

    def test_the_rest_of_the_command_is_unchanged(self, crawl):
        commands = crawl([EXACT], HAKRAWLER_INCLUDE_SUBS=True, HAKRAWLER_DEPTH=3,
                         HAKRAWLER_THREADS=7)
        cmd = commands[0]
        assert cmd[:5] == ["docker", "run", "--rm", "--net=host", "-i"]
        assert cmd[cmd.index("-d") + 1] == "3"
        assert cmd[cmd.index("-t") + 1] == "7"
        assert "-u" in cmd
