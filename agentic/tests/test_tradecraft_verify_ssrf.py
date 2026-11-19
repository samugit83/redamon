"""
CVE-2026-111323: the tradecraft fetches must not be an SSRF. The 1.x /tradecraft/verify route and
its fetch tiers left at the cut-over (T9.2); the layers of the fix that 2.0 shares are held here:
  B. the pinned network backend judges the address at connect time and dials exactly that
     address (DNS rebinding, metadata names, unresolvable hosts);
  D. the GitHub token goes only to exact GitHub hosts, over https.
The other layers are 2.0's own tests: the routes' master key (test_ghsa_8whg_master_key_fail_closed.py,
test_tradecraft_api.py::test_auth_required); a redirect into 169.254.169.254 refused before the
second request (test_tradecraft_fetcher_contract_integration.py, the real fetcher); a refused fetch
never handed to the browser, the builders or the model (test_tradecraft_ingest_fetch.py,
test_tradecraft_ingest_crawl.py, test_tradecraft_fetcher_contract.py); the browser guard script
(test_fetch_guard_browser_script.py).

Run inside the agent container:
    python -m unittest tests.test_tradecraft_verify_ssrf
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpcore

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers import fetch_guard  # noqa: E402
from orchestrator_helpers.fetch_guard import UnsafeFetchURLError  # noqa: E402
from orchestrator_helpers.web_sources import is_github_token_url  # noqa: E402

# Same stand-in public address as test_crawl_ssrf. No test here opens a socket
# to it: dials are recorded or redirected to a loopback server.
PUBLIC_IP = "93.184.216.34"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def _resolver(table):
    """A fetch_guard._resolve_ips stand-in: names from `table`, else the real one."""
    real = fetch_guard._resolve_ips

    def resolve(host):
        if host in table:
            return list(table[host])
        return real(host)
    return resolve


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """Inner backend that records what it was asked to dial and opens nothing."""

    def __init__(self):
        self.dialed = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialed.append((host, port))
        raise httpcore.ConnectError("test backend opens no sockets")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


# =========================================================================
# A. Route authentication
# =========================================================================

# =========================================================================
# B. the pinned network backend
# =========================================================================

class PinnedBackend(unittest.TestCase):
    def _connect(self, host, table, port=443):
        inner = _RecordingBackend()
        backend = fetch_guard._PinnedNetworkBackend(inner)
        with patch.object(fetch_guard, "_resolve_ips", _resolver(table)):
            try:
                asyncio.run(backend.connect_tcp(host, port))
            except Exception as e:  # the outcome is asserted by each test
                return e, inner.dialed
        return None, inner.dialed

    def test_private_answer_is_refused_before_dialing(self):
        err, dialed = self._connect("docs.example.test", {"docs.example.test": ["10.0.0.5"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_one_private_address_among_public_ones_is_refused(self):
        err, dialed = self._connect(
            "docs.example.test", {"docs.example.test": [PUBLIC_IP, "127.0.0.1"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_public_answer_dials_the_checked_address_not_the_name(self):
        err, dialed = self._connect("docs.example.test", {"docs.example.test": [PUBLIC_IP]})
        self.assertIsInstance(err, httpcore.ConnectError)  # from the recording backend
        self.assertEqual(dialed, [(PUBLIC_IP, 443)])

    def test_rebinding_answer_after_validation_is_refused(self):
        # The check before the request sees a public answer; the connection, resolving
        # again, gets an internal one. The connect-time check is the one that counts.
        with patch.object(fetch_guard, "_resolve_ips", _resolver({"rebind.example.test": [PUBLIC_IP]})):
            fetch_guard.assert_safe_fetch_url("https://rebind.example.test/")
        err, dialed = self._connect("rebind.example.test", {"rebind.example.test": ["169.254.169.254"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_metadata_hostname_is_refused_without_resolving(self):
        looked_up = []

        def resolve(host):
            looked_up.append(host)
            return [PUBLIC_IP]

        inner = _RecordingBackend()
        backend = fetch_guard._PinnedNetworkBackend(inner)
        with patch.object(fetch_guard, "_resolve_ips", resolve):
            with self.assertRaises(UnsafeFetchURLError):
                asyncio.run(backend.connect_tcp("metadata.google.internal", 80))
        self.assertEqual(looked_up, [])
        self.assertEqual(inner.dialed, [])

    def test_unresolvable_name_is_never_handed_to_the_inner_backend(self):
        err, dialed = self._connect("gone.example.test", {"gone.example.test": []})
        self.assertIsInstance(err, httpcore.ConnectError)
        self.assertEqual(dialed, [])

    def test_unix_socket_is_refused(self):
        backend = fetch_guard._PinnedNetworkBackend(_RecordingBackend())
        with self.assertRaises(UnsafeFetchURLError):
            asyncio.run(backend.connect_unix_socket("/var/run/docker.sock"))

    def test_transport_dials_through_the_pinned_backend(self):
        # Fails loudly if an httpx/httpcore upgrade moves the pool's backend.
        transport = fetch_guard.pinned_async_transport()
        self.assertIsInstance(transport._pool._network_backend, fetch_guard._PinnedNetworkBackend)


# =========================================================================
# D. the GitHub token's hosts
# =========================================================================

class GithubTokenScope(unittest.TestCase):
    def test_exact_github_hosts_over_https_only(self):
        allowed = [
            "https://github.com/o/r",
            "https://api.github.com/repos/o/r",
            "https://raw.githubusercontent.com/o/r/main/README.md",
            "https://GitHub.com/o/r",
        ]
        refused = [
            "https://github-docs.example.test/",
            "https://github.com.example.test/",
            "https://docs.example.test/github/readme",
            "https://docs.example.test/?ref=github.com",
            "http://github.com/o/r",
            "https://example.test@evil.example.test/github.com",
        ]
        for url in allowed:
            self.assertTrue(is_github_token_url(url), url)
        for url in refused:
            self.assertFalse(is_github_token_url(url), url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
