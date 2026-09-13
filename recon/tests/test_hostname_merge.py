"""merge_discovered_hostnames: the scope-contained SAN/js-recon feedback path.

Security-critical: a certificate SAN list is chosen by the scanned target, so
this test pins the containment rules (apex allow-list, resolve-and-check,
newline rejection, fail-closed) AND the js_recon crash regression (dns.subdomains
is a DICT in a full run; the old bare .append() raised AttributeError).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.target_helpers import merge_discovered_hostnames


def _fake_getaddrinfo(mapping):
    """socket.getaddrinfo stub: name -> ip. Missing name raises (unresolvable)."""
    def _inner(host, *a, **k):
        if host in mapping:
            return [(2, 1, 6, "", (mapping[host], 0))]
        raise OSError("nxdomain")
    return _inner


def _merge(combined, names, root="example.com", settings=None, cap=None):
    with patch("socket.getaddrinfo", _fake_getaddrinfo({
        "www.example.com": "93.184.216.34",
        "api.example.com": "93.184.216.35",
        "example.com": "93.184.216.34",
        "internal.example.com": "10.0.0.5",
        "evil.attacker.com": "1.2.3.4",
    })):
        return merge_discovered_hostnames(
            combined, names, source="tlsx", root_domain=root,
            settings=settings or {}, max_injected=cap,
        )


def test_in_scope_san_becomes_a_target():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["www.example.com"])
    assert "www.example.com" in c["dns"]["subdomains"]
    assert c["dns"]["subdomains"]["www.example.com"]["has_records"] is True


def test_apex_itself_is_in_scope():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["example.com"])
    assert "example.com" in c["dns"]["subdomains"]


def test_foreign_san_goes_external_never_a_target():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["evil.attacker.com"])
    assert "evil.attacker.com" not in c["dns"]["subdomains"]
    ext = {e["domain"] for e in c.get("discovered_external_domains", [])}
    assert "evil.attacker.com" in ext


def test_name_resolving_to_private_ip_is_dropped():
    # SSRF / scope-escape: an in-scope name pointing at RFC1918 must not be probed.
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["internal.example.com"])
    assert "internal.example.com" not in c["dns"]["subdomains"]


def test_newline_injected_san_is_rejected():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["www.example.com\nextra.example.com"])
    # the \\Z anchor rejects the whole malformed label; no split entry appears
    assert "www.example.com\nextra.example.com" not in c["dns"]["subdomains"]
    assert "extra.example.com" not in c["dns"]["subdomains"]


def test_fail_closed_without_root_domain():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["www.example.com"], root=None)
    assert c["dns"]["subdomains"] == {}
    # still recorded as external so discovery value is not lost
    assert any(e["domain"] == "www.example.com" for e in c["discovered_external_domains"])


def test_cap_limits_injected_count():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["www.example.com", "api.example.com"], cap=1)
    assert len(c["dns"]["subdomains"]) == 1


def test_roe_exclusion_narrows_further():
    c = {"dns": {"subdomains": {}}}
    _merge(c, ["www.example.com", "api.example.com"],
           settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["api.example.com"]})
    assert "api.example.com" not in c["dns"]["subdomains"]
    assert "www.example.com" in c["dns"]["subdomains"]


def test_dict_shaped_subdomains_does_not_crash_the_js_recon_regression():
    # The exact shape a full domain run produces. The pre-fix code did
    # dns.subdomains.append(...) here and raised AttributeError, aborting the
    # whole phase and silently discarding every finding.
    c = {"dns": {"subdomains": {"pre.example.com": {"has_records": True}}}}
    _merge(c, ["www.example.com"])
    assert isinstance(c["dns"]["subdomains"], dict)
    assert "pre.example.com" in c["dns"]["subdomains"]   # existing preserved
    assert "www.example.com" in c["dns"]["subdomains"]   # new merged


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
