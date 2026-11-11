"""The IP-mode label helper (recon/helpers/ip_placeholders.py).

IP mode names each target address with a dashed label (203.0.113.2 ->
203-0-113-2) so the graph can hang it off a Subdomain. Every reader that must
tell a label from a real hostname asks one helper, and the four detectors that
used to answer it on their own (target_helpers, security_checks, tls_scan,
masscan_scan) are now names for it. Documentation addresses and reserved names
only.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ip_placeholders import is_placeholder, placeholder_for  # noqa: E402


@pytest.mark.parametrize("ip, label", [
    ("203.0.113.2", "203-0-113-2"),
    ("2001:db8::1", "2001-db8--1"),
    ("::1", "--1"),
    (" 198.51.100.7 ", "198-51-100-7"),
])
def test_placeholder_for_spells_the_label_from_the_listed_address(ip, label):
    assert placeholder_for(ip) == label


@pytest.mark.parametrize("name", [
    "203-0-113-2", "255-255-255-255", "2001-db8--1", "2001-DB8--1", " 203-0-113-2 ", "--1",
])
def test_any_label_that_maps_back_to_an_address_is_a_placeholder(name):
    assert is_placeholder(name) is True


@pytest.mark.parametrize("name", [
    "www.example.com",          # a dot: a real name
    "203-0-113-2.example.com",  # a label inside a real name
    "mail-01",                  # dashes, but no address behind them
    "999-999-999-999",          # IPv4-shaped, not an address
    "1-2-3", "1-2-3-4-5", "8-8",
    "203.0.113.2",              # the address itself is not its label
    "2001:db8::1",              # nor is an IPv6 literal (no dash at all)
    "webserver",
    "", "   ", None, 42,
])
def test_a_real_name_an_address_or_junk_is_never_a_placeholder(name):
    assert is_placeholder(name) is False


def test_with_an_address_only_its_own_label_matches():
    assert is_placeholder("203-0-113-2", "203.0.113.2") is True
    assert is_placeholder("2001-DB8--1", "2001:db8::1") is True
    assert is_placeholder("203-0-113-3", "203.0.113.2") is False
    assert is_placeholder("host1.example.com", "203.0.113.2") is False
    assert is_placeholder("203.0.113.2", "203.0.113.2") is False
    assert is_placeholder("", "203.0.113.2") is False


def test_the_four_old_detectors_answer_as_the_helper_does():
    from recon.helpers import security_checks, target_helpers
    from recon.main_recon_modules import masscan_scan, tls_scan

    names = ["203-0-113-2", "2001-db8--1", "www.example.com", "mail-01", "", None]
    for name in names:
        assert target_helpers._is_mock_ip_hostname(name) is is_placeholder(name), name
        assert security_checks._is_synthetic_ip_host(name) is is_placeholder(name), name
    for name, ip in [("203-0-113-2", "203.0.113.2"), ("2001-db8--1", "2001:db8::1"),
                     ("www.example.com", "203.0.113.2"), ("203-0-113-2", "203.0.113.9")]:
        assert tls_scan._is_mock_hostname(name, ip) is is_placeholder(name, ip), (name, ip)
        assert masscan_scan._is_mock_hostname(name, ip) is is_placeholder(name, ip), (name, ip)
