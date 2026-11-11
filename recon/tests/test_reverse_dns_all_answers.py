"""reverse_dns_lookup_all: every PTR answer of an address, same breakers (P3, B-04).

An address on a shared host carries one PTR record per site, and DNS may
rotate the order: keeping only the first answer lost the others and made the
kept one depend on the resolver. The full answer is returned, in answer order,
without the trailing dot and without duplicates. reverse_dns_lookup keeps its
"first answer or None" contract for existing callers.

dnspython is mocked; documentation ranges (RFC 5737 / RFC 3849) and reserved
names only.
"""
from __future__ import annotations

from unittest import mock

import dns.resolver
import pytest

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import domain_recon as dr


@pytest.fixture(autouse=True)
def _reset_resolver():
    dr.resolver_breaker.reset()
    yield
    dr.resolver_breaker.reset()


def _timeout(*_a, **_k):
    raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])


def _ptr(*names):
    answers = []
    for name in names:
        rr = mock.MagicMock()
        rr.__str__.return_value = name
        answers.append(rr)
    return answers


def test_every_answer_is_returned_in_order_without_the_root_dot():
    with mock.patch.object(dr.dns.resolver, "resolve",
                           return_value=_ptr("web.example.com.", "app.example.com.")) as res:
        assert dr.reverse_dns_lookup_all("203.0.113.10") == ["web.example.com", "app.example.com"]
    rev, rtype = res.call_args.args
    assert rtype == "PTR"
    assert str(rev) == "10.113.0.203.in-addr.arpa."


def test_a_repeated_or_empty_answer_counts_once():
    with mock.patch.object(dr.dns.resolver, "resolve",
                           return_value=_ptr("web.example.com.", "web.example.com", ".")):
        assert dr.reverse_dns_lookup_all("203.0.113.10") == ["web.example.com"]


def test_an_ipv6_address_is_asked_under_ip6_arpa():
    with mock.patch.object(dr.dns.resolver, "resolve", return_value=_ptr("v6.example.com.")) as res:
        assert dr.reverse_dns_lookup_all("2001:db8::1") == ["v6.example.com"]
    assert str(res.call_args.args[0]).endswith(".ip6.arpa.")


def test_no_ptr_is_an_empty_list_and_keeps_the_zone_healthy():
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        for i in range(5):
            assert dr.reverse_dns_lookup_all(f"198.51.100.{i}", max_retries=1) == []
    assert not cb.is_open("rdns:198.51.100")


def test_timeouts_open_the_zone_breaker_and_a_later_address_is_not_asked():
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
        for i in range(3):
            assert dr.reverse_dns_lookup_all(f"203.0.113.{i}", max_retries=1) == []
    assert cb.is_open("rdns:203.0.113")
    with mock.patch.object(dr.dns.resolver, "resolve") as res:
        assert dr.reverse_dns_lookup_all("203.0.113.9", max_retries=1) == []
    res.assert_not_called()


def test_a_down_resolver_asks_nothing():
    dr.resolver_breaker.set_canary("canary.test")
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
        dr.dns_lookup_single("slow.test", "A", max_retries=3)  # opens the resolver breaker
    assert dr.resolver_breaker.is_open()
    with mock.patch.object(dr.dns.resolver, "resolve") as res:
        assert dr.reverse_dns_lookup_all("192.0.2.5") == []
    res.assert_not_called()


def test_a_transient_failure_is_retried_then_answered():
    calls = iter([_timeout, lambda *a, **k: _ptr("late.example.com.")])
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=lambda *a, **k: next(calls)(*a, **k)), \
            mock.patch.object(dr.time, "sleep") as sleep:
        assert dr.reverse_dns_lookup_all("192.0.2.6", max_retries=2) == ["late.example.com"]
    sleep.assert_called_once_with(1)


def test_a_resolver_down_mid_lookup_stops_retrying():
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout) as res, \
            mock.patch.object(dr.resolver_breaker, "note_transient", return_value=True):
        assert dr.reverse_dns_lookup_all("192.0.2.7", max_retries=3) == []
    assert res.call_count == 1


def test_an_unexpected_error_is_no_answer():
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=ValueError("bad")):
        assert dr.reverse_dns_lookup_all("192.0.2.8") == []


def test_zero_retries_asks_nothing():
    with mock.patch.object(dr.dns.resolver, "resolve") as res:
        assert dr.reverse_dns_lookup_all("192.0.2.9", max_retries=0) == []
    res.assert_not_called()


@pytest.mark.parametrize("answers, first", [
    (("web.example.com.", "app.example.com."), "web.example.com"),
    ((), None),
])
def test_reverse_dns_lookup_keeps_the_first_answer_contract(answers, first):
    side = {"return_value": _ptr(*answers)} if answers else {"side_effect": dns.resolver.NXDOMAIN}
    with mock.patch.object(dr.dns.resolver, "resolve", **side):
        assert dr.reverse_dns_lookup("203.0.113.10") == first
