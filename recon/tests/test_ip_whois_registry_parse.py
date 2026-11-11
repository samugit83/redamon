"""IP WHOIS: the organisation and country read from each registry's answer (P3 fix 1).

python-whois 0.9.6's generic parser reads none of the registries' keys (ARIN's
OrgName / Country, RIPE's and AFRINIC's org-name / descr / country, APNIC's
descr / country, LACNIC's owner / country), so an IP's WHOIS came back empty,
the log said org=unknown and IP.organization / IP.country were never written.

The address is asked at ARIN; when ARIN refers the block to another regional
registry, that registry's answer is the one read, never ARIN's pointer to it.

Every sample is SYNTHETIC: documentation addresses and made-up organisations
in each registry's layout, not real registry text. NICClient is faked.
"""
from __future__ import annotations

import pytest

from recon.main_recon_modules import whois_recon as wr

ARIN = """#
# Synthetic ARIN-format answer.
#

NetRange:       203.0.113.0 - 203.0.113.255
CIDR:           203.0.113.0/24
NetName:        EXAMPLE-NET-1
OrgName:        Example Hosting Co
OrgId:          EXHC-1
Address:        1 Example Way
Country:        US

OrgName:        Example Parent Allocation
Country:        CA
"""

RIPE = """% Synthetic RIPE-format answer.
% A comment line: never a field.

inetnum:        198.51.100.0 - 198.51.100.255
netname:        EXAMPLE-NET-2
descr:          Example Network Block
country:        NL
org:            ORG-EX1-TEST

organisation:   ORG-EX1-TEST
org-name:       Example Org BV
country:        DE
"""

APNIC = """% Synthetic APNIC-format answer.

inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-AP
descr:          Example Pacific Hosting
descr:          Second description line
country:        AU
"""

AFRINIC = """% Synthetic AFRINIC-format answer.

inet6num:       2001:db8::/32
netname:        EXAMPLE-AF
descr:          Example Africa Net Description
country:        ZA
org-name:       Example Africa Net
"""

LACNIC = """% Synthetic LACNIC-format answer.

inetnum:     203.0.113.0/24
status:      allocated
owner:       Example Latam Ltda
ownerid:     XX-EXLA-1
country:     BR
"""


@pytest.mark.parametrize("text, org, country", [
    (ARIN, "Example Hosting Co", "US"),
    (RIPE, "Example Org BV", "NL"),
    (APNIC, "Example Pacific Hosting", "AU"),
    (AFRINIC, "Example Africa Net", "ZA"),
    (LACNIC, "Example Latam Ltda", "BR"),
])
def test_each_registry_layout_gives_the_organisation_and_the_country(text, org, country):
    assert wr.registry_fields(text) == {"org": org, "country": country}


def test_an_answer_without_either_field_is_empty():
    assert wr.registry_fields("% only comments\n\nNo match found for 192.0.2.1.\n") == {}
    assert wr.registry_fields("") == {}


def test_a_field_with_no_value_is_skipped():
    assert wr.registry_fields("OrgName:\ndescr:   Example Fallback Org\nCountry:\n") == {
        "org": "Example Fallback Org"}


class _FakeNic:
    """NICClient.whois stand-in: answers per server, records each question."""

    def __init__(self, monkeypatch, answers):
        from whois.whois import NICClient
        self.asked = []

        def whois(_self, query, host, flags, **kwargs):
            self.asked.append((query, host, flags, kwargs.get("ignore_socket_errors")))
            return answers.get(host, "")

        monkeypatch.setattr(NICClient, "whois", whois)


def test_an_arin_block_is_read_from_arin(monkeypatch):
    nic = _FakeNic(monkeypatch, {"whois.arin.net": ARIN})
    assert wr._ip_whois("203.0.113.10") == {"org": "Example Hosting Co", "country": "US"}
    assert nic.asked == [("203.0.113.10", "whois.arin.net", 0, False)]


def test_a_referral_to_another_registry_is_followed_and_only_its_answer_read(monkeypatch):
    referral = ("NetRange: 198.51.100.0 - 198.51.100.255\nOrgName: Example Regional Registry\n"
                "Country: US\nReferralServer:  whois://whois.ripe.net\n")
    nic = _FakeNic(monkeypatch, {"whois.arin.net": referral, "whois.ripe.net": RIPE})
    assert wr._ip_whois("198.51.100.10") == {"org": "Example Org BV", "country": "NL"}
    assert [host for _, host, _, _ in nic.asked] == ["whois.arin.net", "whois.ripe.net"]


@pytest.mark.parametrize("server", ["rwhois://rwhois.example.net:4321", "whois://whois.example.net"])
def test_a_referral_to_anything_but_a_regional_registry_is_not_followed(monkeypatch, server):
    nic = _FakeNic(monkeypatch, {"whois.arin.net": ARIN + f"ReferralServer: {server}\n"})
    assert wr._ip_whois("203.0.113.10")["org"] == "Example Hosting Co"
    assert len(nic.asked) == 1


def test_an_empty_referral_answer_keeps_nothing(monkeypatch):
    _FakeNic(monkeypatch, {"whois.arin.net": "ReferralServer: whois://whois.lacnic.net\n"})
    assert wr._ip_whois("203.0.113.10") == {}


def test_no_answer_at_all_is_the_no_output_error(monkeypatch):
    from whois.exceptions import WhoisError
    _FakeNic(monkeypatch, {})
    with pytest.raises(WhoisError, match="no output"):
        wr._ip_whois("203.0.113.10")


def test_the_lookup_writes_org_and_country_where_the_ip_writer_reads_them(monkeypatch):
    _FakeNic(monkeypatch, {"whois.arin.net": ARIN})
    result = wr.whois_lookup("203.0.113.10", save_output=False, print_settings=False)
    assert result["whois_data"] == {"org": "Example Hosting Co", "country": "US"}


def test_an_address_with_no_registry_fields_is_no_data(monkeypatch):
    _FakeNic(monkeypatch, {"whois.arin.net": "% nothing here\n"})
    result, queried = wr.get_whois_data("203.0.113.10", max_retries=1)
    assert result == {} and queried == "203.0.113.10"
