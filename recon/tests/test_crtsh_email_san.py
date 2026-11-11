"""A crt.sh email SAN under the scan root never becomes a Subdomain name (S-11).

crt.sh's name_value carries every SAN of a certificate, rfc822Name ones too
(`admin@mail.example.test`). query_crtsh keeps them, and discover_subdomains'
fan-in tests only "ends with .<root>": the out-of-scope branch skips a name with
an '@', the in-scope branch does not. With puredns off (no resolver pass to
drop it) the address is in result["subdomains"], which the domain writer turns
into Subdomain nodes, and every later tool targets it.

crt.sh is answered by a mocked requests.Session; the other sources return
nothing. Synthetic names only.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules import domain_recon as dr  # noqa: E402

ROOT = "example.test"
CRTSH_JSON = [
    {"issuer_name": "C=US, O=Example CA", "common_name": "mail.example.test",
     "name_value": "mail.example.test\nadmin@mail.example.test"},
    {"issuer_name": "C=US, O=Example CA", "common_name": "www.example.test",
     "name_value": "www.example.test\n*.example.test\nhostmaster@example.test"},
    {"issuer_name": "C=US, O=Example CA", "common_name": "other.test",
     "name_value": "other.test\npostmaster@other.test"},
]

SETTINGS = {"CRTSH_ENABLED": True, "PUREDNS_ENABLED": False, "HACKERTARGET_ENABLED": False,
            "SUBFINDER_ENABLED": False, "AMASS_ENABLED": False, "KNOCKPY_RECON_ENABLED": False}


def _discover():
    resp = mock.MagicMock(status_code=200)
    resp.json.return_value = CRTSH_JSON
    session = mock.MagicMock()
    session.get.return_value = resp
    with mock.patch.object(dr.requests, "Session", return_value=session), \
            mock.patch.object(dr, "query_hackertarget", return_value={}), \
            mock.patch.object(dr, "run_subfinder", return_value=set()), \
            mock.patch.object(dr, "run_amass", return_value=set()), \
            mock.patch.object(dr, "run_knockpy", return_value=set()):
        out = dr.discover_subdomains(ROOT, resolve=False, save_output=False, settings=dict(SETTINGS))
    assert session.get.call_args and "crt.sh" in session.get.call_args.args[0]
    return out


def test_an_in_scope_email_san_is_no_subdomain():
    out = _discover()
    assert "mail.example.test" in out["subdomains"]
    assert "www.example.test" in out["subdomains"]
    emails = [s for s in out["subdomains"] if "@" in s]
    assert emails == [], f"email SANs became subdomain names: {emails}"
    assert not any("@" in s for s in out["subdomain_status_map"])


def test_control_an_out_of_scope_email_is_no_external_domain():
    out = _discover()
    external = {e["domain"] for e in out["external_domains"]}
    assert "other.test" in external
    assert not any("@" in d for d in external)


def _crtsh(settings):
    resp = mock.MagicMock(status_code=200)
    resp.json.return_value = CRTSH_JSON
    session = mock.MagicMock()
    session.get.return_value = resp
    with mock.patch.object(dr.requests, "Session", return_value=session), \
            mock.patch.object(dr, "query_crtname") as crtname:
        out = dr.query_crtsh(ROOT, dict(settings))
    crtname.assert_not_called()
    return out


def test_query_crtsh_returns_hostnames_only():
    out = _crtsh(SETTINGS)
    assert set(out) == {"mail.example.test", "www.example.test", "other.test"}
    assert all(src == {"crt.sh"} for src in out.values())


def test_email_sans_take_no_slot_under_the_result_cap():
    # Sorted, the three addresses would come before every hostname but one.
    out = _crtsh({**SETTINGS, "CRTSH_MAX_RESULTS": 3})
    assert set(out) == {"mail.example.test", "www.example.test", "other.test"}


def test_an_email_from_any_other_source_is_dropped_at_the_fan_in():
    with mock.patch.object(dr, "query_crtsh", return_value={}), \
            mock.patch.object(dr, "query_hackertarget",
                              return_value={"ops@api.example.test": {"hackertarget"},
                                            "api.example.test": {"hackertarget"}}), \
            mock.patch.object(dr, "run_subfinder", return_value={"x@y.example.test"}), \
            mock.patch.object(dr, "run_amass", return_value=set()), \
            mock.patch.object(dr, "run_knockpy", return_value=set()):
        out = dr.discover_subdomains(ROOT, resolve=False, save_output=False, settings=dict(SETTINGS))
    assert out["subdomains"] == ["api.example.test"]
    assert out["external_domains"] == []
