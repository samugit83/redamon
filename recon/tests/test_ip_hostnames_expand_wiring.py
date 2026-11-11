"""Where run_ip_recon starts and joins the passive search (P5, design §8).

It starts right after the RoE filter (before GROUP 1, so it overlaps PTR,
WHOIS and the scans) with the settings alone, and the hostnames hook joins it
after every IP name source has answered. Only record_filter with the checkbox
on starts it: never in ip_only, record_only or scan_all, never with the
checkbox off, and never in a domain-mode run.

Real run_ip_recon with every later phase off; the search, PTR and DNS are
fakes. Documentation ranges (RFC 5737) and reserved names only.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

PID = "cmipexpandwiring000000001"
T1, T2, FOREIGN = "203.0.113.20", "203.0.113.21", "198.51.100.9"

PHASES_OFF = {
    "DNS_ENABLED": True, "DNS_MAX_RETRIES": 1, "WHOIS_ENABLED": False,
    "SHODAN_ENABLED": False, "NAABU_ENABLED": False, "MASSCAN_ENABLED": False,
    "NMAP_ENABLED": False, "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False,
    "UNCOVER_ENABLED": False, "HTTPX_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False,
    "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROE_ENABLED": False,
    "IP_ATTRIBUTION_ENABLED": False, "SERIALIZED_SCAN_ENABLED": False,
}


@pytest.fixture
def rm(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": [T1, T2],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": PID,
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for name in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[name]
        import recon.main as module
        monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(module, "SCAN_MODULES", [])
        monkeypatch.setattr(module, "UPDATE_GRAPH_DB", False)
        yield module


def _settings(mode="record_filter", **extra):
    base = dict(PHASES_OFF, IP_HOSTNAME_MODE=mode, IP_HOSTNAME_INCLUDE=["*.example.com"], IP_HOSTNAME_EXCLUDE=[],
                IP_HOSTNAME_PASSIVE_EXPAND=True, IP_HOSTNAME_MAX_SCANNED=10,
                IP_HOSTNAME_SCAN_ALL_CONFIRMED=mode == "scan_all")
    base.update(extra)
    return base


def _run(rm, monkeypatch, settings, events=None, ptr=None):
    from recon.helpers import ip_hostnames as ih
    from recon.main_recon_modules import domain_recon
    events = events if events is not None else []
    real_roe = rm._filter_roe_excluded

    def roe(values, *a, **k):
        events.append("roe")
        return real_roe(values, *a, **k)

    def reverse_all(ip, *_a, **_k):
        events.append("ptr")
        return list((ptr or {}).get(ip, []))

    monkeypatch.setattr(rm, "_filter_roe_excluded", roe)
    monkeypatch.setattr(domain_recon, "reverse_dns_lookup_all", reverse_all)
    monkeypatch.setattr(rm, "_graph_update_bg", lambda *a, **k: None)
    monkeypatch.setattr(ih, "_arm_resolver", lambda canary: True)
    table = {"hidden.example.com": [T1], "gone.example.com": [FOREIGN]}
    monkeypatch.setattr(ih, "dns_resolver", lambda s: (lambda name: list(table.get(name, []))))
    monkeypatch.setattr(rm, "_late_names", lambda *a, **k: events.append("late") or {})
    return rm.run_ip_recon([T1, T2], settings)


# ---------------------------------------------------------------------------
# Source order
# ---------------------------------------------------------------------------

def test_started_after_the_roe_filter_before_group_1_and_joined_at_the_hook():
    import recon.main as rm
    body = inspect.getsource(rm.run_ip_recon)
    roe = body.index("_filter_roe_excluded(expanded_ips")
    start = body.index("ip_hostnames_expand.start(settings)")
    group1 = body.index("GROUP 1: Reverse DNS")
    whois = body.index("IP STEP 3: IP WHOIS")
    hook = body.index("_ip_hostnames_step(combined_result, settings, output_file, passive_search=passive_search)")
    assert roe < start < group1 < whois < hook
    assert body.index("_write_netlas(combined_result)") < hook < body.index("should_skip_active_scans(")
    assert body.count("ip_hostnames_expand.start(") == 1
    step = inspect.getsource(rm._ip_hostnames_step)
    assert "passive_search=passive_search" in step


def test_a_domain_run_never_starts_it():
    import recon.main as rm
    assert "ip_hostnames_expand" not in inspect.getsource(rm.run_domain_recon)
    assert "ip_hostnames_expand" not in inspect.getsource(rm.run_domain_group)


# ---------------------------------------------------------------------------
# A real run: order, the settings alone, the names reach the hook
# ---------------------------------------------------------------------------

def test_the_run_starts_it_after_the_roe_filter_and_the_hook_joins_it(rm, monkeypatch):
    from recon.helpers import ip_hostnames_expand as ipe
    events, started = [], []
    found = ipe.Found(domains=("example.com",), names={"hidden.example.com": ("passive_urlscan",),
                                                        "gone.example.com": ("passive_crtsh",)})

    class Handle:
        def join(self):
            events.append("join")
            return found

    def start(*args, **kwargs):
        events.append("start")
        started.append((args, kwargs))
        return Handle()

    monkeypatch.setattr(ipe, "start", start)
    recon = _run(rm, monkeypatch, _settings(), events, ptr={T1: ["app.example.com"]})
    assert events.index("roe") < events.index("start") < events.index("ptr") < events.index("join")
    assert events.count("start") == 1 and events.count("join") == 1
    ((args, kwargs),) = started
    assert kwargs == {} and len(args) == 1 and args[0]["IP_HOSTNAME_MODE"] == "record_filter"
    candidates = recon["ip_hostnames"]["candidates"]
    assert candidates["hidden.example.com"]["sources"] == ["passive_urlscan"]
    assert candidates["hidden.example.com"]["reason"] == "scanned"
    assert candidates["gone.example.com"]["reason"] == "resolves_outside_targets"
    assert recon["ip_hostnames"]["summary"]["expansion"]["queried"] == 1
    assert "hidden.example.com" in recon["metadata"]["ip_mode_hosts"]


def test_the_real_search_runs_in_record_filter(rm, monkeypatch):
    from recon.helpers import ip_hostnames_expand as ipe
    search = mock.Mock(return_value=ipe.Found(domains=("example.com",),
                                              names={"hidden.example.com": ("passive_urlscan",)}))
    monkeypatch.setattr(ipe, "search", search)
    recon = _run(rm, monkeypatch, _settings())
    search.assert_called_once()
    assert search.call_args.args[:2] == (("example.com",), ("example.com",))
    assert recon["ip_hostnames"]["candidates"]["hidden.example.com"]["reason"] == "scanned"


@pytest.mark.parametrize("mode", ["ip_only", "record_only", "scan_all"])
def test_never_in_the_other_modes(rm, monkeypatch, mode):
    from recon.helpers import ip_hostnames_expand as ipe
    search = mock.Mock()
    monkeypatch.setattr(ipe, "search", search)
    recon = _run(rm, monkeypatch, _settings(mode))
    search.assert_not_called()
    assert "expansion" not in recon["ip_hostnames"]["summary"]


def test_never_with_the_checkbox_off(rm, monkeypatch, capsys):
    from recon.helpers import ip_hostnames_expand as ipe
    search = mock.Mock()
    monkeypatch.setattr(ipe, "search", search)
    recon = _run(rm, monkeypatch, _settings(IP_HOSTNAME_PASSIVE_EXPAND=False))
    search.assert_not_called()
    assert "expansion" not in recon["ip_hostnames"]["summary"]
    assert "passive expansion off" in capsys.readouterr().out
