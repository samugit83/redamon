"""
Settings-cascade tests for Origin-IP Discovery.

Focus: the G10 key-fetch gate widening. The scanner keys (Shodan/Censys/FOFA/
ZoomEye/OTX/VT) are otherwise only assembled into settings when each scanner's
OWN tool is enabled; without the widening, enabling OriginDiscovery + its
scanner group would leave those keys absent and the favicon/cert pivots would
silently no-op. Also checks the camelCase mapping and the new passive-DNS keys.

Run: python -m pytest recon/tests/test_origin_discovery_settings.py -v
"""
from unittest.mock import patch

from recon.project_settings import DEFAULT_SETTINGS, fetch_project_settings


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fetch(project_payload: dict) -> dict:
    # The same payload is returned for BOTH the project fetch and the
    # user-settings fetch (both go through requests.get), so keys placed here
    # are visible as user_global secrets too.
    payload = {"userId": "test-user", "targetDomain": "example.com", **project_payload}
    with patch("requests.get", return_value=_FakeResponse(payload)):
        return fetch_project_settings("test-project", "http://mocked")


def test_defaults_present():
    for key in ("ORIGIN_DISCOVERY_ENABLED", "ORIGIN_DISCOVERY_KEYLESS",
                "ORIGIN_DISCOVERY_SCANNERS", "ORIGIN_DISCOVERY_PASSIVE_DNS",
                "ORIGIN_DISCOVERY_MAX_CANDIDATES", "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS",
                "ORIGIN_DISCOVERY_THRESHOLD", "ORIGIN_DISCOVERY_TIMEOUT",
                "ORIGIN_DISCOVERY_WORKERS", "ORIGIN_DISCOVERY_RATE",
                "SECURITYTRAILS_API_KEY", "VIEWDNS_API_KEY"):
        assert key in DEFAULT_SETTINGS, f"{key} missing from DEFAULT_SETTINGS"
    assert DEFAULT_SETTINGS["ORIGIN_DISCOVERY_ENABLED"] is False


def test_camelcase_mapping_honoured():
    s = _fetch({
        "originDiscoveryEnabled": True,
        "originDiscoveryThreshold": 75,
        "originDiscoveryMaxCandidates": 40,
        "originDiscoveryScanners": False,
    })
    assert s["ORIGIN_DISCOVERY_ENABLED"] is True
    assert s["ORIGIN_DISCOVERY_THRESHOLD"] == 75
    assert s["ORIGIN_DISCOVERY_MAX_CANDIDATES"] == 40
    assert s["ORIGIN_DISCOVERY_SCANNERS"] is False


def test_g10_reused_scanner_keys_delivered_when_only_origin_discovery_on():
    """Shodan's own lookups OFF, but OriginDiscovery + scanners ON -> the stored
    Shodan/Censys/FOFA keys must still reach settings for the pivots."""
    s = _fetch({
        "originDiscoveryEnabled": True,
        "originDiscoveryScanners": True,
        # Shodan's own tool fully off:
        "shodanHostLookup": False,
        "shodanReverseDns": False,
        "shodanDomainDns": False,
        "shodanPassiveCves": False,
        # Censys / FOFA / ZoomEye / OTX / VT own toggles off (defaults false-ish):
        "censysEnabled": False,
        "fofaEnabled": False,
        # stored secrets (same payload doubles as user_global):
        "shodanApiKey": "SHODANKEY",
        "censysApiToken": "CENSYSTOK",
        "censysOrgId": "ORG",
        "fofaApiKey": "FOFAKEY",
        "otxApiKey": "OTXKEY",
        "virusTotalApiKey": "VTKEY",
        "zoomEyeApiKey": "ZEKEY",
    })
    assert s.get("SHODAN_API_KEY") == "SHODANKEY", "G10: Shodan key not delivered"
    assert s.get("CENSYS_API_TOKEN") == "CENSYSTOK", "G10: Censys token not delivered"
    assert s.get("FOFA_API_KEY") == "FOFAKEY", "G10: FOFA key not delivered"
    assert s.get("OTX_API_KEY") == "OTXKEY", "G10: OTX key not delivered"
    assert s.get("VIRUSTOTAL_API_KEY") == "VTKEY", "G10: VT key not delivered"
    assert s.get("ZOOMEYE_API_KEY") == "ZEKEY", "G10: ZoomEye key not delivered"


def test_scanner_keys_absent_when_origin_scanners_off():
    """With OriginDiscovery on but its scanner group OFF (and each scanner's own
    tool off), the reused keys are NOT force-delivered."""
    s = _fetch({
        "originDiscoveryEnabled": True,
        "originDiscoveryScanners": False,
        "shodanHostLookup": False,
        "shodanReverseDns": False,
        "shodanDomainDns": False,
        "shodanPassiveCves": False,
        "shodanApiKey": "SHODANKEY",
    })
    assert not s.get("SHODAN_API_KEY"), "Shodan key should be absent when scanners off"


def test_passive_dns_keys_delivered():
    s = _fetch({
        "originDiscoveryEnabled": True,
        "originDiscoveryPassiveDns": True,
        "securitytrailsApiKey": "STKEY",
        "viewdnsApiKey": "VDKEY",
    })
    assert s.get("SECURITYTRAILS_API_KEY") == "STKEY"
    assert s.get("VIEWDNS_API_KEY") == "VDKEY"


def test_passive_dns_keys_absent_when_disabled():
    s = _fetch({
        "originDiscoveryEnabled": False,
        "securitytrailsApiKey": "STKEY",
        "viewdnsApiKey": "VDKEY",
    })
    assert not s.get("SECURITYTRAILS_API_KEY")
    assert not s.get("VIEWDNS_API_KEY")


def test_stealth_mode_throttles_origin_discovery():
    """F3: stealth mode must clamp the active-probe knobs and drop the loud keyed
    scanner searches, or a stealth engagement emits full-rate direct-IP probes."""
    from recon.project_settings import apply_stealth_overrides
    s = {
        "STEALTH_MODE": True,
        "ORIGIN_DISCOVERY_ENABLED": True,
        "ORIGIN_DISCOVERY_WORKERS": 10,
        "ORIGIN_DISCOVERY_RATE": 0,
        "ORIGIN_DISCOVERY_SCANNERS": True,
    }
    out = apply_stealth_overrides(s)
    assert out["ORIGIN_DISCOVERY_WORKERS"] == 1
    assert out["ORIGIN_DISCOVERY_RATE"] == 1
    assert out["ORIGIN_DISCOVERY_SCANNERS"] is False


def test_no_stealth_leaves_origin_discovery_untouched():
    from recon.project_settings import apply_stealth_overrides
    s = {"STEALTH_MODE": False, "ORIGIN_DISCOVERY_WORKERS": 10, "ORIGIN_DISCOVERY_SCANNERS": True}
    out = apply_stealth_overrides(s)
    assert out["ORIGIN_DISCOVERY_WORKERS"] == 10
    assert out["ORIGIN_DISCOVERY_SCANNERS"] is True
