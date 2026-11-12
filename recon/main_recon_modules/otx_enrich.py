"""
OTX (AlienVault Open Threat Exchange) Pipeline Enrichment Module

Passive OSINT via OTX indicators API:
  - IPv4/general  — pulse count, reputation, geo, pulse details (adversary/malware_families/TLP/attack_ids)
  - IPv4/passive_dns — passive DNS hostnames with first/last/record_type
  - IPv4/malware  — malware samples (hash, type, name)
  - IPv4/url_list — URL count associated with IP
  - domain/general — pulse count, whois, pulse details
  - domain/passive_dns — historical IPs the domain has resolved to
  - domain/malware — malware samples
  - domain/url_list — URL count associated with domain

Anonymous requests (no API key) are supported with reduced rate limits (~1 000 req/hr).
Providing an API key raises the limit to ~10 000 req/hr and exposes private pulses.
Optional API key rotation via OTX_KEY_ROTATOR.
"""
from __future__ import annotations

import time
import threading
import logging
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from recon.main_recon_modules.ip_filter import filter_ips_for_enrichment
except ImportError:
    from ip_filter import filter_ips_for_enrichment

logger = logging.getLogger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators"


class _RateLimiter:
    """Thread-safe rate limiter."""
    def __init__(self, interval: float):
        self._interval = interval
        self._lock = threading.Lock()
        self._last = 0.0
    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            delay = self._interval - elapsed if elapsed < self._interval else 0.0
            self._last = now + delay
        if delay > 0:
            time.sleep(delay)

# TLP severity order for picking the "most restrictive" value across pulses
_TLP_ORDER = {"white": 0, "green": 1, "amber": 2, "red": 3}


def _extract_ips_from_recon(combined_result: dict) -> list[str]:
    """Extract unique IPv4 addresses from domain discovery results."""
    ips: set[str] = set()
    dns_data = combined_result.get("dns", {})

    domain_dns = dns_data.get("domain", {})
    for ip in domain_dns.get("ips", {}).get("ipv4", []):
        if ip:
            ips.add(ip)

    for _sub, info in dns_data.get("subdomains", {}).items():
        for ip in info.get("ips", {}).get("ipv4", []):
            if ip:
                ips.add(ip)

    # IP mode: the target list only. A DNS answer (a PTR name's forward
    # address) need not be a target, and the lookup would be about it. A dict
    # that declares no list asks about nothing (every IP-mode builder declares it).
    metadata = combined_result.get("metadata") or {}
    if metadata.get("ip_mode"):
        return sorted({ip for ip in metadata.get("expanded_ips") or [] if ip})

    return sorted(ips)


def _otx_breaker(endpoint: str):
    """One breaker per OTX section. A 429 or a refused key stops every section
    (OTX limits per key); timeouts and 5xx stop only the section that failed,
    since passive_dns is often down while general answers."""
    from recon.helpers import circuit_breaker as cb
    return cb.get_breaker(f"otx:{endpoint}", label="OTX", parent="otx")


def _otx_call(breaker, path: str, keys, *, admitted: bool = False):
    """GET an OTX indicators path through its breaker; returns a CallResult.

    404 is NO_DATA (the indicator has no such section). A 401/403 on a keyed
    request refuses that key: the next pooled key is tried, and the provider
    stops only when none is left. Anonymous requests carry no header.
    """
    from recon.helpers import circuit_breaker as cb
    url = f"{OTX_API_BASE}{path}"

    def send(key):
        headers = {"X-OTX-API-KEY": key} if key else {}
        return requests.get(url, headers=headers, timeout=30), bool(key)

    def classify(sent):
        resp, keyed = sent
        return cb.json_result(resp, keyed=keyed)

    return cb.guarded_call(breaker, send, classify, keys=keys, admitted=admitted)


def _otx_body(result) -> dict | None:
    """The parsed body; ``{}`` for a genuine no-data answer; None for a failure."""
    if result.ok:
        return result.data if isinstance(result.data, dict) else {}
    if result.answered:
        return {}
    return None


def _otx_pulse_count(body: dict | None) -> int:
    if not body:
        return 0
    pulse = body.get("pulse_info") or {}
    if isinstance(pulse, dict):
        return int(pulse.get("count") or 0)
    return 0


def _otx_pulse_details(body: dict | None, max_pulses: int = 10) -> dict:
    """Extract threat intelligence details from pulse_info.pulses array.

    Returns:
        adversaries: unique named threat actors (non-empty strings)
        malware_families: unique malware family names
        tlp: most restrictive TLP seen across pulses
        attack_ids: unique MITRE ATT&CK IDs
        tags: unique tags (up to 20)
        pulses: list of individual pulse records (up to max_pulses) for ThreatPulse graph nodes
    """
    result: dict = {
        "adversaries": [],
        "malware_families": [],
        "tlp": "",
        "attack_ids": [],
        "tags": [],
        "pulses": [],
    }
    if not body:
        return result
    pulse_info = body.get("pulse_info") or {}
    if not isinstance(pulse_info, dict):
        return result
    pulses = pulse_info.get("pulses") or []
    if not isinstance(pulses, list):
        return result

    adversaries: set[str] = set()
    malware_families: set[str] = set()
    attack_ids: set[str] = set()
    tags: set[str] = set()
    max_tlp_rank = -1
    max_tlp = ""
    pulse_records: list[dict] = []

    for pulse in pulses[:max_pulses]:
        if not isinstance(pulse, dict):
            continue
        adv = (pulse.get("adversary") or "").strip()
        if adv:
            adversaries.add(adv)
        pulse_mf: list[str] = []
        for mf in pulse.get("malware_families") or []:
            name = (mf.get("display_name") or mf.get("id") or "") if isinstance(mf, dict) else str(mf)
            name = name.strip()
            if name:
                malware_families.add(name)
                pulse_mf.append(name)
        pulse_aids: list[str] = []
        for aid in pulse.get("attack_ids") or []:
            aid_str = (aid.get("id") or "") if isinstance(aid, dict) else str(aid)
            aid_str = aid_str.strip()
            if aid_str:
                attack_ids.add(aid_str)
                pulse_aids.append(aid_str)
        pulse_tags: list[str] = []
        for tag in pulse.get("tags") or []:
            if tag:
                t = str(tag).strip()
                tags.add(t)
                pulse_tags.append(t)
        tlp_raw = (pulse.get("TLP") or pulse.get("tlp") or "").lower().strip()
        rank = _TLP_ORDER.get(tlp_raw, -1)
        if rank > max_tlp_rank:
            max_tlp_rank = rank
            max_tlp = tlp_raw

        pulse_id = str(pulse.get("id") or "")
        if pulse_id:
            pulse_records.append({
                "pulse_id": pulse_id,
                "name": str(pulse.get("name") or ""),
                "adversary": adv,
                "malware_families": pulse_mf,
                "attack_ids": pulse_aids,
                "tags": pulse_tags[:10],
                "tlp": tlp_raw,
                "author_name": str(pulse.get("author_name") or ""),
                "targeted_countries": [
                    str(c) for c in (pulse.get("targeted_countries") or [])
                    if c
                ],
                "modified": str(pulse.get("modified") or ""),
            })

    result["adversaries"] = sorted(adversaries)
    result["malware_families"] = sorted(malware_families)
    result["tlp"] = max_tlp
    result["attack_ids"] = sorted(attack_ids)
    result["tags"] = sorted(list(tags))[:20]
    result["pulses"] = pulse_records
    return result


def _otx_geo_from_general(body: dict | None) -> dict:
    if not body:
        return {}
    g = body.get("geo")
    if isinstance(g, dict):
        asn = g.get("asn")
        return {
            "country_name": str(g.get("country_name") or ""),
            "country_code": str(g.get("country_code") or ""),
            "city": str(g.get("city") or ""),
            "asn": str(asn) if asn is not None else "",
            "latitude": g.get("latitude"),
            "longitude": g.get("longitude"),
        }
    asn = body.get("asn")
    return {
        "country_name": str(body.get("country_name") or ""),
        "country_code": str(body.get("country_code") or ""),
        "city": str(body.get("city") or ""),
        "asn": str(asn) if asn is not None else "",
        "latitude": body.get("latitude"),
        "longitude": body.get("longitude"),
    }


def _otx_passive_dns_records(body: dict | None) -> list[dict]:
    """Extract passive DNS records with hostname + temporal metadata."""
    if not body:
        return []
    seen: set[str] = set()
    out: list[dict] = []
    records = body.get("passive_dns") or body.get("records") or []
    if not isinstance(records, list):
        return out
    for rec in records:
        if not isinstance(rec, dict):
            continue
        hn = rec.get("hostname") or rec.get("host") or rec.get("domain")
        if not hn or hn in seen:
            continue
        seen.add(hn)
        out.append({
            "hostname": str(hn),
            "first": str(rec.get("first") or ""),
            "last": str(rec.get("last") or ""),
            "record_type": str(rec.get("record_type") or ""),
            "asn": str(rec.get("asn") or ""),
        })
    return out


def _otx_domain_passive_dns_ips(body: dict | None) -> list[dict]:
    """Extract historical IPs from domain/passive_dns response.

    The domain passive_dns endpoint returns the IPs a domain has resolved to
    (inverse of IP passive_dns). Each record has an 'address' field.
    """
    if not body:
        return []
    seen: set[str] = set()
    out: list[dict] = []
    records = body.get("passive_dns") or body.get("records") or []
    if not isinstance(records, list):
        return out
    for rec in records:
        if not isinstance(rec, dict):
            continue
        addr = rec.get("address") or rec.get("hostname")
        if not addr or addr in seen:
            continue
        seen.add(addr)
        out.append({
            "address": str(addr),
            "first": str(rec.get("first") or ""),
            "last": str(rec.get("last") or ""),
            "record_type": str(rec.get("record_type") or ""),
        })
    return out


def _otx_malware_samples(body: dict | None, max_samples: int = 20) -> list[dict]:
    """Extract malware sample hashes from /malware response."""
    if not body:
        return []
    out: list[dict] = []
    data = body.get("data") or []
    if not isinstance(data, list):
        return out
    for sample in data[:max_samples]:
        if not isinstance(sample, dict):
            continue
        h = sample.get("hash") or sample.get("sha256") or sample.get("md5")
        if not h:
            continue
        out.append({
            "hash": str(h),
            "hash_type": "sha256" if len(str(h)) == 64 else "md5" if len(str(h)) == 32 else "unknown",
            "file_type": str(sample.get("type") or sample.get("file_class") or ""),
            "file_name": str(sample.get("file_name") or ""),
        })
    return out


def _otx_url_count(body: dict | None) -> int:
    """Extract URL count from /url_list response."""
    if not body:
        return 0
    url_list = body.get("url_list")
    if isinstance(url_list, list):
        return len(url_list)
    return int(body.get("count") or 0)


def run_otx_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run OTX indicator enrichment for IPs and (domain mode) the root domain.

    Queries the following OTX sections:
      IPv4: general, passive_dns, malware, url_list
      domain: general, passive_dns, malware, url_list

    Supports anonymous requests (no API key) with reduced rate limits.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'otx' key added
    """
    if not settings.get("OTX_ENABLED", False):
        return combined_result

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "OTX",
        settings,
        keys=[
            ("OTX_ENABLED", "Toggle"),
            ("OTX_WORKERS", "Performance"),
            ("OTX_API_KEY", "API credentials"),
            ("OTX_KEY_ROTATOR", "API credentials"),
        ],
    )

    from recon.helpers import circuit_breaker as cb
    keys = cb.KeyPool(settings.get("OTX_KEY_ROTATOR"), settings.get("OTX_API_KEY", "") or "",
                      label="OTX")
    # Allow anonymous requests — OTX API v1 works without a key (reduced rate limits)
    if keys.has_key:
        print(f"[*][OTX] Starting OSINT enrichment (authenticated)")
    else:
        print(f"[*][OTX] Starting OSINT enrichment (anonymous — limited rate)")

    domain = combined_result.get("domain", "") or ""
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)
    # IP only asks no name about a target (I-7): the per-IP passive DNS is
    # nothing but names.
    from recon.helpers.ip_hostnames import names_off
    ask_passive_dns = not names_off(combined_result, settings)
    ips = _extract_ips_from_recon(combined_result)
    ips = filter_ips_for_enrichment(ips, combined_result, "OTX")

    print(f"[+][OTX] Extracted {len(ips)} unique IPs")

    otx_data: dict[str, Any] = {
        "ip_reports": [],
        "domain_report": {
            "domain": domain,
            "pulse_count": 0,
            "pulse_details": {},
            "whois": {},
            "malware": [],
            "url_count": 0,
            "historical_ips": [],
        },
    }
    otx_scope = cb.scope("otx", label="OTX", unit="IP(s)")
    general = _otx_breaker("general")
    passive_dns = _otx_breaker("passive_dns")
    malware = _otx_breaker("malware")
    url_list = _otx_breaker("url_list")

    try:
        rate_limiter = _RateLimiter(0.3)
        max_workers = settings.get("OTX_WORKERS", 5)

        def _section(breaker, path):
            """One secondary section: its body, {} for no data, None if failed/skipped.

            The breaker is checked BEFORE the rate-limiter wait, which reserves
            its slot before sleeping."""
            if not breaker.allow():
                return None
            rate_limiter.wait()
            return _otx_body(_otx_call(breaker, path, keys, admitted=True))

        def _enrich_single_ip(ip):
            """Enrich a single IP via OTX. Returns report dict or None."""
            if not general.allow():
                return None
            rate_limiter.wait()
            gen = _otx_call(general, f"/IPv4/{ip}/general", keys, admitted=True)
            if not gen.ok or not isinstance(gen.data, dict):
                return None
            gen_body = gen.data

            pdns_records = (_otx_passive_dns_records(_section(passive_dns, f"/IPv4/{ip}/passive_dns"))
                            if ask_passive_dns else [])
            malware_list = _otx_malware_samples(_section(malware, f"/IPv4/{ip}/malware"))
            url_count = _otx_url_count(_section(url_list, f"/IPv4/{ip}/url_list"))

            pulse_details = _otx_pulse_details(gen_body)
            report = {
                "ip": ip,
                "pulse_count": _otx_pulse_count(gen_body),
                "pulse_details": pulse_details,
                "reputation": gen_body.get("reputation"),
                "geo": _otx_geo_from_general(gen_body),
                "passive_dns": pdns_records,
                # Legacy field for backward compat -- just the hostname strings
                "passive_dns_hostnames": [r["hostname"] for r in pdns_records],
                "malware": malware_list,
                "url_count": url_count,
            }
            logger.info(
                f"  OTX IPv4: {ip} -- pulses {_otx_pulse_count(gen_body)}, "
                f"pdns {len(pdns_records)}, malware {len(malware_list)}"
            )
            return report

        # ── IPv4 enrichment (parallel) ───────────────────────────────────────
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_enrich_single_ip, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    report = future.result()
                    if report is not None:
                        otx_data["ip_reports"].append(report)
                except Exception as exc:
                    logger.warning(f"OTX IP enrichment thread error: {type(exc).__name__}")

        # ── Domain enrichment: the org, once per run ─────────────────────────
        def _domain_report(d):
            """The org's OTX domain report; its "domain" is "" without an answer."""
            report = dict(otx_data["domain_report"], domain=d)
            answered = False
            if general.allow():
                rate_limiter.wait()
                dg = _otx_call(general, f"/domain/{d}/general", keys, admitted=True)
                if dg.answered:
                    answered = True
                    dg_body = dg.data if isinstance(dg.data, dict) else {}
                    whois = dg_body.get("whois")
                    if not isinstance(whois, dict):
                        whois = {}
                    report.update({
                        "domain": d,
                        "pulse_count": _otx_pulse_count(dg_body),
                        "pulse_details": _otx_pulse_details(dg_body),
                        "whois": whois,
                    })
                    logger.info(f"  OTX domain: {d} -- pulses {report['pulse_count']}")
                elif dg.outcome is not cb.Outcome.SKIPPED:
                    print(f"[!][OTX] Domain general skipped ({dg.detail})")
            if answered:
                # domain/passive_dns -- IPs the domain has historically resolved to
                report["historical_ips"] = _otx_domain_passive_dns_ips(
                    _section(passive_dns, f"/domain/{d}/passive_dns"))
                report["malware"] = _otx_malware_samples(
                    _section(malware, f"/domain/{d}/malware"))
                report["url_count"] = _otx_url_count(
                    _section(url_list, f"/domain/{d}/url_list"))
            else:
                # The report is pre-filled with zeros, and the graph writer SETs
                # whatever it holds for a named domain. With no answer from OTX
                # there is nothing to write, so the domain name goes.
                report["domain"] = ""
            return report

        if domain and not is_ip_mode:
            from recon.helpers.org_work import once_per_org, org_of
            otx_data["domain_report"], _ = once_per_org(
                "otx_domain", org_of(combined_result), _domain_report,
                answered=lambda r: bool(r.get("domain")), label="OTX")
        else:
            otx_data["domain_report"]["domain"] = ""

        ip_count = len(otx_data["ip_reports"])
        dom_pulse = otx_data["domain_report"].get("pulse_count", 0)
        print(
            f"[+][OTX] Enrichment complete: {ip_count} IP report(s), "
            f"domain pulses={dom_pulse}"
        )

    except Exception as e:
        logger.error(f"OTX enrichment failed: {type(e).__name__}")
        print(f"[!][OTX] Enrichment error: {type(e).__name__}")
        print(f"[!][OTX] Pipeline continues with partial or empty OTX data")

    otx_scope.finish("otx_enrich", payload=otx_data)
    combined_result["otx"] = otx_data
    return combined_result


def run_otx_enrichment_isolated(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run OTX enrichment and return only the 'otx' data dict.

    Thread-safe: does not mutate combined_result.

    Args:
        combined_result: The pipeline's combined result dictionary (read-only)
        settings: Project settings dict

    Returns:
        The 'otx' data dictionary
    """
    import copy
    snapshot = copy.deepcopy(combined_result)
    run_otx_enrichment(snapshot, settings)
    return snapshot.get("otx", {})
