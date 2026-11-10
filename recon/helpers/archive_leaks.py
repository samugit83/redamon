"""Leaked one-time links and secrets in the web archives' URLs (GAU, ParamSpider).

The quarantine (url_leaks.split_quarantined) keeps these URLs out of every list
anything requests. They are findings too: a password-reset link or an API key a
web archive published can be opened by anyone. Same shape as urlscan's item 2
(urlscan_enrich._leak_findings), written as Vulnerability / Secret
{source: 'url_archive'}, with the secret and the full links kept in the
display-only fields (graph_db/display_only.py).

Archives give no visit date, so first_seen / last_seen stay empty and the links
keep the order the archive listed them in. Never raises.
"""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

ARCHIVE_LABEL = {"gau": "GAU (Wayback Machine, Common Crawl, OTX, urlscan)",
                 "paramspider": "ParamSpider (Wayback Machine)"}


def report_archive_leaks(quarantined: Iterable, settings: dict, domain: str) -> dict:
    """`resource_enum.archive_leaks` for a run (full or partial), keyed by the
    deployment's HMAC key like urlscan's secrets. Never raises."""
    try:
        from recon.main_recon_modules.urlscan_enrich import _hmac_key
        key = _hmac_key()
    except Exception:  # noqa: BLE001 - no key means one Secret per host, type and parameter
        key = ""
    leaks = build_archive_leaks(quarantined, settings, domain, hmac_key=key)
    if leaks["findings"] or leaks["url_secrets"]:
        print(f"[+][ArchiveLeaks] {len(leaks['findings'])} leaked link finding(s), "
              f"{len(leaks['url_secrets'])} secret(s) in archive URLs")
    return leaks


def build_archive_leaks(quarantined: Iterable, settings: dict, domain: str,
                        hmac_key: str = "") -> dict:
    """{"findings", "url_secrets"} from [(archive, url)] the quarantine held."""
    try:
        return _build(list(quarantined or ()), settings or {}, domain, hmac_key)
    except Exception as exc:  # noqa: BLE001 - a finding builder never stops the scan
        print(f"[!][ArchiveLeaks] skipped ({type(exc).__name__})")
        return {"findings": [], "url_secrets": []}


def _build(quarantined: list, settings: dict, domain: str, hmac_key: str) -> dict:
    from recon.helpers import url_leaks
    from recon.main_recon_modules.urlscan_enrich import (
        LINK_LABEL, LINK_SEVERITY, MAX_UNMASKED_URLS, SECRET_SEVERITY, HostScope,
    )
    scope = HostScope(settings, domain)
    links: dict = {}
    secrets: dict = {}
    for archive, url in quarantined:
        if not isinstance(url, str) or not url:
            continue
        host = (urlparse(url).hostname or "").lower()
        if not host or not scope.host_ok(host):
            continue
        v = url_leaks.inspect_url(url, hmac_key=hmac_key, with_values=True)
        if v["link_kind"]:
            slot = links.setdefault((host, v["masked_path"] or "/", v["link_kind"]), {
                "masked_url": v["masked_url"], "urls": [], "archives": set(), "count": 0})
            slot["count"] += 1
            slot["archives"].add(archive)
            if url not in slot["urls"] and len(slot["urls"]) < MAX_UNMASKED_URLS:
                slot["urls"].append(url)
        for sec in v["secrets"]:
            ident = sec.get("value_hmac") or sec["param_name"]
            slot = secrets.setdefault((host, sec["secret_type"], ident), {
                "sec": sec, "url": url, "masked_url": v["masked_url"], "archives": set(), "count": 0})
            slot["count"] += 1
            slot["archives"].add(archive)

    findings = []
    for (host, path, kind), slot in sorted(links.items()):
        label = LINK_LABEL.get(kind, kind)
        where = ", ".join(ARCHIVE_LABEL.get(a, a) for a in sorted(slot["archives"]))
        findings.append({
            "type": "leaked_one_time_link", "kind": kind, "kind_field": "link_kind",
            "host": host, "path": path, "url": slot["masked_url"],
            "severity": LINK_SEVERITY.get(kind, "medium"),
            "name": f"Leaked {label} link in web archives",
            "description": (
                f"{host}{path} has {slot['count']} {label} link(s) in public web archives ({where}): "
                f"anyone who searches them can open the links. RedAmon never opened one and cannot "
                f"tell whether a link still works. Make one-time links expire within minutes and "
                f"work once, and ask the archives to remove them."),
            "first_seen": "", "last_seen": "",
            "props": {"link_count": slot["count"], "masked_url": slot["masked_url"],
                      "unmasked_url": slot["urls"][0] if slot["urls"] else None,
                      "unmasked_urls": slot["urls"] or None,
                      "archive_sources": sorted(slot["archives"])},
        })
    url_secrets = []
    for (host, stype, _ident), slot in sorted(secrets.items()):
        sec = slot["sec"]
        severity = SECRET_SEVERITY.get(stype, "medium")
        if stype == "jwt" and sec.get("jwt_expired") is True:
            severity = "low"
        parsed = urlparse(slot["masked_url"] or "")
        url_secrets.append({
            "host": host, "secret_type": stype, "param_name": sec["param_name"],
            "value_length": sec["value_length"], "value_hmac": sec.get("value_hmac"),
            "jwt_alg": sec.get("jwt_alg"), "jwt_expired": sec.get("jwt_expired"),
            "masked_url": slot["masked_url"],
            "secret_value": sec.get("value"), "unmasked_url": slot["url"],
            "base_url": f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"https://{host}",
            "severity": severity, "first_seen": "", "last_seen": "", "count": slot["count"],
            "archive_sources": sorted(slot["archives"]),
        })
    return {"findings": findings, "url_secrets": url_secrets}
