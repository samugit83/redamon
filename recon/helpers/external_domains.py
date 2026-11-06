"""External (out-of-scope) domains every pipeline source saw, aggregated.

Shared by the full pipeline and partial recon (which must not import
recon/main.py). Each entry is informational only: never scanned.
"""


def _merge_external_domain(aggregated: dict, entry: dict):
    """Merge a single external domain entry into the aggregated dict."""
    domain = entry.get("domain", "").strip().lower()
    if not domain:
        return
    if domain not in aggregated:
        aggregated[domain] = {
            "domain": domain, "sources": [], "redirect_from_urls": [],
            "redirect_to_urls": [], "status_codes_seen": [], "titles_seen": [],
            "servers_seen": [], "ips_seen": [], "countries_seen": [], "times_seen": 0,
        }
    rec = aggregated[domain]
    rec["times_seen"] += 1
    for val, key in [
        (entry.get("source"), "sources"),
        (entry.get("url"), "redirect_to_urls"),
        (entry.get("redirect_from_url"), "redirect_from_urls"),
        (entry.get("title"), "titles_seen"),
        (entry.get("server"), "servers_seen"),
        (entry.get("ip"), "ips_seen"),
        (entry.get("country"), "countries_seen"),
    ]:
        if val and val not in rec[key]:
            rec[key].append(val)
    sc = entry.get("status_code")
    if sc is not None:
        sc_str = str(sc)
        if sc_str not in rec["status_codes_seen"]:
            rec["status_codes_seen"].append(sc_str)


def _aggregate_external_domains(combined_result: dict) -> list:
    """Aggregate external domains from all pipeline sources."""
    aggregated = {}
    for e in combined_result.get("http_probe", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("urlscan", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("resource_enum", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("domain_discovery_external_domains", []):
        _merge_external_domain(aggregated, e)
    # Out-of-scope names diverted by merge_discovered_hostnames (certificate
    # SANs, js_recon subdomains): recorded, never scanned.
    for e in combined_result.get("discovered_external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in _js_recon_external_domains(combined_result):
        _merge_external_domain(aggregated, e)
    return list(aggregated.values())


def _js_recon_external_domains(combined_result: dict) -> list:
    """Third-party hosts the target's JavaScript names, as external-domain entries.

    The graph keeps no Endpoint for them, so this is their only record. JS recon
    tests hosts against the root domain, which in IP mode is the synthetic
    ip-targets name, so the target IPs come back as "external" and are dropped.
    Only domain and source are passed: a URL a bundle names is not a redirect.
    """
    metadata = combined_result.get("metadata") or {}
    targets = {
        str(h).strip().lower()
        for h in [*(combined_result.get("subdomains") or []),
                  *(metadata.get("subdomain_filter") or []),
                  *(metadata.get("expanded_ips") or [])]
    }
    entries = (combined_result.get("js_recon") or {}).get("external_domains") or []
    return [
        {"domain": e["domain"], "source": "js_recon"}
        for e in entries
        if isinstance(e, dict) and isinstance(e.get("domain"), str)
        and e["domain"].strip().lower() not in targets
    ]
