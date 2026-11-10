"""The recon pipeline's own finding sources, shared by full and partial recon.

A prune only ever touches these, so a recon run can never remove a GVM,
GitHub-hunt or supply-chain finding; the node-filter sweep is scoped to them
for the same reason. graph_db/node_filters/build.py reads this tuple to check
that every source is claimed by a filter kind or listed as unfiltered.
"""

RECON_FINDING_SOURCES = (
    "nuclei", "security_check", "js_recon", "jsluice", "takeover_scan",
    "cache_poisoning", "graphql_scan", "graphql_cop", "ai_surface_recon",
    "vhost_sni_enum", "origin_discovery", "nmap_nse", "resource_enum",
    "http_probe", "vuln_scan", "wcvs", "serialized_scan", "route_exposure",
    "shodan_api", "internetdb", "shodan", "shodan_host_lookup", "netlas", "criminalip",
    # urlscan's history: Vulnerability {source: 'urlscan_leak'} and Secret {source: 'urlscan'}
    "urlscan_leak", "urlscan",
    # the web archives' URLs (GAU, ParamSpider) the quarantine held: Vulnerability and Secret
    "url_archive",
)

#: The `source` each passive CVE writer stamps, per enricher (the key is its
#: pipeline phase). Shodan stamps the API that answered, `shodan_api` or
#: `internetdb`; `shodan` and `shodan_host_lookup` are the writer's fallbacks,
#: and `source` is set on create only, so nodes first written under them keep
#: those values and must be pruned under them too.
PASSIVE_CVE_SOURCES = {
    "shodan": ("shodan_api", "internetdb", "shodan", "shodan_host_lookup"),
    "netlas": ("netlas",),
    "criminalip": ("criminalip",),
}
