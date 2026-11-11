"""Scan-scope host filtering shared by the recon graph mixins.

The mixins must not create nodes for hosts outside the scan scope (a crawler
can wander onto a third-party CDN, and Nuclei follows redirects off-target).
The allowed-host set is assembled here so every mixin agrees on it.
"""
from urllib.parse import urlparse


def _normalize_host(value: str) -> str:
    """Reduce a host-ish string to a bare comparable hostname.

    Accepts what the scanners actually emit: 'example.com', 'example.com:8443',
    'https://example.com/foo' (Nuclei writes the full URL into `host` for some
    template types) and '[::1]:443'.
    """
    if not value:
        return ""
    host = value.strip().lower()
    if "://" in host:
        host = urlparse(host).netloc or host.split("://", 1)[1]
    host = host.split("/")[0]
    if host.startswith("["):                      # IPv6 literal: [::1]:443
        return host[1:].split("]")[0]
    return host.split(":")[0]


# A name no scanner reports: the scope of a run with nothing in it.
_NO_HOST = "\x00"


def build_host_scope(recon_data: dict) -> set:
    """Hosts the graph is allowed to create nodes for, or an empty set for "no filter".

    IP mode is the reason this is not just `subdomains`: run_ip_recon mints a
    dashed placeholder name per IP ("21.40.250.84" -> "21-40-250-84") because a
    Subdomain node needs a name, but every scanner targets the IP literal and
    reports findings under it. Scoping on `subdomains` alone therefore discards
    100% of an IP-mode scan's results. `metadata.subdomain_filter` is the
    allowed-host list httpx already filters on and holds the real IPs.
    """
    scope = {_normalize_host(h) for h in recon_data.get("subdomains") or []}
    metadata = recon_data.get("metadata") or {}
    scope |= {_normalize_host(h) for h in metadata.get("subdomain_filter") or []}
    scope |= {_normalize_host(ip) for ip in metadata.get("expanded_ips") or []}
    scope.discard("")

    # Bare-domain scan with no subdomains discovered: the apexes are the scope,
    # each only when its group made it a target.
    if not scope:
        groups = scope_groups_by_root(recon_data)
        roots = scope_roots(recon_data)
        scope = {_normalize_host(r) for r in roots
                 if groups.get(_clean(r), {}).get("include_root", True)}
        scope.discard("")
        if roots and not scope:
            # Roots that are no target, and nothing found under them: an empty
            # set would read as "no filter" and admit every host.
            scope = {_NO_HOST}
    return scope


def host_in_scope(value: str, scope: set) -> bool:
    """True when `value` (host, host:port or URL) is in scope. Empty scope = no filter."""
    if not scope:
        return True
    return _normalize_host(value) in scope


# ---------------------------------------------------------------------------
# Project roots. A Domain-batch project has one Domain node per root, and a
# write can cover several of them: a partial run over the whole batch, or a full
# run's group, which also carries the other roots (recon/main.py
# run_domain_batch). Mirrors scope_roots/root_for_host in
# recon/partial_recon_modules/helpers.py; graph_db must not import recon.
# ---------------------------------------------------------------------------

def scope_roots(recon_data: dict) -> list:
    """The roots this run SCANS: recon_data["domains"], else the single "domain".

    A partial run scans every root in "domains". The full pipeline runs one
    Domain-batch group at a time, so "domains" is unset there and this is the
    group's own root -- the scan (DNS security checks, takeover targets, the
    vuln-scan host scope) stays inside the group, as before.
    """
    roots = recon_data.get("domains")
    if isinstance(roots, list):
        cleaned = [r for r in roots if isinstance(r, str) and r.strip()]
        if cleaned:
            return cleaned
    domain = recon_data.get("domain")
    return [domain] if isinstance(domain, str) and domain.strip() else []


def attach_roots(recon_data: dict) -> list:
    """The roots a WRITER may attach a discovered host to.

    Every project root, so a host a scan found under another root of the batch
    becomes that root's Subdomain rather than an ExternalDomain. The full
    pipeline runs a group at a time but carries all the batch's roots in
    "all_project_roots" for exactly this. A partial run's dicts mostly lack
    that key, so its roots are the run's own scan roots followed by every
    project group's root (set_run_scope_groups): the run's own come first, as
    a writer reads roots[0] for an IP-mode host or a host under no root. A
    single-domain project, and the full pipeline (which never sets the run's
    groups), get the run's own scan scope.
    """
    roots = recon_data.get("all_project_roots")
    if isinstance(roots, list):
        cleaned = [r for r in roots if isinstance(r, str) and r.strip()]
        if cleaned:
            return cleaned
    roots = scope_roots(recon_data)
    known = {_clean(r) for r in roots}
    for g in _RUN_SCOPE_GROUPS:
        root = g.get("scan_root")
        if isinstance(root, str) and _clean(root) and _clean(root) not in known:
            known.add(_clean(root))
            roots.append(root)
    return roots


def root_for_host(value: str, roots: list, ip_mode: bool = False):
    """The longest root that the host of `value` equals or sits under, or None.

    In IP mode every host belongs to the one synthetic root
    (ip-targets.<project_id>): its Subdomains are dashed IPs, not names under it.
    The root is returned as stored. A writer decides scope with
    scan_root_for_host and attaches with org_for_scan_root instead.
    """
    host = _normalize_host(value).strip(".")
    if not host or not roots:
        return None
    if ip_mode:
        return roots[0]
    best, best_len = None, -1
    for root in roots:
        r = str(root or "").strip().strip(".").lower()
        if r and (host == r or host.endswith("." + r)) and len(r) > best_len:
            best, best_len = root, len(r)
    return best


# ---------------------------------------------------------------------------
# Scope versus attach (§4.11.2). A Domain node is the ORGANISATION (registrable
# domain); a scan root is where a group of the project points. One decides
# whether a host belongs to the project, the other where it is linked.
# ---------------------------------------------------------------------------

IN_SCOPE, SKIPPED, OUT_OF_SCOPE = "in", "skipped", "out"


def _clean(name) -> str:
    return str(name or "").strip().strip(".").lower()


# The project's scope groups for this process (one partial run = one process),
# for a writer handed a recon dict that carries none. Partial recon builds many
# recon dicts across its modules; a missed stamp would attach a deeper scan
# root's hosts to a Domain(<scan root>) that no longer exists. The full
# pipeline stamps every dict, so it never reaches this default.
_RUN_SCOPE_GROUPS: list = []


def set_run_scope_groups(groups: list) -> None:
    """The project's scope groups (snake keys) for a writer handed a recon dict without them (a partial run)."""
    _RUN_SCOPE_GROUPS[:] = [g for g in groups or [] if isinstance(g, dict)]


def scope_groups_by_root(recon_data: dict) -> dict:
    """The scope groups (snake keys) by scan root: recon_data["scope_groups"],
    else this run's default (set_run_scope_groups).

    Neither in a legacy recon file or IP mode, where every caller falls back
    to the scan root itself, which is exactly the old model.
    """
    groups = {}
    for g in (recon_data or {}).get("scope_groups") or _RUN_SCOPE_GROUPS:
        if isinstance(g, dict):
            root = _clean(g.get("scan_root"))
            if root:
                groups.setdefault(root, g)
    return groups


def classify_host(value: str, recon_data: dict):
    """``(IN_SCOPE, scan_root)``, ``(SKIPPED, scan_root)`` or ``(OUT_OF_SCOPE, None)``.

    The longest scan root the host equals or sits under decides, and the match
    STOPS there: a host equal to a scan root whose group leaves Root off is
    SKIPPED (no node, and no ExternalDomain either: it is the project's own
    root), never re-admitted through a shorter root. A host under no scan
    root is OUT_OF_SCOPE, i.e. an ExternalDomain, even when it shares an org
    with a group (D-6).

    IP mode: its synthetic root is no parent of a real name, so a hostname the
    selection rule chose to scan (metadata.ip_mode_hosts, name -> org) is
    IN_SCOPE with its org Domain as the root; any other name stays out (a
    recorded name is no target, I-4).
    """
    metadata = (recon_data or {}).get("metadata") or {}
    if metadata.get("ip_mode") and isinstance(metadata.get("ip_mode_hosts"), dict):
        org = metadata["ip_mode_hosts"].get(_normalize_host(value).strip("."))
        if isinstance(org, str) and _clean(org):
            return IN_SCOPE, _clean(org)
    roots = attach_roots(recon_data)
    root = root_for_host(value, roots)
    if root is None:
        return OUT_OF_SCOPE, None
    host = _normalize_host(value).strip(".")
    if host == _clean(root):
        group = scope_groups_by_root(recon_data).get(_clean(root))
        if group is not None and not group.get("include_root"):
            return SKIPPED, root
    return IN_SCOPE, root


def scan_root_for_host(value: str, recon_data: dict):
    """The scan root a host belongs to (the scope decision), or None when it
    is out of scope or is a scan root that is no target (see classify_host)."""
    kind, root = classify_host(value, recon_data)
    return root if kind == IN_SCOPE else None


def org_for_scan_root(scan_root: str, recon_data: dict) -> str:
    """The Domain a scan root's hosts attach to: its group's org.

    Falls back to the scan root itself (a legacy recon file, IP mode), so an
    old file attaches exactly as it always did.
    """
    group = scope_groups_by_root(recon_data).get(_clean(scan_root))
    org = _clean(group.get("org_domain")) if group else ""
    return org or scan_root


def org_for_host(value: str, recon_data: dict):
    """The org Domain an in-scope host attaches to, or None."""
    root = scan_root_for_host(value, recon_data)
    return org_for_scan_root(root, recon_data) if root else None


def project_orgs(recon_data: dict) -> list:
    """Every org Domain of the project's scan roots, in order, deduplicated."""
    out = []
    for root in attach_roots(recon_data):
        org = org_for_scan_root(root, recon_data)
        if org and org not in out:
            out.append(org)
    return out


def attach_for_host(value: str, recon_data: dict):
    """``(kind, org)`` for a writer: ``(IN_SCOPE, <org Domain>)``,
    ``(SKIPPED, None)`` (a scan root that is no target: write nothing) or
    ``(OUT_OF_SCOPE, None)`` (an ExternalDomain)."""
    kind, root = classify_host(value, recon_data)
    return kind, (org_for_scan_root(root, recon_data) if kind == IN_SCOPE else None)


def home_domain(recon_data: dict) -> str:
    """The org Domain of the run's own scan root (recon_data["domain"]): where
    an ExternalDomain it found is DISCOVERED_BY, and where an org-level report
    of this group attaches."""
    domain = (recon_data or {}).get("domain") or ""
    return org_for_scan_root(domain, recon_data) if domain else domain
