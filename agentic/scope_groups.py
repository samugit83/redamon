"""
A project's scope as scope groups, as the agent reads it.

The webapp derives the groups (webapp/src/lib/scopeGroups.ts) and returns them
as `scopeGroups` from GET /api/projects/[id]; the agent never recomputes them and
carries no Public Suffix List (the webapp and recon own that). This module only
validates what arrives - it crosses a trust boundary - and turns it into the
sets the agent needs: guardrail names, the authenticated-session scope and a
signature that says "the scope changed".

A webapp older than the scope groups sends no `scopeGroups`; the legacy fields
are then read the way 7.1.0 wrote them. A legacy group's `hosts` list is never
read as an auth scope: it holds `*.x` tokens.

Stdlib only: the agent image carries no PSL package, and this is imported on
the guardrail path. recon_settings.ip_hostnames is stdlib too: it is the one
hostname rule every service shares (invariant I-5), baked into the agent image.

An IP-mode project has no scope groups: its scope is the target IPs, plus, in
record_filter / scan_all, the hostnames a scan selected on them that the
project's current policy still admits (design §6.3, §10).
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Iterable, Optional

from recon_settings.ip_hostnames import MODES as IP_HOSTNAME_MODES
from recon_settings.ip_hostnames import matches, normalize_host, normalize_name, parse_entries, split_wildcard

_HOST_CHARSET = re.compile(r'^[a-z0-9.-]+$')

#: At most this many scanned hostnames in the system prompt, plus the total:
#: the names come from DNS, certificates and third-party indexes, text the
#: target influences, so the prompt carries a bounded, charset-checked list.
MAX_PROMPT_HOSTNAMES = 50
#: Target entries listed in the prompt. Entries, not addresses: a /24 is one.
MAX_PROMPT_TARGET_ENTRIES = 100
_SCANNING_MODES = ('record_filter', 'scan_all')


def clean_host(value) -> str:
    """A lower-cased hostname that passes the charset, or '' (dropped, never repaired)."""
    h = str(value or '').strip().lower().rstrip('.')
    if not h or not _HOST_CHARSET.match(h) or '..' in h or h.startswith('.') or h.startswith('-'):
        return ''
    if len(h) > 253 or any(len(label) > 63 for label in h.split('.')):
        return ''
    return h


def _under(host: str, root: str) -> bool:
    return host.endswith(f'.{root}')


def parse_scope_groups(raw) -> list[dict]:
    """The webapp's `scopeGroups`, validated. A malformed group is DROPPED whole:
    a repaired group would be a scope the operator never approved."""
    groups: list[dict] = []
    roots: set[str] = set()
    for g in raw if isinstance(raw, list) else []:
        if not isinstance(g, dict):
            continue
        root = clean_host(g.get('scanRoot'))
        org = clean_host(g.get('orgDomain'))
        mode = g.get('mode')
        include_root = g.get('includeRoot')
        exact = g.get('exactHosts')
        if not root or not org or mode not in ('exact', 'enumerate') or not isinstance(include_root, bool):
            continue
        if not isinstance(exact, list) or root in roots:
            continue
        if root != org and not _under(root, org):
            continue
        hosts = [clean_host(h) for h in exact]
        if any(not h or h == root or not _under(h, root) for h in hosts):
            continue
        if mode == 'exact' and not include_root and not hosts:
            continue
        entries = g.get('entries', [])
        if not isinstance(entries, list):
            continue
        names = [clean_host(str(e).removeprefix('*.')) for e in entries]
        if any(not n or (n != root and not _under(n, root)) for n in names):
            continue
        roots.add(root)
        groups.append({
            'scan_root': root, 'org_domain': org, 'mode': mode,
            'include_root': include_root, 'exact_hosts': list(dict.fromkeys(hosts)),
            'entry_names': list(dict.fromkeys(names)),
        })
    return groups


def legacy_scope_groups(project: dict) -> list[dict]:
    """The groups of a project read from a webapp that sends no `scopeGroups`."""
    if project.get('domainBatchMode'):
        groups: list[dict] = []
        for g in project.get('domainBatchGroups') or []:
            if not isinstance(g, dict):
                continue
            root = clean_host(g.get('rootDomain'))
            prefixes = [p for p in (g.get('prefixes') or []) if isinstance(p, str)]
            if not root or any(x['scan_root'] == root for x in groups):
                continue
            hosts = [clean_host(f"{p.strip().rstrip('.')}.{root}") for p in prefixes if p.strip() not in ('', '.', '*')]
            groups.append({
                'scan_root': root, 'org_domain': root,
                'mode': 'enumerate' if '*' in prefixes else 'exact',
                'include_root': '.' in prefixes,
                'exact_hosts': [h for h in hosts if h], 'entry_names': [],
            })
        return [g for g in groups if g['mode'] == 'enumerate' or g['include_root'] or g['exact_hosts']]
    root = clean_host(str(project.get('targetDomain') or '').removeprefix('*.'))
    if not root:
        return []
    prefixes = [str(p).strip() for p in (project.get('subdomainList') or []) if str(p).strip()]
    hosts = [clean_host(f"{p.rstrip('.')}.{root}") for p in prefixes if p not in ('.', '*')]
    hosts = [h for h in hosts if h]
    return [{
        'scan_root': root, 'org_domain': root,
        'mode': 'exact' if hosts else 'enumerate',
        'include_root': '.' in prefixes,
        'exact_hosts': hosts, 'entry_names': [],
    }]


def scope_groups_from_project(project: dict) -> tuple[list[dict], str, int]:
    """(groups, source, dropped): source is 'webapp' when the project carried
    `scopeGroups`, 'legacy' otherwise, 'ip' in IP mode; dropped counts the
    webapp groups that failed validation, which a session start refuses."""
    if project.get('ipMode'):
        return [], 'ip', 0
    raw = project.get('scopeGroups')
    if isinstance(raw, list):
        groups = parse_scope_groups(raw)
        return groups, 'webapp', len(raw) - len(groups)
    return legacy_scope_groups(project), 'legacy', 0


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def guardrail_names(groups: list[dict]) -> list[str]:
    """Hard-guardrail names, as the webapp's guardrailNames: every entry (marker
    stripped), exact host, scan root and org."""
    return _dedupe([*(n for g in groups for n in g.get('entry_names', ())),
                    *(h for g in groups for h in g['exact_hosts']),
                    *(g['scan_root'] for g in groups),
                    *(g['org_domain'] for g in groups)])


def soft_guardrail_names(groups: list[dict]) -> list[str]:
    """What the LLM guardrail judges: orgs and scan roots."""
    return _dedupe([n for g in groups for n in (g['org_domain'], g['scan_root'])])


def auth_scope_patterns(groups: list[dict], ip_mode: bool = False,
                        target_ips: Iterable[str] = ()) -> list[str]:
    """Where an authenticated session may go (§4.6): `*.<root>` (strict
    subdomains) for an ENUMERATE group, the listed hosts of an EXACT one, the
    scan root only when it is a target; the target IPs in IP mode."""
    if ip_mode:
        return _dedupe(str(ip).strip() for ip in target_ips or ())
    out: list[str] = []
    for g in groups:
        if g['mode'] == 'enumerate':
            out.append(f"*.{g['scan_root']}")
        else:
            out.extend(g['exact_hosts'])
        if g['include_root']:
            out.append(g['scan_root'])
    return _dedupe(out)


def _ip_net(value: str):
    """An IP or CIDR as a network, or None."""
    try:
        return ipaddress.ip_network(value, strict=False) if ('/' in value or _is_ip(value)) else None
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _entry(raw) -> str:
    """An explicit scope entry normalised: `*.<host>`, a host, an IP or a CIDR; '' if none."""
    e = str(raw or '').strip().lower().rstrip('.')
    if e.startswith('*.'):
        h = clean_host(e[2:])
        return f'*.{h}' if h else ''
    net = _ip_net(e)
    if net is not None:
        return e if _is_ip(e) else str(net)
    return clean_host(e)


def _meet(a: str, b: str) -> Optional[str]:
    """The intersection of two scope entries, when it is one entry. `*.x` is the
    strict subdomains of x, so `*.example.com` and `www.example.com` meet at the
    host, and `*.example.com` never admits `example.com` itself."""
    na, nb = _ip_net(a), _ip_net(b)
    if na is not None or nb is not None:
        if na is None or nb is None or na.version != nb.version:
            return None
        if na.subnet_of(nb):
            return a
        return b if nb.subnet_of(na) else None
    wa, wb = a.startswith('*.'), b.startswith('*.')
    ra, rb = (a[2:] if wa else a), (b[2:] if wb else b)
    if wa and wb:
        if ra == rb or _under(ra, rb):
            return a
        return b if _under(rb, ra) else None
    if wa:
        return b if _under(rb, ra) else None
    if wb:
        return a if _under(ra, rb) else None
    return a if a == b else None


def intersect_explicit_scope(explicit: Iterable[str], patterns: list[str]) -> list[str]:
    """An auth profile's explicit scope only NARROWS the project's (D-22): the
    hosts both admit. An explicit `*.a.example.com` survives under an enumerated
    `*.example.com`; an explicit `*.example.com` on a project that lists only
    `www.example.com` leaves `www.example.com`; an explicit host survives only if
    the project admits it. A malformed explicit entry admits nothing."""
    kept: list[str] = []
    for raw in explicit or ():
        e = _entry(raw)
        if not e:
            continue
        for p in patterns:
            q = _entry(p)
            m = _meet(e, q) if q else None
            if m:
                kept.append(m)
    return _dedupe(kept)


def scope_signature(groups: list[dict], ip_mode: bool = False,
                    target_ips: Iterable[str] = (), ip_hostname_policy: Optional[dict] = None,
                    ip_hostnames: Iterable[str] = ()) -> str:
    """A canonical string that changes exactly when the scope does.

    In IP mode with `ip_hostname_policy` (the seven policy fields) it also
    covers the policy and the scanned hostnames the policy admits, so a policy
    edit or a scan that selected new names re-runs a session's guardrails.
    """
    if ip_mode:
        signature = 'ip|' + ','.join(sorted(_dedupe(str(i).strip() for i in target_ips or ())))
        if ip_hostname_policy is None:
            return signature
        # Entry order is not scope: a reordered include list is the same policy.
        policy = {k: sorted(map(str, v)) if isinstance(v, (list, tuple)) else v
                  for k, v in ip_hostname_policy.items()}
        return (signature + '|policy|' + json.dumps(policy, sort_keys=True, default=str)
                + '|names|' + ','.join(sorted(set(ip_hostnames or ()))))
    parts: set[str] = set()
    for g in groups:
        if g['mode'] == 'enumerate':
            parts.add(f"enum|{g['scan_root']}")
        else:
            parts.update(f'exact|{h}' for h in g['exact_hosts'])
        if g['include_root']:
            parts.add(f"root|{g['scan_root']}")
    return ';'.join(sorted(parts))


def compact_scope_text(groups: list[dict], max_hosts: int = 15, max_lines: int = 30) -> Optional[str]:
    """The scope as a few prompt lines, capped; None when there is nothing to show."""
    if not groups:
        return None
    lines: list[str] = []
    listed = 0
    for g in groups[:max_lines]:
        if g['mode'] == 'enumerate':
            lines.append(f"- *.{g['scan_root']} (any host under it"
                         + (f", and {g['scan_root']} itself)" if g['include_root'] else f"; not {g['scan_root']} itself)"))
        else:
            hosts = ([g['scan_root']] if g['include_root'] else []) + g['exact_hosts']
            shown = hosts[:max(0, max_hosts - listed)]
            listed += len(shown)
            if not shown:
                lines.append(f"- {len(hosts)} listed hosts under {g['scan_root']}")
                continue
            more = f" (+{len(hosts) - len(shown)} more)" if len(shown) < len(hosts) else ''
            lines.append(f"- only {', '.join(shown)}{more}")
    if len(groups) > max_lines:
        lines.append(f"- (+{len(groups) - max_lines} more scope groups)")
    return '\n'.join(lines)


def ip_hostname_mode(raw) -> str:
    """The stored hostname mode, or the strictest one when it is not a mode."""
    return raw if raw in IP_HOSTNAME_MODES else 'ip_only'


def ip_hostname_include_bases(include) -> list[str]:
    """The base name of each include entry (`*.x`, `*x` and `x` all give x), as
    the webapp's ipHostnameIncludeBases: the hard guardrail's names. A refused
    entry is named too, so a malformed one cannot hide a blocked name."""
    if not isinstance(include, (list, tuple)):
        return []
    return _dedupe(split_wildcard(normalize_host(e))[1] if isinstance(e, str) else '' for e in include)


def ip_soft_guardrail_names(mode, include) -> list[str]:
    """The include bases the LLM guardrail judges: record_filter only, the one
    mode that scans under them, and only the ones that are hostnames (a refused
    entry is the hard guardrail's and the webapp's to refuse)."""
    if ip_hostname_mode(mode) != 'record_filter':
        return []
    return [n for n in ip_hostname_include_bases(include) if normalize_name(n) == n]


def admitted_ip_hostnames(names: Iterable[str], mode, include, exclude) -> list[str]:
    """The scanned names the project's CURRENT policy admits (design §6.3), as
    the webapp's admittedByCurrentPolicy: a narrowing, a restored Scan Timeline
    version or a failed out_of_policy marker can leave a name marked scanned
    that the policy no longer wants. scan_all admits every name, record_filter
    those include - exclude matches, the other modes none; a filter that does
    not parse admits none. Canonical spelling (a name that is not one is
    dropped), sorted."""
    mode = ip_hostname_mode(mode)
    if mode not in _SCANNING_MODES:
        return []
    clean = sorted({n for n in map(normalize_name, names or ()) if n})
    if mode == 'scan_all':
        return clean
    include_patterns, bad_include = parse_entries(include)
    exclude_patterns, bad_exclude = parse_entries(exclude)
    if bad_include or bad_exclude:
        return []
    return [n for n in clean if matches(n, include_patterns, exclude_patterns).included]


def compact_ip_scope_text(target_ips: Iterable[str], mode, scanned: Iterable[str],
                          max_entries: int = MAX_PROMPT_TARGET_ENTRIES,
                          max_names: int = MAX_PROMPT_HOSTNAMES) -> Optional[str]:
    """An IP-mode project's scope as prompt lines, or None without a target.

    The target list as stored (a CIDR stays one entry), then what a hostname
    on those addresses is in this mode. `scanned` is read only in record_filter
    and scan_all; the caller passes the names the current policy admits, and
    each is checked here again (normalize_name): the names are text the target
    influences, and nothing that is not a hostname reaches the prompt.
    """
    entries = _dedupe(str(i).strip() for i in target_ips or () if i is not None)
    if not entries:
        return None
    shown = entries[:max_entries]
    more = f" (+{len(entries) - len(shown)} more entries)" if len(shown) < len(entries) else ''
    lines = ["- these IP addresses and ranges, as configured (a range covers the addresses in it): "
             + ', '.join(shown) + more]
    mode = ip_hostname_mode(mode)
    if mode == 'ip_only':
        lines.append(
            "- no hostname. This project tests the addresses only and never looked up the names "
            "hosted on them. Connect by IP address; never send a hostname as the Host header or "
            "TLS SNI, and do not resolve or search for names to find more targets.")
        return '\n'.join(lines)
    if mode == 'record_only':
        lines.append(
            "- no hostname. Hostnames seen on these addresses (certificates, reverse DNS, passive "
            "DNS) are recorded in the graph as ExternalDomain nodes for reference only: they are "
            "not targets. Connect by IP address; never send a recorded hostname as the Host "
            "header or TLS SNI.")
        return '\n'.join(lines)
    names = sorted({n for n in map(normalize_name, scanned or ()) if n})
    if not names:
        lines.append(
            "- no hostname yet: no scan has selected one on these addresses. Connect by IP "
            "address; the hostnames recorded in the graph (ExternalDomain nodes) are not "
            "targets: never send one as the Host header or TLS SNI.")
        return '\n'.join(lines)
    listed = names[:max_names]
    count = (f"{len(names)} in total, the first {len(listed)} shown" if len(listed) < len(names)
             else f"{len(names)} in total")
    lines.append(f"- these hostnames, which resolved only to the addresses above at the last scan "
                 f"({count}): " + ', '.join(listed))
    lines.append(
        "  DNS can change: before using one, re-check it with `dig +short A <name>` and "
        "`dig +short AAAA <name>`, and use it only while every address it returns is listed "
        "above; if any address is elsewhere, do not use it. Any other hostname, including the "
        "ExternalDomain nodes recorded in the graph, is not a target: never send it as the Host "
        "header or TLS SNI.")
    return '\n'.join(lines)
