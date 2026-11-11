"""Shared spine piece 1 — the target loader (§6.1).

Reads the AI surface that recon annotated and renders the §2 selectors. Each
tool declares its `applies_to` interface-type filter; the loader applies it. No
tool reimplements node selection.

The request shape comes from recon automatically (§2.3): each Endpoint already
carries ai_interface_type / ai_model_family_guess / ai_supports_* so the attack
tools are pre-configured from the graph.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# The image COPYs recon_settings (the spawn mounts none): the one hostname rule
# and guardrail copy every service shares.
from recon_settings.hard_guardrail import is_hard_blocked
from recon_settings.ip_hostnames import TargetSet, address_verdict, canonical_ip, matches, parse_entries

logger = logging.getLogger("ai-attack-surface")


# Attack-type -> applicable Endpoint.ai_interface_type values (§2.1).
INTERFACE_FILTERS: dict[str, list[str]] = {
    "llm-chat": ["llm-chat"],
    "llm-chat-completion": ["llm-chat", "llm-completion"],
    "llm-tool-call": ["llm-tool-call"],
    "mcp": ["mcp"],
}

# The chat surface the four core tools attack (§2.2). recon stamps EVERY crawled
# endpoint with an ai_interface_type, using the literal 'non-llm' sentinel for
# non-LLM endpoints — so "IS NOT NULL" is NOT a safe selector. The headless
# (no-explicit-selection) path defaults to these attackable types; non-chat
# tools (future RAG/tool-call cards) pass their own interface_types.
ATTACK_SURFACE_INTERFACE_TYPES: list[str] = ["llm-chat", "llm-completion"]
# Sentinel recon writes for classified-but-not-LLM endpoints — never attackable.
NON_LLM_SENTINEL = "non-llm"


@dataclass
class Target:
    """A selected attack target, enriched from recon annotations."""
    baseurl: str
    path: str
    method: str = "POST"
    ai_interface_type: str | None = None
    ai_model_family_guess: str | None = None
    ai_model_ids: list | None = None
    ai_supports_tools: bool | None = None
    ai_supports_streaming: bool | None = None

    @property
    def url(self) -> str:
        base = (self.baseurl or "").rstrip("/")
        path = self.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"


_RETURN = """
    e.baseurl AS baseurl, e.path AS path,
    coalesce(e.method, 'POST') AS method,
    e.ai_interface_type AS ai_interface_type,
    e.ai_model_family_guess AS ai_model_family_guess,
    e.ai_model_ids AS ai_model_ids,
    e.ai_supports_tools AS ai_supports_tools,
    e.ai_supports_streaming AS ai_supports_streaming
"""


def _row_to_target(row) -> Target:
    return Target(
        baseurl=row.get("baseurl") or "",
        path=row.get("path") or "/",
        method=row.get("method") or "POST",
        ai_interface_type=row.get("ai_interface_type"),
        ai_model_family_guess=row.get("ai_model_family_guess"),
        ai_model_ids=row.get("ai_model_ids"),
        ai_supports_tools=row.get("ai_supports_tools"),
        ai_supports_streaming=row.get("ai_supports_streaming"),
    )


def load_targets(
    session,
    user_id: str,
    project_id: str,
    interface_types: list[str] | None = None,
    selected: list[dict] | None = None,
    scope: "IpModeScope | None" = None,
) -> list[Target]:
    """Load attack targets from the graph.

    - `selected`: explicit picker rows ({baseurl, path, method}); each is matched
      to its Endpoint and enriched. This is the normal UI path (the user must
      explicitly select which nodes to attack, §2).
    - else: load every attackable chat Endpoint. `interface_types` narrows it;
      when omitted it defaults to the chat surface (NOT "any ai_interface_type"
      — recon stamps every crawled endpoint, mostly with the 'non-llm' sentinel).
    - `scope` (an IP-mode project, see ip_mode_scope): every target, a typed
      custom one included, must pass it; the refused ones are listed.
    """
    if selected:
        targets = _load_selected(session, user_id, project_id, selected)
    else:
        if interface_types is None:
            interface_types = ATTACK_SURFACE_INTERFACE_TYPES
        targets = _load_all_ai(session, user_id, project_id, interface_types)
    if scope is None:
        return targets
    admitted = []
    for target in targets:
        reason = scope.refusal(target)
        if reason is None:
            admitted.append(target)
        else:
            print(f"    [-] refused {target.url}: {reason}")
    logger.info(f"Target loader: {len(admitted)} of {len(targets)} target(s) in the IP-mode scope")
    return admitted


# ---------------------------------------------------------------------------
# IP mode (design §11): the project's addresses, and the hostnames its
# selection rule scanned that its current policy still admits
# ---------------------------------------------------------------------------

class ScopeRefused(Exception):
    """The run cannot tell what its targets are: nothing is attacked."""


_NOT_SCANNED = "not a hostname this project scans"
_ROE = "excluded by the rules of engagement"

_IP_MODE_ROOT = """
MATCH (d:Domain {user_id: $uid, project_id: $pid})
WHERE d.is_mock = true AND d.ip_mode = true
RETURN count(d) AS n
"""

# Only the selection's own names, and only those the last run left scanned:
# an out_of_policy name (a narrowing) is not one, and a recorded name is an
# ExternalDomain, never read here.
_SCANNED_NAMES = """
MATCH (s:Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})
WHERE s.ip_hostname_reason = 'scanned'
RETURN s.name AS name
"""


def _host(value: str) -> str:
    try:
        return (urlsplit(value or "").hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


# A copy of recon/helpers/roe_scope.py's RoE matcher (_is_roe_excluded and its
# normalizers), line for line: this image carries no recon/, and the start route
# hands the project's raw roeExcludedHosts, so this is the scanner's only RoE
# check. Pinned to recon/tests/fixtures/roe_exclusion_vectors.json by
# tests/test_roe_exclusion_vectors.py (drift map: "RoE exclusion matching").

def _roe_excluded(host, excluded_list) -> bool:
    """True when ``host`` matches an RoE exclusion: an exact host or IP; a
    domain, which also excludes its subdomains; ``*.domain``, its subdomains
    only; or a CIDR. Case, port, scheme, path and a trailing dot are ignored on
    both sides, and an IPv6 address matches in any spelling."""
    host = _roe_host(host)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for value in excluded_list or ():
        entry = _roe_entry(value)
        if not entry:
            continue
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif "/" in entry or address is not None:
            try:
                if address is not None and address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        elif host == entry or host.endswith("." + entry):
            return True
    return False


def _roe_host(host) -> str:
    if not isinstance(host, str):
        return ""
    host = host.strip()
    if "://" in host:
        host = _roe_url_hostname(host)
    elif host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.strip().rstrip(".").lower()


def _roe_url_hostname(url: str) -> str:
    # urlsplit raises on an unbalanced or non-IP bracket; one such entry must
    # not abort the whole check.
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _roe_is_network(entry: str) -> bool:
    head, _, tail = entry.partition("/")
    try:
        ipaddress.ip_address(head)
    except ValueError:
        return False
    if tail.isascii() and tail.isdigit():
        return True
    try:
        ipaddress.IPv4Address(tail)
        return True
    except ValueError:
        return False


def _roe_entry_host(entry: str) -> str:
    head = entry.split("/", 1)[0]
    try:
        # A bare IPv6 has colons urlsplit would read as a port.
        ipaddress.ip_address(head)
        return head.lower()
    except ValueError:
        return _roe_host(_roe_url_hostname("//" + entry))


def _roe_entry(entry) -> str:
    if not isinstance(entry, str):
        return ""
    entry = entry.strip()
    if entry.startswith("*."):
        rest = entry[2:]
        return "*." + (_roe_entry_host(rest) if "/" in rest and "://" not in rest else _roe_host(rest))
    if "/" in entry and "://" not in entry:
        return entry.lower() if _roe_is_network(entry) else _roe_entry_host(entry)
    return _roe_host(entry)


def _resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return sorted({canonical_ip(info[4][0].split("%")[0]) for info in infos})


class IpModeScope:
    """Whether one attack target is the project's to attack (I-1, I-4)."""

    def __init__(self, cfg, scanned_names):
        self.excluded = list(cfg.roe_excluded_hosts or [])
        self.targets = TargetSet.from_entries(cfg.target_ips)
        self.names = self._admitted(cfg, {str(n).lower() for n in scanned_names if n})

    @staticmethod
    def _admitted(cfg, names: set) -> set:
        """The scanned names the project's CURRENT policy admits: a narrowing,
        a restored Scan Timeline version or a failed out_of_policy marker can
        leave a name the policy no longer wants marked scanned."""
        if cfg.ip_hostname_mode == "scan_all":
            return names
        if cfg.ip_hostname_mode != "record_filter":
            return set()
        if cfg.ip_hostname_include is None or cfg.ip_hostname_exclude is None:
            return set()
        include, bad_include = parse_entries(cfg.ip_hostname_include)
        exclude, bad_exclude = parse_entries(cfg.ip_hostname_exclude)
        if bad_include or bad_exclude:
            return set()
        return {n for n in names if matches(n, include, exclude).included}

    def _address_refusal(self, address: str) -> str | None:
        if _roe_excluded(address, self.excluded):
            return _ROE
        return None if address in self.targets else "outside the target IPs"

    def refusal(self, target: Target) -> str | None:
        """None when the target may be attacked, else why not."""
        host = _host(target.baseurl)
        if not host:
            return "no host"
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return self._address_refusal(host)
        if host not in self.names:
            return _NOT_SCANNED
        if _roe_excluded(host, self.excluded):
            return _ROE
        if is_hard_blocked(host)[0] is not False:
            return "a protected government or public domain"
        try:
            answer = _resolve(host)
        except (OSError, UnicodeError):
            answer = []
        verdict = address_verdict(answer, self.targets)
        if verdict is not None:
            return verdict
        return next((r for r in map(self._address_refusal, answer) if r), None)


def ip_mode_scope(session, cfg) -> IpModeScope | None:
    """The IP-mode scope of this run, or None for a domain-mode project.

    The run config says (the start route copies the project row); a config
    that does not, for a project whose graph is IP mode, is refused rather
    than run unscoped (I-6), and so is an IP-mode one without targets.
    """
    if cfg.ip_mode is None:
        row = session.run(_IP_MODE_ROOT, uid=cfg.user_id, pid=cfg.project_id).single()
        count = row.get("n") if row else 0
        if not isinstance(count, int) or count > 0:
            raise ScopeRefused("the project is in IP mode (or the graph cannot say) and the run config "
                               "carries no IP-mode scope")
        return None
    if cfg.ip_mode is not True:
        return None
    if not cfg.target_ips:
        raise ScopeRefused("an IP-mode run config without target IPs")
    rows = session.run(_SCANNED_NAMES, uid=cfg.user_id, pid=cfg.project_id)
    return IpModeScope(cfg, [r.get("name") for r in rows])


def _load_all_ai(session, user_id, project_id, interface_types) -> list[Target]:
    cypher = f"""
        MATCH (e:Endpoint {{user_id: $uid, project_id: $pid}})
        WHERE e.ai_interface_type IN $ifaces
          AND e.ai_interface_type <> $non_llm
        RETURN {_RETURN}
    """
    rows = session.run(cypher, uid=user_id, pid=project_id,
                       ifaces=interface_types, non_llm=NON_LLM_SENTINEL)
    targets = [_row_to_target(r.data()) for r in rows]
    logger.info(f"Target loader: {len(targets)} AI endpoint(s) (filter={interface_types})")
    return targets


def _load_selected(session, user_id, project_id, selected) -> list[Target]:
    targets: list[Target] = []
    for sel in selected:
        baseurl = sel.get("baseurl")
        path = sel.get("path") or "/"
        method = sel.get("method")
        if not baseurl:
            logger.warning(f"Skipping selection without baseurl: {sel}")
            continue
        cypher = f"""
            MATCH (e:Endpoint {{baseurl: $baseurl, user_id: $uid, project_id: $pid}})
            WHERE e.path = $path AND ($method IS NULL OR coalesce(e.method,'POST') = $method)
            // Prefer the AI-typed endpoint over a bare sibling on the same path.
            WITH e ORDER BY (CASE WHEN e.ai_interface_type IS NOT NULL THEN 0 ELSE 1 END) LIMIT 1
            RETURN {_RETURN}
        """
        row = session.run(
            cypher, baseurl=baseurl, path=path, method=method,
            uid=user_id, pid=project_id,
        ).single()
        if row:
            targets.append(_row_to_target(row.data()))
        else:
            # Not in the graph: either a custom URL the operator typed, or a
            # selection the graph lost. Build a placeholder from the raw
            # selection, carrying any interface_type/model the operator supplied
            # for a custom target (so the request shape can still be inferred).
            model = sel.get("model")
            model_ids = [model] if model else None
            if sel.get("custom"):
                logger.info(f"Custom (off-graph) target: {baseurl}{path}")
            else:
                logger.warning(f"Selected endpoint not found in graph: {baseurl} {path}")
            targets.append(Target(
                baseurl=baseurl, path=path, method=method or "POST",
                ai_interface_type=sel.get("interface_type"),
                ai_model_ids=model_ids,
            ))
    logger.info(f"Target loader: {len(targets)} selected endpoint(s)")
    return targets
