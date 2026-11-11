"""
RedAmon - IP attribution
========================
Labels every IP of the run once, so the scanners that ask "does this IP belong
to the target?" read one answer instead of guessing on their own:

  shared_edge  a CDN edge serving many tenants: a published edge prefix, an
               edge-only CDN a scanner named, an edge's response header, or an
               edge-only ASN whose default certificate is not the target's
  dedicated    the certificate it presents without SNI covers a target domain
  unknown      neither can be shown

Never "not ours": a real server on a cloud provider has a generic PTR and the
cloud's whois, so a missing signal proves nothing.

The signals are the ones the run already holds (naabu, tlsx and httpx CDN
flags, httpx's ASN and headers, this run's DNS block) plus one active check: a
TLS handshake WITHOUT SNI to :443, only where 443 was found open. That handshake
is traffic to the target: it skips RoE-excluded addresses, loopback and
link-local ones (cloud metadata) and hosts marked down, is paced at the
engagement rate ceiling, is capped per run (IP_ATTRIBUTION_TLS_MAX_PROBES, 0 in
stealth mode), and a failed one is never evidence: the tag falls back to the
other signals and the reasons say the certificate was not checked.

The step writes no finding, so it has nothing for the prune to keep. It never
raises and never blocks the run: on a failure an IP is tagged unknown with the
reason.
"""

from __future__ import annotations

import copy
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from urllib.parse import urlparse

from recon.helpers.cdn_ranges import EDGE_REASON_ASN, classify_ip, is_reliable_edge_cdn_name
from recon.helpers.peer_cert import cert_covers, cert_names, tls_failure_reason, tls_handshake_cert
from recon.helpers.public_suffix import org_domain
from recon.helpers.recon_scope import recon_scope
from recon.helpers.roe_scope import _is_roe_excluded
from recon.helpers.target_admission import clamp_to_targets
from recon.main_recon_modules.ip_filter import is_never_scannable_ip

SHARED_EDGE = "shared_edge"
DEDICATED = "dedicated"
UNKNOWN = "unknown"

CERT_TARGET = "target"
CERT_FOREIGN = "foreign"
CERT_NOT_CHECKED = "not_checked"

NO_EDGE_SIGNAL = "no CDN or edge signal"
ATTRIBUTION_FAILED = "attribution failed"

TLS_PORT = 443
DEFAULT_TLS_MAX_PROBES = 500
_TLS_TIMEOUT_S = 5
_TLS_WORKERS = 8
# The step's own pace; the engagement ceiling can only lower it.
_TLS_RPS = 10.0


def _print(symbol: str, msg: str) -> None:
    print(f"[{symbol}][IpAttribution] {msg}")


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------
def cert_reason(status: str, detail: str = "") -> str:
    if status == CERT_TARGET:
        return f"default certificate covers {detail or 'a target domain'}"
    if status == CERT_FOREIGN:
        return "default certificate covers no target domain"
    return f"default certificate not checked ({detail})" if detail else "default certificate not checked"


def ownership_tag(edge_reasons: list, cert_status: str, cert_detail: str = "") -> tuple[str, list]:
    """(tag, sorted reasons) for one IP. Pure.

    ``edge_reasons`` is classify_ip's list (empty: no CDN signal). An edge-only
    ASN is the one signal a certificate can overrule: a CDN can give a customer
    a dedicated edge that answers with the customer's own certificate.
    """
    asn_only = list(edge_reasons) == [EDGE_REASON_ASN]
    if edge_reasons and not (asn_only and cert_status == CERT_TARGET):
        tag = SHARED_EDGE
    elif cert_status == CERT_TARGET:
        tag = DEDICATED
    else:
        tag = UNKNOWN
    reasons = set(edge_reasons or [NO_EDGE_SIGNAL])
    reasons.add(cert_reason(cert_status, cert_detail))
    return tag, sorted(reasons)


# ---------------------------------------------------------------------------
# What the run already holds
# ---------------------------------------------------------------------------
def _is_address(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _header_map(headers) -> Optional[dict]:
    """httpx stores headers as a dict, or sometimes as one CRLF-joined string."""
    if isinstance(headers, dict):
        return headers
    if isinstance(headers, str):
        pairs = (line.split(":", 1) for line in headers.splitlines() if ":" in line)
        return {k.strip(): v.strip() for k, v in pairs}
    return None


def _signals(combined_result: dict) -> dict:
    """{ip: {cdn_names, asn, headers}} from the port scan (naabu, tlsx) and httpx."""
    out: dict = {}

    def entry(ip):
        return out.setdefault(ip, {"cdn_names": [], "asn": None, "headers": []})

    def flag(e, info):
        if info.get("is_cdn") and info.get("cdn"):
            e["cdn_names"].append(info["cdn"])

    port_scan = combined_result.get("port_scan") or {}
    for ip, info in (port_scan.get("by_ip") or {}).items():
        if ip and isinstance(info, dict):
            e = entry(ip)
            flag(e, info)
            e["asn"] = e["asn"] or info.get("asn")
    for info in (port_scan.get("by_host") or {}).values():
        if isinstance(info, dict) and info.get("ip"):
            flag(entry(info["ip"]), info)
    for info in ((combined_result.get("http_probe") or {}).get("by_url") or {}).values():
        if isinstance(info, dict) and info.get("ip"):
            e = entry(info["ip"])
            flag(e, info)
            e["asn"] = e["asn"] or info.get("asn")
            headers = _header_map(info.get("headers"))
            if headers:
                e["headers"].append(headers)
    return out


def _dns_rows(combined_result: dict):
    dns = combined_result.get("dns") or {}
    yield combined_result.get("domain"), dns.get("domain")
    yield from (dns.get("subdomains") or {}).items()


def _entry_ips(entry: dict) -> list:
    ips = entry.get("ips") or {}
    return list(ips.get("ipv4") or []) + list(ips.get("ipv6") or [])


def current_dns_names(combined_result: dict) -> dict:
    """{ip: how many names in THIS run's DNS block resolve to it}.

    In memory, not the graph's RESOLVES_TO edges, which a passive source can
    write for a name that no longer points there. An IP-mode placeholder (a
    target with no PTR) is no DNS name.
    """
    names: dict = {}
    for name, entry in _dns_rows(combined_result):
        if not name or not isinstance(entry, dict) or entry.get("is_mock"):
            continue
        for ip in _entry_ips(entry):
            names.setdefault(ip, set()).add(str(name).strip(".").lower())
    return {ip: len(n) for ip, n in names.items()}


def _run_ips(combined_result: dict, signals: dict) -> list:
    ips = set(signals)
    for _name, entry in _dns_rows(combined_result):
        if isinstance(entry, dict):
            ips.update(_entry_ips(entry))
    ips.update((combined_result.get("metadata") or {}).get("expanded_ips") or [])
    # IP mode: a DNS answer or a signal on an address outside the target list
    # is never attributed; the attribution's no-SNI handshake would reach it.
    return sorted(clamp_to_targets(combined_result, (ip for ip in ips if ip and _is_address(ip))))


def _tls_open(combined_result: dict) -> set:
    """IPs where this run found :443 open: the port scan, or an https URL httpx reached."""
    def has_tls(ports) -> bool:
        for port in ports or []:
            try:
                if int(port) == TLS_PORT:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    out = set()
    port_scan = combined_result.get("port_scan") or {}
    for ip, info in (port_scan.get("by_ip") or {}).items():
        if isinstance(info, dict) and has_tls(info.get("ports")):
            out.add(ip)
    for info in (port_scan.get("by_host") or {}).values():
        if isinstance(info, dict) and info.get("ip") and has_tls(info.get("ports")):
            out.add(info["ip"])
    for url, info in ((combined_result.get("http_probe") or {}).get("by_url") or {}).items():
        if not isinstance(info, dict) or not info.get("ip"):
            continue
        try:
            parsed = urlparse(str(url))
            port = parsed.port or (TLS_PORT if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        if parsed.scheme == "https" and port == TLS_PORT:
            out.add(info["ip"])
    return out


def _target_domains(combined_result: dict) -> list:
    """The registrable domains a default certificate must cover to be the target's.
    IP mode has none: its targets are addresses."""
    if recon_scope(combined_result).ip_mode:
        return []
    roots = (combined_result.get("all_project_roots") or combined_result.get("domains")
             or [combined_result.get("domain")])
    out = set()
    for root in roots if isinstance(roots, list) else []:
        root = str(root or "").strip().strip(".").lower()
        if root:
            out.add(org_domain(root) or root)
    return sorted(out)


# ---------------------------------------------------------------------------
# The handshake
# ---------------------------------------------------------------------------
def pace_rps(settings: dict) -> float:
    """The step's pace, lowered to the engagement ceiling when one is set."""
    rps = _TLS_RPS
    if settings.get("ROE_ENABLED"):
        try:
            ceiling = float(settings.get("ROE_GLOBAL_MAX_RPS") or 0)
        except (TypeError, ValueError):
            ceiling = 0.0
        if ceiling > 0:
            rps = min(rps, ceiling)
    return rps


class _Pacer:
    def __init__(self, rps: float):
        self._interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self._interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self._interval
        if start > now:
            time.sleep(start - now)


def _max_probes(settings: dict) -> int:
    try:
        return max(0, int(settings.get("IP_ATTRIBUTION_TLS_MAX_PROBES", DEFAULT_TLS_MAX_PROBES)))
    except (TypeError, ValueError):
        return DEFAULT_TLS_MAX_PROBES


def _probe_plan(ips: list, tls_open: set, settings: dict) -> tuple[list, dict]:
    """(IPs to dial, {ip: why its certificate is not checked}). Deterministic.

    Stealth and a zero cap come first: no handshake would have been made
    anywhere, and stealth's passive port scan cannot say 443 is closed.
    """
    stealth = bool(settings.get("STEALTH_MODE"))
    cap = _max_probes(settings)
    excluded = settings.get("ROE_EXCLUDED_HOSTS") or [] if settings.get("ROE_ENABLED") else []
    to_probe: list = []
    skipped: dict = {}
    for ip in ips:
        if stealth:
            skipped[ip] = "stealth mode"
        elif cap <= 0:
            skipped[ip] = "the TLS probe is off"
        elif ip not in tls_open:
            skipped[ip] = f"port {TLS_PORT} not found open"
        elif excluded and _is_roe_excluded(ip, excluded):
            skipped[ip] = "excluded by the rules of engagement"
        elif is_never_scannable_ip(ip):
            skipped[ip] = "address never scanned"
        elif len(to_probe) >= cap:
            skipped[ip] = "probe cap reached"
        else:
            to_probe.append(ip)
    return to_probe, skipped


def _default_cert(ip: str, domains: list, pacer: _Pacer) -> tuple[str, str, list]:
    """(status, detail, certificate names) for the certificate ``ip`` presents
    to a client that sends no SNI."""
    from recon.helpers import circuit_breaker as cb
    target = f"https://[{ip}]:{TLS_PORT}" if ":" in ip else f"https://{ip}:{TLS_PORT}"
    if not cb.host_health.allow(target):
        return CERT_NOT_CHECKED, "host marked unreachable", []
    pacer.wait()
    try:
        cert = tls_handshake_cert(ip, None, TLS_PORT, _TLS_TIMEOUT_S)
    except (OSError, ValueError) as e:
        cb.host_health.record_failure(target, e)
        return CERT_NOT_CHECKED, tls_failure_reason(e, TLS_PORT), []
    cb.host_health.record_alive(target)
    names = cert_names(cert)
    if not names:
        return CERT_NOT_CHECKED, "no certificate presented", []
    covered = next((d for d in domains if cert_covers(cert, d)), None)
    return (CERT_TARGET, covered, names) if covered else (CERT_FOREIGN, "", names)


def _probe_all(to_probe: list, domains: list, settings: dict) -> dict:
    pacer = _Pacer(pace_rps(settings))

    def one(ip):
        try:
            return ip, _default_cert(ip, domains, pacer)
        except Exception:  # noqa: BLE001 - an unexpected dial error is a missing signal
            return ip, (CERT_NOT_CHECKED, "connection failed", [])

    if not to_probe:
        return {}
    with ThreadPoolExecutor(max_workers=min(_TLS_WORKERS, len(to_probe)),
                            thread_name_prefix="ip-attr") as pool:
        return dict(pool.map(one, to_probe))


# ---------------------------------------------------------------------------
# The step
# ---------------------------------------------------------------------------
def _attribute(ip: str, signal: Optional[dict], cert: tuple, dns_count: int) -> dict:
    signal = signal or {}
    name = next((n for n in signal.get("cdn_names", []) if is_reliable_edge_cdn_name(n)), None)
    headers = next((h for h in signal.get("headers", []) if classify_ip(None, headers=h)[0]), None)
    _is_edge, provider, edge_reasons = classify_ip(ip, asn=signal.get("asn"), headers=headers,
                                                   cdn_name=name)
    status, detail, names = cert
    tag, reasons = ownership_tag(edge_reasons, status, detail)
    entry = {"ownership": tag, "ownership_reasons": reasons, "current_dns_names": dns_count}
    if tag == SHARED_EDGE and provider:
        entry["cdn_name"] = provider
    if names:
        entry["default_cert_names"] = names
    return entry


def _failed() -> dict:
    return {"ownership": UNKNOWN, "ownership_reasons": [ATTRIBUTION_FAILED]}


def run_ip_attribution(combined_result: dict, settings: Optional[dict] = None) -> dict:
    """Tag every IP of the run. Writes combined_result["ip_attribution"] and
    returns combined_result. Never raises."""
    settings = settings or {}
    if not settings.get("IP_ATTRIBUTION_ENABLED", True):
        _print("-", "Disabled via settings -- skipping")
        return combined_result

    print(f"\n[*][IpAttribution] Labelling IPs: shared edge / dedicated / unknown")
    by_ip: dict = {}
    ips: list = []
    handshakes = 0
    try:
        signals = _signals(combined_result)
        dns_names = current_dns_names(combined_result)
        ips = _run_ips(combined_result, signals)
        domains = _target_domains(combined_result)
        to_probe, skipped = _probe_plan(ips, _tls_open(combined_result), settings)
        certs = _probe_all(to_probe, domains, settings)
        handshakes = len(certs)
        for ip in ips:
            cert = certs.get(ip) or (CERT_NOT_CHECKED, skipped.get(ip, ""), [])
            try:
                by_ip[ip] = _attribute(ip, signals.get(ip), cert, dns_names.get(ip, 0))
            except Exception:  # noqa: BLE001 - one bad IP is tagged unknown, never the run
                by_ip[ip] = _failed()
    except Exception as e:  # noqa: BLE001 - the step never blocks the run
        _print("!", f"attribution failed ({type(e).__name__}); its IPs are tagged unknown")
        for ip in ips:
            by_ip.setdefault(ip, _failed())

    summary = {"ips": len(by_ip), SHARED_EDGE: 0, DEDICATED: 0, UNKNOWN: 0,
               "tls_handshakes": handshakes}
    for entry in by_ip.values():
        summary[entry["ownership"]] += 1
    combined_result["ip_attribution"] = {
        "by_ip": by_ip,
        "summary": summary,
        "scan_metadata": {"tls_port": TLS_PORT, "tls_max_probes": _max_probes(settings),
                          "stealth_mode": bool(settings.get("STEALTH_MODE"))},
    }
    stealth = " (stealth mode: none)" if settings.get("STEALTH_MODE") else ""
    _print("+", f"{summary['ips']} IP(s): {summary[SHARED_EDGE]} shared edge, "
                f"{summary[DEDICATED]} dedicated, {summary[UNKNOWN]} unknown; "
                f"{handshakes} TLS handshake(s) without SNI{stealth}")
    return combined_result


def run_ip_attribution_isolated(combined_result: dict, settings: Optional[dict] = None) -> dict:
    """Thread-safe: does not mutate combined_result. Returns only the payload."""
    snapshot = copy.deepcopy(combined_result)
    run_ip_attribution(snapshot, settings)
    return snapshot.get("ip_attribution", {})


def shared_edge_ips(combined_result: dict) -> set:
    """The IPs tagged shared_edge: by this run, or read from the graph in a partial run."""
    by_ip = ((combined_result or {}).get("ip_attribution") or {}).get("by_ip") or {}
    return {ip for ip, entry in by_ip.items()
            if isinstance(entry, dict) and entry.get("ownership") == SHARED_EDGE}
