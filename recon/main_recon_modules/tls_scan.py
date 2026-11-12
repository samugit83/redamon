"""tlsx TLS certificate grab (GROUP 3.6).

Runs one TLS handshake per already-open, non-HTTP port and captures the
certificate + posture, filling the gap httpx leaves (httpx only grabs certs on
the 5 HTTPS ports it dials). Runs BEFORE http_probe so SAN-derived hostnames
become probe targets, and before vhost so it can feed SNI candidates.

tlsx is a compiled Go binary run as a sibling container through the broker
socket, matching every other ProjectDiscovery tool in the pipeline.

Contract (recon-tool-integration):
  - top-level result key is exactly ``combined_result["tlsx"]``,
  - ``run_tlsx_enrichment_isolated`` is the deep-copy test / fan-out call path,
  - never raises: records ``metadata.phase_errors["tlsx"]`` instead,
  - a target a failed run (timeout, missing runner, exit, crash) never
    answered keeps its security_check findings (``_note_unchecked``),
  - every ``print`` is ``[symbol][Tlsx] message``.
"""

import copy
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

# HTTP/HTTPS ports httpx already grabs certs on (http_probe.py). tlsx excludes
# these by default so we never pay a second handshake for zero new fields.
_HTTPS_PORTS = {443, 8443, 4443, 9443, 8843}
_HTTP_PORTS = {80, 8080, 8000, 8888, 8008, 3000, 5000, 9000}

# Service hint per well-known TLS port (advisory only; never renames a Service).
_TLS_SERVICE_HINTS = {
    993: "imaps", 995: "pop3s", 465: "smtps", 636: "ldaps", 990: "ftps",
    5671: "amqps", 8883: "mqtts", 2376: "docker-tls", 6443: "kubernetes-api",
    989: "ftps-data", 5061: "sips", 6697: "ircs-tls", 8443: "https-alt",
}


def _print(symbol: str, msg: str) -> None:
    print(f"[{symbol}][Tlsx] {msg}")


def _coerce_port(value):
    """Parse a port (tlsx emits it as a string). Returns int, or None."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _is_mock_hostname(hostname: str, ip: str) -> bool:
    """``ip``'s IP-mode label (ip_placeholders.is_placeholder), under its old name.

    H8: a partial run reads the label ("192-88-98-10") back out of the graph as
    a hostname; handed to tlsx as SNI it never resolves, and the run stamped
    tls_probe_failed over the enrichment a full scan had written.
    """
    # Lazy, as every recon.helpers import here: the package init is heavy.
    from recon.helpers.ip_placeholders import is_placeholder
    return is_placeholder(hostname, ip)


def _strip_wildcard(name: str) -> str:
    return name.strip().lower().lstrip("*.")


def _host_matches_cert(host: str, names: list) -> bool:
    """One level of wildcard matching, mirroring TLS name-check semantics."""
    if not host:
        return True  # nothing submitted to check (bare IP): not a mismatch
    host = host.strip().lower().rstrip(".")
    for raw in names:
        if not raw:
            continue
        name = raw.strip().lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            # a single wildcard label: foo.example.com matches *.example.com,
            # but bar.foo.example.com does not.
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0:
                return True
    return False


def _hostnames_by_ip(combined_result: dict) -> dict:
    """{ip: {hostname, ...}}: every real name port_scan resolved to each IP."""
    by_ip = ((combined_result.get("port_scan") or {}).get("by_ip")) or {}
    out = {}
    for ip, info in by_ip.items():
        if not ip or not isinstance(info, dict):
            continue
        names = {h.strip().lower().rstrip(".") for h in (info.get("hostnames") or [])
                 if isinstance(h, str) and h.strip()}
        names = {h for h in names if not _is_mock_hostname(h, ip)}
        if names:
            out[ip] = names
    return out


def _siblings_the_cert_names(submitted: str, cert_names: list, siblings) -> list:
    """The OTHER hostnames resolving to the same IP that the cert is valid for, sorted."""
    submitted = (submitted or "").strip().lower().rstrip(".")
    return sorted(name for name in (siblings or ())
                  if name and name != submitted and _host_matches_cert(name, cert_names))


def build_tlsx_command(targets_file: str, targets_dir: str, settings: dict,
                       container_name: str = None) -> list:
    """Build the ``docker run`` argv for tlsx.

    Only the base grab (``-json -silent -duc -tps -se -hash sha256``) is
    unconditional. The loud probes (JARM/JA3, version/cipher enum) are flag
    gated. The output *filters* (-ex/-ss/-mm/-re/-un) are NEVER passed: they
    would silently drop every healthy host from the scan.

    ``container_name``: the name the run timeout kills the container by.
    """
    settings = settings or {}
    image = settings.get("TLSX_DOCKER_IMAGE", "projectdiscovery/tlsx:latest")
    concurrency = int(settings.get("TLSX_CONCURRENCY", 50))
    timeout = int(settings.get("TLSX_TIMEOUT", 5))
    retries = int(settings.get("TLSX_RETRIES", 1))

    cmd = ["docker", "run", "--rm", "--net=host"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "-v", f"{targets_dir}:{targets_dir}:ro",
        image,
        "-l", targets_file,
        "-json", "-silent", "-duc",
        "-tps", "-se", "-hash", "sha256",
        "-c", str(concurrency),
        "-timeout", str(timeout),
        "-retry", str(retries),
    ]

    scan_mode = settings.get("TLSX_SCAN_MODE", "auto")
    if scan_mode and scan_mode != "auto":
        cmd += ["-sm", scan_mode]
    if settings.get("TLSX_PROBE_JARM"):
        cmd += ["-jarm", "-ja3"]
    if settings.get("TLSX_VERSION_ENUM"):
        cmd += ["-ve"]
    if settings.get("TLSX_CIPHER_ENUM"):
        cmd += ["-ce", "-ct", "weak", "-cec", str(int(settings.get("TLSX_CIPHER_CONCURRENCY", 10)))]
    if settings.get("TLSX_REV_PTR_SNI"):
        cmd += ["-rps"]
    delay = settings.get("TLSX_DELAY")
    if delay:
        cmd += ["-delay", str(delay)]
    # Resolve as the DNS step did (recon/helpers/system_resolvers.py).
    from recon.helpers.system_resolvers import resolver_args
    cmd += resolver_args()
    return cmd


def _target_line(host: str, port: int) -> str:
    """Format one tlsx target line.

    An IPv6 literal MUST be bracketed: "2001:db8::1:993" is ambiguous (is the
    last group a port or an address group?) and tlsx cannot parse it, so IPv6
    hosts were silently never scanned.
    """
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _build_tlsx_targets(combined_result: dict, settings: dict):
    """Return (target_lines, meta) from port_scan.by_ip.

    meta maps ``"submitted:port" -> scanned_ip`` so the parser keys by_target on
    the IP the target line was BUILT from, never the ``ip`` tlsx returns (they
    differ when a hostname has several A records). Sends a hostname whenever an
    admitted one is known so tlsx presents SNI and grabs the right cert on a
    vhost frontend.
    """
    # Lazy imports: recon.helpers.__init__ pulls heavy deps not needed here.
    from recon.main_recon_modules.ip_filter import is_non_routable_ip
    from recon.helpers.roe_scope import _is_roe_excluded

    settings = settings or {}
    include_http = bool(settings.get("TLSX_INCLUDE_HTTP_PORTS", False))
    max_hostnames = int(settings.get("TLSX_MAX_HOSTNAMES_PER_IP", 1))
    max_targets = int(settings.get("TLSX_MAX_TARGETS", 2000))
    roe_enabled = bool(settings.get("ROE_ENABLED", False))
    roe_list = settings.get("ROE_EXCLUDED_HOSTS", []) if roe_enabled else []

    excluded_ports = set() if include_http else (_HTTPS_PORTS | _HTTP_PORTS)

    # A cap of 0 means scan nothing. The check below fires only after a target
    # has been appended, so without this an explicit 0 still sent one handshake.
    if max_targets <= 0:
        _print("-", "TLSX_MAX_TARGETS is 0; no targets will be scanned")
        return [], {}

    by_ip = ((combined_result.get("port_scan") or {}).get("by_ip")) or {}
    # IP mode: an address is handshaken only when it is a target, and then even
    # when it is private (D-13: an internal engagement lists private targets).
    from recon.helpers.target_admission import (admission_context, admit_targets, ip_mode_targets,
                                                is_target, known_addresses)
    targets = ip_mode_targets(combined_result)
    sni_admitted = None
    # tlsx resolves an SNI name itself and may land on any address the name
    # has, not the one the line was built from. So a name is sent only when
    # every address it has may be reached: in IP mode every one a target;
    # under RoE IP or CIDR entries none excluded (D2). A refused name's
    # address is handshaken as a bare IP. Asked once for every name, not once
    # per address.
    if targets is not None or admission_context(settings, combined_result).ip_rules:
        known = known_addresses(combined_result)
        names = {h.strip().lower() for info in by_ip.values() if isinstance(info, dict)
                 for h in (info.get("hostnames") or []) if isinstance(h, str) and h.strip()}
        # IP mode reads the target list from the recon dict, and its refusals
        # are decisions, never coverage gaps; an RoE refusal is noted.
        sni_admitted = set(admit_targets(None if targets is not None else settings, combined_result,
                                         names={h: known.get(h, []) for h in names},
                                         module="tlsx", resolves_names=True,
                                         record=targets is None).names)

    lines = []
    meta = {}
    seen = set()
    for ip, info in sorted(by_ip.items()):
        if not ip or not isinstance(info, dict):
            continue
        if targets is not None:
            if not is_target(ip, targets):
                continue
        elif is_non_routable_ip(ip):
            continue
        if roe_list and _is_roe_excluded(ip, roe_list):
            continue
        ports = [p for p in (info.get("ports") or []) if _coerce_port(p) is not None]
        ports = [int(p) for p in ports if int(p) not in excluded_ports]
        if not ports:
            continue
        # Deterministic hostname pick: the list order is not stable across runs.
        hostnames = sorted({h.strip().lower() for h in (info.get("hostnames") or []) if h})
        hostnames = [h for h in hostnames if not _is_mock_hostname(h, ip)]
        hostnames = [h for h in hostnames if not (roe_list and _is_roe_excluded(h, roe_list))]
        if sni_admitted is not None:
            hostnames = [h for h in hostnames if h in sni_admitted]
        submit_names = hostnames[:max_hostnames] if hostnames else [ip]
        for port in sorted(set(ports)):
            for submitted in submit_names:
                target = _target_line(submitted, port)
                if target in seen:
                    continue
                seen.add(target)
                lines.append(target)
                # Key on the SCANNED ip:port so Phase 2's Service MATCH lands.
                # tlsx echoes `host` unbracketed, so meta is keyed unbracketed.
                meta[f"{submitted}:{port}"] = ip
                if len(lines) >= max_targets:
                    _print("*", f"target cap reached ({max_targets}); truncating")
                    return lines, meta
    return lines, meta


def _parse_tlsx_output(stdout: str, meta: dict, ip_hostnames: dict | None = None) -> dict:
    """Parse tlsx JSONL into by_target keyed on the scanned ip:port.

    ``ip_hostnames`` ({ip: {hostname}}, from ``_hostnames_by_ip``) lets a
    mismatch record which other names sharing the scanned IP the cert is valid
    for (``mismatch_cert_covers_siblings``).
    """
    by_target = {}
    now = datetime.now(timezone.utc)
    for raw in (stdout or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except (ValueError, TypeError):
            continue  # one malformed line must not sink the phase
        if not isinstance(row, dict):
            continue

        submitted = row.get("host") or ""
        port = _coerce_port(row.get("port"))
        if port is None:
            continue
        scanned_ip = meta.get(f"{submitted}:{port}") or row.get("ip") or submitted
        key = f"{scanned_ip}:{port}"

        probe_status = bool(row.get("probe_status"))
        error = row.get("error")
        san = [_strip_wildcard(n) for n in _as_list(row.get("subject_an")) if n]
        raw_san = _as_list(row.get("subject_an"))
        subject_cn = row.get("subject_cn") or ""
        subject_dn = row.get("subject_dn") or ""
        issuer_dn = row.get("issuer_dn") or ""
        not_after = row.get("not_after")

        # Derive verdicts unconditionally (they are omitempty booleans in tlsx;
        # deriving removes a hidden coupling to a tlsx flag/version change).
        expired = bool(row.get("expired"))
        if not_after:
            try:
                dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                expired = expired or (dt < now)
            except (ValueError, TypeError):
                pass
        self_signed = bool(row.get("self_signed")) or (
            bool(subject_dn) and subject_dn == issuer_dn)
        # host mismatch: only meaningful when we submitted a hostname.
        submitted_is_host = bool(submitted) and submitted != scanned_ip
        covers_siblings = []
        if submitted_is_host:
            names = ([subject_cn] if subject_cn else []) + raw_san
            derived = not _host_matches_cert(submitted, names) if probe_status else False
            mismatched = bool(row.get("mismatched")) or derived
            # The SNI is the alphabetically first of the IP's names
            # (TLSX_MAX_HOSTNAMES_PER_IP defaults to 1), an arbitrary pick, so a
            # service whose one cert names a sibling on the IP looks mismatched
            # for the name tlsx happened to dial. That is still what a client
            # asking for that name gets, so the verdict is never cleared:
            # clearing it would also hide a frontend serving another site's
            # cert, and this entry replaces httpx's verdict for the same
            # host:port in _iter_cert_targets. The covered siblings are
            # recorded instead, for the finding to weigh.
            if derived:
                covers_siblings = _siblings_the_cert_names(
                    submitted, names, (ip_hostnames or {}).get(scanned_ip))
        else:
            # H5: tlsx compares the cert against whatever it dialled, so on a
            # bare IP it reports mismatched=true for EVERY correctly configured
            # host -- a cert names hostnames, never the IP. Trusting that flag
            # made an IP-mode scan raise a mismatch on every TLS port it found.
            # Not determinable is not a finding, matching how the httpx-sourced
            # verdicts leave what they cannot derive unset.
            mismatched = False

        fp = ((row.get("fingerprint_hash") or {}) if isinstance(row.get("fingerprint_hash"), dict) else {})
        entry = {
            "host": submitted, "ip": row.get("ip") or scanned_ip, "port": port,
            "scanned_ip": scanned_ip,
            "probe_status": probe_status, "error": error,
            "tls_version": row.get("tls_version"), "cipher": row.get("cipher"),
            "key_exchange": row.get("key_exchange"), "tls_connection": row.get("tls_connection"),
            "sni": row.get("sni"),
            "subject_cn": subject_cn or None, "subject_dn": subject_dn or None,
            "subject_org": _as_list(row.get("subject_org")),
            "san": san, "san_raw": raw_san,
            "issuer_cn": row.get("issuer_cn"), "issuer_dn": issuer_dn or None,
            "issuer_org": _as_list(row.get("issuer_org")),
            "serial": row.get("serial"),
            "fingerprint_sha256": fp.get("sha256"),
            "not_before": row.get("not_before"), "not_after": not_after,
            "expired": expired, "self_signed": self_signed, "mismatched": mismatched,
            "revoked": bool(row.get("revoked")), "untrusted": bool(row.get("untrusted")),
            "wildcard": bool(row.get("wildcard_certificate")),
            "jarm": row.get("jarm_hash"), "ja3": row.get("ja3_hash"), "ja3s": row.get("ja3s_hash"),
            "version_enum": _as_list(row.get("version_enum")),
            "cipher_enum": _as_list(row.get("cipher_enum")),
            # Derived here rather than in the mixin: graph_db must not import
            # recon. Advisory only -- it never renames the Service.
            "tls_service_hint": _TLS_SERVICE_HINTS.get(port),
        }
        if covers_siblings:
            entry["mismatch_cert_covers_siblings"] = covers_siblings
        # One ip:port can be probed under SEVERAL hostnames when
        # TLSX_MAX_HOSTNAMES_PER_IP > 1, and a vhost frontend legitimately
        # presents a DIFFERENT certificate per SNI. Overwriting on the shared
        # ip:port key silently discarded every cert but the last, defeating the
        # only reason to raise that setting. Keep the first under the canonical
        # key (Service MATCH and get_cert_for rely on it) and park the rest
        # under an SNI-qualified key so consumers that iterate still see them.
        existing = by_target.get(key)
        if existing is None:
            by_target[key] = entry
        elif existing.get("fingerprint_sha256") == entry.get("fingerprint_sha256"):
            by_target[key] = entry          # same cert re-observed: refresh
        else:
            by_target[f"{key}@{submitted}"] = entry
    return by_target


def _enrich_port_details(combined_result: dict, by_target: dict) -> None:
    """Write TLS posture back onto port_scan.by_host port_details (Phase 2.1)."""
    by_host = ((combined_result.get("port_scan") or {}).get("by_host")) or {}
    for _host, hinfo in by_host.items():
        if not isinstance(hinfo, dict):
            continue
        ip = hinfo.get("ip")
        for pd in hinfo.get("port_details") or []:
            port = _coerce_port(pd.get("port"))
            if port is None:
                continue
            # A domain run's name on several addresses: the detail names its own.
            cert = by_target.get(f"{pd.get('ip') or ip}:{port}")
            if not cert or not cert.get("probe_status"):
                continue
            pd["tls"] = {
                "version": cert.get("tls_version"), "cipher": cert.get("cipher"),
                "subject_cn": cert.get("subject_cn"), "issuer": cert.get("issuer_cn"),
                "expired": cert.get("expired"), "self_signed": cert.get("self_signed"),
                "mismatched": cert.get("mismatched"),
            }
            hint = cert.get("tls_service_hint")
            if hint:
                pd["tls_service_hint"] = hint


def _attribute_cdn(combined_result: dict, by_target: dict) -> int:
    """Fill is_cdn/cdn from the certificate issuer where naabu left them unset.

    Phase 2.3. naabu reports a CDN only when its own fingerprinting says so, and
    ``response_is_cdn_edge`` needs a requests.Response, so neither can attribute
    a CDN on a non-HTTP TLS port. A certificate issuer works from the handshake
    alone. Only fills a BLANK value -- naabu's own attribution always wins --
    and ip_filter consumes the result with no change to that module.
    """
    from recon.helpers.cdn_ranges import cdn_from_certificate

    port_scan = combined_result.get("port_scan") or {}
    by_ip = port_scan.get("by_ip") or {}
    by_host = port_scan.get("by_host") or {}

    cdn_by_ip = {}
    for entry in by_target.values():
        if not isinstance(entry, dict) or not entry.get("probe_status"):
            continue
        name = cdn_from_certificate(entry.get("issuer_dn") or entry.get("issuer_cn")
                                    or entry.get("issuer_org"))
        if name:
            cdn_by_ip.setdefault(entry.get("scanned_ip") or entry.get("ip"), name)

    filled = 0
    for ip, name in cdn_by_ip.items():
        if not ip:
            continue
        info = by_ip.get(ip)
        if isinstance(info, dict) and not info.get("cdn"):
            info["cdn"] = name
            info["is_cdn"] = True
            info["cdn_source"] = "tls_certificate"
            filled += 1
        for hinfo in by_host.values():
            if isinstance(hinfo, dict) and hinfo.get("ip") == ip and not hinfo.get("cdn"):
                hinfo["cdn"] = name
                hinfo["is_cdn"] = True
                hinfo["cdn_source"] = "tls_certificate"
    if filled:
        _print("+", f"attributed a CDN from the certificate issuer on {filled} IP(s)")
    return filled


def _cdn_attributions(combined_result: dict) -> dict:
    """{ip: cdn} for the IPs whose CDN tag came from tlsx's certificate issuer.

    In a full run the port graph write happens before tlsx, so the tag
    _attribute_cdn puts on port_scan.by_ip would never reach IP.is_cdn; the tlsx
    writer reads this map from the payload instead.
    """
    by_ip = ((combined_result.get("port_scan") or {}).get("by_ip")) or {}
    return {ip: info["cdn"] for ip, info in by_ip.items()
            if ip and isinstance(info, dict) and info.get("cdn")
            and info.get("cdn_source") == "tls_certificate"}


def _discovered_hostnames(by_target: dict) -> list:
    out = set()
    for cert in by_target.values():
        for name in cert.get("san") or []:
            if name:
                out.add(name)
        cn = cert.get("subject_cn")
        if cn:
            out.add(_strip_wildcard(cn))
    return sorted(out)


def _wildcard_dropped(combined_result: dict, names: list, settings: dict) -> set:
    """The certificate names that answer only through their zone's wildcard
    DNS (recon/helpers/wildcard_control.py). Both the full pipeline and partial
    tlsx call run_tlsx_enrichment, so the check sits here: these names are
    never merged as targets, and the tlsx writer links no Subdomain to them.
    The roots are the ones that writer uses."""
    roots = [r for r in (combined_result.get("domains") or [combined_result.get("domain")])
             if isinstance(r, str) and r.strip()]
    if not roots or not names:
        return set()
    from recon.helpers import wildcard_control
    candidates = sorted({_strip_wildcard(n).rstrip(".") for n in names if n})
    control = wildcard_control.filter_late_names(candidates, roots, settings, label="tlsx")
    if control.zones:
        combined_result.setdefault("wildcard_zones", {}).update(control.zones)
    return set(control.dropped)


def _unanswered_targets(meta: dict, by_target: dict) -> list:
    """The target lines tlsx returned no row for. A row with a failed handshake
    is an answer: the target was checked and found closed or not TLS."""
    answered = {(str(e.get("host") or ""), e.get("port")) for e in by_target.values()
                if isinstance(e, dict)}
    out = []
    for key in meta:
        submitted, _, port = key.rpartition(":")
        if (submitted, _coerce_port(port)) not in answered:
            out.append(_target_line(submitted, _coerce_port(port)))
    return out


def _note_unchecked(lines: list, reason: str) -> None:
    """Keep the security_check findings on the targets tlsx never answered.

    The TLS-hygiene findings are built from tlsx's answer, and for a non-HTTP
    TLS port it is the only one, so no answer is "not checked", not "no
    certificate problem". Cut for security_check alone: the other tools
    re-checked these hosts. With no target list (a crash before it was built),
    the whole source is kept. Never raises.
    """
    try:
        from recon.helpers import circuit_breaker
        if lines:
            circuit_breaker.note_degraded("tlsx", hosts=lines, host_source="security_check",
                                          source_only_hosts=True, reason=reason)
        else:
            circuit_breaker.note_degraded("tlsx", sources=["security_check"], reason=reason)
    except Exception:  # noqa: BLE001
        pass


def run_tlsx_enrichment(combined_result: dict, settings: dict) -> dict:
    """Grab TLS certificates for open non-HTTP ports. Never raises."""
    settings = settings or {}
    combined_result.setdefault("metadata", {})
    scan_id = uuid.uuid4().hex[:12]
    scan_temp_dir = Path(f"/tmp/redamon/.tlsx_scan_{scan_id}")
    lines = None

    try:
        lines, meta = _build_tlsx_targets(combined_result, settings)
        if not lines:
            _print("-", "no eligible TLS targets (all HTTP ports or filtered)")
            combined_result["tlsx"] = {
                "by_target": {}, "discovered_hostnames": [], "cdn_by_ip": {},
                "summary": {"targets": 0, "with_cert": 0},
                "scan_metadata": {"targets": 0, "skipped": "no eligible targets"},
            }
            return combined_result

        scan_temp_dir.mkdir(parents=True, exist_ok=True)
        targets_file = str(scan_temp_dir / "tlsx_targets.txt")
        Path(targets_file).write_text("\n".join(lines) + "\n")

        from recon.helpers.docker_helpers import kill_container, tool_container_name
        container_name = tool_container_name("tlsx")
        cmd = build_tlsx_command(targets_file, str(scan_temp_dir), settings,
                                 container_name=container_name)
        run_timeout = int(settings.get("TLSX_RUN_TIMEOUT", 900))
        _print("*", f"scanning {len(lines)} TLS target(s), timeout {run_timeout}s")

        started = datetime.now(timezone.utc)
        stdout = ""
        failure = ""
        timed_out = False
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=run_timeout)
            if process.returncode not in (0, None):
                failure = f"tlsx exited {process.returncode}"
                _print("!", f"{failure}: {(stderr or '')[:200]}")
        except subprocess.TimeoutExpired:
            _print("!", f"tlsx timed out after {run_timeout}s -- killing")
            timed_out = True
            failure = f"tlsx timed out after {run_timeout}s"
            # Killing the docker CLI alone leaves the container handshaking.
            kill_container(container_name)
            # The rows tlsx printed before the kill are real answers;
            # communicate() after kill() hands them back.
            try:
                process.kill()
                stdout, _ = process.communicate(timeout=10)
            except Exception:
                pass
            stdout = stdout or ""
        except FileNotFoundError as e:
            failure = "tlsx runner missing"
            _print("!", f"{failure}: {e}")
        duration = (datetime.now(timezone.utc) - started).total_seconds()

        by_target = _parse_tlsx_output(stdout, meta,
                                       ip_hostnames=_hostnames_by_ip(combined_result))
        unchecked = _unanswered_targets(meta, by_target) if failure else []
        if unchecked:
            _print("!", f"{len(unchecked)} of {len(lines)} target(s) not checked; "
                        f"their earlier security-check findings are kept")
            _note_unchecked(unchecked, failure)
        if failure and not by_target:
            combined_result["metadata"].setdefault("phase_errors", {})["tlsx"] = failure
        _enrich_port_details(combined_result, by_target)
        _attribute_cdn(combined_result, by_target)

        with_cert = sum(1 for c in by_target.values() if c.get("fingerprint_sha256") or c.get("subject_cn"))
        discovered = _discovered_hostnames(by_target)
        dropped = _wildcard_dropped(combined_result, discovered, settings)
        combined_result["tlsx"] = {
            "by_target": by_target,
            "discovered_hostnames": [n for n in discovered
                                     if _strip_wildcard(n).rstrip(".") not in dropped],
            "wildcard_dropped": sorted(dropped),
            "cdn_by_ip": _cdn_attributions(combined_result),
            "summary": {
                "targets": len(lines),
                "responded": sum(1 for c in by_target.values() if c.get("probe_status")),
                "with_cert": with_cert,
                "expired": sum(1 for c in by_target.values() if c.get("expired")),
                "self_signed": sum(1 for c in by_target.values() if c.get("self_signed")),
                "mismatched": sum(1 for c in by_target.values() if c.get("mismatched")),
            },
            "scan_metadata": {
                "targets": len(lines), "duration_seconds": round(duration, 1),
                "command": " ".join(cmd),
            },
        }
        if failure:
            combined_result["tlsx"]["scan_metadata"].update(
                error=failure, unchecked_targets=len(unchecked),
                **({"timed_out": True} if timed_out else {}))
        _print("+", f"grabbed {with_cert} cert(s) from {len(by_target)} target(s)")
    except Exception as e:  # never raise out of the phase
        _print("!", f"tlsx failed: {e}")
        _note_unchecked(lines or [], f"tlsx failed: {type(e).__name__}")
        combined_result["metadata"].setdefault("phase_errors", {})["tlsx"] = str(e)
        combined_result.setdefault("tlsx", {"by_target": {}, "discovered_hostnames": [],
                                            "cdn_by_ip": {}, "summary": {},
                                            "scan_metadata": {"error": str(e),
                                                              "unchecked_targets": len(lines or [])}})
    finally:
        try:
            import shutil
            if scan_temp_dir.exists():
                shutil.rmtree(scan_temp_dir, ignore_errors=True)
        except Exception:
            pass
    return combined_result


def run_tlsx_enrichment_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe deep-copy call path (fan-out + tests). Returns tlsx payload."""
    snapshot = copy.deepcopy(combined_result)
    run_tlsx_enrichment(snapshot, settings)
    return snapshot.get("tlsx", {})
