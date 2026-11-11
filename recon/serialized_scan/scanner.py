"""Serialized-object detection over the in-memory recon corpus (plan §5).

Passive, deterministic, no DB, no network, and it NEVER deserializes. It reads
only what the pipeline already holds in memory -- response headers + Set-Cookie
(http_probe ``by_url``), enumerated endpoints/parameters (resource_enum
``by_base_url``) and the crawled forms' fields (resource_enum ``forms``) -- runs
every value through the bomb-safe decode-and-recurse normalizer, and matches the
family signatures. Each format a value carries becomes one :Vulnerability
candidate (needs_agent_confirmation=true, severity=info) that the agent's
deserialization skill confirms out of band.

Request-side blobs (POST bodies, request cookies) are not in the in-memory slice
(bodies are popped at http_probe.py:2051); that gap is the agent's half.
"""

from __future__ import annotations

import copy
import re
from urllib.parse import urljoin, urlparse

from recon.serialized_scan import decoders, normalizers, signatures

# A serialized blob usually rides as a substring: a cookie VALUE after `=`, one
# query pair, or a long base64/hex run embedded in a larger string. Scanning the
# whole value catches inline text markers (O:4:, @class, <java version); these
# extracted tokens are what the decode-and-recurse normalizer peels.
_MAX_VALUE_LEN = 64 * 1024
_MAX_TOKENS = 24
_KV_SPLIT = re.compile(r"[;&,\s]+")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")


def _candidate_tokens(value: str) -> list:
    """The whole value plus embedded cookie/query values and base64/hex runs."""
    value = value[:_MAX_VALUE_LEN]
    tokens = [value]
    for part in _KV_SPLIT.split(value):
        if "=" in part:
            v = part.split("=", 1)[1]
            if v:
                tokens.append(v)
    tokens.extend(_B64_RUN.findall(value))
    tokens.extend(_HEX_RUN.findall(value))
    seen: set = set()
    out: list = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
        if len(out) >= _MAX_TOKENS:
            break
    return out

try:
    from recon.helpers.roe_scope import _is_roe_excluded
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.roe_scope import _is_roe_excluded


def _host_excluded(url: str, roe_excluded: list) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return False
    return bool(host) and _is_roe_excluded(host, roe_excluded)


def _scan_value(value, transport: str, location: str, ctx: dict, sink) -> None:
    """Decode-and-recurse one value, emitting one finding per format it carries.

    A value often matches one family more than once: base64 Java shows ``rO0AB``
    on its surface and ``AC ED 00 05`` once decoded. That is one sink, so it is one
    candidate; two would leave a twin pending after the agent confirms the other.

    The hit kept is a byte signature (the decoded header itself) over a text
    marker; among byte hits the one reached through more decoding (url+base64 over
    a base64 fragment of it), among text hits the one reached through less (a
    marker readable in the raw value needs none); then the first. Its
    encoding_layers are the layers peeled to reach that hit, which the agent
    re-applies to a payload, so an unrelated %XX elsewhere in a header never
    decides them.
    """
    if not isinstance(value, str) or not value:
        return
    best: dict = {}
    for token in _candidate_tokens(value):
        decoded = decoders.decode_layers(token)
        chain = list(decoded["encoding_chain"])
        flag = ["truncated"] if decoded["truncated"] else []
        for depth, layer in enumerate(decoded["layers"]):
            ranked = ([(hit, (1, depth)) for hit in signatures.scan_bytes(layer["raw"])]
                      + [(hit, (0, -depth)) for hit in signatures.scan_text(layer["text"])])
            for hit, rank in ranked:
                kept = best.get(hit["format"])
                if kept is None or rank > kept[2]:
                    best[hit["format"]] = (hit, chain[:depth] + flag, rank)
    for hit, layers, _ in best.values():
        sink(normalizers.build_finding(
            endpoint_url=ctx["endpoint_url"],
            http_method=ctx["http_method"],
            baseurl=ctx["baseurl"],
            path=ctx["path"],
            transport=transport,
            location=location,
            hit=hit,
            encoding_layers=layers,
        ))


#: Set-Cookie attribute names, never a cookie's own.
_COOKIE_ATTRIBUTES = frozenset({
    "path", "domain", "expires", "max-age", "secure", "httponly", "samesite",
    "priority", "partitioned",
})


def _header_location(name) -> str:
    """One spelling per header. httpx keys headers lowercase_underscored
    (content_type), a raw header string keeps their case (Content-Type), and the
    probe's own content_type field names the same header again: three spellings
    of one sink would be three candidates."""
    return str(name).strip().lower().replace("_", "-")


def _cookie_pairs(header_value: str):
    """(name, value) of every cookie a Set-Cookie value sets. `;` separates a
    cookie from its attributes, and `,` or a newline separates the Set-Cookie
    lines httpx joined into one value; an Expires date's comma leaves a fragment
    with no `=`, which is skipped."""
    for part in re.split(r"[;,\n]", header_value):
        name, sep, value = part.partition("=")
        name = name.strip()
        if sep and name and name.lower() not in _COOKIE_ATTRIBUTES:
            yield name, value.strip()


def _scan_http_probe(combined_result: dict, roe_excluded: list, sink) -> None:
    """Response headers + Set-Cookie carry serialized blobs on the response side.

    A cookie's candidate is located at the cookie's own name, the one the agent
    tampers with, rather than at the Set-Cookie header that carried it.
    """
    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    for url, entry in by_url.items():
        if not isinstance(entry, dict):
            continue
        if _host_excluded(url, roe_excluded):
            continue
        parsed = urlparse(url)
        ctx = {
            "endpoint_url": url,
            "http_method": "GET",
            "baseurl": f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else url,
            "path": parsed.path or "/",
        }

        content_type = entry.get("content_type")
        if isinstance(content_type, str):
            for hit in signatures.scan_header_value(content_type):
                sink(normalizers.build_finding(
                    endpoint_url=url, http_method="GET", baseurl=ctx["baseurl"],
                    path=ctx["path"], transport="header", location=_header_location("Content-Type"),
                    hit=hit, encoding_layers=[]))

        headers = entry.get("headers")
        if isinstance(headers, str):
            # httpx sometimes stores response headers as one CRLF-joined string
            # (http_probe normalises both forms). Parse it back into name/value
            # pairs so Set-Cookie and serialization content types are not missed.
            # A repeated header (one Set-Cookie line per cookie) keeps every value.
            parsed: dict = {}
            for line in headers.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed.setdefault(k.strip(), []).append(v.strip())
            headers = parsed
        if isinstance(headers, dict):
            for name, raw_val in headers.items():
                # httpx stores response headers underscore-cased (set_cookie).
                values = raw_val if isinstance(raw_val, list) else [raw_val]
                for val in values:
                    if not isinstance(val, str):
                        continue
                    location = _header_location(name)
                    for hit in signatures.scan_header_value(val):
                        sink(normalizers.build_finding(
                            endpoint_url=url, http_method="GET",
                            baseurl=ctx["baseurl"], path=ctx["path"],
                            transport="header", location=location, hit=hit,
                            encoding_layers=[]))
                    if "cookie" not in location:
                        _scan_value(val, "header", location, ctx, sink)
                        continue
                    pairs = list(_cookie_pairs(val))
                    for cookie, cookie_value in pairs:
                        # The name too: a cookie NAMED like a sink is a signal.
                        _scan_value(cookie, "cookie", cookie, ctx, sink)
                        _scan_value(cookie_value, "cookie", cookie, ctx, sink)
                    if not pairs:
                        _scan_value(val, "cookie", location, ctx, sink)


def _scan_resource_enum(combined_result: dict, roe_excluded: list, sink) -> None:
    """Enumerated endpoints + parameters (names and example values)."""
    by_base = (combined_result.get("resource_enum") or {}).get("by_base_url") or {}
    for base_url, base_data in by_base.items():
        if not isinstance(base_data, dict):
            continue
        if _host_excluded(base_url, roe_excluded):
            continue
        endpoints = base_data.get("endpoints") or {}
        for path, endpoint in endpoints.items():
            if not isinstance(endpoint, dict):
                continue
            method = _endpoint_method(endpoint)
            endpoint_url = base_url.rstrip("/") + "/" + str(path).lstrip("/")
            ctx = {
                "endpoint_url": endpoint_url,
                "http_method": method,
                "baseurl": base_url,
                "path": path,
            }
            for pname, sample_values in _iter_params(endpoint.get("parameters")):
                # A parameter NAMED like a serialization sink (__VIEWSTATE) is a
                # signal even without a value; scan the name too.
                _scan_value(pname, "param", pname, ctx, sink)
                for val in sample_values:
                    _scan_value(val, "param", pname, ctx, sink)


def _scan_forms(combined_result: dict, roe_excluded: list, sink) -> None:
    """Crawled forms: hidden inputs are a classic carrier (ViewState, a serialized
    `data` field), and the client sends them back to the form's action, so a sink
    there receives them. The by_base_url endpoints keep no field values, so this is
    the only place the corpus holds them. A field is a `param` whatever the method,
    as the body-position parameters above are; the method rides in http_method.
    """
    forms = (combined_result.get("resource_enum") or {}).get("forms") or []
    if not isinstance(forms, list):
        return
    for form in forms:
        if not isinstance(form, dict):
            continue
        found_at = form.get("found_at") if isinstance(form.get("found_at"), str) else ""
        action = form.get("action") if isinstance(form.get("action"), str) else ""
        try:
            target = urljoin(found_at, action) if found_at else action
            parsed = urlparse(target)
        except ValueError:
            # A malformed host (`https://[x]/`) costs this form, not the run's
            # other candidates.
            continue
        if not parsed.scheme or not parsed.netloc or _host_excluded(target, roe_excluded):
            continue
        ctx = {
            "endpoint_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}",
            "http_method": str(form.get("method") or "GET").upper(),
            "baseurl": f"{parsed.scheme}://{parsed.netloc}",
            "path": parsed.path or "/",
        }
        inputs = form.get("inputs")
        for field in inputs if isinstance(inputs, list) else []:
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if not isinstance(name, str) or not name:
                continue
            # A field NAMED like a sink (__VIEWSTATE) is a signal even when empty.
            _scan_value(name, "param", name, ctx, sink)
            _scan_value(field.get("value"), "param", name, ctx, sink)


def _endpoint_method(endpoint: dict) -> str:
    """The endpoint's primary HTTP method, uppercased.

    resource_enum stores `methods` (a list, the shape resource_mixin reads);
    partial recon and older/hand-built shapes carry a singular `method`. Both
    are tolerated; default GET.
    """
    methods = endpoint.get("methods") or endpoint.get("method") or "GET"
    if isinstance(methods, str):
        methods = [methods]
    first = methods[0] if methods else "GET"
    return str(first or "GET").upper()


def _iter_params(parameters):
    """Yield (name, [string sample values]) for every enumerated parameter.

    The real recon corpus keys parameters by POSITION, each a list of parameter
    dicts (the shape resource_mixin reads):
        {"query": [{"name": "...", "sample_values": [...], ...}], "body": [...]}
    A flat {name: value | {value/sample_values/...}} shape (partial recon, a
    hand-built fixture) is also tolerated so the scanner never silently reads the
    wrong shape again.
    """
    if not isinstance(parameters, dict):
        return
    for key, val in parameters.items():
        if isinstance(val, list):
            # positional bucket: a list of parameter dicts (or bare name strings)
            for param in val:
                if isinstance(param, dict):
                    name = param.get("name")
                    if not name:
                        continue
                    samples = [s for s in (param.get("sample_values") or []) if isinstance(s, str)]
                    yield str(name), samples
                elif isinstance(param, str) and param:
                    yield param, []
        elif isinstance(val, dict):
            # flat {name: {value/sample_values/...}} shape
            yield str(key), _param_values(val)
        elif isinstance(val, str):
            yield str(key), [val]


def _param_values(pdata: dict) -> list:
    """Pull candidate string values out of a flat-shape parameter record."""
    out: list = []
    for key in ("value", "example", "default", "sample"):
        v = pdata.get(key)
        if isinstance(v, str):
            out.append(v)
    vals = pdata.get("values") or pdata.get("examples") or pdata.get("sample_values")
    if isinstance(vals, list):
        out.extend(v for v in vals if isinstance(v, str))
    return out


_FINDING_SOURCE = "serialized_scan"
# The phases whose output is the corpus (headers and Set-Cookie; endpoints,
# parameters and forms). Each records its crash in metadata.phase_errors.
_INPUT_PHASES = ("http_probe", "resource_enum")


def _keep_candidates(reason: str) -> None:
    """Keep every earlier serialized-object candidate out of the prune. Never raises.

    This scan never raises, so main's _note_phase_error never fires for it, and
    a run that re-read nothing would read as "every candidate is gone". A
    failure here says nothing about which hosts were read, so the whole
    source is cut (README "Degrade by host before degrading by source": no
    host to degrade by).
    """
    try:
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded(_FINDING_SOURCE, sources=[_FINDING_SOURCE], reason=reason)
        print(f"[!][SerializedScan] {reason}: earlier candidates are kept")
    except Exception:  # noqa: BLE001 - coverage bookkeeping never fails the scan
        pass


def run_serialized_scan(combined_result: dict, settings: dict) -> dict:
    """Scan the in-memory corpus; mutate combined_result in place, return it.

    Guarded by SERIALIZED_SCAN_ENABLED. Never raises: on any error it writes an
    empty result, logs, and keeps every earlier candidate out of the prune, so a
    malformed corpus can neither fail the pipeline nor delete candidates.
    """
    if not settings.get("SERIALIZED_SCAN_ENABLED", False):
        print("[-][SerializedScan] disabled")
        return combined_result

    print("[*][SerializedScan] scanning in-memory corpus for serialized-object signatures")
    metadata = combined_result.get("metadata")
    phase_errors = metadata.get("phase_errors") if isinstance(metadata, dict) else None
    failed_inputs = [p for p in _INPUT_PHASES if isinstance(phase_errors, dict) and p in phase_errors]
    if failed_inputs:
        # Still scanned: what the other input gave is new candidates to write.
        _keep_candidates(f"input phase failed ({', '.join(failed_inputs)})")
    findings: list = []
    try:
        roe_excluded = settings.get("ROE_EXCLUDED_HOSTS", []) or []
        if not settings.get("ROE_ENABLED", False):
            roe_excluded = []

        seen: set = set()

        def sink(finding: dict) -> None:
            key = normalizers.dedup_key(finding)
            if key in seen:
                return
            seen.add(key)
            findings.append(finding)

        _scan_http_probe(combined_result, roe_excluded, sink)
        _scan_resource_enum(combined_result, roe_excluded, sink)
        _scan_forms(combined_result, roe_excluded, sink)
    except Exception as e:  # noqa: BLE001 - never-raise contract (plan §5.2)
        # An empty result alone is what the prune reads as "every candidate is
        # gone"; the degraded note is what keeps them. The type only: a message
        # can quote target text, and the drawer reads phases out of stdout.
        print(f"[!][SerializedScan] Error ({type(e).__name__}) - no candidates this run")
        _keep_candidates(f"scan raised {type(e).__name__}")
        combined_result["serialized_scan"] = normalizers.build_result([])
        return combined_result

    # Optional Jev assessment (AI in pipeline). Hooked here, in the entry the full
    # pipeline and partial recon share, so both inherit it. Annotates and ranks
    # only, and an import or wiring failure never costs the scan its candidates.
    try:
        from recon.helpers.ai_planner import serialized_assess
        serialized_assess.run_for_scan(findings, settings, combined_result)
    except Exception as e:  # noqa: BLE001
        print(f"[!][SerializedScan] Jev assessment skipped ({type(e).__name__})")

    combined_result["serialized_scan"] = normalizers.build_result(findings)
    if findings:
        print(f"[+][SerializedScan] {len(findings)} serialized-object candidate(s) flagged")
    else:
        print("[-][SerializedScan] no serialized-object signatures found")
    return combined_result


def run_serialized_scan_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe wrapper: deep-copies, runs, returns only this tool's payload.

    The fan-out and test call path (plan §5.2); required even for a sequential
    slot so the module can later join a parallel group without a shared-dict race.
    """
    snapshot = copy.deepcopy(combined_result)
    run_serialized_scan(snapshot, settings)
    return snapshot.get("serialized_scan", {})
