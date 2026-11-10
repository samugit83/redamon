"""S4/S5: what each route's answers mean.

``observe`` is the first pass of one route: the anonymous request, the
signatures (first, so a debug page answering 500 is still seen), the logged-in
request whatever the anonymous answer was, the drops (denied, empty, catch-all,
wall) and the content signals. ``assess`` is the second pass over every route:
the neighbour hints, then the candidate and finding rules.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from recon.helpers import catchall
from recon.route_exposure import gitwalk, normalizers, prober as prober_mod, riders, seeds, signals, signatures
from recon.route_exposure.harvest import Route, has_extension

try:
    from recon.helpers.ai_planner.page_type import prefilter as page_prefilter
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.ai_planner.page_type import prefilter as page_prefilter

MIN_BODY_BYTES = 64
DENIED = frozenset({401, 403, 407})
#: Page classes of a 2xx that is not the route's content: a login form, an
#: error page, an empty holding page.
WALL_CLASSES = frozenset({"login_only", "error", "placeholder", "default", "parked"})
CANDIDATE_KINDS = ("anonymous_access", "sensitive_data")
#: auth_expected_by is a closed set (plan §5.6).
AUTH_EXPECTED = ("openapi", "openapi_tag", "declared_only", "seen_denied", "path_word",
                 "host_word", "siblings_locked", "version_locked", "vary_auth")
_STRONG_HINTS = frozenset({"openapi", "siblings_locked", "version_locked", "vary_auth"})
_STRUCTURED = frozenset({"json", "xml"})
_LOGIN_LOCATION = re.compile(
    r"/(login|log-in|signin|sign-in|sso|auth|oauth2?|session|account/login|users/sign_in|"
    r"wp-login\.php|cas/login)\b", re.I)
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

#: The kinds whose paths never become Endpoint nodes (plan §7.1 b).
NEW_ENDPOINT_GENERATORS = frozenset({"seed", "version", "sibling", "catalog", "cross_host"})


@dataclass
class Observation:
    route: Route
    anon: Optional[prober_mod.Answer] = None
    head: Optional[prober_mod.Answer] = None
    authed: Optional[prober_mod.Answer] = None
    signature: Optional[dict] = None
    drop: str = ""
    catch_all_check: str = "n/a"
    content_class: str = "other"
    size: int = 0
    anon_signals: signals.Signals = field(default_factory=signals.Signals)
    authed_signals: signals.Signals = field(default_factory=signals.Signals)
    authed_usable: bool = False
    bodies_match: Optional[bool] = None
    vary_auth: bool = False
    api_spec: bool = False
    snippet: str = ""
    # v2 riders and proofs (plan §5.7, §5.8)
    cors_variants: list = field(default_factory=list)
    cache_signals: list = field(default_factory=list)
    git_walk: dict = field(default_factory=dict)

    @property
    def anon_status(self) -> Optional[int]:
        return self.anon.status_code if self.anon is not None else None

    @property
    def authed_status(self) -> Optional[int]:
        return self.authed.status_code if self.authed is not None else None


def _ok(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


def _size(answer: prober_mod.Answer) -> int:
    try:
        declared = int(answer.header("content-length") or 0)
    except ValueError:
        declared = 0
    return max(len(answer.content), declared if answer.truncated or answer.method == "HEAD" else 0)


def _title(body: bytes) -> str:
    match = _TITLE.search(body[:64 * 1024])
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1).decode("utf-8", "replace")).strip()[:200]


def page_entry(answer: prober_mod.Answer, url: str) -> dict:
    """The httpx-shaped entry page_type.prefilter (and Jev hook B) reads."""
    text = answer.content[:64 * 1024].decode("utf-8", "replace")
    return {
        "url": url,
        "host": urlsplit(url).hostname or "",
        "status_code": answer.status_code,
        "content_length": len(answer.content),
        "content_type": answer.header("content-type"),
        "title": _title(answer.content),
        "server": answer.header("server"),
        "headers": dict(answer.headers),
        "word_count": len(text.split()),
        "body": signals.mask_text(text[:4096]),
    }


def _snippet(answer: prober_mod.Answer, sig: signals.Signals) -> str:
    if sig.key_paths:
        # A JSON answer is described by its keys: its values are the records.
        return "keys: " + ", ".join(sig.key_paths[:12])
    text = answer.content[:2048].decode("utf-8", "replace")
    return re.sub(r"\s+", " ", signals.mask_text(text)).strip()


def _vary_auth(answer: prober_mod.Answer) -> bool:
    vary = answer.header("vary").lower()
    cache = answer.header("cache-control").lower()
    return "cookie" in vary or "authorization" in vary or "private" in cache


def observe(route: Route, probe: prober_mod.Prober, cfg: dict) -> Observation:
    """The first pass of one route. Never raises; a request that was never sent
    leaves ``anon`` None (guard, stop, or a host already down)."""
    obs = Observation(route=route)
    url = route.url
    if route.request == "backup":
        # HEAD first, then the first KB: an archive is identified by its magic
        # bytes and never downloaded.
        head = probe.send("HEAD", url)
        obs.head = head
        if head is None or not head.ok:
            obs.anon = head
            return obs
        if _ok(head.status_code) or head.status_code in (405, 501):
            obs.anon = probe.send("GET", url, range_bytes=prober_mod.RANGE_BYTES,
                                  max_bytes=prober_mod.RANGE_BYTES)
        else:
            obs.anon = head
    elif route.request == "head":
        obs.anon = probe.send("HEAD", url)
    else:
        obs.anon = probe.send("GET", url)
    anon = obs.anon
    if anon is None or not anon.ok:
        return obs

    status = anon.status_code
    obs.content_class = signals.content_class(anon.header("content-type"), anon.content)
    obs.size = _size(anon)
    if _ok(status):
        obs.anon_signals = signals.analyse(anon.content, content_class=obs.content_class,
                                           pii=cfg.get("pii_detection", True), secrets=True,
                                           source_url=url)
    sig = signatures.match(path=route.path, method=anon.method, status=status,
                           headers=anon.headers, body=anon.content,
                           content_class=obs.content_class, generated_by=route.generated_by,
                           secret_types=obs.anon_signals.secret_types)
    if sig is not None and sig["kind"] in ("backup_file", "secret_in_response"):
        # Both must differ from a made-up path: a server that answers every
        # path with one archive, or one shell with one inline key, is not a leak.
        verdict = probe.control(anon, shape="range" if anon.range_read else "anon",
                                range_bytes=prober_mod.RANGE_BYTES if anon.range_read else None)
        obs.catch_all_check = verdict.control_check
        if verdict.catch_all:
            obs.drop = "catch_all"
            return obs
    if sig is not None:
        obs.signature = sig
        if (sig["kind"] == "vcs_exposure" and cfg.get("git_walk")
                and route.path.lower().endswith("/.git/head")):
            obs.git_walk = gitwalk.walk(probe, url[:-len("/HEAD")], anon.content)
        return obs

    _logged_in(obs, probe, cfg)

    if status in DENIED or status >= 400:
        obs.drop = "denied"
    elif 300 <= status < 400:
        location = urlsplit(anon.header("location") or "").path or "/"
        obs.drop = "wall" if _LOGIN_LOCATION.search(location) or location == "/" else "denied"
    elif not _ok(status):
        obs.drop = "denied"
    elif len(anon.content) < MIN_BODY_BYTES and anon.method != "HEAD":
        obs.drop = "empty"
    else:
        verdict = probe.control(anon, shape="anon")
        obs.catch_all_check = verdict.control_check
        if verdict.catch_all:
            obs.drop = "catch_all"
        elif page_prefilter(page_entry(anon, url)) in WALL_CLASSES:
            obs.drop = "wall"
        else:
            obs.api_spec = signatures.is_api_spec(anon.content.decode("utf-8", "replace")) is not None
            obs.snippet = _snippet(anon, obs.anon_signals)
            if obs.authed_usable and _ok(obs.authed_status):
                hosts = [urlsplit(url).hostname or ""]
                echoes = [route.path]
                obs.bodies_match = catchall.same_page(
                    catchall.normalise_body(anon.content, hostnames=hosts, echoes=echoes),
                    catchall.normalise_body(obs.authed.content, hostnames=hosts, echoes=echoes))
    if obs.drop and obs.drop != "catch_all":
        obs.catch_all_check = "n/a"
    _check_logged_in_content(obs, probe)
    _riders(obs, probe, cfg)
    return obs


def _riders(obs: Observation, probe: prober_mod.Prober, cfg: dict) -> None:
    """The CORS and cache riders, only on a logged-in 2xx that is personalised (the
    anonymous answer was denied or differs) and carries a leak signal (plan §5.7)."""
    if not (cfg.get("cors_rider") or cfg.get("cache_rider")) or not obs.authed_usable:
        return
    sig = obs.authed_signals
    if not (sig.leak_signals or sig.sensitive_fields or sig.pii_others):
        return
    if not (obs.anon_status in DENIED or obs.drop == "denied" or obs.bodies_match is False):
        return
    if cfg.get("cors_rider"):
        obs.cors_variants = riders.cors_rider(probe, obs.route).get("cors_variants", [])
    if cfg.get("cache_rider"):
        obs.cache_signals = riders.cache_rider(obs.authed).get("cache_signals", [])


def _logged_in(obs: Observation, probe: prober_mod.Prober, cfg: dict) -> None:
    """The logged-in GET, sent whatever the anonymous answer was: a route that
    answers 401 anonymously can still return too much to its own user.

    Version-control and backup guesses are judged on the anonymous answer
    alone (an artifact is exposed or it is not), so they never send one.
    """
    route = obs.route
    if (not cfg.get("compare_logged_in", True) or route.request != "get"
            or route.generated_by in ("vcs", "backup")):
        return
    auth = probe.auth_headers(route.url)
    if not auth:
        return
    authed = probe.send("GET", route.url, auth=auth)
    obs.authed = authed
    if authed is None or not _ok(authed.status_code):
        return
    obs.authed_usable = True
    cc = signals.content_class(authed.header("content-type"), authed.content)
    obs.authed_signals = signals.analyse(authed.content, content_class=cc,
                                         pii=cfg.get("pii_detection", True), secrets=False)
    obs.vary_auth = _vary_auth(authed)


def _check_logged_in_content(obs: Observation, probe: prober_mod.Prober) -> None:
    """A logged-in answer that would be reported on its own content is checked
    against a made-up path too, sent logged in."""
    sig = obs.authed_signals
    if not obs.authed_usable or not (sig.sensitive_fields or sig.pii_others):
        return
    if not obs.drop and _ok(obs.anon_status):
        return  # the anonymous answer already speaks for this route
    verdict = probe.control(obs.authed, shape="auth", auth=probe.auth_headers(obs.route.url))
    if verdict.catch_all:
        obs.authed_signals = signals.Signals()


# ---------------------------------------------------------------------------
# Second pass
# ---------------------------------------------------------------------------

def parent_prefix(path: str) -> str:
    trimmed = (path or "/").rstrip("/")
    head = trimmed.rsplit("/", 1)[0] if "/" in trimmed else ""
    return (head or "") + "/"


def route_class(route: Route) -> str:
    """The closed route class (plan §5.6): never part of a finding's identity."""
    words = {t for seg in route.path.split("/") for t in seeds.tokens(seg)}
    if route.generated_by == "version":
        return "old_version"
    if route.router or route.client_gated:
        return "client_gated"
    if words & {"debug", "actuator", "metrics", "management", "health", "pprof", "trace",
                "console", "prometheus", "status", "env"}:
        return "debug_management"
    if words & {"admin", "administrator", "manage", "manager", "dashboard", "panel", "cpanel",
                "backend"} or route.category in ("admin", "admin_debug"):
        return "admin_function"
    if words & {"export", "exports", "report", "reports", "dump", "download", "print", "csv"}:
        return "data_export"
    if has_extension(route.path) and words & seeds.UPLOAD_DIR_WORDS:
        return "uploaded_content"
    if words & {"internal", "private", "system"} or route.category in ("api", "file_access"):
        return "internal_api"
    return "unknown"


def _neighbour_hints(observations: list) -> dict:
    """{route key: [siblings_locked | version_locked]}.

    An open route counts as locked-among-siblings only when it answers the
    same kind of content as most of its locked neighbours: a public HTML help
    page beside locked JSON endpoints is documentation, an open JSON endpoint
    among them is the one that was missed.
    """
    denied_by_prefix: dict = {}
    status_by_key: dict = {}
    for obs in observations:
        route = obs.route
        status_by_key[(route.baseurl, route.path)] = obs.anon_status
        if obs.anon_status in (401, 403):
            key = (route.baseurl, parent_prefix(route.path))
            denied_by_prefix.setdefault(key, Counter())[obs.content_class] += 1
    hints: dict = {}
    for obs in observations:
        if not _ok(obs.anon_status):
            continue
        route = obs.route
        found = []
        locked = denied_by_prefix.get((route.baseurl, parent_prefix(route.path)), Counter())
        if sum(locked.values()) >= 3 and locked.most_common(1)[0][0] == obs.content_class:
            found.append("siblings_locked")
        if route.generated_by == "version" and status_by_key.get(
                (route.baseurl, route.variant_of)) in (401, 403):
            found.append("version_locked")
        if found:
            hints[route.key] = found
    return hints


def _auth_expected(obs: Observation, neighbours: list) -> list:
    hints = list(obs.route.hints)
    if route_class(obs.route) == "uploaded_content" and "path_word" not in hints:
        # A file under an uploads directory is somebody's document.
        hints.append("path_word")
    hints += neighbours
    if obs.vary_auth:
        hints.append("vary_auth")
    return [h for h in AUTH_EXPECTED if h in hints]


def _anon_confidence(expected: list, obs: Observation) -> float:
    leaks = obs.anon_signals.leak_signals
    if set(expected) & _STRONG_HINTS or (obs.bodies_match and leaks):
        return 0.9
    if {"path_word", "seen_denied"} & set(expected) and obs.content_class in _STRUCTURED:
        return 0.6
    return 0.4


def _original_matches(obs: Observation, by_key: dict) -> bool:
    """A backup guess the server answers exactly as the original file is the
    original file (an ignored suffix), not a backup."""
    route = obs.route
    original = by_key.get((route.baseurl, route.variant_of))
    if original is None or original.anon is None or not _ok(original.anon_status):
        return False
    head = original.anon.content[:len(obs.anon.content)]
    return bool(head) and head == obs.anon.content


def is_artifact_path(path: str) -> bool:
    low = (path or "").lower()
    return any(d in low + "/" for d in seeds.VCS_DIRS)


def assess(observations: list, cfg: dict) -> dict:
    """Findings, Endpoint statuses, new Endpoints and drop counts of a run."""
    neighbours = _neighbour_hints(observations)
    by_key = {(o.route.baseurl, o.route.path): o for o in observations}
    findings, endpoint_status, new_endpoints = [], [], []
    dropped = {"denied": 0, "catch_all": 0, "wall": 0, "empty": 0}
    seen: set = set()
    compared = 0

    def emit(finding: dict) -> None:
        key = normalizers.dedup_key(finding)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for obs in observations:
        route = obs.route
        if obs.anon_status is not None and route.generated_by == "found":
            endpoint_status.append({"baseurl": route.baseurl, "path": route.path,
                                    "method": route.method, "anon_status": obs.anon_status})
        if obs.authed is not None and obs.authed.ok:
            compared += 1
        if obs.drop in dropped:
            dropped[obs.drop] += 1
        if obs.signature is not None:
            if obs.signature["kind"] == "backup_file" and _original_matches(obs, by_key):
                continue
            emit(normalizers.build_finding(obs, kind=obs.signature["kind"],
                                           route_class=route_class(route),
                                           auth_expected_by=[], confidence=0.95,
                                           sig=obs.signature, extra=obs.git_walk))
            continue
        expected = _auth_expected(obs, neighbours.get(route.key, []))
        kinds = []
        anon_ok = _ok(obs.anon_status) and not obs.drop and not obs.api_spec
        if anon_ok and (expected or obs.anon_signals.leak_signals):
            kinds.append("anonymous_access")
            emit(normalizers.build_finding(obs, kind="anonymous_access",
                                           route_class=route_class(route),
                                           auth_expected_by=expected,
                                           confidence=_anon_confidence(expected, obs)))
        source = None
        if anon_ok and (obs.anon_signals.sensitive_fields or obs.anon_signals.pii_others):
            source = obs.anon_signals
        elif obs.authed_usable and (obs.authed_signals.sensitive_fields or obs.authed_signals.pii_others):
            source = obs.authed_signals
        if source is not None:
            kinds.append("sensitive_data")
            emit(normalizers.build_finding(obs, kind="sensitive_data",
                                           route_class=route_class(route),
                                           auth_expected_by=expected,
                                           confidence=0.6 if source.sensitive_fields else 0.5,
                                           content=source))
        # v2 riders: leads only; the agent proves the cross-origin read or the cache hit.
        if obs.cors_variants:
            emit(normalizers.build_finding(obs, kind="cors_misconfig", route_class=route_class(route),
                                           auth_expected_by=expected, confidence=0.7,
                                           content=obs.authed_signals,
                                           extra={"cors_variants": list(obs.cors_variants)}))
        if obs.cache_signals:
            emit(normalizers.build_finding(obs, kind="auth_cacheable", route_class=route_class(route),
                                           auth_expected_by=expected, confidence=0.6,
                                           content=obs.authed_signals,
                                           extra={"cache_signals": list(obs.cache_signals)}))
        if (kinds and route.generated_by in NEW_ENDPOINT_GENERATORS and _ok(obs.anon_status)
                and obs.anon.content and not is_artifact_path(route.path)):
            new_endpoints.append({"baseurl": route.baseurl, "path": route.path, "method": "GET",
                                  "category": route.category, "anon_status": obs.anon_status,
                                  "generated_by": route.generated_by})
    return {"findings": findings, "endpoint_status": endpoint_status,
            "new_endpoints": new_endpoints, "dropped": dropped, "logged_in_compared": compared}
