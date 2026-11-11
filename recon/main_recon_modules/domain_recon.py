"""
Subdomain Discovery & DNS Resolution - Unified OSINT tool
Discovers subdomains using crt.sh (crt.name when crt.sh gives no answer),
HackerTarget, Subfinder, Amass, and Knockpy.
Resolves full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) for domain and all subdomains.
Outputs a single JSON report.

Parallelization:
- All 5 discovery tools run concurrently via ThreadPoolExecutor (fan-out/fan-in)
- DNS resolution runs concurrently across subdomains (configurable worker count)
"""

import os
import subprocess
import requests
import re
import glob
import json
import time
import shutil
import threading
import uuid
import dns.resolver
import dns.reversename
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from helpers.ai_signal_catalog import match_ai_txt_hint, match_ai_ns_hint

# Settings are passed from main.py to avoid multiple database queries

OUTPUT_DIR = Path(__file__).parent / "output"
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']


# ---------------------------------------------------------------------------
# DNS resolver health (circuit_breaker integration)
# ---------------------------------------------------------------------------
# The recursive resolver is a single shared dependency: when it dies, EVERY
# name lookup times out and the old code retried each 80x7 lookup three times.
# A canary tells a dead resolver apart from a dead name: on a transient failure
# we re-resolve a root that already answered this run. Canary answers -> the
# resolver is fine, this name is just unreachable (per-zone, stay closed);
# canary times out too -> the resolver itself is down, open and stop retrying.

# Errors that are a definitive answer ("this name does not resolve"), never a
# resolver fault: no retry, no breaker impact.
def _dns_definitive_errors():
    import dns.resolver
    import dns.name
    errs = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)
    for extra in ("YXDOMAIN",):
        e = getattr(dns.resolver, extra, None)
        if e is not None:
            errs = errs + (e,)
    # dns.name.* syntax errors (EmptyLabel, LabelTooLong, NameTooLong, ...)
    errs = errs + (dns.name.EmptyLabel, dns.name.LabelTooLong,
                   dns.name.NameTooLong, dns.name.BadEscape)
    return errs


def _cb_enabled() -> bool:
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.enabled()
    except Exception:  # noqa: BLE001
        return False


# Inside one batch group (or partial root), an open latch is probed again after
# this long, doubling up to the maximum, by one thread at a time; the same
# half-open rhythm as circuit_breaker.Breaker.
RESOLVER_COOLDOWN_S = 120.0
RESOLVER_COOLDOWN_MAX_S = 1800.0


class _ResolverBreaker:
    """Shared DNS resolver liveness, canary-gated (see the block comment).

    It used to latch for the rest of the process, and batch groups and partial
    roots run one after another in one process: after one bad moment, every
    later group resolved nothing (so it scanned nothing), had its ownership
    check refused, and recorded no DNS gap. Now recheck() gives each group and
    each root a fresh canary probe, an open latch is probed again after a
    cooldown inside a group, and every lookup it skips is recorded by host.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._clock = time.monotonic
        self.reset()

    def reset(self):
        """Tests only: forget everything, the canary included."""
        with self._lock:
            self._open = False
            self._canary = None
            self._noted = False
            self._probing = False
            self._cooldown = RESOLVER_COOLDOWN_S
            self._retry_at = 0.0
            self._skipped = set()

    def set_canary(self, name: str):
        """The most recent root that answered: the likeliest to answer again."""
        if not name:
            return
        with self._lock:
            self._canary = name

    def is_open(self) -> bool:
        if not _cb_enabled():
            return False
        with self._lock:
            if not self._open:
                return False
            if self._probing or self._clock() < self._retry_at:
                return True
            self._probing = True
        alive = self._probe()
        with self._lock:
            if alive:
                self._close_locked()
            else:
                self._cooldown = min(self._cooldown * 2, RESOLVER_COOLDOWN_MAX_S)
                self._retry_at = self._clock() + self._cooldown
        if alive:
            print("[+][DNS] Resolver answering again: lookups resumed")
        return not alive

    def recheck(self) -> bool:
        """At the start of a batch group or a partial root: one canary probe
        if the latch is open. True when lookups may run. Either way a new trip
        in this group is noted in this group's coverage."""
        if not _cb_enabled():
            return True
        with self._lock:
            self._noted = False
            self._skipped = set()
            if not self._open:
                return True
            if self._probing:
                return False
            self._probing = True
        alive = self._probe()
        with self._lock:
            if alive:
                self._close_locked()
            else:
                self._noted = True
                self._retry_at = self._clock() + self._cooldown
        if alive:
            print("[+][DNS] Resolver answering again: lookups resumed")
            return True
        print("[!][DNS] Resolver still down: skipping this group's lookups")
        self._note_gap()
        return False

    def note_skipped(self, hostname: str) -> None:
        """A lookup skipped because the latch is open: nothing re-checked this
        host, so its findings are kept for every source (the note_degraded
        default for hosts). Once per host per group."""
        if not hostname:
            return
        with self._lock:
            if hostname in self._skipped:
                return
            self._skipped.add(hostname)
        try:
            from recon.helpers import circuit_breaker as cb
            cb.note_degraded("domain_recon", hosts=[hostname], host_source="dns",
                             reason="DNS resolver down")
        except Exception:  # noqa: BLE001
            pass

    def _close_locked(self):
        self._open = False
        self._noted = False
        self._cooldown = RESOLVER_COOLDOWN_S
        self._retry_at = 0.0
        self._probing = False

    def _probe(self) -> bool:
        """One canary probe; the caller set _probing."""
        try:
            return self._canary_responds()
        finally:
            with self._lock:
                self._probing = False

    @staticmethod
    def _note_gap():
        try:
            from recon.helpers import circuit_breaker as cb
            cb.note_degraded("domain_recon", sources=["dns"], reason="DNS resolver down")
        except Exception:  # noqa: BLE001
            pass

    def _canary_responds(self) -> bool:
        """True if the canary root gets ANY definitive DNS response (even
        NXDOMAIN = the resolver is reachable); False on a transient failure."""
        with self._lock:
            canary = self._canary
        if not canary:
            return True  # no canary yet -> cannot blame the resolver
        import dns.resolver
        try:
            dns.resolver.resolve(canary, 'A', lifetime=5)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return True
        except Exception:  # noqa: BLE001 - Timeout / NoNameservers / etc.
            return False

    def note_transient(self) -> bool:
        """Record a transient resolution failure. Returns True when the resolver
        is now considered DOWN (the caller should stop retrying this group).
        One thread asks the canary at a time; the others retry as usual."""
        if not _cb_enabled():
            return False
        with self._lock:
            if self._open:
                return True
            if self._canary is None:
                return False  # can't distinguish a dead resolver from a dead name
            if self._probing:
                return False
            self._probing = True
        if self._probe():
            return False  # resolver is fine; this specific name is unreachable
        with self._lock:
            self._open = True
            self._cooldown = RESOLVER_COOLDOWN_S
            self._retry_at = self._clock() + self._cooldown
            noted = self._noted
            self._noted = True
        if not noted:
            print("[!][DNS] Resolver appears down (canary root did not answer) - "
                  "skipping remaining lookups this group")
            self._note_gap()
        return True


resolver_breaker = _ResolverBreaker()


# ---------------------------------------------------------------------------
# Per-source subdomain breakers (crt.sh / HackerTarget / subfinder / knockpy /
# amass / puredns). One call per root, repeated every Domain-batch group, so a
# source that failed in group 1 is skipped in the rest instead of failing again.
# ---------------------------------------------------------------------------
def _source_breaker(name: str):
    if not _cb_enabled():
        return None
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.get_breaker(f"subsrc:{name}", label="Subdomains",
                              threshold=cb.INTERNAL_THRESHOLD)
    except Exception:  # noqa: BLE001
        return None


def _source_skipped(name: str, label: str) -> bool:
    b = _source_breaker(name)
    if b is None:
        return False
    try:
        if not b.allow():
            print(f"[-][{label}] paused this run after repeated failures - skipping")
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _source_record(name: str, outcome, detail: str = "") -> None:
    b = _source_breaker(name)
    if b is None:
        return
    try:
        b.record(outcome, detail=detail)
    except Exception:  # noqa: BLE001
        pass


def _outcome(name: str):
    from recon.helpers import circuit_breaker as cb
    return getattr(cb.Outcome, name)


def _annotate_ai_service_hint(dns_entry: dict, settings: dict | None) -> None:
    """Apply AI surface recon TXT/NS hint to a per-host DNS result.

    Mutates ``dns_entry`` in place, setting ``ai_service_hint`` to the matched
    provider name (e.g. ``"anthropic"``, ``"replicate"``, ``"huggingface"``)
    when a TXT record matches the AI vendor catalogue, or to
    ``"ai-hosting-candidate"`` when only an NS hint fires. The TXT hint always
    wins — the NS branch only runs if no TXT match was found, because Vercel /
    Netlify / Replit / Modal host plenty of non-AI sites.

    No-op when ``settings`` is None (e.g. legacy test harnesses) or when both
    toggles are off. An empty dict means "use defaults" — both toggles default
    True per the integration plan's "default-coverage" rule.
    """
    if settings is None:
        return
    txt_on = settings.get('DOMAIN_RECON_AI_TXT_HINT_ENABLED', True)
    ns_on = settings.get('DOMAIN_RECON_AI_NS_HINT_ENABLED', True)
    if not (txt_on or ns_on):
        return

    records = (dns_entry or {}).get('records') or {}
    hint: str | None = None

    if txt_on:
        for value in (records.get('TXT') or []):
            matched = match_ai_txt_hint(value)
            if matched:
                hint = matched
                break  # first-match wins; AI_TXT_PATTERNS is ordered by strength

    if not hint and ns_on:
        for value in (records.get('NS') or []):
            if match_ai_ns_hint(value):
                hint = 'ai-hosting-candidate'
                break

    if hint:
        dns_entry['ai_service_hint'] = hint


def query_crtsh(domain: str, settings: dict = None) -> dict:
    """Query crt.sh certificate transparency logs for subdomains.

    Thread-safe: creates its own requests.Session.

    When crt.sh gives no answer (it is paused, answers a non-200, or the call
    raises) the names come from crt.name instead - see query_crtname.

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}

    if not settings.get('CRTSH_ENABLED', True):
        print(f"[-][crt.sh] Disabled — skipping")
        return {}

    if _source_skipped("crtsh", "crt.sh"):
        return query_crtname(domain, settings)

    sourced = {}
    answered = False
    session = requests.Session()
    try:
        print(f"[*][crt.sh] Querying certificate transparency logs...")
        crtsh_subs = set()
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        if resp.status_code == 200:
            for entry in resp.json():
                for sub in entry['name_value'].lower().split('\n'):
                    sub = sub.strip()
                    # name_value lists every SAN, email ones too: an address
                    # under the root would otherwise pass the "ends with
                    # .<root>" scope test and become a Subdomain.
                    if sub and not sub.startswith('*.') and '@' not in sub:
                        crtsh_subs.add(sub)
            max_results = settings.get('CRTSH_MAX_RESULTS', 5000)
            if len(crtsh_subs) > max_results:
                crtsh_subs = set(sorted(crtsh_subs)[:max_results])
                print(f"[*][crt.sh] Capped at {max_results} results")
            print(f"[+][crt.sh] Found {len(crtsh_subs)} subdomains")
            for s in crtsh_subs:
                sourced.setdefault(s, set()).add("crt.sh")
            _source_record("crtsh", _outcome("OK"))
            answered = True
        else:
            # requests does not raise on 4xx/5xx, so without this a 502 - which
            # crt.sh returns regularly - produced NO line at all: not a success,
            # not an error. The source simply vanished from the run, which reads
            # exactly like "this domain has no CT entries" or "crt.sh is off".
            print(f"[!][crt.sh] HTTP {resp.status_code} - no results from this "
                  f"source (it is degraded, not empty)")
            _source_record("crtsh",
                           _outcome("RATE_LIMIT") if resp.status_code == 429 else _outcome("TRANSIENT"),
                           detail=f"HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!][crt.sh] Error: {e}")
        _source_record("crtsh", _outcome("TRANSIENT"), detail=type(e).__name__)
    finally:
        session.close()

    if not answered:
        return query_crtname(domain, settings)
    return sourced


# ---------------------------------------------------------------------------
# crt.name - the fallback for crt.sh
# ---------------------------------------------------------------------------
# crt.sh answers 502 for hours at a stretch, and origin discovery has no other
# keyless certificate source. crt.name serves the same kind of name list from
# its own index, but its free tier is 100 requests per IP per day and a refused
# request is charged too. So it is asked only when crt.sh gave no answer, once
# per name per run, and not again once the day's quota is spent.
CRTNAME_URL = "https://crt.name/v1/search"
CRTNAME_TIMEOUT_S = 20
# crt.name serves a domain with 200,000 names as one answer, so the answer is
# read as a stream and cut at whichever of these comes first. 50,000 is the
# highest value CRTSH_MAX_RESULTS accepts: no caller can use more names.
CRTNAME_MAX_NAMES = 50_000
CRTNAME_MAX_BYTES = 32 * 1024 * 1024
CRTNAME_DEADLINE_S = 90
_CRTNAME_HOST = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
# The 400 crt.name answers to a name that is not a registrable domain names the
# one it would accept: "invalid apex: not an apex (eTLD+1 is example.com)".
_CRTNAME_APEX_HINT = re.compile(r"etld\+1 is ([a-z0-9-]+(?:\.[a-z0-9-]+)+)")
# One lookup at a time: origin discovery asks for the same registrable domain
# from several host threads at once, and each would spend a request before the
# first answer reached the cache.
_crtname_lock = threading.Lock()
# Run-cache key for "today's quota is spent". A tuple, so it cannot collide with
# a root. Kept beside the answers and not only in the breaker, so the stop holds
# with RECON_CIRCUIT_BREAKERS=off too.
_CRTNAME_QUOTA_SPENT = ("quota spent",)


def _crtname_remaining(resp):
    """Requests left today, from ``x-ratelimit-remaining``; None when unreadable.

    Reads the leading integer, so a header a proxy repeated ("0, 0") still counts.
    """
    try:
        match = re.match(r"\s*(\d+)", str(resp.headers.get("x-ratelimit-remaining")))
        return int(match.group(1)) if match else None
    except Exception:  # noqa: BLE001
        return None


def _crtname_chunks(resp, size: int = 65536):
    """The decoded body, each piece handed over as soon as some bytes arrive.

    iter_content waits until a whole chunk has arrived, so a peer sending a few
    bytes a second - never idle long enough to trip the read timeout - would
    hold the read, and the lock, far past the deadline. read1 returns after one
    receive; it is absent before urllib3 2.0, where iter_content has to do.
    """
    read1 = getattr(getattr(resp, "raw", None), "read1", None)
    if not callable(read1):
        yield from resp.iter_content(chunk_size=size)
        return
    while True:
        chunk = read1(size, decode_content=True)
        if not chunk:
            return
        yield chunk


def _crtname_apex_hint(resp, domain: str) -> str:
    """The registrable domain a 400 names, when it is a parent of ``domain``.

    Reads the first 512 bytes only: the body is a third party's, and unbounded.
    """
    try:
        head = next(_crtname_chunks(resp, 512), b"")[:512]
        match = _CRTNAME_APEX_HINT.search(head.decode("ascii", "ignore").lower())
    except Exception:  # noqa: BLE001
        return ""
    apex = match.group(1) if match else ""
    return apex if apex and domain.endswith("." + apex) else ""


def _crtname_read(resp, domain: str):
    """Stream a crt.name answer (one hostname per line) into the names at or under ``domain``.

    Returns (names, cut): the names in the order served, and whether reading
    stopped at a ceiling before the answer ended. Raises when the answer is
    still arriving at the deadline: that is a failure, not a short answer.
    """
    names = {}
    pending = b""
    size = 0
    cut = False
    deadline = time.monotonic() + CRTNAME_DEADLINE_S

    def keep(raw: bytes) -> None:
        try:
            name = raw.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            return
        if len(name) <= 253 and _CRTNAME_HOST.match(name) \
                and (name == domain or name.endswith("." + domain)):
            names[name] = None

    for chunk in _crtname_chunks(resp):
        if time.monotonic() > deadline:
            raise TimeoutError("answer still arriving at the deadline")
        size += len(chunk)
        lines = (pending + chunk).split(b"\n")
        pending = lines.pop()
        for raw in lines:
            keep(raw)
        if len(names) >= CRTNAME_MAX_NAMES or size > CRTNAME_MAX_BYTES:
            cut = True
            break
    else:
        keep(pending)
    return list(names)[:CRTNAME_MAX_NAMES], cut


def _crtname_get(session, apex: str):
    return session.get(CRTNAME_URL, params={"apex": apex},
                       timeout=CRTNAME_TIMEOUT_S, stream=True)


def _crtname_fetch(domain: str):
    """One crt.name lookup. Returns (names, quota_spent).

    ``names`` is the names under ``domain``, or None when there was no answer.
    An answer - names, none, or a refusal of the name itself - is a list the
    caller caches for the run. A failure is None and is never cached, so a
    later call can retry it. ``quota_spent`` says the next request today
    would be refused.
    """
    session = requests.Session()
    try:
        print("[*][crt.name] crt.sh gave no answer - querying crt.name instead...")
        resp = _crtname_get(session, domain)
        if resp.status_code == 400:
            # crt.name searches registrable domains only. For a root that is a
            # subdomain, ask for the parent it names; _crtname_read keeps only
            # what sits under the root.
            apex = _crtname_apex_hint(resp, domain)
            if apex:
                resp.close()
                resp = _crtname_get(session, apex)

        code = resp.status_code
        if code == 200:
            # A 200 that declares another type (a proxy's or portal's page) must
            # fail here, or its lines would be read as "no names" and cached.
            declared = str(resp.headers.get("content-type") or "").lower()
            if declared and not declared.startswith("text/plain"):
                raise ValueError("the answer is not a plain-text name list")
            names, cut = _crtname_read(resp, domain)
            if cut:
                print(f"[*][crt.name] The answer is too large to read whole - kept its first {len(names)} names")
            remaining = _crtname_remaining(resp)
            quota = "" if remaining is None else f" ({remaining} requests left today)"
            print(f"[+][crt.name] Found {len(names)} subdomains{quota}")
            _source_record("crtname", _outcome("OK" if names else "NO_DATA"))
            if remaining == 0:
                # Stop before the request that is certain to be refused.
                _source_record("crtname", _outcome("FATAL"), detail="daily quota reached")
            return names, remaining == 0
        if code in (400, 413):
            # An answer about the name, not a fault of the source: it must not
            # count toward pausing crt.name, and asking again would only spend
            # another request on the same refusal. 413 is crt.name declining a
            # domain with more names than it serves in one answer. A 404 is not
            # in this set: an unknown name answers 200, so a 404 means the
            # endpoint moved, which is a fault.
            why = ("has too many names for crt.name to serve" if code == 413
                   else "is not a name crt.name can search")
            print(f"[-][crt.name] HTTP {code} - this domain {why}; no fallback for it")
            _source_record("crtname", _outcome("NO_DATA"), detail=f"HTTP {code}")
            return [], False
        if code == 429 and _crtname_remaining(resp) == 0:
            # The daily quota does not come back within a breaker cooldown, so
            # this stops the source for the run instead of pausing it.
            print("[!][crt.name] HTTP 429 - daily quota reached, no results from this source")
            _source_record("crtname", _outcome("FATAL"), detail="daily quota reached")
            return None, True
        print(f"[!][crt.name] HTTP {code} - no results from this source (it is degraded, not empty)")
        _source_record("crtname",
                       _outcome("RATE_LIMIT") if code == 429 else _outcome("TRANSIENT"),
                       detail=f"HTTP {code}")
        return None, False
    except Exception as e:
        print(f"[!][crt.name] Error: {e}")
        _source_record("crtname", _outcome("TRANSIENT"), detail=type(e).__name__)
        return None, False
    finally:
        session.close()


def query_crtname(domain: str, settings: dict = None) -> dict:
    """Ask crt.name for the names under ``domain``: the fallback for crt.sh.

    Thread-safe, never raises. Returns {subdomain: {"crt.name"}}, the shape
    query_crtsh returns, in the order crt.name served the names. Only names at
    or under ``domain`` are kept, so a root that is itself a subdomain never
    drags its siblings in as external domains.
    """
    try:
        return _query_crtname(domain, settings or {})
    except Exception as e:  # noqa: BLE001 - a fallback must not fail the discovery fan-out
        print(f"[!][crt.name] Error: {e}")
        return {}


def _query_crtname(domain, settings: dict) -> dict:
    root = str(domain or "").strip().lower().strip(".")
    # A single-label or IP-shaped root can only be refused, and a refusal is
    # charged against the quota like any other request.
    if len(root) > 253 or not _CRTNAME_HOST.match(root) or root.rsplit(".", 1)[-1].isdigit():
        print("[-][crt.name] Not a domain name crt.name can search - skipping")
        return {}

    # crt.name searches registrable domains: asking for a deeper scan root
    # spends a refused request first. Ask the org once per run, and keep the
    # names under this root.
    from recon.helpers.public_suffix import org_domain
    scan_root, root = root, (org_domain(root) or root)

    from recon.helpers import circuit_breaker as cb
    cache = cb.run_cache("crtname")
    with _crtname_lock:
        hit, names = cache.get(root)
        if hit:
            # Neutral on purpose: an earlier refusal is cached as no names, and
            # "found 0" would read as "this domain has none".
            print(f"[*][crt.name] Reusing this run's earlier answer: {len(names)} subdomains")
        elif cache.get(_CRTNAME_QUOTA_SPENT)[0]:
            print("[-][crt.name] daily quota reached - skipping")
            return {}
        elif _source_skipped("crtname", "crt.name"):
            return {}
        else:
            names, quota_spent = _crtname_fetch(root)
            if quota_spent:
                cache.put(_CRTNAME_QUOTA_SPENT, True)
            if names is None:
                return {}
            cache.put(root, names)

    if scan_root != root:
        names = [n for n in names if n == scan_root or n.endswith("." + scan_root)]

    # The first names as served, not the first alphabetically: origin discovery
    # reads the first 500, and a sorted list would hand it only the names that
    # start with a digit or an "a".
    max_results = settings.get('CRTSH_MAX_RESULTS', 5000)
    if len(names) > max_results:
        names = names[:max_results]
        print(f"[*][crt.name] Capped at {max_results} results")
    return {name: {"crt.name"} for name in names}


def query_hackertarget(domain: str, settings: dict = None) -> dict:
    """Query HackerTarget API for subdomains.

    Thread-safe: creates its own requests.Session.

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}

    if not settings.get('HACKERTARGET_ENABLED', True):
        print(f"[-][HackerTarget] Disabled — skipping")
        return {}

    if _source_skipped("hackertarget", "HackerTarget"):
        return {}

    sourced = {}
    session = requests.Session()
    try:
        print(f"[*][HackerTarget] Querying host search API...")
        ht_subs = set()
        resp = session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        body_lower = resp.text.lower()
        if resp.status_code == 200 and "error" not in body_lower:
            for line in resp.text.strip().split('\n'):
                if ',' in line:
                    ht_subs.add(line.split(',')[0].strip())
            max_results = settings.get('HACKERTARGET_MAX_RESULTS', 5000)
            if len(ht_subs) > max_results:
                ht_subs = set(sorted(ht_subs)[:max_results])
                print(f"[*][HackerTarget] Capped at {max_results} results")
            print(f"[+][HackerTarget] Found {len(ht_subs)} subdomains")
            for s in ht_subs:
                sourced.setdefault(s, set()).add("hackertarget")
            _source_record("hackertarget", _outcome("OK"))
        elif resp.status_code == 429 or "api count exceeded" in body_lower or "rate" in body_lower:
            # HackerTarget's free tier caps daily calls; the body says so on a
            # 200. Escalate to RATE_LIMIT so the source is paused, not retried.
            print(f"[!][HackerTarget] Rate-limited (HTTP {resp.status_code}) - source degraded, not empty")
            _source_record("hackertarget", _outcome("RATE_LIMIT"), detail=f"HTTP {resp.status_code}")
        else:
            # A non-200 (or an "error" body) used to print nothing, so the source
            # silently vanished and read as "0 subdomains". Say it failed.
            print(f"[!][HackerTarget] HTTP {resp.status_code} - source failed (degraded, not empty)")
            _source_record("hackertarget", _outcome("TRANSIENT"), detail=f"HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!][HackerTarget] Error: {e}")
        _source_record("hackertarget", _outcome("TRANSIENT"), detail=type(e).__name__)
    finally:
        session.close()

    return sourced


def get_passive_subdomains(domain: str, session, settings: dict = None) -> dict:
    """Combine crt.sh and HackerTarget passive discovery (legacy sequential wrapper).

    Returns dict {subdomain: set_of_sources} for per-source attribution.
    """
    if settings is None:
        settings = {}
    sourced = {}
    for s, sources in query_crtsh(domain, settings=settings).items():
        sourced.setdefault(s, set()).update(sources)
    for s, sources in query_hackertarget(domain, settings=settings).items():
        sourced.setdefault(s, set()).update(sources)
    return sourced


def run_knockpy(domain: str, bruteforce: bool = False, settings: dict = None) -> set:
    """Run Knockpy to get subdomains."""
    if settings is None:
        settings = {}

    # Check if Knockpy recon mode is enabled
    if not settings.get('KNOCKPY_RECON_ENABLED', True) and not bruteforce:
        print(f"[-][Knockpy] Disabled — skipping")
        return set()

    if _source_skipped("knockpy", "Knockpy"):
        return set()

    subdomains = set()
    mode = "recon + bruteforce" if bruteforce else "recon only"
    print(f"[*][Knockpy] Running ({mode})...")

    command = ['knockpy', '-d', domain, '--recon']
    if bruteforce:
        command.append('--bruteforce')

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        # A non-zero exit means the tool failed; parsing its stdout would print
        # "Found 0 subdomains" and hide the failure. Record it and stop here.
        if result.returncode != 0:
            tail = (result.stderr or "").strip().splitlines()[-1:] or ["no stderr"]
            print(f"[!][Knockpy] Failed (exit {result.returncode}): {tail[0][:200]}")
            _source_record("knockpy", _outcome("TRANSIENT"), detail=f"exit {result.returncode}")
            return set()

        # Strip ANSI color codes from output before parsing
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean_output = ansi_escape.sub('', result.stdout.lower())

        # Extract everything that looks like a subdomain
        matches = re.findall(r'([\w.-]+\.' + re.escape(domain) + r')', clean_output)
        subdomains.update(matches)

        max_results = settings.get('KNOCKPY_RECON_MAX_RESULTS', 5000)
        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Knockpy] Capped at {max_results} results")
        _source_record("knockpy", _outcome("OK"))
        if subdomains:
            print(f"[+][Knockpy] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Knockpy] Found 0 subdomains")

    except subprocess.TimeoutExpired:
        print("[!][Knockpy] Timed out")
        _source_record("knockpy", _outcome("TRANSIENT"), detail="timeout")
    except FileNotFoundError:
        print("[!][Knockpy] Not installed (pip install knockpy)")
    except Exception as e:
        print(f"[!][Knockpy] Error: {e}")
        _source_record("knockpy", _outcome("TRANSIENT"), detail=type(e).__name__)
    finally:
        # Clean up knockpy's auto-generated files
        for f in glob.glob(str(PROJECT_ROOT / f"{domain}_*.json")):
            try:
                Path(f).unlink()
            except Exception:
                pass
    
    return subdomains


def run_subfinder(domain: str, settings: dict = None) -> set:
    """Run Subfinder passive subdomain enumeration via Docker."""
    if settings is None:
        settings = {}

    if not settings.get('SUBFINDER_ENABLED', True):
        print(f"[-][Subfinder] Disabled — skipping")
        return set()

    docker_image = settings.get('SUBFINDER_DOCKER_IMAGE', 'projectdiscovery/subfinder:latest')
    max_results = settings.get('SUBFINDER_MAX_RESULTS', 5000)

    print(f"[*][Subfinder] Running passive enumeration...")

    command = [
        'docker', 'run', '--rm',
        docker_image,
        '-d', domain,
        '-json', '-silent',
        '-timeout', '30',
        '-max-time', '10',
    ]

    if _source_skipped("subfinder", "Subfinder"):
        return set()

    from recon.helpers.docker_helpers import run_tool_container
    subdomains = set()
    try:
        result = run_tool_container(command, tool="subfinder", timeout=720)

        if not result.timed_out and result.returncode != 0:
            tail = (result.stderr or "").strip().splitlines()[-1:] or ["no stderr"]
            print(f"[!][Subfinder] Failed (exit {result.returncode}): {tail[0][:200]}")
            _source_record("subfinder", _outcome("TRANSIENT"), detail=f"exit {result.returncode}")
            return set()

        # A cut-short run's last line may be a half-written object: it does not parse.
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get('host', '').strip().lower()
                if host:
                    subdomains.add(host)
            except json.JSONDecodeError:
                continue

        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Subfinder] Capped at {max_results} results")

        if result.timed_out:
            print(f"[!][Subfinder] Timed out: stopped it, keeping the {len(subdomains)} "
                  f"subdomain(s) it printed")
            _source_record("subfinder", _outcome("TRANSIENT"), detail="timeout")
            return subdomains

        _source_record("subfinder", _outcome("OK"))
        if subdomains:
            print(f"[+][Subfinder] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Subfinder] Found 0 subdomains")

    except FileNotFoundError:
        print("[!][Subfinder] Docker not found — cannot run")
    except Exception as e:
        print(f"[!][Subfinder] Error: {e}")
        _source_record("subfinder", _outcome("TRANSIENT"), detail=type(e).__name__)

    return subdomains


def _atomic_install(dst: Path, write) -> None:
    """Have `write(tmp)` build the file under a temp name in dst's directory, then
    os.replace() it over dst, so a concurrent scan reading dst sees the old file
    or the new one, never half of one. 0644 because the sibling tool containers
    that mount it do not necessarily run as root."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f".{dst.name}.{uuid.uuid4().hex[:12]}.tmp")
    try:
        write(tmp)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


# Same pinned gist revision as recon/Dockerfile, so a fetched copy matches a baked one.
JHADDIX_WORDLIST_URL = (
    "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056"
    "/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt"
)
# Baked outside /app/recon: the host's recon/ is bind-mounted over /app/recon.
JHADDIX_BAKED_PATH = '/opt/redamon/wordlists/jhaddix-all.txt'
# /app/recon/wordlists IS the host's recon/wordlists, and the Amass sibling
# container mounts the list by host path, so this is where it must exist.
JHADDIX_WORDLIST_PATH = '/app/recon/wordlists/jhaddix-all.txt'


def _download_jhaddix_wordlist(dst: Path) -> None:
    with requests.get(JHADDIX_WORDLIST_URL, stream=True, timeout=(15, 120)) as resp:
        resp.raise_for_status()
        with open(dst, 'wb') as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    if dst.stat().st_size == 0:
        raise ValueError("empty download")


def _ensure_jhaddix_wordlist() -> bool:
    """Put jhaddix all.txt in recon/wordlists/ if it is not there yet. Never raises."""
    installed = Path(JHADDIX_WORDLIST_PATH)
    if installed.is_file():
        return True
    try:
        if os.path.isfile(JHADDIX_BAKED_PATH):
            print("[*][Amass] Copying the image's jhaddix all.txt into recon/wordlists/ (first use)")
            _atomic_install(installed, lambda tmp: shutil.copy2(JHADDIX_BAKED_PATH, tmp))
        else:
            print("[*][Amass] jhaddix all.txt is not in this image - downloading it (first use)")
            _atomic_install(installed, _download_jhaddix_wordlist)
        return True
    except Exception as e:  # noqa: BLE001 - Amass still runs with its built-in list
        print(f"[!][Amass] Could not provide jhaddix all.txt: {type(e).__name__}: {e}")
        return False


def run_amass(domain: str, settings: dict = None) -> set:
    """Run OWASP Amass subdomain enumeration via Docker."""
    if settings is None:
        settings = {}

    if not settings.get('AMASS_ENABLED', False):
        print(f"[-][Amass] Disabled — skipping")
        return set()

    docker_image = settings.get('AMASS_DOCKER_IMAGE', 'caffix/amass:latest')
    max_results = settings.get('AMASS_MAX_RESULTS', 5000)
    timeout_min = settings.get('AMASS_TIMEOUT', 10)
    active = settings.get('AMASS_ACTIVE', False)
    brute = settings.get('AMASS_BRUTE', False)

    mode_parts = ["active" if active else "passive"]
    if brute:
        mode_parts.append("brute")
    mode = "+".join(mode_parts)
    print(f"[*][Amass] Running enumeration ({mode})...")

    # Amass v4 needs a writable config dir. One per run: concurrent scans share
    # /tmp/redamon, and the dir is deleted when the run ends.
    amass_temp = Path(f"/tmp/redamon/.amass_temp_{uuid.uuid4().hex[:12]}")
    amass_temp.mkdir(parents=True, exist_ok=True)

    # For the Amass sibling container, we need the HOST path.
    # HOST_RECON_OUTPUT_PATH = <host_project>/recon/output
    # parent = <host_project>/recon
    # wordlist = <host_project>/recon/wordlists/jhaddix-all.txt
    host_recon_output = os.environ.get('HOST_RECON_OUTPUT_PATH', '')
    if host_recon_output:
        host_recon_dir = os.path.dirname(host_recon_output)
        wordlist_host_path = os.path.join(host_recon_dir, 'wordlists', 'jhaddix-all.txt')
    else:
        wordlist_host_path = ''

    brute_wordlists = settings.get('AMASS_BRUTE_WORDLISTS', ['default'])

    command = [
        'docker', 'run', '--rm',
        '-v', f'{amass_temp}:/root/.config/amass',
        docker_image,
        'enum', '-d', domain,
        '-timeout', str(timeout_min),
    ]

    if active:
        command.append('-active')
    if brute:
        command.append('-brute')
        jhaddix_selected = 'jhaddix-all' in brute_wordlists
        if jhaddix_selected and wordlist_host_path and _ensure_jhaddix_wordlist():
            # Insert volume mount BEFORE the docker image name in the command
            img_idx = command.index(docker_image)
            command.insert(img_idx, f'{wordlist_host_path}:/wordlist/jhaddix-all.txt:ro')
            command.insert(img_idx, '-v')
            command += ['-w', '/wordlist/jhaddix-all.txt']
            print(f"[*][Amass] Using jhaddix all.txt wordlist (~2.18M entries) for brute force")
        else:
            if jhaddix_selected:
                reason = ("the file is unavailable" if wordlist_host_path
                          else "HOST_RECON_OUTPUT_PATH is unset, so it cannot be mounted")
                print(f"[!][Amass] WARNING: jhaddix all.txt was selected but {reason}; "
                      f"falling back to the built-in wordlist")
            print(f"[*][Amass] Using Amass built-in wordlist (~8K entries) for brute force")

    if _source_skipped("amass", "Amass"):
        shutil.rmtree(amass_temp, ignore_errors=True)
        return set()

    from recon.helpers.docker_helpers import run_tool_container
    subdomains = set()
    try:
        result = run_tool_container(command, tool="amass", timeout=(timeout_min * 60) + 120)

        if not result.timed_out and result.returncode != 0:
            tail = (result.stderr or "").strip().splitlines()[-1:] or ["no stderr"]
            print(f"[!][Amass] Failed (exit {result.returncode}): {tail[0][:200]}")
            _source_record("amass", _outcome("TRANSIENT"), detail=f"exit {result.returncode}")
            return set()

        # Output format: "name (FQDN) --> record_type --> target (FQDN)"
        # Capture ALL FQDNs per line (both source and target can be subdomains).
        # A name counts only once its "(FQDN)" follows it, so a name the
        # timeout's kill cut short is never taken.
        fqdn_pattern = re.compile(r'([\w.\-]+)\s+\(FQDN\)')
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            for match in fqdn_pattern.finditer(line):
                host = match.group(1).strip().lower()
                if host:
                    subdomains.add(host)

        if len(subdomains) > max_results:
            subdomains = set(sorted(subdomains)[:max_results])
            print(f"[*][Amass] Capped at {max_results} results")

        if result.timed_out:
            print(f"[!][Amass] Timed out: stopped it, keeping the {len(subdomains)} "
                  f"subdomain(s) it printed")
            _source_record("amass", _outcome("TRANSIENT"), detail="timeout")
            return subdomains

        _source_record("amass", _outcome("OK"))
        if subdomains:
            print(f"[+][Amass] Found {len(subdomains)} subdomains")
        else:
            print(f"[*][Amass] Found 0 subdomains")

    except FileNotFoundError:
        print("[!][Amass] Docker not found — cannot run")
    except Exception as e:
        print(f"[!][Amass] Error: {e}")
        _source_record("amass", _outcome("TRANSIENT"), detail=type(e).__name__)
    finally:
        shutil.rmtree(amass_temp, ignore_errors=True)

    return subdomains


def dns_lookup_single(hostname: str, rtype: str, max_retries: int = 3) -> list:
    """
    Perform DNS lookup for a single record type with retry logic.

    Args:
        hostname: Domain or subdomain to resolve
        rtype: DNS record type (A, AAAA, MX, etc.)
        max_retries: Maximum retry attempts

    Returns:
        List of DNS records or None if not found/failed
    """
    
    # A resolver already proven down this group: skip immediately, don't retry
    # into a timeout wall (inert under the off switch).
    if resolver_breaker.is_open():
        resolver_breaker.note_skipped(hostname)
        return None

    definitive = _dns_definitive_errors()

    for attempt in range(max_retries):
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            return [rr.to_text() for rr in answers]
        except definitive:
            # A definitive "does not resolve" answer - not a resolver fault,
            # never retried.
            return None
        except (dns.resolver.NoNameservers, dns.resolver.Timeout,
                dns.resolver.LifetimeTimeout) as e:
            # Transient. The canary decides whether the resolver itself is down;
            # if so, stop retrying every remaining record type/host this group.
            if resolver_breaker.note_transient():
                resolver_breaker.note_skipped(hostname)
                return None
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                time.sleep(delay)
                continue
            return None
        except Exception:
            # An unexpected resolver error is treated as transient (canary-gated)
            # but a dns.name syntax error was already handled above.
            if resolver_breaker.note_transient():
                resolver_breaker.note_skipped(hostname)
                return None
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                time.sleep(delay)
                continue
            return None

    return None


def dns_lookup(hostname: str, max_retries: int = 3, parallel: bool = True) -> dict:
    """
    Perform full DNS lookup for all record types with retry logic.

    Args:
        hostname: Domain or subdomain to resolve
        max_retries: Maximum retry attempts per record type
        parallel: Query all 7 record types concurrently (default True)

    Returns:
        Dictionary with all DNS records
    """

    dns_data = {}

    if parallel and len(DNS_RECORD_TYPES) > 1:
        with ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES)) as executor:
            future_to_rtype = {
                executor.submit(dns_lookup_single, hostname, rtype, max_retries): rtype
                for rtype in DNS_RECORD_TYPES
            }
            for future in as_completed(future_to_rtype):
                rtype = future_to_rtype[future]
                try:
                    dns_data[rtype] = future.result()
                except Exception:
                    dns_data[rtype] = None
    else:
        for rtype in DNS_RECORD_TYPES:
            dns_data[rtype] = dns_lookup_single(hostname, rtype, max_retries)

    # Extract IPs for convenience
    ips = {
        "ipv4": dns_data.get("A") or [],
        "ipv6": dns_data.get("AAAA") or []
    }

    return {
        "records": dns_data,
        "ips": ips,
        "has_records": any(v for v in dns_data.values() if v)
    }


def _ownership_txt(record_name: str, max_retries: int = 3):
    """The TXT records at `record_name`, as ``(records, failed)``.

    ``(None, False)`` is a definite "no record" (NXDOMAIN, no answer);
    ``(None, True)`` means the lookup itself failed. dns_lookup_single answers
    None for both, which is fine for discovery and wrong for ownership.
    """
    if resolver_breaker.is_open():
        return None, True
    definitive = _dns_definitive_errors()
    for attempt in range(max_retries):
        try:
            return [rr.to_text() for rr in dns.resolver.resolve(record_name, "TXT")], False
        except definitive:
            return None, False
        except Exception:  # noqa: BLE001 - every other failure is the resolver's
            if resolver_breaker.note_transient():
                return None, True
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    return None, True


def verify_domain_ownership(domain: str, token: str, txt_prefix: str = "_redamon-verify") -> dict:
    """
    Verify domain ownership via DNS TXT record.

    Checks for a TXT record at {txt_prefix}.{domain} containing "redamon-verify={token}".

    Args:
        domain: Root domain to verify (e.g., "example.com")
        token: Expected ownership token
        txt_prefix: DNS record prefix (default: "_redamon-verify")

    Returns:
        Dictionary with:
        - verified: True if ownership verified, False otherwise
        - record_name: Full DNS record name checked
        - expected_value: The value we're looking for
        - found_values: List of TXT values found (if any)
        - error: Error message if verification failed
        - resolver_failed: True when the lookup itself failed, so the answer is
          not "no record" and must never be cached or read as one
    """
    record_name = f"{txt_prefix}.{domain}"
    expected_value = f"redamon-verify={token}"

    result = {
        "verified": False,
        "record_name": record_name,
        "expected_value": expected_value,
        "found_values": [],
        "error": None,
        "resolver_failed": False,
    }

    print(f"[*][DNS] Verifying domain ownership: {record_name}")

    try:
        txt_records, failed = _ownership_txt(record_name)

        if txt_records is None:
            # A resolver that is down must not read as "no TXT record": that
            # would abort with the wrong instruction, and a caller caching the
            # answer would keep it for the whole run.
            if failed:
                result["error"] = "DNS resolver down - cannot verify ownership (retry later)"
                result["resolver_failed"] = True
            else:
                result["error"] = f"No TXT record found at {record_name}"
            return result

        # Clean up TXT records (remove quotes)
        cleaned_records = []
        for record in txt_records:
            cleaned = record.strip('"').strip("'")
            cleaned_records.append(cleaned)

        result["found_values"] = cleaned_records

        # Check if expected value is in the records
        if expected_value in cleaned_records:
            result["verified"] = True
            print(f"[+][DNS] Domain ownership verified")
        else:
            result["error"] = f"TXT record found but value doesn't match"

    except Exception as e:
        result["error"] = f"DNS lookup failed: {str(e)}"
        result["resolver_failed"] = True

    return result


def resolve_all_dns(domain: str, subdomains: list, max_workers: int = 20, record_parallelism: bool = True, settings: dict = None) -> dict:
    """
    Resolve DNS for domain and all subdomains using parallel workers.

    Args:
        domain: Root domain
        subdomains: List of discovered subdomains
        max_workers: Max concurrent DNS resolution threads (default: 20)
        record_parallelism: Query 7 record types in parallel per host (default: True)
        settings: Optional settings dict; when provided, AI surface recon TXT/NS
            hint annotation runs against each resolved host (gated by
            DOMAIN_RECON_AI_TXT_HINT_ENABLED / DOMAIN_RECON_AI_NS_HINT_ENABLED).

    Returns:
        Dictionary with DNS data for domain and each subdomain
    """
    subs_to_resolve = [s for s in subdomains if s != domain]
    print(f"\n[*][DNS] Resolving {len(subs_to_resolve) + 1} hosts ({max_workers} parallel workers)...")

    result = {
        "domain": {},
        "subdomains": {}
    }

    # Resolve root domain first
    print(f"[*][DNS] {domain} (root)")
    result["domain"] = dns_lookup(domain, parallel=record_parallelism)
    _annotate_ai_service_hint(result["domain"], settings)
    if result["domain"]["ips"]["ipv4"]:
        print(f"[+][DNS] {domain} → {', '.join(result['domain']['ips']['ipv4'])}")
        # This root answered, so it is a good canary: a later transient failure
        # re-resolves it to tell a dead resolver from a dead name.
        resolver_breaker.set_canary(domain)

    # Resolve all subdomains in parallel
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dns") as executor:
        future_to_sub = {
            executor.submit(dns_lookup, sub, 3, record_parallelism): sub
            for sub in subs_to_resolve
        }
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            try:
                dns_result = future.result()
                _annotate_ai_service_hint(dns_result, settings)
                result["subdomains"][subdomain] = dns_result
                if dns_result["ips"]["ipv4"] or dns_result["ips"]["ipv6"]:
                    all_ips = dns_result["ips"]["ipv4"] + dns_result["ips"]["ipv6"]
                    print(f"[+][DNS] {subdomain} → {', '.join(all_ips)}")
            except Exception as e:
                print(f"[!][DNS] {subdomain}: error: {e}")
                result["subdomains"][subdomain] = {
                    "records": {}, "ips": {"ipv4": [], "ipv6": []}, "has_records": False
                }

    # Stats
    resolved_count = sum(1 for v in result["subdomains"].values() if v["has_records"])
    ai_hint_count = sum(
        1 for v in result["subdomains"].values() if v.get("ai_service_hint")
    ) + (1 if result["domain"].get("ai_service_hint") else 0)
    print(f"[+][DNS] Resolved: {resolved_count}/{len(subs_to_resolve)} subdomains")
    if settings and ai_hint_count:
        print(f"[+][DNS] AI service hint set on {ai_hint_count} host(s)")

    return result


def _refresh_shared_resolvers(src: Path, shared: Path) -> None:
    """Keep the copy puredns reads from /tmp/redamon in step with the list the
    entrypoint refreshes weekly. Replaced atomically and never deleted, because
    other scans may be reading it. Never raises."""
    try:
        if not src.is_file():
            return
        if shared.is_file() and src.stat().st_mtime <= shared.stat().st_mtime:
            return
        # copy2 carries src's mtime over, which is what marks the copy current.
        _atomic_install(shared, lambda tmp: shutil.copy2(src, tmp))
    except OSError as e:
        print(f"[!][Puredns] Could not refresh the shared resolver list: {e}")


# Why puredns was meant to run and did not, as the coverage note words it.
_PUREDNS_SKIP_REASONS = {
    "breaker_open": "paused after repeated failures",
    "no_resolvers": "no resolver list",
    "no_output": "produced no output",
    "timeout": "timed out",
    "docker_missing": "Docker not found",
    "error": "failed",
}


def _puredns_skipped(subdomains: list, reason: str) -> tuple:
    """``(subdomains, "skipped:<reason>")``, recording the cut for the report.

    Subdomains are assets, not findings, so this is a gap note with no prune
    effect; it reaches the report's Coverage Limitations block.
    """
    try:
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded("puredns", entries=[{
            "source": "puredns",
            "reason": f"{_PUREDNS_SKIP_REASONS[reason]}; names not wildcard-checked by puredns",
            "skipped": len(subdomains),
        }])
    except Exception:  # noqa: BLE001 - a lost note must not fail discovery
        pass
    return subdomains, f"skipped:{reason}"


def run_puredns_resolve(subdomains: list, domain: str, settings: dict = None) -> tuple:
    """
    Filter subdomains using puredns resolve to remove wildcards and DNS-poisoned entries.

    Runs puredns via Docker-in-Docker. Takes the combined subdomain list from all
    discovery tools, validates each entry against public DNS resolvers, and returns
    only the subdomains that are confirmed to exist (not wildcards or poisoned).

    Returns ``(names, status)``: status "filtered", or "skipped:<reason>" with the
    input list unchanged. "disabled" (configuration or stealth mode) and
    "no_input" are not cuts; every other skip is recorded as a coverage gap.
    """
    if settings is None:
        settings = {}

    if not settings.get('PUREDNS_ENABLED', True):
        print(f"[-][Puredns] Disabled — skipping wildcard filtering")
        return subdomains, "skipped:disabled"

    if not subdomains:
        print(f"[-][Puredns] No subdomains to validate")
        return subdomains, "skipped:no_input"

    if _source_skipped("puredns", "Puredns"):
        return _puredns_skipped(subdomains, "breaker_open")

    docker_image = settings.get('PUREDNS_DOCKER_IMAGE', 'frost19k/puredns:latest')
    threads = settings.get('PUREDNS_THREADS', 0)
    rate_limit = settings.get('PUREDNS_RATE_LIMIT', 0)
    wildcard_batch = settings.get('PUREDNS_WILDCARD_BATCH', 0)
    skip_validation = settings.get('PUREDNS_SKIP_VALIDATION', False)

    print(f"[*][Puredns] Validating {len(subdomains)} subdomains (wildcard filtering)...")

    # Prepare temp files in /tmp/redamon (same path inside and outside container)
    data_dir = Path("/tmp/redamon")
    data_dir.mkdir(parents=True, exist_ok=True)
    # Per-run names: two scans of the same domain would otherwise share, and then
    # delete, one input/output pair.
    run_id = uuid.uuid4().hex[:12]
    input_file = data_dir / f"puredns_input_{domain}_{run_id}.txt"
    output_file = data_dir / f"puredns_output_{domain}_{run_id}.txt"
    resolver_src = Path("/app/recon/data/resolvers.txt")
    resolver_shared = data_dir / "resolvers.txt"

    _refresh_shared_resolvers(resolver_src, resolver_shared)
    if not resolver_shared.exists():
        print(f"[!][Puredns] No resolver list found — skipping")
        return _puredns_skipped(subdomains, "no_resolvers")

    # Write input subdomain list
    with open(input_file, 'w') as f:
        f.write('\n'.join(subdomains))

    command = [
        'docker', 'run', '--rm',
        '-v', f'{data_dir}:/data',
        docker_image,
        'resolve', f'/data/{input_file.name}',
        '-r', '/data/resolvers.txt',
        '--write', f'/data/{output_file.name}',
        '-q',
    ]

    if threads > 0:
        command.extend(['-t', str(threads)])
    if rate_limit > 0:
        command.extend(['--rate-limit', str(rate_limit)])
    if wildcard_batch > 0:
        command.extend(['--wildcard-batch', str(wildcard_batch)])
    if skip_validation:
        command.append('--skip-validation')

    from recon.helpers.docker_helpers import run_tool_container
    try:
        result = run_tool_container(command, tool="puredns", timeout=600)

        if result.timed_out:
            # puredns writes its list as it goes: a cut-short list would drop
            # every name it had not reached yet.
            print("[!][Puredns] Timed out (600s): stopped it, returning the unfiltered list")
            _source_record("puredns", _outcome("TRANSIENT"), detail="timeout")
            return _puredns_skipped(subdomains, "timeout")

        if output_file.exists():
            with open(output_file, 'r') as f:
                filtered = [line.strip() for line in f if line.strip()]
            removed = len(subdomains) - len(filtered)
            print(f"[+][Puredns] Validated: {len(filtered)} real, {removed} filtered (wildcards/poisoned)")
            _source_record("puredns", _outcome("OK"))
            return filtered, "filtered"
        else:
            print(f"[!][Puredns] No output file produced — returning unfiltered list")
            if result.stderr:
                print(f"[!][Puredns] stderr: {result.stderr[:500]}")
            _source_record("puredns", _outcome("TRANSIENT"),
                           detail=f"no output (exit {result.returncode})")
            return _puredns_skipped(subdomains, "no_output")

    except FileNotFoundError:
        print("[!][Puredns] Docker not found — cannot run")
        return _puredns_skipped(subdomains, "docker_missing")
    except Exception as e:
        print(f"[!][Puredns] Error: {e} — returning unfiltered list")
        _source_record("puredns", _outcome("TRANSIENT"), detail=type(e).__name__)
        return _puredns_skipped(subdomains, "error")
    finally:
        # Cleanup temp files (may be root-owned from Docker)
        for tmp in [input_file, output_file]:
            try:
                tmp.unlink(missing_ok=True)
            except PermissionError:
                # The cleanup container itself must be bounded: without a timeout
                # a hung `docker run` here would stall the whole scan at the end.
                try:
                    run_tool_container(
                        ["docker", "run", "--rm", "-v", f"{data_dir}:/cleanup",
                         "alpine", "rm", "-f", f"/cleanup/{tmp.name}"],
                        tool="puredns-cleanup", timeout=60)
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass


def _guessing_sources(bruteforce: bool, settings: dict) -> set:
    """Discovery sources that guess names from a wordlist instead of observing
    them. knockpy --recon alone reads passive sources; amass guesses only with
    -brute, and its passive names come back in the same set."""
    guessing = set()
    if bruteforce:
        guessing.add("knockpy")
    if settings.get('AMASS_ENABLED', False) and settings.get('AMASS_BRUTE', False):
        guessing.add("amass")
    return guessing


def discover_subdomains(domain: str, bruteforce: bool = False,
                        resolve: bool = True, save_output: bool = True, project_id: str = None,
                        settings: dict = None) -> dict:
    """
    Main discovery function - subdomain enumeration + DNS resolution.

    Args:
        domain: Target domain (e.g., "example.com")
        bruteforce: Enable Knockpy bruteforce mode (slower but more thorough)
        resolve: Whether to resolve DNS for all hosts
        save_output: Whether to save JSON report
        project_id: Project ID for filename (if None, falls back to domain)
        settings: Project settings dict for tool toggles

    Returns:
        Complete reconnaissance data for domain and subdomains
    """
    print(f"\n{'=' * 50}")
    print(f"[*][Discovery] TARGET: {domain}")
    if bruteforce:
        print(f"[⚡] BRUTEFORCE MODE")
    print(f"{'=' * 50}\n")

    if settings:
        from recon.helpers import print_effective_settings
        print_effective_settings(
            "Discovery",
            settings,
            keys=[
                ("CRTSH_ENABLED", "crt.sh"),
                ("CRTSH_MAX_RESULTS", "crt.sh"),
                ("HACKERTARGET_ENABLED", "HackerTarget"),
                ("HACKERTARGET_MAX_RESULTS", "HackerTarget"),
                ("KNOCKPY_RECON_ENABLED", "Knockpy"),
                ("KNOCKPY_RECON_MAX_RESULTS", "Knockpy"),
                ("SUBFINDER_ENABLED", "Subfinder"),
                ("SUBFINDER_DOCKER_IMAGE", "Subfinder"),
                ("SUBFINDER_MAX_RESULTS", "Subfinder"),
                ("AMASS_ENABLED", "Amass"),
                ("AMASS_ACTIVE", "Amass"),
                ("AMASS_BRUTE", "Amass"),
                ("AMASS_TIMEOUT", "Amass"),
                ("AMASS_BRUTE_WORDLISTS", "Amass"),
                ("AMASS_DOCKER_IMAGE", "Amass"),
                ("AMASS_MAX_RESULTS", "Amass"),
                ("PUREDNS_ENABLED", "Puredns wildcard filter"),
                ("PUREDNS_DOCKER_IMAGE", "Puredns wildcard filter"),
                ("PUREDNS_THREADS", "Puredns wildcard filter"),
                ("PUREDNS_RATE_LIMIT", "Puredns wildcard filter"),
                ("PUREDNS_WILDCARD_BATCH", "Puredns wildcard filter"),
                ("PUREDNS_SKIP_VALIDATION", "Puredns wildcard filter"),
                ("DNS_MAX_WORKERS", "DNS resolution"),
                ("DNS_RECORD_PARALLELISM", "DNS resolution"),
            ],
        )

    # Subdomain Discovery — fan-out all 5 tools in parallel
    print(f"[*][Discovery] Launching 5 discovery tools in parallel...")
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="discovery") as executor:
        futures = {
            executor.submit(query_crtsh, domain, settings): "crtsh",
            executor.submit(query_hackertarget, domain, settings): "hackertarget",
            executor.submit(run_subfinder, domain, settings): "subfinder",
            executor.submit(run_amass, domain, settings): "amass",
            executor.submit(run_knockpy, domain, bruteforce, settings): "knockpy",
        }

        discovery_results = {}
        for future in as_completed(futures):
            label = futures[future]
            try:
                discovery_results[label] = future.result()
            except Exception as e:
                print(f"[!][{label}] Failed: {e}")
                # crtsh/hackertarget return dict, others return set
                discovery_results[label] = {} if label in ("crtsh", "hackertarget") else set()

    print(f"[+][Discovery] All discovery tools complete — merging results")

    # Fan-in: combine results from all tools
    # crtsh and hackertarget return {subdomain: set_of_sources}
    # subfinder, amass, knockpy return set of subdomains
    sourced_subs = {}  # domain -> set of source labels
    for s, sources in discovery_results.get("crtsh", {}).items():
        sourced_subs.setdefault(s, set()).update(sources)
    for s, sources in discovery_results.get("hackertarget", {}).items():
        sourced_subs.setdefault(s, set()).update(sources)
    for s in discovery_results.get("subfinder", set()):
        sourced_subs.setdefault(s, set()).add("subfinder")
    for s in discovery_results.get("amass", set()):
        sourced_subs.setdefault(s, set()).add("amass")
    for s in discovery_results.get("knockpy", set()):
        sourced_subs.setdefault(s, set()).add("knockpy")

    filtered_subs = []
    external_domain_entries = []
    for s, sources in sourced_subs.items():
        if not s or '@' in s:  # an email address (a certificate SAN) is no hostname
            continue
        if s == domain or s.endswith("." + domain):
            filtered_subs.append(s)
        else:
            for source in sources:
                external_domain_entries.append({"domain": s, "source": source})
    all_subs = sorted(filtered_subs)

    # Puredns wildcard filtering (after discovery fan-in, before DNS resolution)
    pre_filter_count = len(all_subs)
    all_subs, wildcard_filter = run_puredns_resolve(all_subs, domain, settings)
    if len(all_subs) < pre_filter_count:
        print(f"[+][Puredns] Wildcard filtering: {pre_filter_count} → {len(all_subs)} subdomains")

    # Build result structure
    result = {
        "metadata": {
            "scan_type": "subdomain_dns_discovery",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain,
            "anonymous_mode": False,
            "bruteforce_mode": bruteforce,
            "wildcard_filter": wildcard_filter,
        },
        "domain": domain,
        "subdomains": all_subs,
        "subdomain_count": len(all_subs),
        "dns": {},
        "external_domains": external_domain_entries,
    }
    
    # DNS Resolution for domain + all subdomains
    from recon.helpers import wildcard_control
    if resolve:
        dns_workers = (settings or {}).get('DNS_MAX_WORKERS', 50)
        dns_record_parallel = (settings or {}).get('DNS_RECORD_PARALLELISM', True)
        result["dns"] = resolve_all_dns(domain, all_subs, max_workers=dns_workers, record_parallelism=dns_record_parallel, settings=settings)
        # RedAmon's own wildcard check, whatever puredns did: it stands in when
        # puredns was skipped and records which zones are wildcards.
        control = wildcard_control.filter_discovered(
            domain, all_subs, result["dns"], sourced_subs, settings or {},
            guessing=_guessing_sources(bruteforce, settings or {}))
        if control.dropped:
            dropped = set(control.dropped)
            all_subs = [s for s in all_subs if s not in dropped]
            for s in dropped:
                (result["dns"].get("subdomains") or {}).pop(s, None)
            result["subdomains"] = all_subs
            result["subdomain_count"] = len(all_subs)
        result["wildcard_zones"] = control.zones
        result["metadata"]["wildcard_dropped"] = len(control.dropped)
    elif wildcard_filter != "filtered":
        wildcard_control.note_unchecked(len(all_subs), wildcard_control.REASON_DNS_OFF)

    # Build subdomain status map from DNS results
    subdomain_status_map = {}
    if result["dns"]:
        dns_subs = result["dns"].get("subdomains", {})
        for s in all_subs:
            info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
            if info.get("has_records", False):
                subdomain_status_map[s] = "resolved"
    else:
        # Nothing was resolved, brute-forced guesses included: "unverified" is
        # the value every writer uses for a name nobody resolved.
        for s in all_subs:
            subdomain_status_map[s] = "unverified"
    result["subdomain_status_map"] = subdomain_status_map

    # Save JSON output (use project_id for filename if provided, fallback to domain)
    if save_output:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        file_id = project_id if project_id else domain
        output_file = OUTPUT_DIR / f"recon_{file_id}.json"

        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f"\n{'=' * 50}")
        print(f"[+][Discovery] TOTAL: {len(all_subs)} unique subdomains")
        print(f"[+][Discovery] SAVED: {output_file}")
        print(f"{'=' * 50}\n")
    
    return result


def reverse_dns_lookup(ip_address: str, max_retries: int = 3):
    """The first PTR name of an address, or None. Kept for callers that want
    one name; an IP-mode run asks reverse_dns_lookup_all."""
    names = reverse_dns_lookup_all(ip_address, max_retries)
    return names[0] if names else None


def reverse_dns_lookup_all(ip_address: str, max_retries: int = 3) -> list:
    """Every PTR name of an address, in answer order, without the root dot or
    duplicates; [] when there is none or no answer could be had.

    A shared host carries one PTR record per site, and the resolver may rotate
    their order, so keeping only the first lost the others and made the one
    kept depend on the resolver.
    """
    if resolver_breaker.is_open():
        return []

    # Per-/24 (reverse-zone) breaker: a zone whose PTR authority stops answering
    # is skipped for its remaining IPs, instead of timing out on each one. A
    # definitive "no PTR" is an answer (keeps the zone healthy); only timeouts
    # count against it.
    zone_breaker = _rdns_zone_breaker(ip_address)
    if zone_breaker is not None and _breaker_is_open(zone_breaker):
        return []

    definitive = _dns_definitive_errors()
    for attempt in range(max_retries):
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            _rdns_record_ok(zone_breaker)
            names = []
            for answer in answers:
                name = str(answer).rstrip('.')
                if name and name not in names:
                    names.append(name)
            return names
        except definitive:
            _rdns_record_ok(zone_breaker)  # a definitive answer = zone is alive
            return []
        except (dns.resolver.LifetimeTimeout, dns.resolver.Timeout,
                dns.resolver.NoNameservers):
            if resolver_breaker.note_transient():
                return []
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            _rdns_record_timeout(zone_breaker)
            return []
        except Exception:
            return []
    return []


def _rdns_zone_breaker(ip_address: str):
    """The circuit breaker for an IP's reverse zone (/24 for IPv4), or None."""
    if not _cb_enabled():
        return None
    try:
        if ":" in ip_address:  # IPv6: group by the first four hextets
            zone = ":".join(ip_address.split(":")[:4])
        else:
            zone = ip_address.rsplit(".", 1)[0]
        if not zone:
            return None
        from recon.helpers import circuit_breaker as cb
        return cb.get_breaker(f"rdns:{zone}", label="DNS",
                              threshold=cb.INTERNAL_THRESHOLD)
    except Exception:  # noqa: BLE001
        return None


def _breaker_is_open(breaker) -> bool:
    try:
        return not breaker.allow()
    except Exception:  # noqa: BLE001
        return False


def _rdns_record_ok(breaker) -> None:
    if breaker is None:
        return
    try:
        from recon.helpers import circuit_breaker as cb
        breaker.record(cb.Outcome.OK)
    except Exception:  # noqa: BLE001
        pass


def _rdns_record_timeout(breaker) -> None:
    if breaker is None:
        return
    try:
        from recon.helpers import circuit_breaker as cb
        breaker.record(cb.Outcome.TRANSIENT, detail="PTR timeout")
    except Exception:  # noqa: BLE001
        pass

