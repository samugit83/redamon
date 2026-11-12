"""
RedAmon - passive search of the filter domains (IP mode, record_filter)
=======================================================================
"Also search subdomains of the filter domains" (design §8). A site whose name
no IP source revealed (no PTR, not in the default certificate, never in a
passive-DNS index of the address) is found only by asking third-party indexes
for the names under each `*.x` include entry: crt.sh (which falls back to
crt.name itself), HackerTarget, Subfinder and, with a key, urlscan
(`page.domain:x`). Never Amass, knockpy, puredns or any guessing.

None of them sends a packet to a target, so the search starts right after the
RoE filter on its own thread and overlaps WHOIS and the scans; the hostnames
hook joins it (recon/helpers/ip_hostnames.py) and its names become candidates
with source `passive_<src>`, judged by the same selection rule as every other
name. The thread is handed a copy of the settings and nothing of the run: it
returns data, and never touches the recon dict or its file.

Bounded before any lookup: at most IP_HOSTNAME_PASSIVE_MAX_NAMES names per run
(never more than the hook's per-run candidate bound), one search per domain
and source. RedAmon's wildcard-DNS control then marks the names that resolve
only through a wildcard record under a filter domain, or sit under a zone it
could not probe; the rule refuses them (wildcard_zone). A paused or failing
source is a coverage gap, never a failed run, and so is one still running when
the hook's wait runs out (JOIN_BUDGET_S): the hook goes on with the names found
so far and checks them itself. The search's threads, all daemons, are left
behind; one left behind never starts the wildcard control, whose worker pool
is the only thread here that the interpreter would wait for at exit.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Any, Callable, Optional

from recon.helpers import circuit_breaker
from recon.helpers.ip_hostnames import MAX_CANDIDATES_PER_RUN, PASSIVE_PREFIX, candidate_name, hostname_mode
from recon_settings.hard_guardrail import is_hard_blocked
from recon_settings.ip_hostnames import matches, parse_entries

#: IP_HOSTNAME_PASSIVE_MAX_NAMES' registry default, for a settings dict the
#: loader did not fill (the loader bounds the stored value to 1..10000).
DEFAULT_MAX_NAMES = 500

#: The longest the hostnames hook waits for the search, in seconds. Each
#: source asks its domains one after another and Subfinder alone may take 720 s
#: per domain, so many `*.x` entries would otherwise hold the run for hours.
JOIN_BUDGET_S = 900

#: The order the log line lists them in.
SOURCES = ("crtsh", "hackertarget", "subfinder", "urlscan")
_LABEL = {"crtsh": "crt.sh", "hackertarget": "hackertarget", "subfinder": "subfinder", "urlscan": "urlscan"}
_TOGGLE = {"crtsh": "CRTSH_ENABLED", "hackertarget": "HACKERTARGET_ENABLED", "subfinder": "SUBFINDER_ENABLED"}

#: The coverage-note module, so the gaps read as the hook's.
NOTE_MODULE = "ip_hostnames"

#: A label no operator writes: when a rule refuses it, it refuses every name
#: under the root, and searching that root could only record refusals.
_PROBE_LABEL = "rdm-probe"


# ---------------------------------------------------------------------------
# What to search
# ---------------------------------------------------------------------------

def _patterns(settings: dict, key: str) -> list:
    value = settings.get(key)
    return parse_entries(value if isinstance(value, list) else [])[0]


def _not_searched(root: str, settings: dict, exclude: list) -> str:
    """Why no name under `root` could ever be scanned, or ""."""
    from recon.helpers.public_suffix import org_domain
    from recon.helpers.roe_scope import _is_roe_excluded

    probe = f"{_PROBE_LABEL}.{root}"
    if org_domain(root) is None:
        return "a public suffix reaches every registrant"
    if is_hard_blocked(probe)[0]:
        return "the hard guardrail protects it"
    if settings.get("ROE_ENABLED") and _is_roe_excluded(probe, settings.get("ROE_EXCLUDED_HOSTS") or []):
        return "the RoE excludes it"
    if matches(probe, [], exclude).excluded:
        return "an exclude entry covers it"
    return ""


def plan(settings: dict) -> tuple[list, list]:
    """(roots, domains): the hosts of the `*.x` include entries, and the ones
    searched. An exact entry names a host the operator already knows. A root
    under another root is covered by that root's search, so it is asked once."""
    roots = [p.host for p in _patterns(settings, "IP_HOSTNAME_INCLUDE") if p.wildcard]
    exclude = _patterns(settings, "IP_HOSTNAME_EXCLUDE")
    domains = []
    for root in roots:
        if any(root.endswith("." + other) for other in roots):
            continue
        why = _not_searched(root, settings, exclude)
        if why:
            print(f"[-][IpNames] Passive search skips *.{root}: {why}")
        else:
            domains.append(root)
    return roots, domains


# ---------------------------------------------------------------------------
# The sources
# ---------------------------------------------------------------------------

def _crtsh(domain: str, settings: dict) -> dict:
    from recon.main_recon_modules import domain_recon
    found = domain_recon.query_crtsh(domain, settings) or {}
    # query_crtsh answers from crt.name when crt.sh gave none; say which did.
    return {name: PASSIVE_PREFIX + ("crtname" if "crt.name" in tags else "crtsh") for name, tags in found.items()}


def _hackertarget(domain: str, settings: dict) -> dict:
    from recon.main_recon_modules import domain_recon
    return {name: PASSIVE_PREFIX + "hackertarget" for name in domain_recon.query_hackertarget(domain, settings) or {}}


def _subfinder(domain: str, settings: dict) -> dict:
    # run_subfinder's argv has no -active, so subfinder only asks its passive
    # sources (-active would resolve every name it finds).
    from recon.main_recon_modules import domain_recon
    return {name: PASSIVE_PREFIX + "subfinder" for name in domain_recon.run_subfinder(domain, settings) or ()}


def _urlscan_keys(settings: dict):
    return circuit_breaker.KeyPool(settings.get("URLSCAN_KEY_ROTATOR"), settings.get("URLSCAN_API_KEY") or "",
                                   label="URLScan")


def _urlscan(domain: str, settings: dict) -> Optional[dict]:
    """The urlscan module's own search, so its base URL (URLSCAN_API_BASE, the
    lab hook), key pool, breaker and search budget all apply. None when it
    failed or was rate-limited: an empty answer is not "no names"."""
    from recon.main_recon_modules import urlscan_enrich
    results = urlscan_enrich.urlscan_search(
        urlscan_enrich.main_query(domain), settings.get("URLSCAN_API_KEY") or "",
        max_results=urlscan_enrich.effective_max_results(settings, _urlscan_keys(settings).has_key),
        key_rotator=settings.get("URLSCAN_KEY_ROTATOR"), breaker_key=urlscan_enrich.MAIN_BREAKER,
        caller="search", root=domain)
    if results.failed or results.rate_limited:
        return None
    return {str((r.get("page") or {}).get("domain") or ""): PASSIVE_PREFIX + "urlscan"
            for r in results if isinstance(r, dict)}


_CALLS = {"crtsh": _crtsh, "hackertarget": _hackertarget, "subfinder": _subfinder, "urlscan": _urlscan}


def _enabled(source: str, settings: dict) -> bool:
    if source == "urlscan":
        # Asked only with a key, as the design says: keyless, urlscan answers
        # the last 30 days only (and the lab stub answers its key alone).
        return bool(settings.get("URLSCAN_ENABLED", False)) and _urlscan_keys(settings).has_key
    return bool(settings.get(_TOGGLE[source], True))


def _breakers(source: str) -> list:
    """The breakers the source's own function records into, from the shared
    registry (circuit_breaker.get_breaker, through each module's accessor so
    the thresholds stay the module's)."""
    if source == "urlscan":
        from recon.main_recon_modules import urlscan_enrich
        return [urlscan_enrich._breaker(urlscan_enrich.MAIN_BREAKER)]
    from recon.main_recon_modules import domain_recon
    keys = ("crtsh", "crtname") if source == "crtsh" else (source,)
    return [b for b in (domain_recon._source_breaker(k) for k in keys) if b is not None]


def _misses(breakers: list) -> int:
    return sum(b.failures + b.skipped for b in breakers)


def _note_gap(tag: str, reason: str, skipped: int) -> None:
    """A gap in what the search could ask. The search writes no finding, so
    the note prunes nothing; it marks the run partial in the coverage record."""
    circuit_breaker.note_degraded(NOTE_MODULE, entries=[{"source": tag, "reason": reason, "skipped": skipped}])


@dataclass
class SourceAnswer:
    """One source's progress. Its thread updates it domain by domain under
    `lock`, so the hook can read what came so far when it stops waiting."""
    enabled: bool = True
    answered: int = 0
    paused: int = 0
    failed: int = 0
    names: dict = field(default_factory=dict)
    done: list = field(default_factory=list)
    lock: Any = field(default_factory=threading.Lock, repr=False, compare=False)

    def snapshot(self) -> "SourceAnswer":
        with self.lock:
            return SourceAnswer(self.enabled, self.answered, self.paused, self.failed,
                                {name: set(tags) for name, tags in self.names.items()}, list(self.done))


def _ask(source: str, domain: str, settings: dict) -> tuple[str, dict]:
    """One search: ("answered" | "paused" | "failed", {raw name: tag}). Never raises."""
    try:
        breakers = _breakers(source)
        if breakers and all(b.is_open for b in breakers):
            return "paused", {}
        before = _misses(breakers)
        got = _CALLS[source](domain, settings)
        # The domain_recon sources swallow their errors and answer empty: what
        # their breaker recorded meanwhile tells a failure from "none".
        if got is None or (not got and _misses(breakers) > before):
            return "failed", {}
        return "answered", got
    except Exception as e:  # noqa: BLE001 - one source failing never stops the others
        print(f"[!][IpNames] Passive search: {_LABEL[source]} failed ({type(e).__name__})")
        return "failed", {}


def _search_source(source: str, domains: tuple, settings: dict, out: SourceAnswer) -> SourceAnswer:
    """One enabled source over every domain, one search each, into `out`.
    Never raises."""
    for domain in domains:
        status, got = _ask(source, domain, settings)
        names: dict = {}
        for raw, tag in got.items():
            name = candidate_name(raw)
            if name and name.endswith("." + domain):
                names.setdefault(name, set()).add(tag)
        with out.lock:
            setattr(out, status, getattr(out, status) + 1)
            for name, tags in names.items():
                out.names.setdefault(name, set()).update(tags)
            out.done.append(domain)
    if out.paused:
        _note_gap(PASSIVE_PREFIX + source, "passive search paused after repeated failures", out.paused)
    if out.failed:
        _note_gap(PASSIVE_PREFIX + source, "passive search got no answer", out.failed)
    return out


# ---------------------------------------------------------------------------
# The result
# ---------------------------------------------------------------------------

def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _source_of(tag: str) -> str:
    source = tag[len(PASSIVE_PREFIX):]
    return "crtsh" if source == "crtname" else source


@dataclass
class Found:
    """What the search hands the hook.

    `names`: {name: its passive sources}, within the cap. `truncated`: names
    over the cap, never kept. `wildcard_zone`: kept names the wildcard-DNS
    control found resolving only through a wildcard record. `unfinished`:
    {source: the domains it was still on when the hook stopped waiting}.
    """
    domains: tuple = ()
    names: dict = field(default_factory=dict)
    answers: dict = field(default_factory=dict)
    truncated: int = 0
    wildcard_zone: frozenset = frozenset()
    unfinished: dict = field(default_factory=dict)

    def listed(self, source: str) -> int:
        return sum(1 for tags in self.names.values() if any(_source_of(t) == source for t in tags))

    def log_line(self) -> str:
        parts = []
        for source in SOURCES:
            answer = self.answers.get(source)
            if answer is None or not answer.enabled:
                continue
            missed = answer.paused + answer.failed
            late = len(self.unfinished.get(source, ()))
            if not answer.answered:
                if late and not missed:
                    word = "not finished"
                else:
                    word = "paused" if answer.paused and not answer.failed else "failed"
                parts.append(f"{_LABEL[source]} {word}")
                continue
            gaps = [f"{_plural(missed, 'domain')} not searched"] if missed else []
            if late:
                gaps.append(f"{_plural(late, 'domain')} not finished")
            parts.append(f"{_LABEL[source]} {self.listed(source)}" + (f" [{', '.join(gaps)}]" if gaps else ""))
        line = (f"[*][IpNames] Passive search: {_plural(len(self.domains), 'domain')}, "
                f"{_plural(len(self.names), 'name')}")
        line += f" ({', '.join(parts)})" if parts else ""
        if self.truncated:
            line += f"; {self.truncated} more not kept (passive search limit)"
        return line

    def summary(self) -> dict:
        """The hook's summary.expansion block (design §3)."""
        sources, missed = {}, {}
        for source, answer in self.answers.items():
            if not answer.enabled:
                continue
            if answer.answered:
                sources[source] = self.listed(source)
            if answer.paused + answer.failed:
                missed[source] = answer.paused + answer.failed
        return {"queried": len(self.domains), "names": len(self.names), "truncated": self.truncated,
                "wildcard_zone": len(self.wildcard_zone), "sources": sources, "not_searched": missed,
                "not_finished": {source: len(domains) for source, domains in self.unfinished.items()}}


def _limit(settings: dict) -> int:
    try:
        limit = int(settings.get("IP_HOSTNAME_PASSIVE_MAX_NAMES", DEFAULT_MAX_NAMES))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_NAMES
    return max(0, min(limit, MAX_CANDIDATES_PER_RUN))


def _bounded(names: dict, domains: tuple, settings: dict) -> tuple[list, int]:
    """The names kept under the cap, and how many were cut.

    Deterministic, and fair to every domain: one name of each domain in turn,
    each domain's in name order with the names an exclude entry refuses last
    (they can only be recorded)."""
    exclude = _patterns(settings, "IP_HOSTNAME_EXCLUDE")
    queues = []
    for domain in domains:
        under = [n for n in names if n.endswith("." + domain)]
        under.sort(key=lambda n: (matches(n, [], exclude).excluded, n))
        queues.append(under)
    order = [n for row in zip_longest(*queues) for n in row if n is not None]
    limit = _limit(settings)
    return order[:limit], max(0, len(order) - limit)


def _wildcard_zone(names: list, roots: tuple, settings: dict) -> frozenset:
    """The passive names check 15 refuses: those the wildcard-DNS control
    drops, and every name under a zone it could not probe (a failed probe,
    its zone cap, an RoE-excluded zone). The control keeps the latter and
    only notes them, which suits a name a target IP showed; a name only an
    index listed would then be scanned unchecked, so it is refused (I-6). A
    control that fails refuses every passive name for the same reason."""
    if not names:
        return frozenset()
    from recon.helpers import wildcard_control
    try:
        result = wildcard_control.filter_late_names(list(names), roots=list(roots), settings=settings,
                                                    label="ip_hostnames")
        zone_of = wildcard_control.assign_zones(list(names), list(roots))
    except Exception as e:  # noqa: BLE001
        print(f"[!][IpNames] Wildcard DNS check of the passive names failed ({type(e).__name__}): "
              f"none of them is scanned")
        _note_gap(PASSIVE_PREFIX + "search", "wildcard DNS check failed; passive names refused", len(names))
        return frozenset(names)
    unchecked = frozenset(n for n in names if zone_of.get(n) not in result.zones)
    if unchecked:
        print(f"[!][IpNames] Wildcard DNS could not be checked for {len(unchecked)} passive name(s): "
              f"none of them is scanned")
    return frozenset(result.dropped) | unchecked


def new_answers(settings: dict) -> dict:
    """{source: SourceAnswer}, each source's switch read before any thread
    starts, so a reader never takes a source that is off for one not done."""
    return {source: SourceAnswer(enabled=_enabled(source, settings)) for source in SOURCES}


def finish(domains, roots, settings: dict, answers: dict, unfinished: Optional[dict] = None) -> Found:
    """The cap, then the wildcard control, over what the sources found so far."""
    answers = {source: answer.snapshot() for source, answer in answers.items()}
    every: dict = {}
    for answer in answers.values():
        for name, tags in answer.names.items():
            every.setdefault(name, set()).update(tags)
    kept, cut = _bounded(every, tuple(domains), settings)
    kept.sort()
    return Found(domains=tuple(domains), names={n: tuple(sorted(every[n])) for n in kept}, answers=answers,
                 truncated=cut, wildcard_zone=_wildcard_zone(kept, tuple(roots), settings),
                 unfinished=dict(unfinished or {}))


def search(domains, roots, settings: dict, answers: Optional[dict] = None,
           claim: Optional[Callable[[], bool]] = None) -> Optional[Found]:
    """Every source over every domain (the sources in parallel), then the cap,
    then the wildcard control. Returns data only.

    `answers` (new_answers) receives each source's progress as it goes. The
    source threads are daemons and start no thread of their own. `claim()`,
    asked once the sources are done, says whether this search may still
    finish; when it says no (the caller stopped waiting and checks the names
    itself) the search returns None without starting the wildcard control,
    so a search left behind never holds the process open at exit."""
    domains, roots = tuple(domains), tuple(roots)
    answers = answers if answers is not None else new_answers(settings)
    threads = [threading.Thread(target=_search_source, args=(source, domains, settings, answer),
                                name=f"ipn-source-{source}", daemon=True)
               for source, answer in answers.items() if answer.enabled]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if claim is not None and not claim():
        return None
    return finish(domains, roots, settings, answers)


# ---------------------------------------------------------------------------
# The thread
# ---------------------------------------------------------------------------

def _crashed(domains: tuple, e: BaseException) -> Found:
    print(f"[!][IpNames] Passive search failed ({type(e).__name__}): no name from it this run")
    _note_gap(PASSIVE_PREFIX + "search", "passive search failed", len(domains))
    return Found(domains=domains)


class PassiveSearch:
    """The search running on its own daemon thread; join() hands its result
    over once, after at most `budget` seconds of waiting for its sources.

    Exactly one side runs the cap and the wildcard control, decided under
    `_lock`: the search thread once its sources are done, unless the hook
    gave up on it first; then the hook, over what came so far."""

    def __init__(self, domains, roots, settings: dict, budget: Optional[float] = None):
        self.domains, self.roots, self.settings = tuple(domains), tuple(roots), settings
        self.budget = JOIN_BUDGET_S if budget is None else budget
        self.answers = new_answers(settings)
        self._found: Optional[Found] = None
        self._result: Optional[Found] = None
        self._error: Optional[BaseException] = None
        self._lock = threading.Lock()
        self._finishing = False
        self._abandoned = False
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, name="ipn-passive", daemon=True)
        self._thread.start()

    def _claim(self) -> bool:
        with self._lock:
            if self._abandoned:
                return False
            self._finishing = True
            return True

    def _abandon(self) -> bool:
        """Give up on the search unless it is already checking its names."""
        with self._lock:
            if not self._finishing:
                self._abandoned = True
            return self._abandoned

    def _run(self) -> None:
        try:
            self._result = search(self.domains, self.roots, self.settings, self.answers, claim=self._claim)
        except Exception as e:  # noqa: BLE001 - handed to join()
            self._error = e
        finally:
            self._done.set()

    def join(self) -> Found:
        """Wait for the search, at most `budget` seconds for its sources, and
        log its line. Never raises: a crashed search hands over no name, one
        whose sources are still running hands over what they found so far;
        both leave a coverage note. A search already checking its names for
        wildcard DNS is waited for: that check is the hook's own work
        otherwise, bounded by its DNS timeouts."""
        if self._found is not None:
            return self._found
        if not self._done.is_set():
            print(f"[*][IpNames] Waiting for the passive search to finish (at most {self.budget:g} s)")
        if self._done.wait(self.budget) or not self._abandon():
            if not self._done.is_set():
                print(f"[*][IpNames] Passive search over its {self.budget:g} s budget while checking its "
                      f"names for wildcard DNS: waiting for that check")
                self._done.wait()
            # It has set the event, its last act: this join cannot wait long.
            self._thread.join()
            found = self._result if self._error is None else _crashed(self.domains, self._error)
        else:
            found = self._partial()
        print(found.log_line())
        self._found = found
        return found

    def _partial(self) -> Found:
        """What the sources found before the budget ran out, checked here. The
        threads stay behind and whatever they find later is dropped."""
        unfinished = {}
        for source, answer in self.answers.items():
            seen = answer.snapshot()
            pending = tuple(d for d in self.domains if d not in seen.done) if seen.enabled else ()
            if pending:
                unfinished[source] = pending
        # Every source may have answered between the timeout and the snapshot,
        # before the search thread asked to finish: then nothing is missing.
        late = "; ".join(f"{_LABEL[s]} ({', '.join(d)})" for s, d in unfinished.items())
        print(f"[!][IpNames] Passive search over its {self.budget:g} s budget: going on with the names "
              f"found so far; not finished: {late or 'nothing (its sources had just answered)'}")
        for source, pending in unfinished.items():
            _note_gap(PASSIVE_PREFIX + source, f"not finished in the time budget: {', '.join(pending)}",
                      len(pending))
        try:
            return finish(self.domains, self.roots, self.settings, self.answers, unfinished)
        except Exception as e:  # noqa: BLE001 - join never raises
            return _crashed(self.domains, e)


def start(settings: Optional[dict]) -> Optional[PassiveSearch]:
    """Start the passive search, or None: only record_filter with the
    expansion explicitly on and DNS lookups on, and only for `*.x` include
    entries. Never raises."""
    try:
        settings = dict(settings or {})
        if hostname_mode(settings) != "record_filter" or settings.get("IP_HOSTNAME_PASSIVE_EXPAND") is not True:
            return None
        # The hook's own reading of DNS_ENABLED: off, the rule refuses every
        # name dns_disabled, so the indexes would be asked for nothing.
        if settings.get("DNS_ENABLED", True) is not True:
            print("[-][IpNames] Passive search skipped: DNS lookups are off, so no name it found could be scanned")
            return None
        roots, domains = plan(settings)
        if not domains:
            print("[-][IpNames] Passive search: no *.<domain> include entry to search")
            return None
        print(f"[*][IpNames] Passive search started for {_plural(len(domains), 'domain')}: {', '.join(domains)}")
        return PassiveSearch(domains, roots, settings)
    except Exception as e:  # noqa: BLE001 - the run goes on with the names its IPs show
        print(f"[!][IpNames] Passive search not started ({type(e).__name__})")
        return None
