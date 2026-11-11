"""What a passive CVE lookup re-checked this run, told to the end-of-run prune.

Shodan, Netlas and CriminalIP answer per IP, from their own crawls, so their
CVEs follow the positive-coverage prune (design decision D1): a lookup
records the IPs it decided about (`circuit_breaker.note_checked`), and the
prune deletes a passive CVE only on those.

- An IP it asked about and saw the whole answer for, "no data" included, is
  decided: a CVE that IP no longer carries goes.
- An IP its CDN or private-address filter dropped before asking is decided
  too (plan 04.1): an edge's CVEs describe the provider, not the target.
- An IP it asked about and got no answer for brings no news: it is noted
  degraded by host, and its earlier CVEs are kept.
- An IP no longer in the run at all is not checked, so its CVEs are kept
  until a run re-checks it (D1's rule for a host discovery stops finding).

A lookup that could ask about nothing (a refused key, a crash, no IP at all)
keeps its whole source. A lookup switched off by configuration notes nothing,
so its old findings are pruned by the source-level rule.
"""
from __future__ import annotations

from typing import Iterable

from recon.helpers import circuit_breaker
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES


def note_cve_coverage(provider: str, module: str, queried: Iterable[str] = (),
                      checked: Iterable[str] = (), *, considered: Iterable[str] = (),
                      no_input: bool = False, failed: bool = False,
                      reached: bool | None = None, reason: str = "") -> None:
    """Record which IPs this lookup decided about, and which of `queried` it
    could not re-check. Never raises.

    `considered` are the IPs the lookup started from, before its CDN and
    private-address filter; `queried` are those it set out to ask about after
    it. The ones the filter dropped were decided, not skipped. `checked` are
    those whose answer it saw whole, "no data" included. `no_input` means
    there was no IP before that filter either. `reached` says the provider
    answered at all; it defaults to "some IP was checked", and a lookup whose
    every answer was cut short passes True, so its IPs are kept one by one
    rather than the whole source, which would then never be pruned.
    """
    sources = PASSIVE_CVE_SOURCES.get(provider, (provider,))
    # The provider names its one coverage gap; its other source values (which
    # API answered, older fallbacks) are cut with it.
    aliases = [s for s in sources if s != provider]
    queried = {ip for ip in queried if ip}
    checked = set(checked) & queried
    filtered = {ip for ip in considered if ip} - queried
    if reached is None:
        reached = bool(checked)
    if failed or no_input or (queried and not reached):
        reason = reason or ("the lookup failed" if failed else "no IP to look up" if no_input
                            else "no IP could be looked up")
        circuit_breaker.note_degraded(module, sources=[provider], aliases=aliases, reason=reason)
        return
    missed = sorted(queried - checked)
    if missed:
        circuit_breaker.note_degraded(
            module, hosts=missed, host_source=provider, aliases=aliases,
            source_only_hosts=True, reason=reason or f"{len(missed)} IP(s) not looked up")
    # Every source value, since the prune selects findings by the one each
    # carries (Shodan's say which of its APIs answered).
    decided = sorted(checked | filtered)
    for source in sources:
        circuit_breaker.note_checked(source, hosts=decided, module=module)
