"""Per-host coverage of one recon module, for the BaseURL stamps (plan 09.1).

A module that works per web host reports one row for every host it considered:
``{"status", "inputs", "outputs", "reason"}``. The graph writer stamps each row
on the matching BaseURL (``graph_db/coverage_stamps.py``). A host the module
never considered gets no row, and its BaseURL no stamp: that absence is what
lets a reader say "not scanned" instead of "clean".
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from recon.helpers import circuit_breaker
from recon.helpers.circuit_breaker import host_key

# Kept in step with COVERAGE_STATUSES in graph_db/coverage_stamps.py, which
# drops any other value before it reaches the graph.
STATUSES = ("complete", "partial", "no_input", "failed")


def base_url_key(url) -> str:
    """One spelling per web service: ``https://App.example.com/x.js`` ->
    ``https://app.example.com:443``, the port always explicit so ``https://x``
    and ``https://x:443`` count as one host. ``''`` when not http(s)."""
    text = str(url or "").strip()
    try:
        scheme = urlsplit(text).scheme.lower()
    except ValueError:
        return ""
    if scheme not in ("http", "https"):
        return ""
    key = host_key(text)
    return f"{scheme}://{key}" if key else ""


def run_started_at() -> str:
    """The stamp time: when the module's run started, in UTC."""
    return datetime.now(timezone.utc).isoformat()


def coverage_row(status: str, inputs: int = 0, outputs: int = 0, reason=None) -> dict:
    if status not in STATUSES:
        raise ValueError(f"unknown coverage status {status!r}")
    return {"status": status, "inputs": int(inputs), "outputs": int(outputs), "reason": reason or None}


def note_rows_checked(source: str, rows, *, module: str = "") -> None:
    """Tell the end-of-run prune what a coverage record says (D1). Never raises.

    ``rows`` is a record's ``hosts`` map, ``{base_url_key: row}``, so one
    record feeds both the BaseURL stamps and the prune of ``source``:
    ``complete`` hosts are re-checked (``circuit_breaker.note_checked``);
    ``partial`` and ``failed`` ones are cut for ``source`` alone, since the
    other tools re-checked them, and reach the coverage record as a gap;
    ``no_input`` ones are neither: the module had nothing to read there, so
    their earlier findings stay, as on any host it did not re-check. Calling
    this makes ``source`` positive-prune for the run, even with no row: call
    it only when the module was meant to run. A record that is no mapping
    marks the accumulator broken, so the prune fails closed.
    """
    try:
        checked, cut = set(), set()
        for url, row in (rows or {}).items():
            status = row.get("status") if isinstance(row, dict) else None
            key = host_key(url)
            if not key or status not in STATUSES:
                continue
            if status == "complete":
                checked.add(key)
            elif status in ("partial", "failed"):
                cut.add(key)
    except Exception:  # noqa: BLE001
        circuit_breaker._mark_accumulator_broken()
        return
    module = module or source
    circuit_breaker.note_checked(source, hosts=sorted(checked), module=module)
    if cut:
        circuit_breaker.note_degraded(module, hosts=sorted(cut), host_source=source,
                                      source_only_hosts=True,
                                      reason=f"{len(cut)} host(s) not fully covered")
