"""OSV-Scanner runner + parser (the verdict engine).

Verified against OSV-Scanner v2.4.0 (2026-08-06):
  - Scan a lockfile:   osv-scanner scan source -L <path> --format json
  - Scan a directory:  osv-scanner scan source -r <dir> --format json
  - Scan an SBOM:       osv-scanner scan source <bom.cdx.json> --format json
                        (v2 auto-detects CycloneDX/SPDX by content; there is no
                         separate --sbom flag in v2, unlike v1)
  - OFFLINE (mandatory for passivity): pass --offline and point the scanner at
    the pre-downloaded local DB via the environment variable
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<db_path>. The DB is fetched ONCE by the
    Phase-0 updater with --download-offline-databases; scans never download.
    VERIFIED 2026-08-06 against v2.4.0: --offline loads the local DB (logs
    "Loaded npm local db from <path>/osv-scanner/npm/all.zip") and matches MAL-
    ids. --offline-vulnerabilities did NOT load the local DB in this build and
    returned empty results; do not use it for the offline path. The plan's §2
    said --offline-vulnerabilities; this corrects it.
  - LOCKFILE NAME MATTERS: osv-scanner picks the extractor from the file's
    BASENAME (package-lock.json, requirements.txt, ...). A path like /work/pl.json
    fails with "could not determine extractor". Callers MUST name the scanned
    file with a recognized lockfile name (or pass lockfile_type to force it).
  - Exit codes: 0 = no findings, 1 = findings present, 127/128/... = tool error.
    We never gate on exit code alone; anything outside {0,1} is a runner error
    but we still attempt to parse stdout.

A vulnerability whose `id` starts with 'MAL-' is a terminal MALICIOUS verdict.
CVE-/GHSA- ids are known-vulnerable (not malicious) and are routed to the
`vulnerable` bucket, never written as a malicious finding by this feature.
"""

import json
import re
import os

from ._run import run_argv
from .purl import build_purl
from .security import sanitize_name

__all__ = ["run_osv_scan", "parse_osv_json", "OSV_OK_EXIT_CODES"]

OSV_OK_EXIT_CODES = {0, 1}

_MODE_FLAG = {
    "lockfile": "-L",
    "dir": "-r",
    # sbom: passed as a positional path (v2 auto-detects the SBOM format)
    "sbom": None,
}


def run_osv_scan(target, *, mode="lockfile", db_path=None, offline=True,
                 timeout=120, binary="osv-scanner"):
    """Run osv-scanner over `target` and return {raw, parsed, exit_code, error}.

    `mode` in {lockfile, dir, sbom}. `target` is a filesystem path already
    inside a trusted scratch dir (the caller owns path safety). `db_path` is the
    local OSV DB cache directory; required when offline=True.
    """
    if mode not in _MODE_FLAG:
        return {"raw": None, "parsed": _empty_parsed(),
                "exit_code": None, "error": "unknown mode: {}".format(mode)}

    if offline:
        # F5: running --offline with no local DB (missing dir OR an empty volume
        # that was created but never populated by `redamon.sh supply-chain-sync`)
        # returns an EMPTY result with exit 0 - a silent false-clean where a
        # genuinely malicious package passes. Fail hard with an actionable error
        # instead of reporting a misleading clean verdict.
        db = str(db_path) if db_path else ""
        if not db or not os.path.isdir(db) or not os.listdir(db):
            return {"raw": None, "parsed": _empty_parsed(), "exit_code": None,
                    "error": ("offline OSV DB missing or empty at {!r}; run "
                              "'./redamon.sh supply-chain-sync <ecosystems>' "
                              "first".format(db_path))}

    argv = [binary, "scan", "source"]
    flag = _MODE_FLAG[mode]
    if flag:
        argv += [flag, str(target)]
    else:
        argv += [str(target)]

    env = dict(os.environ)
    if offline:
        # --offline (NOT --offline-vulnerabilities) is what loads the local DB
        # and matches MAL- ids in v2.4.0. Verified 2026-08-06; see module docstring.
        argv.append("--offline")
        if db_path:
            env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(db_path)
    argv += ["--format", "json"]

    res = run_argv(argv, timeout=timeout, env=env)

    # A missing ecosystem DB is its OWN case and owns the whole message.
    #
    # Checked BEFORE the generic explainer because both can fire on the same
    # run: a total DB miss exits 127 (explainer) while ALSO printing
    # "could not load db for X ecosystem". Letting both speak produced one
    # error with the same instruction twice, e.g.
    #   "...no 'PyPI' ecosystem(s); run ... to add them; ...no 'PyPI'
    #    ecosystem(s); those packages were NOT checked - run ..."
    #
    # The PARTIAL case is the dangerous one and the reason this exists at all:
    # osv-scanner scans every lockfile it finds, loads whatever ecosystem DBs
    # it has, reports nothing for the rest - and exits 0/1, a SUCCESS code:
    #
    #   Scanned .../requirements.txt file and found 2 packages
    #   Loaded npm local db from /osv-db/osv-scanner/npm/all.zip
    #   could not load db for PyPI ecosystem: ...
    #   exit 1, results = [ the npm package only ]
    #
    # So the Python half reads CLEAN. Verified against v2.4.0 on 2026-08-07.
    # Findings that DID resolve are kept; the gap is reported alongside them,
    # because "we could not check these" is not "these are fine".
    error = res["error"]
    missing = _missing_ecosystems(res["stderr"])
    if error is None and missing:
        error = ("offline OSV database has no {} ecosystem(s); those packages "
                 "were NOT checked - run './redamon.sh supply-chain-sync {}'"
                 .format(", ".join("'{}'".format(e) for e in missing),
                         " ".join(missing)))
    elif error is None and res["exit_code"] not in OSV_OK_EXIT_CODES:
        # Non-{0,1} exit is a tool/usage error. osv-scanner prints a filesystem
        # walk log BEFORE the real cause, so surface the meaningful lines (and
        # the TAIL, not the head) instead of 500 chars of walk noise.
        error = _explain_osv_stderr(res["stderr"], res["exit_code"])

    raw = None
    if res["stdout"]:
        try:
            raw = json.loads(res["stdout"])
        except (ValueError, TypeError):
            if error is None:
                error = "osv-scanner produced non-JSON output"

    return {
        "raw": raw,
        "parsed": parse_osv_json(raw),
        "exit_code": res["exit_code"],
        "error": error,
    }


# "could not load db for PyPI ecosystem: ..." - the ecosystem was never synced
# into the offline DB. Turn it into an actionable instruction.
_MISSING_DB_RE = re.compile(r"could not load db for (\S+) ecosystem")


def _missing_ecosystems(stderr):
    """Every ecosystem osv-scanner could not load a local DB for.

    findall, not search: a DIRECTORY scan (a cloned repository) covers as many
    ecosystems as the repo has lockfiles, and naming only the first would send
    the operator to sync one ecosystem and hit the next on the following run.
    """
    seen = []
    for eco in _MISSING_DB_RE.findall(stderr or ""):
        if eco not in seen:
            seen.append(eco)
    return seen

# Lines worth showing the operator; everything else is walk/progress noise.
_NOISE_PREFIXES = ("Starting filesystem walk", "End status:", "Scanned ",
                   "Filesystem walk", "Loaded ")


def _explain_osv_stderr(stderr, exit_code):
    """Turn raw osv-scanner stderr into one actionable error line."""
    text = (stderr or "").strip()
    missing = _missing_ecosystems(text)
    if missing:
        return ("offline OSV database has no {} ecosystem(s); run "
                "'./redamon.sh supply-chain-sync {}' to add them"
                .format(", ".join("'{}'".format(e) for e in missing),
                        " ".join(missing)))
    meaningful = [ln.strip() for ln in text.splitlines()
                  if ln.strip() and not ln.strip().startswith(_NOISE_PREFIXES)]
    detail = " | ".join(meaningful[-3:]) if meaningful else text[-300:]
    return "osv-scanner exit {}: {}".format(exit_code, detail[:400])


def _empty_parsed():
    return {"packages": [], "malicious": [], "vulnerable": []}


# GitHub advisory severity (OSV `database_specific.severity`) -> the graph's
# lowercase Vulnerability enum. OSV also carries CVSS vectors in `severity[]`,
# but the GitHub band is already the qualitative judgement we want and needs no
# vector parsing.
_OSV_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def severity_for_vuln(vuln):
    """Qualitative severity for one OSV advisory, or 'unknown'.

    The parser used to hardcode "unknown" and drop this, which meant every
    CVE/GHSA reached the graph with no way to triage it.
    """
    if not isinstance(vuln, dict):
        return "unknown"
    db = vuln.get("database_specific") or {}
    raw = db.get("severity") if isinstance(db, dict) else None
    if isinstance(raw, str):
        mapped = _OSV_SEVERITY_MAP.get(raw.strip().upper())
        if mapped:
            return mapped
    return "unknown"


def cvss_vector_for_vuln(vuln):
    """First CVSS vector string in an OSV advisory, or None."""
    if not isinstance(vuln, dict):
        return None
    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict) and entry.get("score"):
            return str(entry["score"])[:200]
    return None


def fixed_version_for_vuln(vuln, package_name=None):
    """The version that fixes this advisory, or "". Never raises.

    Without it a fix item can only say "upgrade this package"; with it, it says
    "upgrade to 4.17.21", which is the difference between a ticket somebody has
    to research and one they can act on.

    OSV puts it in `affected[].ranges[].events[].fixed`. An advisory can carry
    several affected packages and several ranges, so the LOWEST fixed version
    that appears is taken: it is the smallest upgrade that resolves it.
    """
    if not isinstance(vuln, dict):
        return ""
    candidates = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        if package_name:
            pkg = affected.get("package") or {}
            name = pkg.get("name") if isinstance(pkg, dict) else None
            if name and name != package_name:
                continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    candidates.append(str(event["fixed"])[:64])
    if not candidates:
        return ""
    # Sorted as strings rather than parsed as semver: this is display text, and
    # a wrong-but-plausible parse of an odd version scheme would be worse than
    # an occasionally suboptimal pick.
    return sorted(set(candidates))[0]


def parse_osv_json(raw):
    """Split an osv-scanner JSON document into packages / malicious / vulnerable.

    Fully defensive: `raw` may be None, `results` may be [] or null, a package
    may have no `vulnerabilities`. Never raises.
    """
    out = _empty_parsed()
    if not isinstance(raw, dict):
        return out

    for result in raw.get("results") or []:
        if not isinstance(result, dict):
            continue
        source_path = ((result.get("source") or {}).get("path")) if isinstance(
            result.get("source"), dict) else None
        for pkg_entry in result.get("packages") or []:
            if not isinstance(pkg_entry, dict):
                continue
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name")
            version = pkg.get("version")
            ecosystem = pkg.get("ecosystem")
            if not name or not ecosystem:
                continue
            try:
                sanitize_name(name)
                purl = build_purl(ecosystem, name, version)
            except Exception:
                # A package name that fails our charset gate is not something we
                # will emit; skip it rather than risk it downstream.
                continue

            out["packages"].append({
                "purl": purl,
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "source_path": source_path,
            })

            for vuln in pkg_entry.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                vid = vuln.get("id") or ""
                finding = {
                    "purl": purl,
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "advisory_id": vid,
                    "aliases": vuln.get("aliases") or [],
                    "summary": vuln.get("summary") or "",
                    "severity": severity_for_vuln(vuln),
                    "cvss_vector": cvss_vector_for_vuln(vuln),
                    "fixed_version": fixed_version_for_vuln(vuln, name),
                    "summary_detail": vuln.get("details") or "",
                }
                if vid.startswith("MAL-"):
                    out["malicious"].append(finding)
                else:
                    # CVE-, GHSA-, and anything else = known-vulnerable, not
                    # malicious. Kept for the raw path; not a MalPackageFinding.
                    out["vulnerable"].append(finding)

    return out
