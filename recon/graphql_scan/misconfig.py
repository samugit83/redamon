"""graphql-cop integration (Docker-in-Docker).

Wraps `dolevf/graphql-cop` as an external misconfig scanner. Runs 12 checks per
endpoint (alias overloading, batch query DoS, directive overloading, GraphiQL
detection, trace mode, GET-based CSRF, unhandled errors, etc.) and normalizes
the JSON output into RedAmon's Vulnerability dict shape.

Pinned to `dolevf/graphql-cop:1.14` (DockerHub). Re-verify TITLE_TO_KEY on image
bumps -- graphql-cop's JSON output discriminates by `title`, not by internal key.

Phase 2 integration per PLAN_INTEGRATION_GRAPH_QL.md §17.
"""
from __future__ import annotations

import copy
import json
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional


DEFAULT_IMAGE = 'dolevf/graphql-cop:1.14'

# --------------------------------------------------------------------------
# graphql-cop test registry
# --------------------------------------------------------------------------
# Internal key (-e exclusion flag) -> RedAmon vulnerability_type.
# Keys match graphql-cop/lib/tests/__init__.py tests dict exactly.
GRAPHQL_COP_TEST_TO_VULN_TYPE: Dict[str, str] = {
    'field_suggestions':            'graphql_field_suggestions_enabled',
    'introspection':                'graphql_introspection_enabled',
    'detect_graphiql':              'graphql_ide_exposed',
    'get_method_support':           'graphql_get_method_allowed',
    'alias_overloading':            'graphql_alias_overloading',
    'batch_query':                  'graphql_batch_query_allowed',
    'trace_mode':                   'graphql_tracing_enabled',
    'directive_overloading':        'graphql_directive_overloading',
    'circular_query_introspection': 'graphql_circular_introspection',
    'get_based_mutation':           'graphql_get_based_mutation',
    'post_based_csrf':              'graphql_post_csrf',
    'unhandled_error_detection':    'graphql_unhandled_error',
    'field_duplication':            'graphql_field_duplication_allowed',
}

# JSON output discriminates by `title`. Verbatim from graphql-cop 1.14 source
# (github.com/dolevf/graphql-cop/blob/main/lib/tests/*.py). Re-verify on image bump.
TITLE_TO_KEY: Dict[str, str] = {
    'Field Suggestions':                                'field_suggestions',
    'Introspection':                                    'introspection',
    'GraphQL IDE':                                      'detect_graphiql',
    'GET Method Query Support':                         'get_method_support',
    'Alias Overloading':                                'alias_overloading',
    'Array-based Query Batching':                       'batch_query',
    'Trace Mode':                                       'trace_mode',
    'Directive Overloading':                            'directive_overloading',
    'Introspection-based Circular Query':               'circular_query_introspection',
    'Mutation is allowed over GET (possible CSRF)':     'get_based_mutation',
    'POST based url-encoded query (possible CSRF)':     'post_based_csrf',
    'Unhandled Errors Detection':                       'unhandled_error_detection',
    # Field Duplication surfaced in graphql-cop 1.14 output but wasn't in the
    # upstream test listing we audited against — duplicate-field queries are
    # an Apollo-specific parser quirk that leaks schema info through errors.
    'Field Duplication':                                'field_duplication',
}

# Tests that generate noisy/DoS-class traffic. Auto-excluded in stealth mode.
HEAVY_TRAFFIC_TESTS = frozenset({
    'alias_overloading',
    'batch_query',
    'directive_overloading',
    'circular_query_introspection',
})

# Test key -> Endpoint property name (for capability flags set regardless of result)
TEST_TO_ENDPOINT_FLAG: Dict[str, str] = {
    'detect_graphiql':      'graphql_graphiql_exposed',
    'trace_mode':           'graphql_tracing_enabled',
    'get_method_support':   'graphql_get_allowed',
    'field_suggestions':    'graphql_field_suggestions_enabled',
    'batch_query':          'graphql_batching_enabled',
}


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def run_graphql_cop(
    endpoint: str,
    auth_headers: Dict[str, str],
    settings: dict,
    timeout: Optional[int] = None,
) -> Optional[Dict[str, list]]:
    """Run graphql-cop against one endpoint.

    Returns a dict `{'findings': [...], 'raw': [...]}` where:
        - 'findings': normalized Vulnerability dicts (only entries with result=True)
        - 'raw': the complete JSON-decoded graphql-cop output (all 12 test rows),
          used by the scanner to set Endpoint capability flags including negatives
          (e.g. "GraphiQL exposed=false" as a signal, not just silence).

    Returns:
        - dict with both arrays on success (possibly both empty)
        - None on execution error (logged, not raised -- does not kill parent scan)
    """
    if not settings.get('GRAPHQL_COP_ENABLED', False):
        return None

    timeout = timeout or settings.get('GRAPHQL_COP_TIMEOUT', 120)
    image = settings.get('GRAPHQL_COP_DOCKER_IMAGE', DEFAULT_IMAGE) or DEFAULT_IMAGE
    excluded = _build_excluded_tests(settings)
    excluded_set = set(excluded)

    # Network mode: match Nuclei's pattern -- add --network host only when Tor is on.
    # Default docker-bridge network works for external targets.
    use_tor = bool(settings.get('USE_TOR_FOR_RECON', False))
    net_flags = ['--network', 'host'] if use_tor else []

    cmd = ['docker', 'run', '--rm', *net_flags, image,
           '-t', endpoint, '-o', 'json']

    # NOTE: the dolevf/graphql-cop:1.14 Docker image does NOT support the `-e`
    # exclusion flag (added in git main v1.15 but unreleased on DockerHub as of
    # 2026-04-20). We post-filter findings Python-side instead. A side-effect:
    # DoS probes still hit the target even when "excluded" by per-test toggles.
    # For true stealth, disable the GRAPHQL_COP_ENABLED master toggle.
    if excluded_set and len(excluded_set) == len(GRAPHQL_COP_TEST_TO_VULN_TYPE):
        print(f"[-][GraphQL-Cop] All tests excluded by per-test toggles -- skipping {endpoint}")
        return {'findings': [], 'raw': []}

    if settings.get('GRAPHQL_COP_FORCE_SCAN', False):
        cmd.append('-f')

    if settings.get('GRAPHQL_COP_DEBUG', False):
        cmd.append('-d')

    # One -H per header per graphql-cop's argparse (action='append').
    for k, v in (auth_headers or {}).items():
        cmd += ['-H', json.dumps({k: v})]

    if use_tor:
        cmd.append('-T')

    proxy = settings.get('HTTP_PROXY')
    if proxy:
        cmd += ['-x', proxy]

    active_test_count = len(GRAPHQL_COP_TEST_TO_VULN_TYPE) - len(excluded_set)
    print(f"[*][GraphQL-Cop] {endpoint}  image={image}  tests={active_test_count}/12  timeout={timeout}s"
          + (f"  (filtering {len(excluded_set)} excluded tests post-execution)" if excluded_set else ""))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!][GraphQL-Cop] Timeout after {timeout}s against {endpoint}")
        return None
    except FileNotFoundError:
        print(f"[!][GraphQL-Cop] 'docker' binary not found -- is the Docker socket mounted?")
        return None
    except Exception as e:
        print(f"[!][GraphQL-Cop] Subprocess failed: {e}")
        return None

    if result.returncode != 0:
        print(f"[!][GraphQL-Cop] Non-zero exit ({result.returncode}): {result.stderr[:500].strip()}")

    findings_raw = _extract_json_array(result.stdout)
    if findings_raw is None:
        print(f"[!][GraphQL-Cop] No parseable JSON in output. First 300 chars: {result.stdout[:300]!r}")
        return None

    if not findings_raw:
        print(f"[-][GraphQL-Cop] {endpoint}: endpoint not detected as GraphQL. Enable GRAPHQL_COP_FORCE_SCAN to override.")
        return {'findings': [], 'raw': []}

    # Python-side post-filter: graphql-cop 1.14 runs all 12 tests unconditionally,
    # we strip excluded ones from the output so user intent is respected downstream.
    filtered_raw = _filter_excluded(findings_raw, excluded_set)

    return {
        'findings': _normalize_findings(endpoint, filtered_raw),
        'raw': filtered_raw,
    }


def _filter_excluded(raw_findings: List[dict], excluded_keys: set) -> List[dict]:
    """Strip findings whose test-key (via TITLE_TO_KEY) is in the excluded set.

    Used because graphql-cop 1.14 doesn't support the -e flag. Filtering is
    applied to both `findings` (Vulnerability candidates) and `raw` (used for
    capability flags), so user intent is enforced end-to-end in the graph.
    """
    if not excluded_keys:
        return raw_findings
    kept = []
    for f in raw_findings:
        title = (f.get('title') or '').strip()
        key = TITLE_TO_KEY.get(title)
        if key and key in excluded_keys:
            continue  # suppressed by per-test toggle
        kept.append(f)
    return kept


# --------------------------------------------------------------------------
# Helpers (exported for unit tests)
# --------------------------------------------------------------------------

def _build_excluded_tests(settings: dict) -> List[str]:
    """Per-test toggles -> comma-separated exclusion list for graphql-cop's -e flag.

    Each per-test setting key defaults to True (test runs). A setting value of False
    adds the test to the excluded list.
    """
    toggle_map = {
        'field_suggestions':            'GRAPHQL_COP_TEST_FIELD_SUGGESTIONS',
        'introspection':                'GRAPHQL_COP_TEST_INTROSPECTION',
        'detect_graphiql':              'GRAPHQL_COP_TEST_GRAPHIQL',
        'get_method_support':           'GRAPHQL_COP_TEST_GET_METHOD',
        'alias_overloading':            'GRAPHQL_COP_TEST_ALIAS_OVERLOADING',
        'batch_query':                  'GRAPHQL_COP_TEST_BATCH_QUERY',
        'trace_mode':                   'GRAPHQL_COP_TEST_TRACE_MODE',
        'directive_overloading':        'GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING',
        'circular_query_introspection': 'GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION',
        'get_based_mutation':           'GRAPHQL_COP_TEST_GET_MUTATION',
        'post_based_csrf':              'GRAPHQL_COP_TEST_POST_CSRF',
        'unhandled_error_detection':    'GRAPHQL_COP_TEST_UNHANDLED_ERROR',
    }
    # Default for introspection is False (dedupes with PR's native check); all others default True.
    defaults = {'introspection': False}

    excluded: List[str] = []
    for key, setting_name in toggle_map.items():
        default_enabled = defaults.get(key, True)
        if not settings.get(setting_name, default_enabled):
            excluded.append(key)
    return excluded


def _extract_json_array(stdout: str) -> Optional[list]:
    """Extract the final JSON array from graphql-cop stdout, tolerating leading text.

    graphql-cop may print informational messages to stdout before the JSON array
    when is_graphql() fails (e.g. "<url> does not seem to be running GraphQL...\n[]\n").
    """
    stdout = (stdout or '').strip()
    if not stdout:
        return None

    # Fast path: pure JSON
    if stdout.startswith('['):
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            pass

    # Try the last newline-prefixed '['
    idx = stdout.rfind('\n[')
    if idx != -1:
        try:
            return json.loads(stdout[idx + 1:])
        except json.JSONDecodeError:
            pass

    # Fallback: first '[' to end
    idx = stdout.find('[')
    if idx != -1:
        try:
            return json.loads(stdout[idx:])
        except json.JSONDecodeError:
            pass

    return None


def _normalize_findings(endpoint: str, raw_findings: List[dict]) -> List[dict]:
    """Convert graphql-cop JSON -> RedAmon Vulnerability dict shape.

    Only findings with result=True become Vulnerability records. All 12 test
    results (result=True/False) are kept in evidence so the mixin can set
    capability flags on the Endpoint node regardless of trigger.
    """
    normalized: List[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for f in raw_findings:
        title = (f.get('title') or '').strip()
        key = TITLE_TO_KEY.get(title)
        if not key:
            print(f"[!][GraphQL-Cop] Unknown test title in output: {title!r} (upstream may have added tests)")
            continue
        if not f.get('result'):
            continue

        vuln_type = GRAPHQL_COP_TEST_TO_VULN_TYPE[key]
        severity = _map_severity(f.get('severity', 'INFO'))

        normalized.append({
            'vulnerability_type': vuln_type,
            'severity': severity,
            'endpoint': endpoint,
            'title': title,
            'description': f.get('description') or '',
            'impact': f.get('impact') or '',
            'source': 'graphql_cop',
            'evidence': {
                'curl_verify': f.get('curl_verify') or '',
                'raw_severity': (f.get('severity') or '').upper(),
                'color': f.get('color') or '',
                'graphql_cop_key': key,
            },
            'timestamp': now,
        })

    return normalized


def _map_severity(raw: str) -> str:
    """graphql-cop severity -> RedAmon canonical lowercase."""
    return {
        'HIGH':   'high',
        'MEDIUM': 'medium',
        'LOW':    'low',
        'INFO':   'info',
    }.get((raw or '').upper(), 'low')


def derive_endpoint_flags(raw_findings: List[dict]) -> Dict[str, bool]:
    """Return boolean capability flags to set on the Endpoint node.

    Uses ALL raw findings (result=True/False) so the mixin records server state
    even for tests where nothing triggered (e.g. 'GraphiQL exposed: false').
    """
    flags: Dict[str, bool] = {}
    for f in raw_findings or []:
        key = TITLE_TO_KEY.get((f.get('title') or '').strip())
        prop = TEST_TO_ENDPOINT_FLAG.get(key) if key else None
        if prop is not None:
            flags[prop] = bool(f.get('result'))
    return flags
