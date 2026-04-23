"""
JS Recon Framework Fingerprinting + DOM Sink Detection

Detects JavaScript frameworks and their versions, identifies DOM-based XSS
sinks and prototype pollution patterns, and extracts developer comments.
"""

import re
import json
import hashlib
from typing import Optional


# ========== FRAMEWORK SIGNATURES ==========
# Each: (name, patterns_list, version_regex_or_None)
FRAMEWORK_SIGNATURES = [
    {
        'name': 'React',
        'patterns': [
            re.compile(r'React\.version'),
            re.compile(r'react-dom'),
            re.compile(r'__REACT_DEVTOOLS_GLOBAL_HOOK__'),
            re.compile(r'reactVersion'),
            re.compile(r'React\.createElement'),
        ],
        'version_re': re.compile(r'(?:React\.version|reactVersion)\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Next.js',
        'patterns': [
            re.compile(r'__NEXT_DATA__'),
            re.compile(r'/_next/'),
            re.compile(r'next/router'),
            re.compile(r'nextjs'),
        ],
        'version_re': re.compile(r'(?:next|Next\.js)[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Vue.js',
        'patterns': [
            re.compile(r'Vue\.version'),
            re.compile(r'__vue__'),
            re.compile(r'createApp'),
            re.compile(r'vue-router'),
        ],
        'version_re': re.compile(r'Vue\.version\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Nuxt.js',
        'patterns': [
            re.compile(r'__NUXT__'),
            re.compile(r'/_nuxt/'),
            re.compile(r'nuxtApp'),
        ],
        'version_re': re.compile(r'nuxt[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Angular',
        'patterns': [
            re.compile(r'ng\.version'),
            re.compile(r'@angular/core'),
            re.compile(r'platformBrowserDynamic'),
            re.compile(r'NgModule'),
            re.compile(r'ng-version'),
        ],
        'version_re': re.compile(r'(?:ng\.version|angular[/\s]*)[:=]?\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'jQuery',
        'patterns': [
            re.compile(r'jQuery\.fn\.jquery'),
            re.compile(r'\$\.fn\.jquery'),
            re.compile(r'jquery[.-]([0-9]+\.[0-9]+)'),
        ],
        'version_re': re.compile(r'(?:jQuery\.fn\.jquery|jquery)[/\s.-]*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Svelte',
        'patterns': [
            re.compile(r'__svelte'),
            re.compile(r'SvelteComponent'),
            re.compile(r'svelte/internal'),
        ],
        'version_re': re.compile(r'svelte[/\s]*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Ember',
        'patterns': [
            re.compile(r'Ember\.VERSION'),
            re.compile(r'ember-cli'),
            re.compile(r'ember-source'),
        ],
        'version_re': re.compile(r'Ember\.VERSION\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Backbone',
        'patterns': [
            re.compile(r'Backbone\.VERSION'),
            re.compile(r'backbone\.js'),
        ],
        'version_re': re.compile(r'Backbone\.VERSION\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Lodash',
        'patterns': [
            re.compile(r'_\.VERSION'),
            re.compile(r'lodash\.js'),
        ],
        'version_re': re.compile(r'(?:_\.VERSION|lodash)\s*[:=]?\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
    {
        'name': 'Moment.js',
        'patterns': [
            re.compile(r'moment\.version'),
            re.compile(r'moment\.js'),
        ],
        'version_re': re.compile(r'moment\.version\s*[:=]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'),
    },
    {
        'name': 'Bootstrap',
        'patterns': [
            re.compile(r'bootstrap.*version', re.IGNORECASE),
            re.compile(r'Bootstrap\s*v'),
        ],
        'version_re': re.compile(r'[Bb]ootstrap\s*v?([0-9]+\.[0-9]+\.[0-9]+)'),
    },
]

# ========== DOM SINK PATTERNS ==========
# Each: (pattern, sink_type, severity, description)
DOM_SINK_PATTERNS = [
    # Direct HTML injection
    (re.compile(r'\.innerHTML\s*='), 'innerHTML', 'high', 'Direct HTML injection via innerHTML'),
    (re.compile(r'\.outerHTML\s*='), 'outerHTML', 'high', 'Direct HTML injection via outerHTML'),
    (re.compile(r'document\.write\s*\('), 'document.write', 'high', 'DOM injection via document.write'),
    (re.compile(r'document\.writeln\s*\('), 'document.writeln', 'high', 'DOM injection via document.writeln'),

    # Code execution
    (re.compile(r'[^a-zA-Z]eval\s*\('), 'eval', 'critical', 'Arbitrary code execution via eval()'),
    (re.compile(r'[^a-zA-Z]Function\s*\('), 'Function', 'critical', 'Arbitrary code execution via Function()'),
    (re.compile(r'setTimeout\s*\(\s*["\']'), 'setTimeout', 'high', 'Code execution via setTimeout with string'),
    (re.compile(r'setInterval\s*\(\s*["\']'), 'setInterval', 'high', 'Code execution via setInterval with string'),

    # URL/navigation manipulation
    (re.compile(r'location\.href\s*='), 'location.href', 'medium', 'URL redirection via location.href'),
    (re.compile(r'location\.assign\s*\('), 'location.assign', 'medium', 'URL redirection via location.assign'),
    (re.compile(r'location\.replace\s*\('), 'location.replace', 'medium', 'URL redirection via location.replace'),
    (re.compile(r'window\.open\s*\('), 'window.open', 'medium', 'Window opening -- potential phishing vector'),

    # Cross-origin messaging
    (re.compile(r'postMessage\s*\('), 'postMessage', 'medium', 'Cross-origin messaging -- check origin validation'),

    # Prototype pollution
    (re.compile(r'__proto__'), '__proto__', 'high', 'Prototype pollution vector via __proto__'),
    (re.compile(r'constructor\.prototype'), 'constructor.prototype', 'high', 'Prototype pollution via constructor.prototype'),
    (re.compile(r'Object\.assign\s*\([^)]*,\s*(?:req|params|query|body|input|data|user)'), 'Object.assign', 'high', 'Potential prototype pollution via Object.assign with user input'),

    # React-specific
    (re.compile(r'dangerouslySetInnerHTML'), 'dangerouslySetInnerHTML', 'high', 'React unsafe HTML injection'),
]


def detect_frameworks(
    content: str,
    source_url: str,
    custom_signatures: Optional[list] = None,
) -> list:
    """
    Detect JavaScript frameworks and their versions in JS content.

    Args:
        content: JavaScript file content
        source_url: URL of the JS file
        custom_signatures: Optional user-uploaded framework signatures

    Returns:
        List of framework detection dicts
    """
    findings = []
    detected_names = set()

    signatures = list(FRAMEWORK_SIGNATURES)
    if custom_signatures:
        for cs in custom_signatures:
            try:
                sig = {
                    'name': cs['name'],
                    'patterns': [re.compile(p) for p in cs.get('patterns', [])],
                    'version_re': re.compile(cs['version_regex']) if cs.get('version_regex') else None,
                }
                signatures.append(sig)
            except (re.error, KeyError, TypeError) as e:
                print(f"[!][JsRecon] Failed to load custom framework '{cs.get('name', 'unknown')}': {e}")
                continue

    for sig in signatures:
        try:
            if sig['name'] in detected_names:
                continue

            for pattern in sig['patterns']:
                if pattern.search(content):
                    # Framework detected -- try to extract version
                    version = None
                    if sig['version_re']:
                        ver_match = sig['version_re'].search(content)
                        if ver_match:
                            version = ver_match.group(1)

                    detected_names.add(sig['name'])
                    finding_id = hashlib.sha256(f"fw:{sig['name']}:{source_url}".encode()).hexdigest()[:16]
                    findings.append({
                        'id': finding_id,
                        'finding_type': 'framework',
                        'name': sig['name'],
                        'version': version,
                        'source_url': source_url,
                        'severity': 'info',
                        'confidence': 'high' if version else 'medium',
                    })
                    break
        except Exception as e:
            print(f"[!][JsRecon] Framework detection failed for sig '{sig.get('name', '?')}': {e}")

    return findings


def detect_dom_sinks(content: str, source_url: str) -> list:
    """
    Detect DOM-based XSS sinks and prototype pollution patterns.

    Returns:
        List of DOM sink finding dicts
    """
    findings = []
    lines = content.split('\n')
    seen = set()

    for line_num, line in enumerate(lines, 1):
        try:
            for pattern, sink_type, severity, description in DOM_SINK_PATTERNS:
                if pattern.search(line):
                    # Deduplicate by sink type + source file
                    key = f"{sink_type}:{source_url}:{line_num}"
                    if key in seen:
                        continue
                    seen.add(key)

                    finding_id = hashlib.sha256(f"sink:{key}".encode()).hexdigest()[:16]
                    findings.append({
                        'id': finding_id,
                        'finding_type': 'dom_sink',
                        'type': sink_type,
                        'pattern': line.strip()[:200],
                        'description': description,
                        'source_url': source_url,
                        'line': line_num,
                        'severity': severity,
                        'confidence': 'medium',
                    })
        except Exception as e:
            print(f"[!][JsRecon] DOM sink detection failed at line {line_num} in {source_url}: {e}")

    return findings


def detect_dev_comments(content: str, source_url: str) -> list:
    """
    Extract developer comments with TODO/FIXME/HACK markers and sensitive keywords.

    Delegates to patterns.scan_dev_comments() for consistency.
    Import is deferred to avoid circular import at module load time.
    """
    try:
        from recon.helpers.js_recon.patterns import scan_dev_comments
        return scan_dev_comments(content, source_url)
    except ImportError:
        # Fallback: import failed (e.g., running standalone)
        from .patterns import scan_dev_comments as _scan
        return _scan(content, source_url)


def load_custom_frameworks(file_path: str) -> list:
    """
    Load custom framework signatures from a user-uploaded JSON file.

    JSON format:
    [
        {
            "name": "MyFramework",
            "patterns": ["myframework\\.init", "__MY_FRAMEWORK__"],
            "version_regex": "MyFramework\\.version\\s*=\\s*[\"']([0-9.]+)[\"']"
        }
    ]
    """
    if not file_path:
        return []

    try:
        with open(file_path, 'r') as f:
            data = json.loads(f.read())
        if isinstance(data, list):
            return data
    except Exception as e:
        print(f"[!][JsRecon] Failed to load custom frameworks from {file_path}: {e}")

    return []
