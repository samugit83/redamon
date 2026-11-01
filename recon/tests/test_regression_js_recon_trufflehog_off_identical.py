"""R1: with TruffleHog off, js_recon's output is what it was before TruffleHog.

The engine ships off by default, and a project that keeps it off must see
nothing change: no staging, no container, no `scan_metadata.trufflehog` key,
the same secrets with the same ids, severities and validation states. The
golden (`fixtures/js_recon_trufflehog_off_golden.json`) was recorded from the
code before TruffleHog was wired in, with every value stored as a hash.

Downloads and the provider validators are fakes; nothing leaves the process.
Every value is synthetic and assembled at runtime. Regenerate only from code
without the TruffleHog wiring:

    python recon/tests/test_regression_js_recon_trufflehog_off_identical.py --regen
"""
from __future__ import annotations

import hashlib
import json
import random
import string
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "js_recon_trufflehog_off_golden.json"
HOST = "app.example.com"
ALNUM = string.ascii_letters + string.digits
SETTINGS = {
    "JS_RECON_MAX_FILES": 100, "JS_RECON_TIMEOUT": 60, "JS_RECON_VALIDATE_KEYS": True,
    "JS_RECON_SOURCE_MAPS": False, "JS_RECON_DEPENDENCY_CHECK": False,
    "JS_RECON_TRUFFLEHOG_ENABLED": False,
}


def _rnd(label, n, alphabet=ALNUM):
    rng = random.Random(f"r1:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def _files() -> dict:
    gh = "gh" + "p_" + _rnd("gh", 36)
    stripe = "sk" + "_live_" + _rnd("stripe", 28)
    aws = "AK" + "IA" + _rnd("aws", 16, string.ascii_uppercase + string.digits)
    gcp = "AI" + "zaSy" + _rnd("gcp", 33)
    slack = "xo" + "xb-" + _rnd("s1", 12, string.digits) + "-" + _rnd("s2", 12, string.digits) + "-" + _rnd("s3", 24)
    sendgrid = "SG." + _rnd("sg1", 22) + "." + _rnd("sg2", 43)
    main = (f'!function(){{var c={{apiKey:"{gcp}",authDomain:"demo.firebaseapp.com"}};'
            f'var t="{gh}",s="{stripe}";e.aws={{accessKeyId:"{aws}"}};'
            f'var p="https://ops:{_rnd("pw", 14)}@db.example.org:5432/x";'
            'var u={id:"' + _rnd("u", 8, "0123456789abcdef") + '-1234-4abc-8def-' + _rnd("u2", 12, "0123456789abcdef") + '"};'
            '}();')
    chunk = (f'const slackToken = "{slack}";\nconst SENDGRID = "{sendgrid}";\n'
             f'// TODO remove the hardcoded password\nvar password = "Tr0{_rnd("pwd", 9)}!";\n')
    return {f"https://{HOST}/assets/main.js": main, f"https://{HOST}/assets/chunk.js": chunk}


def _answer(name, matched_text, validator_ref=None, timeout=5):
    if "GitHub" in name:
        return {"valid": False, "state": "rejected", "error": "", "info": "status=401"}
    if "Stripe" in name:
        return {"valid": True, "state": "valid", "scope": "account", "info": "live"}
    return {"valid": False, "state": "unknown", "error": "", "info": "status=503"}


def _h(value) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def _run() -> dict:
    files = _files()

    def download(urls, work_dir, max_files, unreachable=None, **_kw):
        return [{"url": u, "filepath": "", "content": files[u], "headers": {}, "size": len(files[u])}
                for u in urls]

    combined = {"metadata": {}, "http_probe": {"by_url": {f"https://{HOST}": {"status_code": 200}}},
                "resource_enum": {"discovered_urls": []}}
    cb.reset_registry()
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=sorted(files)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=download), \
            mock.patch.object(js_recon, "validate_secret", side_effect=_answer), \
            mock.patch.object(js_recon.time, "strftime", return_value="2026-01-01T00:00:00Z"):
        out = js_recon.run_js_recon(combined, dict(SETTINGS))["js_recon"]
    cb.reset_registry()
    return out


def normalize(js: dict) -> dict:
    """Every value as a hash; the run's clock and paths dropped."""
    secrets = sorted(({
        "id": s["id"], "name": s["name"], "severity": s["severity"], "confidence": s["confidence"],
        "category": s["category"], "line_number": s["line_number"], "source_url": s["source_url"],
        "public_client_key": s.get("public_client_key"), "detection_method": s.get("detection_method"),
        "alternate_names": s.get("alternate_names", []),
        "validation": {k: v for k, v in (s.get("validation") or {}).items() if k != "checked_at"},
        "matched_text": _h(s["matched_text"]), "redacted_value": _h(s["redacted_value"]),
        "context": _h(s.get("context", "")),
    } for s in js.get("secrets", [])), key=lambda s: s["id"])
    meta = {k: v for k, v in js["scan_metadata"].items()
            if k not in ("scan_timestamp", "duration_seconds", "coverage")}
    coverage = {h: row for h, row in js["scan_metadata"]["coverage"]["hosts"].items()}
    summary = js.get("summary", {})
    return {"secrets": secrets, "scan_metadata": meta, "coverage": coverage, "summary": summary,
            "keys": sorted(js)}


def test_off_is_identical_to_the_golden():
    out = _run()
    assert "trufflehog" not in out["scan_metadata"]
    assert normalize(out) == json.loads(GOLDEN.read_text())


def test_off_never_touches_the_bridge():
    with mock.patch.object(js_recon, "trufflehog_bridge", create=True) as bridge:
        out = _run()
    assert not bridge.method_calls
    assert "trufflehog" not in out["scan_metadata"]


if __name__ == "__main__":
    if "--regen" in sys.argv:
        GOLDEN.write_text(json.dumps(normalize(_run()), indent=1, sort_keys=True) + "\n")
        print(f"wrote {GOLDEN}")
