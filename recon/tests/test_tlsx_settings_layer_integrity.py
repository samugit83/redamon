"""Strategy row 2 (L1): tlsx settings must not drift between layers.

A tlsx setting is declared in four places with three spellings. If the
camelCase Prisma field and the ``project.get('<camel>')`` key in
``fetch_project_settings`` disagree by even one character, the fetch silently
falls back to the default FOREVER: the operator flips the toggle in the UI, the
row updates in Postgres, and the scan keeps using the old value with no error
anywhere. That is the exact failure this file owns.

Structural (source-text) assertions only; the runtime behaviour of
DEFAULT_SETTINGS/fetch lives in the tlsx module tests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _read(rel_path: str) -> str:
    return (PROJECT_ROOT / rel_path).read_text(encoding="utf-8")


def _snake_to_camel(snake: str) -> str:
    head, *rest = snake.lower().split("_")
    return head + "".join(w.capitalize() for w in rest)


def _tlsx_python_keys() -> list[str]:
    """SCREAMING_SNAKE tlsx keys declared in recon DEFAULT_SETTINGS."""
    src = _read("recon/project_settings.py")
    block = re.search(r"DEFAULT_SETTINGS\s*[:=].*?\n\}", src, re.S)
    assert block, "DEFAULT_SETTINGS block not found"
    return sorted(set(re.findall(r"'(TLSX_[A-Z0-9_]+)'\s*:", block.group(0))))


def test_default_settings_declares_tlsx_keys():
    keys = _tlsx_python_keys()
    assert "TLSX_ENABLED" in keys
    assert len(keys) >= 15, f"expected the full tlsx block, got {keys}"


def test_every_python_key_has_a_fetch_mapping_with_the_matching_camel_case():
    """The drift that makes a toggle inert."""
    src = _read("recon/project_settings.py")
    missing = []
    for key in _tlsx_python_keys():
        camel = _snake_to_camel(key)
        # settings['TLSX_X'] = project.get('tlsxX', DEFAULT_SETTINGS['TLSX_X'])
        pattern = (r"settings\['" + re.escape(key) + r"'\]\s*=\s*project\.get\(\s*'"
                   + re.escape(camel) + r"'")
        if not re.search(pattern, src):
            missing.append(f"{key} -> project.get('{camel}')")
    assert not missing, "fetch_project_settings drift (toggle would be inert): " + "; ".join(missing)


def test_every_python_key_has_a_prisma_field_with_the_matching_map():
    schema = _read("webapp/prisma/schema.prisma")
    missing = []
    for key in _tlsx_python_keys():
        camel = _snake_to_camel(key)
        if camel not in schema:
            missing.append(f"Prisma field {camel}")
            continue
        line = next((ln for ln in schema.splitlines() if re.search(r"\b" + re.escape(camel) + r"\b", ln)), "")
        expected_col = key.lower()
        if f'@map("{expected_col}")' not in line:
            missing.append(f"{camel} @map should be {expected_col!r}, line={line.strip()!r}")
    assert not missing, "Prisma drift: " + "; ".join(missing)


def test_tlsx_enabled_defaults_true_in_both_python_and_prisma():
    """A default mismatch means the UI and the backend disagree on day one."""
    settings_src = _read("recon/project_settings.py")
    assert re.search(r"'TLSX_ENABLED'\s*:\s*True", settings_src)
    schema = _read("webapp/prisma/schema.prisma")
    line = next(ln for ln in schema.splitlines() if "tlsxEnabled" in ln)
    assert "@default(true)" in line, f"Prisma tlsxEnabled default disagrees with Python: {line.strip()!r}"


def test_preset_zod_schema_carries_every_tlsx_key():
    """Missing from Zod => AI-generated presets silently strip the setting."""
    zod = _read("webapp/src/lib/recon-preset-schema.ts")
    # tlsxDockerImage is deliberately not preset-tunable (image pinning is an
    # operator/deploy concern, not a scan-profile one).
    missing = [_snake_to_camel(k) for k in _tlsx_python_keys()
               if _snake_to_camel(k) not in zod and _snake_to_camel(k) != "tlsxDockerImage"]
    assert not missing, f"preset Zod schema missing: {missing}"
