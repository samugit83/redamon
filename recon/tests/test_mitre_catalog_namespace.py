"""MITRE CWE/CAPEC metadata: the catalog's namespace is read, never assumed.

CWE 5.0 (2026-10-28) moved its XML from the http://cwe.mitre.org/cwe-7 namespace
to cwe-8. The parser matched the hardcoded cwe-7 namespace, found no element, and
wrote {} over cwe_metadata.json, so every scan lost the CWE names, abstraction and
mapping status. These tests feed each schema version through the real parser, with
requests.get mocked and the database in a tmp dir; the tracked data is never touched.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import add_mitre  # noqa: E402

SETTINGS = {"MITRE_CACHE_TTL_HOURS": 24}


def _cwe_zip(namespace: str) -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="5.0" xmlns="{namespace}"
                  xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Structure="Simple">
      <Description>Improper neutralization of input during web page generation.</Description>
      <Extended_Description>
        <xhtml:p>The page reflects   the input.</xhtml:p>
        <xhtml:p>A script runs.</xhtml:p>
      </Extended_Description>
      <Mapping_Notes><Usage>Allowed</Usage></Mapping_Notes>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("cwec_v5.0.xml", xml)
    return buf.getvalue()


def _capec_xml(namespace: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog Name="CAPEC" Version="3.9" xmlns="{namespace}">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Draft">
      <Description>An attacker constructs input that alters a SQL query.</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>""".encode()


def _serve(content: bytes):
    response = MagicMock(content=content)
    response.raise_for_status.return_value = None
    return patch.object(add_mitre.requests, "get", return_value=response)


def _stale_file(path: Path, content: str) -> None:
    """A metadata file older than the TTL, so the refresh really downloads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    old = time.time() - 48 * 3600
    os.utime(path, (old, old))


def test_cwe_catalog_in_the_cwe_8_namespace_is_parsed(tmp_path):
    with _serve(_cwe_zip("http://cwe.mitre.org/cwe-8")):
        assert add_mitre.download_cwe_metadata(tmp_path, SETTINGS) is True
    data = json.loads((tmp_path / "resources" / "cwe_metadata.json").read_text())
    assert data["79"]["name"] == "Cross-site Scripting"
    assert data["79"]["abstraction"] == "Base"
    assert data["79"]["mapping"] == "ALLOWED"
    assert data["79"]["description"].startswith("Improper neutralization")
    # CWE 5.0 writes extended descriptions as XHTML paragraphs.
    assert data["79"]["extended_description"] == "The page reflects the input. A script runs."


def test_cwe_catalog_in_the_older_cwe_7_namespace_still_parses(tmp_path):
    with _serve(_cwe_zip("http://cwe.mitre.org/cwe-7")):
        assert add_mitre.download_cwe_metadata(tmp_path, SETTINGS) is True
    data = json.loads((tmp_path / "resources" / "cwe_metadata.json").read_text())
    assert list(data) == ["79"]


def test_an_unparsable_cwe_catalog_keeps_the_current_file(tmp_path):
    dest = tmp_path / "resources" / "cwe_metadata.json"
    _stale_file(dest, '{"22": {"name": "Path Traversal"}}')
    with _serve(_cwe_zip("http://example.com/not-cwe")):
        assert add_mitre.download_cwe_metadata(tmp_path, SETTINGS) is False
    assert json.loads(dest.read_text()) == {"22": {"name": "Path Traversal"}}


def test_a_cwe_catalog_with_no_weakness_keeps_the_current_file(tmp_path):
    dest = tmp_path / "resources" / "cwe_metadata.json"
    _stale_file(dest, '{"22": {"name": "Path Traversal"}}')
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("cwec.xml", '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"/>')
    with _serve(empty.getvalue()):
        assert add_mitre.download_cwe_metadata(tmp_path, SETTINGS) is False
    assert json.loads(dest.read_text()) == {"22": {"name": "Path Traversal"}}


def test_capec_catalog_namespace_is_read_from_the_root(tmp_path):
    with _serve(_capec_xml("http://capec.mitre.org/capec-4")):
        assert add_mitre.download_capec_metadata(tmp_path, SETTINGS) is True
    data = json.loads((tmp_path / "resources" / "capec_metadata.json").read_text())
    assert data["66"]["name"] == "SQL Injection"


def test_an_empty_capec_parse_keeps_the_current_file(tmp_path):
    dest = tmp_path / "resources" / "capec_metadata.json"
    _stale_file(dest, '{"66": {"name": "SQL Injection"}}')
    with _serve(b'<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"/>'):
        assert add_mitre.download_capec_metadata(tmp_path, SETTINGS) is False
    assert json.loads(dest.read_text()) == {"66": {"name": "SQL Injection"}}
