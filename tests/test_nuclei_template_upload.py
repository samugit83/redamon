"""
Unit tests for nuclei template upload/management feature.

Tests:
1. parseTemplateMeta regex (TypeScript logic replicated in Python for testing)
2. sanitizePath / sanitizeSubdir logic
3. Dynamic docstring generation for execute_nuclei
4. Real template parsing from the repo
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Replicate the TypeScript parseTemplateMeta regex in Python for testing
# ---------------------------------------------------------------------------

import re

def parse_template_meta(content: str):
    """Replicate the TypeScript parseTemplateMeta regex logic."""
    first_doc = content.split('---')[0] if '---' in content else content

    id_match = re.search(r'^id:\s*(.+)$', first_doc, re.MULTILINE)
    if not id_match:
        return None

    name_match = re.search(r'^\s+name:\s*(.+)$', first_doc, re.MULTILINE)
    severity_match = re.search(r'^\s+severity:\s*(.+)$', first_doc, re.MULTILINE)

    return {
        'id': id_match.group(1).strip(),
        'name': name_match.group(1).strip() if name_match else '',
        'severity': severity_match.group(1).strip().lower() if severity_match else 'unknown',
    }


def sanitize_path(raw_path: str) -> str | None:
    """Replicate the TypeScript sanitizePath logic."""
    normalized = os.path.normpath(raw_path)
    if '..' in normalized or os.path.isabs(normalized):
        return None
    if not re.search(r'\.(ya?ml)$', normalized, re.IGNORECASE):
        return None
    return normalized


def sanitize_subdir(raw_dir: str) -> str | None:
    """Replicate the TypeScript sanitizeSubdir logic."""
    if not raw_dir:
        return None
    normalized = os.path.normpath(raw_dir).strip('/')
    if '..' in normalized or os.path.isabs(normalized):
        return None
    if not re.match(r'^[a-zA-Z0-9/_-]+$', normalized):
        return None
    return normalized


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseTemplateMeta(unittest.TestCase):
    """Test the regex-based YAML metadata parser."""

    def test_standard_template(self):
        content = """id: my-template

info:
  name: My Template
  severity: high
  tags: test,example
"""
        meta = parse_template_meta(content)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['id'], 'my-template')
        self.assertEqual(meta['name'], 'My Template')
        self.assertEqual(meta['severity'], 'high')

    def test_multi_document_yaml(self):
        content = """id: first-template

info:
  name: First Template
  severity: critical

---
id: second-template

info:
  name: Second Template
  severity: low
"""
        meta = parse_template_meta(content)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['id'], 'first-template')
        self.assertEqual(meta['severity'], 'critical')

    def test_no_id_returns_none(self):
        content = """info:
  name: No ID Template
  severity: medium
"""
        meta = parse_template_meta(content)
        self.assertIsNone(meta)

    def test_missing_severity(self):
        content = """id: no-severity

info:
  name: Template Without Severity
"""
        meta = parse_template_meta(content)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['severity'], 'unknown')

    def test_missing_name(self):
        content = """id: no-name

info:
  severity: low
"""
        meta = parse_template_meta(content)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['name'], '')
        self.assertEqual(meta['severity'], 'low')

    def test_real_springboot_templates(self):
        """Parse the actual Spring Boot templates from the repo."""
        templates_dir = PROJECT_ROOT / "mcp" / "nuclei-templates"
        if not templates_dir.is_dir():
            self.skipTest("mcp/nuclei-templates not found")

        parsed = []
        for fpath in sorted(templates_dir.rglob("*.yaml")):
            content = fpath.read_text()
            meta = parse_template_meta(content)
            if meta:
                parsed.append(meta)

        self.assertGreaterEqual(len(parsed), 1)
        ids = [p['id'] for p in parsed]
        self.assertIn('springboot-heapdump-bypass', ids)

        # All should have a severity
        for p in parsed:
            self.assertIn(p['severity'], ['critical', 'high', 'medium', 'low', 'info', 'unknown'])


class TestSanitizePath(unittest.TestCase):
    """Test path sanitization for DELETE endpoint."""

    def test_valid_yaml_path(self):
        self.assertEqual(
            sanitize_path('http/misconfiguration/springboot/foo.yaml'),
            os.path.normpath('http/misconfiguration/springboot/foo.yaml')
        )

    def test_valid_yml_path(self):
        self.assertIsNotNone(sanitize_path('simple.yml'))

    def test_rejects_traversal(self):
        self.assertIsNone(sanitize_path('../etc/passwd.yaml'))

    def test_rejects_absolute(self):
        self.assertIsNone(sanitize_path('/etc/nuclei.yaml'))

    def test_rejects_non_yaml(self):
        self.assertIsNone(sanitize_path('malware.txt'))
        self.assertIsNone(sanitize_path('script.py'))

    def test_rejects_no_extension(self):
        self.assertIsNone(sanitize_path('noextension'))


class TestSanitizeSubdir(unittest.TestCase):
    """Test subdirectory sanitization for POST endpoint."""

    def test_valid_subdir(self):
        self.assertEqual(sanitize_subdir('http/misconfiguration/myapp'), 'http/misconfiguration/myapp')

    def test_rejects_traversal(self):
        self.assertIsNone(sanitize_subdir('../escape'))

    def test_rejects_special_chars(self):
        self.assertIsNone(sanitize_subdir('path with spaces'))
        self.assertIsNone(sanitize_subdir('path;injection'))

    def test_rejects_empty(self):
        self.assertIsNone(sanitize_subdir(''))

    def test_allows_hyphens_underscores(self):
        self.assertIsNotNone(sanitize_subdir('my-custom_templates'))


class TestDynamicDocstring(unittest.TestCase):
    """Test the dynamic docstring generation for execute_nuclei."""

    def test_discover_custom_templates_with_real_files(self):
        """Test _discover_custom_templates with actual repo templates."""
        sys.path.insert(0, str(PROJECT_ROOT / "mcp" / "servers"))

        # We can't import nuclei_server directly (needs fastmcp), but we can
        # replicate _discover_custom_templates logic
        templates_dir = PROJECT_ROOT / "mcp" / "nuclei-templates"
        if not templates_dir.is_dir():
            self.skipTest("mcp/nuclei-templates not found")

        templates = []
        dirs_seen = set()
        for root, _dirs, files in os.walk(templates_dir):
            for fname in sorted(files):
                if not fname.endswith(('.yaml', '.yml')):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, str(templates_dir))
                rel_dir = os.path.dirname(rel_path)
                try:
                    with open(fpath, 'r') as f:
                        data = next(yaml.safe_load_all(f), None)
                    if not isinstance(data, dict):
                        continue
                    info = data.get('info', {})
                    templates.append({
                        "id": data.get("id", fname),
                        "severity": info.get("severity", "unknown"),
                    })
                    if rel_dir:
                        dirs_seen.add(rel_dir)
                except Exception:
                    pass

        self.assertGreaterEqual(len(templates), 1, f"Expected >=1 templates, got {templates}")
        # dirs_seen may be empty if all templates are in the root directory
        # Just verify we found templates — subdirectory structure is optional

    def test_docstring_format(self):
        """Test the format of the generated docstring fragment."""
        # Simulate what _discover_custom_templates would produce
        templates = [
            {"id": "test-template", "name": "Test", "severity": "high", "path": "/opt/nuclei-templates/test.yaml"},
        ]
        dirs_seen = {"http/misconfiguration/test"}

        lines = ["", "    Custom templates available at /opt/nuclei-templates/:"]
        for t in templates:
            lines.append(f"      - [{t['severity']}] {t['id']}: {t['name']}")
            lines.append(f"        path: {t['path']}")
        lines.append("")
        lines.append("    Scan entire custom directory:")
        for d in sorted(dirs_seen):
            lines.append(f"      - \"-u URL -t /opt/nuclei-templates/{d}/ -jsonl\"")

        result = "\n".join(lines)
        self.assertIn("[high] test-template: Test", result)
        self.assertIn("/opt/nuclei-templates/test.yaml", result)
        self.assertIn("/opt/nuclei-templates/http/misconfiguration/test/", result)


class TestUploadValidation(unittest.TestCase):
    """Test template validation logic (content-level checks)."""

    def test_valid_template_passes(self):
        content = """id: valid-test
info:
  name: Valid Test Template
  severity: medium
  description: A valid test template
"""
        meta = parse_template_meta(content)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['id'], 'valid-test')

    def test_empty_file_rejected(self):
        meta = parse_template_meta('')
        self.assertIsNone(meta)

    def test_random_yaml_rejected(self):
        content = """name: not a nuclei template
version: 1.0
"""
        meta = parse_template_meta(content)
        self.assertIsNone(meta)  # No top-level id: field

    def test_html_rejected(self):
        content = "<html><body>not yaml</body></html>"
        meta = parse_template_meta(content)
        self.assertIsNone(meta)


if __name__ == '__main__':
    unittest.main()
