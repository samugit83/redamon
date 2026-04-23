"""
Unit tests for custom nuclei templates integration.

Tests:
1. list_custom_templates MCP tool (YAML parsing, directory walking)
2. build_nuclei_command with use_custom_templates flag
3. project_settings default and mapping
4. tool_registry entries
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add project paths — order matters: recon before agentic to avoid
# agentic/project_settings.py shadowing recon/project_settings.py
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "mcp" / "servers"))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))
sys.path.insert(0, str(PROJECT_ROOT / "agentic"))

# Pre-import recon's project_settings before agentic's can shadow it
import importlib.util
_recon_ps_spec = importlib.util.spec_from_file_location(
    "recon_project_settings",
    str(PROJECT_ROOT / "recon" / "project_settings.py"),
)
recon_project_settings = importlib.util.module_from_spec(_recon_ps_spec)
_recon_ps_spec.loader.exec_module(recon_project_settings)


class TestListCustomTemplates(unittest.TestCase):
    """Test the list_custom_templates MCP tool logic."""

    def test_parses_valid_yaml_template(self):
        """Should parse a nuclei YAML template and extract metadata."""
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            template = {
                "id": "test-template",
                "info": {
                    "name": "Test Template",
                    "severity": "high",
                    "tags": "test,example",
                    "description": "A test template for unit testing.",
                },
            }
            template_path = os.path.join(tmpdir, "test.yaml")
            with open(template_path, "w") as f:
                yaml.dump(template, f)

            # Simulate the tool's logic
            templates = []
            for root, _dirs, files in os.walk(tmpdir):
                for fname in sorted(files):
                    if not fname.endswith((".yaml", ".yml")):
                        continue
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, tmpdir)
                    with open(fpath, "r") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        info = data.get("info", {})
                        templates.append({
                            "id": data.get("id", fname),
                            "name": info.get("name", ""),
                            "severity": info.get("severity", "unknown"),
                            "tags": info.get("tags", ""),
                            "description": (info.get("description", "") or "")[:200].strip(),
                            "path": f"/opt/nuclei-templates/{rel_path}",
                        })

            self.assertEqual(len(templates), 1)
            t = templates[0]
            self.assertEqual(t["id"], "test-template")
            self.assertEqual(t["name"], "Test Template")
            self.assertEqual(t["severity"], "high")
            self.assertEqual(t["tags"], "test,example")
            self.assertEqual(t["path"], "/opt/nuclei-templates/test.yaml")

    def test_skips_non_yaml_files(self):
        """Should skip README, .txt, and other non-YAML files."""
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a YAML template
            template = {"id": "real-template", "info": {"name": "Real", "severity": "low"}}
            with open(os.path.join(tmpdir, "template.yaml"), "w") as f:
                yaml.dump(template, f)
            # Create non-YAML files
            with open(os.path.join(tmpdir, "README.md"), "w") as f:
                f.write("# Readme")
            with open(os.path.join(tmpdir, "wordlist.txt"), "w") as f:
                f.write("path1\npath2\n")

            count = 0
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    if fname.endswith((".yaml", ".yml")):
                        count += 1
            self.assertEqual(count, 1)

    def test_handles_multi_document_yaml(self):
        """Should parse only the first document in multi-document YAML."""
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            # Nuclei templates use --- separators for multi-document
            content = """id: first-template
info:
  name: First Template
  severity: critical
  tags: test

---
id: second-template
info:
  name: Second Template
  severity: low
"""
            fpath = os.path.join(tmpdir, "multi.yaml")
            with open(fpath, "w") as f:
                f.write(content)

            with open(fpath, "r") as f:
                # safe_load_all handles multi-document YAML
                data = next(yaml.safe_load_all(f), None)

            self.assertEqual(data["id"], "first-template")
            self.assertEqual(data["info"]["severity"], "critical")

    def test_empty_directory(self):
        """Should return empty list for directory with no templates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            templates = []
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    if fname.endswith((".yaml", ".yml")):
                        templates.append(fname)
            self.assertEqual(templates, [])

    def test_real_springboot_templates(self):
        """Should parse the actual Spring Boot templates from the repo."""
        import yaml

        templates_dir = PROJECT_ROOT / "mcp" / "nuclei-templates"
        if not templates_dir.is_dir():
            self.skipTest("mcp/nuclei-templates not found")

        templates = []
        for root, _dirs, files in os.walk(templates_dir):
            for fname in sorted(files):
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r") as f:
                        data = next(yaml.safe_load_all(f), None)
                    if isinstance(data, dict) and "id" in data:
                        templates.append(data["id"])
                except Exception:
                    pass

        # PR #69 added 7 YAML files, but we parse first document per file
        self.assertGreaterEqual(len(templates), 1, f"Expected >=1 templates, got {len(templates)}: {templates}")
        # Check a known template exists
        self.assertIn("springboot-heapdump-bypass", templates)


class TestBuildNucleiCommand(unittest.TestCase):
    """Test nuclei command builder with custom templates."""

    def _build_cmd(self, selected_custom_templates=None, host_path="", custom_templates=None):
        """Helper to build a nuclei command with mocked env."""
        # Import directly from file to avoid helpers/__init__.py pulling in dns/security_checks
        spec = importlib.util.spec_from_file_location(
            "nuclei_helpers",
            str(PROJECT_ROOT / "recon" / "helpers" / "nuclei_helpers.py"),
            submodule_search_locations=[str(PROJECT_ROOT / "recon" / "helpers")],
        )
        mod = importlib.util.module_from_spec(spec)
        # Mock the docker_helpers import that nuclei_helpers uses
        import types
        docker_helpers_mock = types.ModuleType("helpers.docker_helpers")
        docker_helpers_mock.NUCLEI_TEMPLATES_VOLUME = "nuclei-templates"
        sys.modules["helpers.docker_helpers"] = docker_helpers_mock
        sys.modules[".docker_helpers"] = docker_helpers_mock
        # Also need to handle relative import
        mod.__package__ = "helpers"
        spec.loader.exec_module(mod)
        build_nuclei_command = mod.build_nuclei_command

        env = {"HOST_CUSTOM_TEMPLATES_PATH": host_path}
        with patch.dict(os.environ, env, clear=False):
            return build_nuclei_command(
                targets_file="/tmp/redamon/.nuclei_temp/targets.txt",
                output_file="/tmp/redamon/.nuclei_temp/output.jsonl",
                docker_image="projectdiscovery/nuclei:latest",
                custom_templates=custom_templates,
                selected_custom_templates=selected_custom_templates,
            )

    def test_no_selected_templates(self):
        """When no templates selected, no custom templates volume or -t flag."""
        cmd = self._build_cmd(selected_custom_templates=None, host_path="/some/path")
        cmd_str = " ".join(cmd)
        self.assertNotIn("/custom-templates", cmd_str)

    def test_empty_selected_templates(self):
        """When empty list, no custom templates volume or -t flag."""
        cmd = self._build_cmd(selected_custom_templates=[], host_path="/some/path")
        cmd_str = " ".join(cmd)
        self.assertNotIn("/custom-templates", cmd_str)

    def test_selected_templates_with_host_path(self):
        """When templates selected with host path, should add -v mount and individual -t flags."""
        cmd = self._build_cmd(
            selected_custom_templates=["http/misconfiguration/springboot/springboot-heapdump-bypass.yaml"],
            host_path="/host/nuclei-templates",
        )
        cmd_str = " ".join(cmd)
        self.assertIn("/host/nuclei-templates:/custom-templates:ro", cmd_str)
        self.assertIn("-t", cmd_str)
        self.assertIn("/custom-templates/http/misconfiguration/springboot/springboot-heapdump-bypass.yaml", cmd_str)

    def test_selected_templates_no_host_path(self):
        """When templates selected but no host path, should not add volume or -t."""
        cmd = self._build_cmd(
            selected_custom_templates=["some/template.yaml"],
            host_path="",
        )
        cmd_str = " ".join(cmd)
        self.assertNotIn("/custom-templates", cmd_str)

    def test_multiple_selected_templates(self):
        """Each selected template gets its own -t flag."""
        cmd = self._build_cmd(
            selected_custom_templates=["template-a.yaml", "sub/template-b.yaml"],
            host_path="/host/templates",
        )
        cmd_str = " ".join(cmd)
        self.assertIn("/custom-templates/template-a.yaml", cmd_str)
        self.assertIn("/custom-templates/sub/template-b.yaml", cmd_str)

    def test_volume_mount_before_image_name(self):
        """The -v mount must appear before the docker image name."""
        cmd = self._build_cmd(
            selected_custom_templates=["test.yaml"],
            host_path="/host/templates",
        )
        image_idx = cmd.index("projectdiscovery/nuclei:latest")
        for i, arg in enumerate(cmd):
            if "/custom-templates:ro" in arg:
                volume_idx = i
                break
        else:
            self.fail("Custom templates volume mount not found")
        self.assertLess(volume_idx, image_idx, "Volume mount must come before docker image name")

    def test_t_flag_after_image_name(self):
        """The -t flags must appear after the docker image name."""
        cmd = self._build_cmd(
            selected_custom_templates=["test.yaml"],
            host_path="/host/templates",
        )
        image_idx = cmd.index("projectdiscovery/nuclei:latest")
        for i, arg in enumerate(cmd):
            if arg == "/custom-templates/test.yaml":
                t_idx = i
                break
        else:
            self.fail("-t /custom-templates/test.yaml not found")
        self.assertGreater(t_idx, image_idx, "-t flag must come after docker image name")

    def test_both_custom_templates_list_and_selected(self):
        """Both explicit custom_templates list AND selected should work together."""
        cmd = self._build_cmd(
            selected_custom_templates=["selected.yaml"],
            host_path="/host/templates",
            custom_templates=["/some/other/template.yaml"],
        )
        cmd_str = " ".join(cmd)
        self.assertIn("/some/other/template.yaml", cmd_str)
        self.assertIn("/custom-templates/selected.yaml", cmd_str)


class TestProjectSettings(unittest.TestCase):
    """Test project_settings.py defaults."""

    def test_default_settings_has_selected_custom_templates(self):
        """DEFAULT_SETTINGS should include NUCLEI_SELECTED_CUSTOM_TEMPLATES = []."""
        self.assertIn("NUCLEI_SELECTED_CUSTOM_TEMPLATES", recon_project_settings.DEFAULT_SETTINGS)
        self.assertEqual(recon_project_settings.DEFAULT_SETTINGS["NUCLEI_SELECTED_CUSTOM_TEMPLATES"], [])

    def test_default_is_empty_list(self):
        """Custom templates should be empty list by default."""
        self.assertIsInstance(recon_project_settings.DEFAULT_SETTINGS["NUCLEI_SELECTED_CUSTOM_TEMPLATES"], list)


class TestToolRegistry(unittest.TestCase):
    """Test tool registry entries."""

    def test_execute_nuclei_mentions_custom_templates(self):
        """execute_nuclei description should reference custom templates."""
        from prompts.tool_registry import TOOL_REGISTRY
        desc = TOOL_REGISTRY["execute_nuclei"]["description"]
        self.assertIn("/opt/nuclei-templates/", desc)
        self.assertIn("Custom", desc)

    def test_execute_nuclei_has_custom_template_example(self):
        """execute_nuclei description should have a custom template example."""
        from prompts.tool_registry import TOOL_REGISTRY
        desc = TOOL_REGISTRY["execute_nuclei"]["description"]
        self.assertIn("springboot", desc)


if __name__ == "__main__":
    unittest.main()
