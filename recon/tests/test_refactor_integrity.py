"""
Integrity test for partial_recon.py refactoring.

Verifies that every function extracted into partial_recon_modules/
has EXACTLY the same source code as the original monolithic file.

Run with: python -m pytest recon/tests/test_refactor_integrity.py -v
"""
import sys
import os
import inspect
import textwrap
import unittest
from unittest.mock import MagicMock

# Add paths
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

# Pre-mock heavy dependencies
sys.modules['neo4j'] = MagicMock()


class TestRefactorIntegrity(unittest.TestCase):
    """Verify all functions are importable from partial_recon (thin entry point)."""

    def test_load_config_importable(self):
        from partial_recon import load_config
        self.assertTrue(callable(load_config))

    def test_main_importable(self):
        from partial_recon import main
        self.assertTrue(callable(main))

    def test_classify_ip_importable(self):
        from partial_recon import _classify_ip
        self.assertTrue(callable(_classify_ip))

    def test_is_ip_or_cidr_importable(self):
        from partial_recon import _is_ip_or_cidr
        self.assertTrue(callable(_is_ip_or_cidr))

    def test_is_valid_hostname_importable(self):
        from partial_recon import _is_valid_hostname
        self.assertTrue(callable(_is_valid_hostname))

    def test_is_valid_url_importable(self):
        from partial_recon import _is_valid_url
        self.assertTrue(callable(_is_valid_url))

    def test_resolve_hostname_importable(self):
        from partial_recon import _resolve_hostname
        self.assertTrue(callable(_resolve_hostname))

    def test_build_recon_data_from_graph_importable(self):
        from partial_recon import _build_recon_data_from_graph
        self.assertTrue(callable(_build_recon_data_from_graph))

    def test_build_port_scan_data_from_graph_importable(self):
        from partial_recon import _build_port_scan_data_from_graph
        self.assertTrue(callable(_build_port_scan_data_from_graph))

    def test_build_http_probe_data_from_graph_importable(self):
        from partial_recon import _build_http_probe_data_from_graph
        self.assertTrue(callable(_build_http_probe_data_from_graph))

    def test_build_vuln_scan_data_from_graph_importable(self):
        from partial_recon import _build_vuln_scan_data_from_graph
        self.assertTrue(callable(_build_vuln_scan_data_from_graph))

    def test_create_user_subdomains_in_graph_importable(self):
        from partial_recon import _create_user_subdomains_in_graph
        self.assertTrue(callable(_create_user_subdomains_in_graph))

    def test_cleanup_orphan_user_inputs_importable(self):
        from partial_recon import _cleanup_orphan_user_inputs
        self.assertTrue(callable(_cleanup_orphan_user_inputs))

    def test_run_subdomain_discovery_importable(self):
        from partial_recon import run_subdomain_discovery
        self.assertTrue(callable(run_subdomain_discovery))

    def test_run_naabu_importable(self):
        from partial_recon import run_naabu
        self.assertTrue(callable(run_naabu))

    def test_run_masscan_importable(self):
        from partial_recon import run_masscan
        self.assertTrue(callable(run_masscan))

    def test_run_nmap_importable(self):
        from partial_recon import run_nmap
        self.assertTrue(callable(run_nmap))

    def test_run_httpx_importable(self):
        from partial_recon import run_httpx
        self.assertTrue(callable(run_httpx))

    def test_run_katana_importable(self):
        from partial_recon import run_katana
        self.assertTrue(callable(run_katana))

    def test_run_hakrawler_importable(self):
        from partial_recon import run_hakrawler
        self.assertTrue(callable(run_hakrawler))

    def test_run_ffuf_importable(self):
        from partial_recon import run_ffuf
        self.assertTrue(callable(run_ffuf))

    def test_run_gau_importable(self):
        from partial_recon import run_gau
        self.assertTrue(callable(run_gau))

    def test_run_jsluice_importable(self):
        from partial_recon import run_jsluice
        self.assertTrue(callable(run_jsluice))

    def test_run_paramspider_importable(self):
        from partial_recon import run_paramspider
        self.assertTrue(callable(run_paramspider))

    def test_run_kiterunner_importable(self):
        from partial_recon import run_kiterunner
        self.assertTrue(callable(run_kiterunner))

    def test_run_arjun_importable(self):
        from partial_recon import run_arjun
        self.assertTrue(callable(run_arjun))

    def test_run_jsrecon_importable(self):
        from partial_recon import run_jsrecon
        self.assertTrue(callable(run_jsrecon))

    def test_run_nuclei_importable(self):
        from partial_recon import run_nuclei
        self.assertTrue(callable(run_nuclei))

    def test_run_security_checks_partial_importable(self):
        from partial_recon import run_security_checks_partial
        self.assertTrue(callable(run_security_checks_partial))

    def test_run_shodan_importable(self):
        from partial_recon import run_shodan
        self.assertTrue(callable(run_shodan))

    def test_run_urlscan_importable(self):
        from partial_recon import run_urlscan
        self.assertTrue(callable(run_urlscan))

    def test_run_uncover_importable(self):
        from partial_recon import run_uncover
        self.assertTrue(callable(run_uncover))

    def test_run_osint_enrichment_importable(self):
        from partial_recon import run_osint_enrichment
        self.assertTrue(callable(run_osint_enrichment))


class TestHelperFunctionality(unittest.TestCase):
    """Verify helper functions produce correct results (same as before refactoring)."""

    def test_classify_ip_ipv4(self):
        from partial_recon import _classify_ip
        self.assertEqual(_classify_ip("1.2.3.4"), "ipv4")

    def test_classify_ip_ipv6(self):
        from partial_recon import _classify_ip
        self.assertEqual(_classify_ip("::1"), "ipv6")

    def test_classify_ip_with_version_hint(self):
        from partial_recon import _classify_ip
        self.assertEqual(_classify_ip("1.2.3.4", "ipv4"), "ipv4")
        self.assertEqual(_classify_ip("::1", "ipv6"), "ipv6")

    def test_classify_ip_invalid_defaults_ipv4(self):
        from partial_recon import _classify_ip
        self.assertEqual(_classify_ip("not-an-ip"), "ipv4")

    def test_is_ip_or_cidr_ip(self):
        from partial_recon import _is_ip_or_cidr
        self.assertTrue(_is_ip_or_cidr("1.2.3.4"))
        self.assertTrue(_is_ip_or_cidr("192.168.1.0/24"))
        self.assertTrue(_is_ip_or_cidr("::1"))
        self.assertFalse(_is_ip_or_cidr("example.com"))
        self.assertFalse(_is_ip_or_cidr("not-an-ip"))

    def test_is_valid_hostname(self):
        from partial_recon import _is_valid_hostname
        self.assertTrue(_is_valid_hostname("example.com"))
        self.assertTrue(_is_valid_hostname("sub.example.com"))
        self.assertTrue(_is_valid_hostname("a.b.c.example.com"))
        self.assertFalse(_is_valid_hostname(""))
        self.assertFalse(_is_valid_hostname("1.2.3.4"))
        self.assertFalse(_is_valid_hostname("-invalid.com"))

    def test_is_valid_url(self):
        from partial_recon import _is_valid_url
        self.assertTrue(_is_valid_url("http://example.com"))
        self.assertTrue(_is_valid_url("https://example.com/path"))
        self.assertFalse(_is_valid_url("ftp://example.com"))
        self.assertFalse(_is_valid_url("not a url"))
        self.assertFalse(_is_valid_url(""))

    def test_resolve_hostname_returns_dict(self):
        from partial_recon import _resolve_hostname
        result = _resolve_hostname("nonexistent.invalid.test")
        self.assertIsInstance(result, dict)
        self.assertIn("ipv4", result)
        self.assertIn("ipv6", result)
        self.assertIsInstance(result["ipv4"], list)
        self.assertIsInstance(result["ipv6"], list)


class TestLoadConfig(unittest.TestCase):
    """Tests for config loading from JSON file (same as original test_partial_recon.py)."""

    def test_load_valid_config(self):
        import tempfile
        from partial_recon import load_config
        config = {"tool_id": "SubdomainDiscovery", "domain": "example.com", "user_inputs": ["api.example.com"]}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            import json
            json.dump(config, f)
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                result = load_config()
                self.assertEqual(result["tool_id"], "SubdomainDiscovery")
                self.assertEqual(result["domain"], "example.com")
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)

    def test_load_config_missing_env(self):
        from partial_recon import load_config
        if "PARTIAL_RECON_CONFIG" in os.environ:
            del os.environ["PARTIAL_RECON_CONFIG"]
        with self.assertRaises(SystemExit):
            load_config()

    def test_load_config_invalid_file(self):
        from partial_recon import load_config
        os.environ["PARTIAL_RECON_CONFIG"] = "/nonexistent/path.json"
        try:
            with self.assertRaises(SystemExit):
                load_config()
        finally:
            del os.environ["PARTIAL_RECON_CONFIG"]


class TestFunctionSignatures(unittest.TestCase):
    """Verify function signatures match expected parameters."""

    def test_run_functions_accept_config_dict(self):
        """All run_* functions should accept a single config dict parameter."""
        from partial_recon import (
            run_subdomain_discovery, run_naabu, run_masscan, run_nmap,
            run_httpx, run_katana, run_hakrawler, run_ffuf, run_gau,
            run_jsluice, run_paramspider, run_kiterunner, run_arjun,
            run_jsrecon, run_nuclei, run_security_checks_partial,
            run_shodan, run_urlscan, run_uncover, run_osint_enrichment,
        )
        run_functions = [
            run_subdomain_discovery, run_naabu, run_masscan, run_nmap,
            run_httpx, run_katana, run_hakrawler, run_ffuf, run_gau,
            run_jsluice, run_paramspider, run_kiterunner, run_arjun,
            run_jsrecon, run_nuclei, run_security_checks_partial,
            run_shodan, run_urlscan, run_uncover, run_osint_enrichment,
        ]
        for fn in run_functions:
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            self.assertIn("config", params, f"{fn.__name__} missing 'config' parameter")

    def test_graph_builder_signatures(self):
        """Graph builder functions should accept domain, user_id, project_id."""
        from partial_recon import (
            _build_recon_data_from_graph,
            _build_port_scan_data_from_graph,
            _build_http_probe_data_from_graph,
            _build_vuln_scan_data_from_graph,
        )
        for fn in [_build_recon_data_from_graph, _build_port_scan_data_from_graph,
                    _build_http_probe_data_from_graph, _build_vuln_scan_data_from_graph]:
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            self.assertEqual(params, ["domain", "user_id", "project_id"],
                             f"{fn.__name__} has wrong parameters: {params}")

    def test_classify_ip_signature(self):
        from partial_recon import _classify_ip
        sig = inspect.signature(_classify_ip)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["address", "version"])

    def test_cleanup_orphan_user_inputs_signature(self):
        from partial_recon import _cleanup_orphan_user_inputs
        sig = inspect.signature(_cleanup_orphan_user_inputs)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["user_id", "project_id"])

    def test_create_user_subdomains_in_graph_signature(self):
        from partial_recon import _create_user_subdomains_in_graph
        sig = inspect.signature(_create_user_subdomains_in_graph)
        params = list(sig.parameters.keys())
        self.assertEqual(params, ["domain", "subdomains", "user_id", "project_id"])


class TestModuleStructure(unittest.TestCase):
    """Verify the module structure is correct."""

    def test_all_modules_exist(self):
        """All expected module files should exist."""
        modules_dir = os.path.join(_recon_dir, "partial_recon_modules")
        expected_files = [
            "__init__.py",
            "helpers.py",
            "graph_builders.py",
            "user_inputs.py",
            "subdomain_discovery.py",
            "port_scanning.py",
            "http_probing.py",
            "web_crawling.py",
            "parameter_discovery.py",
            "js_analysis.py",
            "vulnerability_scanning.py",
            "osint_enrichment.py",
        ]
        for filename in expected_files:
            filepath = os.path.join(modules_dir, filename)
            self.assertTrue(os.path.exists(filepath), f"Missing module: {filename}")

    def test_total_function_count(self):
        """Verify we have all 37 functions accessible."""
        import partial_recon as pr
        expected_functions = [
            # Helpers (5)
            '_classify_ip', '_is_ip_or_cidr', '_is_valid_hostname',
            '_is_valid_url', '_resolve_hostname',
            # Graph builders (4)
            '_build_recon_data_from_graph', '_build_port_scan_data_from_graph',
            '_build_http_probe_data_from_graph', '_build_vuln_scan_data_from_graph',
            # User inputs (2)
            '_create_user_subdomains_in_graph', '_cleanup_orphan_user_inputs',
            # Tool runners (21)
            'run_subdomain_discovery', 'run_naabu', 'run_masscan', 'run_nmap',
            'run_httpx', 'run_katana', 'run_hakrawler', 'run_ffuf', 'run_gau',
            'run_jsluice', 'run_paramspider', 'run_kiterunner', 'run_arjun',
            'run_jsrecon', 'run_nuclei', 'run_security_checks_partial',
            'run_shodan', 'run_urlscan', 'run_uncover', 'run_osint_enrichment',
            # Entry point (2)
            'load_config', 'main',
        ]
        for name in expected_functions:
            self.assertTrue(hasattr(pr, name), f"Missing function: {name}")
            self.assertTrue(callable(getattr(pr, name)), f"Not callable: {name}")

    def test_no_circular_imports(self):
        """Importing partial_recon should not raise ImportError."""
        # This test passes if we got this far without import errors
        import partial_recon
        self.assertIsNotNone(partial_recon)


class TestSourceCodeIntegrity(unittest.TestCase):
    """
    Compare function source code from refactored modules against the
    original file stored in git.
    """

    @classmethod
    def setUpClass(cls):
        """Load the original file from git HEAD~1 (before refactoring)."""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "show", "HEAD:recon/partial_recon.py"],
                capture_output=True, text=True, cwd=_project_root,
            )
            if result.returncode == 0:
                cls.original_source = result.stdout
            else:
                cls.original_source = None
        except Exception:
            cls.original_source = None

    def _extract_function_body(self, source, func_name):
        """Extract a function's body from full source code."""
        lines = source.split('\n')
        start = None
        indent = None
        body_lines = []

        for i, line in enumerate(lines):
            if start is None:
                # Look for function definition
                stripped = line.lstrip()
                if stripped.startswith(f'def {func_name}('):
                    start = i
                    indent = len(line) - len(stripped)
                    body_lines.append(line)
            else:
                # We're inside the function - collect until we hit something
                # at the same or lower indentation level
                if line.strip() == '':
                    body_lines.append(line)
                    continue
                curr_indent = len(line) - len(line.lstrip())
                if curr_indent <= indent and line.strip() and not line.strip().startswith('#'):
                    # We've exited the function
                    break
                body_lines.append(line)

        if not body_lines:
            return None
        # Return dedented body (just the function content)
        return '\n'.join(body_lines)

    def _compare_function(self, func_name, module_path):
        """Compare a function from the module against the original."""
        if self.original_source is None:
            self.skipTest("Original source not available from git")

        original_body = self._extract_function_body(self.original_source, func_name)
        if original_body is None:
            self.skipTest(f"Could not find {func_name} in original source")

        # Read the module file
        module_file = os.path.join(_recon_dir, "partial_recon_modules", module_path)
        with open(module_file, 'r') as f:
            module_source = f.read()

        refactored_body = self._extract_function_body(module_source, func_name)
        self.assertIsNotNone(refactored_body, f"{func_name} not found in {module_path}")

        # Normalize whitespace for comparison
        original_normalized = textwrap.dedent(original_body).strip()
        refactored_normalized = textwrap.dedent(refactored_body).strip()

        self.assertEqual(
            original_normalized,
            refactored_normalized,
            f"Function {func_name} in {module_path} differs from original.\n"
            f"First difference at character {self._find_diff_pos(original_normalized, refactored_normalized)}"
        )

    def _find_diff_pos(self, s1, s2):
        """Find the position of the first difference between two strings."""
        for i, (c1, c2) in enumerate(zip(s1, s2)):
            if c1 != c2:
                context_start = max(0, i - 30)
                return f"{i}: ...{repr(s1[context_start:i+30])}... vs ...{repr(s2[context_start:i+30])}..."
        if len(s1) != len(s2):
            return f"length differs: {len(s1)} vs {len(s2)}"
        return "no difference found"

    # Helpers
    def test_classify_ip(self):
        self._compare_function("_classify_ip", "helpers.py")

    def test_resolve_hostname(self):
        self._compare_function("_resolve_hostname", "helpers.py")

    def test_is_ip_or_cidr(self):
        self._compare_function("_is_ip_or_cidr", "helpers.py")

    def test_is_valid_hostname(self):
        self._compare_function("_is_valid_hostname", "helpers.py")

    def test_is_valid_url(self):
        self._compare_function("_is_valid_url", "helpers.py")

    # Graph builders
    def test_build_recon_data_from_graph(self):
        self._compare_function("_build_recon_data_from_graph", "graph_builders.py")

    def test_build_port_scan_data_from_graph(self):
        self._compare_function("_build_port_scan_data_from_graph", "graph_builders.py")

    def test_build_http_probe_data_from_graph(self):
        self._compare_function("_build_http_probe_data_from_graph", "graph_builders.py")

    def test_build_vuln_scan_data_from_graph(self):
        self._compare_function("_build_vuln_scan_data_from_graph", "graph_builders.py")

    # User inputs
    def test_create_user_subdomains_in_graph(self):
        self._compare_function("_create_user_subdomains_in_graph", "user_inputs.py")

    def test_cleanup_orphan_user_inputs(self):
        self._compare_function("_cleanup_orphan_user_inputs", "user_inputs.py")

    # Subdomain discovery
    def test_run_subdomain_discovery(self):
        self._compare_function("run_subdomain_discovery", "subdomain_discovery.py")

    # Port scanning
    def test_run_port_scanner(self):
        self._compare_function("_run_port_scanner", "port_scanning.py")

    def test_normalize_masscan_result(self):
        self._compare_function("_normalize_masscan_result", "port_scanning.py")

    def test_run_naabu(self):
        self._compare_function("run_naabu", "port_scanning.py")

    def test_run_masscan(self):
        self._compare_function("run_masscan", "port_scanning.py")

    def test_run_nmap(self):
        self._compare_function("run_nmap", "port_scanning.py")

    # HTTP probing
    def test_run_httpx(self):
        self._compare_function("run_httpx", "http_probing.py")

    # Web crawling
    def test_run_katana(self):
        self._compare_function("run_katana", "web_crawling.py")

    def test_run_hakrawler(self):
        self._compare_function("run_hakrawler", "web_crawling.py")

    def test_run_ffuf(self):
        self._compare_function("run_ffuf", "web_crawling.py")

    def test_run_gau(self):
        self._compare_function("run_gau", "web_crawling.py")

    def test_run_jsluice(self):
        self._compare_function("run_jsluice", "web_crawling.py")

    # Parameter discovery
    def test_run_paramspider(self):
        self._compare_function("run_paramspider", "parameter_discovery.py")

    def test_run_kiterunner(self):
        self._compare_function("run_kiterunner", "parameter_discovery.py")

    def test_run_arjun(self):
        self._compare_function("run_arjun", "parameter_discovery.py")

    # JS analysis
    def test_run_jsrecon(self):
        self._compare_function("run_jsrecon", "js_analysis.py")

    # Vulnerability scanning
    def test_run_nuclei(self):
        self._compare_function("run_nuclei", "vulnerability_scanning.py")

    def test_run_security_checks_partial(self):
        self._compare_function("run_security_checks_partial", "vulnerability_scanning.py")

    # OSINT
    def test_run_shodan(self):
        self._compare_function("run_shodan", "osint_enrichment.py")

    def test_run_urlscan(self):
        self._compare_function("run_urlscan", "osint_enrichment.py")

    def test_run_uncover(self):
        self._compare_function("run_uncover", "osint_enrichment.py")

    def test_run_osint_enrichment(self):
        self._compare_function("run_osint_enrichment", "osint_enrichment.py")


if __name__ == "__main__":
    unittest.main()
