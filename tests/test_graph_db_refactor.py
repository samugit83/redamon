"""
Unit tests for graph_db refactoring (neo4j_client.py → mixin modules).

Tests are designed to work without a live Neo4j connection by stubbing
the neo4j package. Run with:
    python3 tests/test_graph_db_refactor.py
    # or from repo root:
    python3 -m pytest tests/test_graph_db_refactor.py -v
"""
import sys
import ast
import os
import re
import unittest
from unittest.mock import MagicMock

# ─── Stub neo4j + dotenv before any graph_db import ───────────────────────────

_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())

import importlib.util

# Resolve repo root so the test can be run from any cwd
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _load(name, relpath):
    path = os.path.join(_REPO, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

# Load in dependency order
_cpe  = _load("graph_db.cpe_resolver",       "graph_db/cpe_resolver.py")
_schema = _load("graph_db.schema",            "graph_db/schema.py")
sys.modules.setdefault("graph_db", MagicMock())
sys.modules["graph_db.schema"] = _schema
sys.modules["graph_db.cpe_resolver"] = _cpe
_base = _load("graph_db.mixins.base_mixin",   "graph_db/mixins/base_mixin.py")


# ─── SYNTAX & STRUCTURAL TESTS ────────────────────────────────────────────────

class TestSyntax(unittest.TestCase):
    FILES = [
        "graph_db/neo4j_client.py",
        "graph_db/cpe_resolver.py",
        "graph_db/schema.py",
        "graph_db/mixins/__init__.py",
        "graph_db/mixins/base_mixin.py",
        "graph_db/mixins/recon_mixin.py",
        "graph_db/mixins/gvm_mixin.py",
        "graph_db/mixins/secret_mixin.py",
        "graph_db/mixins/osint_mixin.py",
        # recon_mixin split (per-topic sub-mixins)
        "graph_db/mixins/recon/__init__.py",
        "graph_db/mixins/recon/domain_mixin.py",
        "graph_db/mixins/recon/port_mixin.py",
        "graph_db/mixins/recon/http_mixin.py",
        "graph_db/mixins/recon/vuln_mixin.py",
        "graph_db/mixins/recon/resource_mixin.py",
        "graph_db/mixins/recon/js_recon_mixin.py",
        "graph_db/mixins/recon/user_input_mixin.py",
    ]

    def test_all_files_parse(self):
        for f in self.FILES:
            with self.subTest(file=f):
                src = open(os.path.join(_REPO, f)).read()
                try:
                    ast.parse(src)
                except SyntaxError as e:
                    self.fail(f"Syntax error in {f}: {e}")

    # Intentional inline imports added after the refactor. Each entry is
    # (relpath, method_name); keep this list tight so new stragglers are caught.
    _ALLOWED_INLINE_IMPORTS = {
        ("graph_db/mixins/recon/port_mixin.py", "update_graph_from_nmap"),  # local `import re`
        # lazy `stable_vuln_id` import: a top-level graph_db.mixins.* import here
        # breaks tests that load osint_mixin with graph_db stubbed as a MagicMock.
        ("graph_db/mixins/osint_mixin.py", "update_graph_from_origin_discovery"),
    }

    def test_no_inline_imports_in_methods(self):
        """No import statements inside method bodies (except a documented allowlist)."""
        mixin_files = [f for f in self.FILES
                       if "mixin" in f and f.endswith(".py") and "__init__" not in f]
        for fpath in mixin_files:
            with self.subTest(file=fpath):
                src = open(os.path.join(_REPO, fpath)).read()
                tree = ast.parse(src)
                for cls in ast.walk(tree):
                    if not isinstance(cls, ast.ClassDef):
                        continue
                    for method in ast.walk(cls):
                        if not isinstance(method, ast.FunctionDef):
                            continue
                        if (fpath, method.name) in self._ALLOWED_INLINE_IMPORTS:
                            continue
                        for node in ast.walk(method):
                            if isinstance(node, (ast.Import, ast.ImportFrom)):
                                self.fail(
                                    f"Inline import in {fpath}::{method.name} "
                                    f"at line {node.lineno}"
                                )

    def test_no_init_schema_calls_in_methods(self):
        """_init_schema must not be called inside any mixin method body."""
        for fpath in self.FILES:
            if "__init__" in fpath or not fpath.endswith(".py"):
                continue
            with self.subTest(file=fpath):
                src = open(os.path.join(_REPO, fpath)).read()
                tree = ast.parse(src)
                for cls in ast.walk(tree):
                    if not isinstance(cls, ast.ClassDef):
                        continue
                    for method in ast.walk(cls):
                        if not isinstance(method, ast.FunctionDef):
                            continue
                        if method.name == "__init__":
                            continue
                        for node in ast.walk(method):
                            if isinstance(node, ast.Call):
                                func = node.func
                                if (isinstance(func, ast.Attribute)
                                        and func.attr == "_init_schema"):
                                    self.fail(
                                        f"_init_schema called in {fpath}::{method.name} "
                                        f"at line {node.lineno}"
                                    )

    def test_no_bare_module_code_in_mixins(self):
        """No if __name__ == '__main__' blocks inside mixin files."""
        mixin_files = [f for f in self.FILES
                       if "mixin" in f and f.endswith(".py") and "__init__" not in f]
        for fpath in mixin_files:
            with self.subTest(file=fpath):
                src = open(os.path.join(_REPO, fpath)).read()
                self.assertNotIn('__name__', src,
                                 f"__main__ block found in mixin {fpath}")


# ─── METHOD PRESENCE TESTS ────────────────────────────────────────────────────

class TestMethodPresence(unittest.TestCase):
    @staticmethod
    def _methods(relpath, classname=None):
        tree = ast.parse(open(os.path.join(_REPO, relpath)).read())
        methods = set()
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            if classname and cls.name != classname:
                continue
            for n in ast.walk(cls):
                if isinstance(n, ast.FunctionDef):
                    methods.add(n.name)
        return methods

    # NOTE: test_all_original_public_methods_preserved was removed together with
    # the pre-refactor snapshot `graph_db/neo4j_client copy.py`. That snapshot was
    # migration scaffolding for the one-time mixin split (long completed) and the
    # only consumer of the copy; the per-mixin presence checks below now stand on
    # their own.

    def test_expected_methods_per_mixin(self):
        checks = {
            "graph_db/mixins/base_mixin.py":   {
                "__init__", "close", "verify_connection",
                "clear_project_data", "clear_gvm_data"
            },
            # After recon_mixin split: methods live in per-topic sub-mixins
            "graph_db/mixins/recon/domain_mixin.py": {
                "update_graph_from_domain_discovery", "update_graph_from_ip_recon",
            },
            "graph_db/mixins/recon/port_mixin.py": {
                "update_graph_from_port_scan",
            },
            "graph_db/mixins/recon/http_mixin.py": {
                "update_graph_from_http_probe",
            },
            "graph_db/mixins/recon/vuln_mixin.py": {
                "update_graph_from_vuln_scan",
            },
            "graph_db/mixins/recon/resource_mixin.py": {
                "update_graph_from_resource_enum",
            },
            "graph_db/mixins/gvm_mixin.py": {
                "_extract_gvm_technologies", "_merge_gvm_technology",
                "_parse_traceroute", "update_graph_from_gvm_scan",
            },
            "graph_db/mixins/secret_mixin.py": {
                "clear_github_hunt_data", "update_graph_from_github_hunt",
                "clear_trufflehog_data", "update_graph_from_trufflehog",
            },
            "graph_db/mixins/osint_mixin.py": {
                "update_graph_from_shodan", "update_graph_from_urlscan_discovery",
                "update_graph_from_urlscan_enrichment", "update_graph_from_external_domains",
                "update_graph_from_censys", "update_graph_from_fofa", "update_graph_from_otx",
                "update_graph_from_netlas", "update_graph_from_virustotal",
                "update_graph_from_zoomeye", "update_graph_from_criminalip",
                "update_graph_from_uncover",
            },
        }
        for fpath, required in checks.items():
            with self.subTest(file=fpath):
                actual = self._methods(fpath)
                for m in required:
                    self.assertIn(m, actual, f"{m} missing from {fpath}")


# ─── NEO4JCLIENT ORCHESTRATOR TESTS ──────────────────────────────────────────

class TestNeo4jClientOrchestrator(unittest.TestCase):
    def _src(self):
        return open(os.path.join(_REPO, "graph_db/neo4j_client.py")).read()

    def test_is_thin(self):
        lines = self._src().splitlines()
        self.assertLess(len(lines), 50, f"neo4j_client.py has {len(lines)} lines, expected < 50")

    def test_imports_all_mixins(self):
        src = self._src()
        for mixin in ["BaseMixin", "ReconMixin", "GvmMixin", "SecretMixin", "OsintMixin"]:
            self.assertIn(mixin, src)

    def test_mro_order(self):
        tree = ast.parse(self._src())
        cls = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.ClassDef) and n.name == "Neo4jClient")
        bases = [b.id if isinstance(b, ast.Name) else b.attr for b in cls.bases]
        self.assertEqual(bases,
                         ["BaseMixin", "ReconMixin", "GvmMixin", "SecretMixin", "OsintMixin",
                          "GraphQLMixin", "CacheMixin", "SupplyChainMixin"])

    def test_init_py_unchanged(self):
        src = open(os.path.join(_REPO, "graph_db/__init__.py")).read()
        self.assertIn("Neo4jClient", src)
        for name in ["BaseMixin", "ReconMixin", "GvmMixin", "SecretMixin", "OsintMixin"]:
            self.assertNotIn(name, src, f"{name} leaked into __init__.py")


# ─── CPE RESOLVER TESTS ───────────────────────────────────────────────────────

class TestCpeResolver(unittest.TestCase):
    def setUp(self):
        self.mod = _cpe

    def test_parse_cpe_23(self):
        r = self.mod._parse_cpe_string("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual(r["vendor"], "apache")
        self.assertEqual(r["product"], "http_server")
        self.assertEqual(r["version"], "2.4.49")

    def test_parse_cpe_22(self):
        r = self.mod._parse_cpe_string("cpe:/a:apache:http_server:2.4.49")
        self.assertEqual(r["vendor"], "apache")
        self.assertEqual(r["product"], "http_server")
        self.assertEqual(r["version"], "2.4.49")

    def test_parse_cpe_empty_or_none(self):
        self.assertIsNone(self.mod._parse_cpe_string(""))
        self.assertIsNone(self.mod._parse_cpe_string(None))

    def test_parse_cpe_wildcard_version_is_none(self):
        r = self.mod._parse_cpe_string("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        self.assertIsNone(r["version"])

    def test_resolve_reverse_cpe_mappings(self):
        resolve = self.mod._resolve_cpe_to_display_name
        self.assertEqual(resolve("apache", "http_server"), "Apache HTTP Server")
        self.assertEqual(resolve("f5", "nginx"), "Nginx")
        self.assertEqual(resolve("php", "php"), "PHP")
        self.assertEqual(resolve("oracle", "mysql"), "MySQL")

    def test_resolve_gvm_display_names(self):
        resolve = self.mod._resolve_cpe_to_display_name
        self.assertEqual(resolve("openbsd", "openssh"), "OpenSSH")
        self.assertEqual(resolve("canonical", "ubuntu_linux"), "Ubuntu")
        self.assertEqual(resolve("isc", "bind"), "BIND")

    def test_resolve_humanized_fallback(self):
        resolve = self.mod._resolve_cpe_to_display_name
        self.assertEqual(resolve("acme_corp", "super_tool"), "Super Tool")
        self.assertEqual(resolve("x", "my_product_name"), "My Product Name")

    def test_is_ip_address_ipv4(self):
        f = self.mod._is_ip_address
        self.assertTrue(f("192.168.1.1"))
        self.assertTrue(f("10.0.0.1"))
        self.assertTrue(f("255.255.255.255"))

    def test_is_ip_address_ipv6(self):
        f = self.mod._is_ip_address
        self.assertTrue(f("2001:db8::1"))
        self.assertTrue(f("::1"))

    def test_is_ip_address_false_for_hostnames(self):
        f = self.mod._is_ip_address
        self.assertFalse(f("example.com"))
        self.assertFalse(f("sub.domain.org"))
        self.assertFalse(f(""))
        self.assertFalse(f(None))

    def test_cpe_skip_list_present(self):
        self.assertIn(("ietf", "secure_shell_protocol"), self.mod._CPE_SKIP_LIST)


# ─── SCHEMA TESTS ─────────────────────────────────────────────────────────────

class TestSchema(unittest.TestCase):
    def setUp(self):
        self.mod = _schema

    def test_all_ddl_lists_non_empty(self):
        self.assertGreater(len(self.mod.DROP_LEGACY_CONSTRAINTS), 0)
        self.assertGreater(len(self.mod.CONSTRAINTS), 0)
        self.assertGreater(len(self.mod.TENANT_INDEXES), 0)
        self.assertGreater(len(self.mod.ADDITIONAL_INDEXES), 0)

    def test_all_ddl_idempotent(self):
        for stmt in self.mod.CONSTRAINTS + self.mod.TENANT_INDEXES + self.mod.ADDITIONAL_INDEXES:
            self.assertIn("IF NOT EXISTS", stmt, f"Missing guard: {stmt}")
        for stmt in self.mod.DROP_LEGACY_CONSTRAINTS:
            self.assertIn("IF EXISTS", stmt, f"Missing guard: {stmt}")

    def test_init_schema_calls_every_statement(self):
        """Every DDL statement is executed.

        Asserted by inclusion rather than by call count: init_schema also runs
        the legacy-label migration, whose probe queries are not DDL. A bare count
        would have to be bumped for every migration ever added, and would fail
        for a reason that has nothing to do with the schema being applied.
        """
        mock_session = MagicMock()
        mock_session.run.return_value = None
        self.mod.init_schema(mock_session)
        executed = [c.args[0] for c in mock_session.run.call_args_list if c.args]
        for stmt in (self.mod.DROP_LEGACY_CONSTRAINTS + self.mod.CONSTRAINTS
                     + self.mod.TENANT_INDEXES + self.mod.ADDITIONAL_INDEXES):
            self.assertIn(stmt, executed)

    def test_init_schema_migrates_labels_before_creating_constraints(self):
        """Ordering is load-bearing: a uniqueness constraint on the new label
        cannot be satisfied while data still carries the old one."""
        mock_session = MagicMock()
        mock_session.run.return_value = None
        self.mod.init_schema(mock_session)
        executed = [c.args[0] for c in mock_session.run.call_args_list if c.args]
        first_migration = next(
            i for i, q in enumerate(executed) if "TrufflehogFinding" in q)
        first_constraint = next(
            i for i, q in enumerate(executed) if q.startswith("CREATE CONSTRAINT"))
        self.assertLess(first_migration, first_constraint)

    def test_init_schema_tolerates_errors(self):
        mock_session = MagicMock()
        mock_session.run.side_effect = Exception("already exists")
        try:
            self.mod.init_schema(mock_session)
        except Exception as e:
            self.fail(f"init_schema raised: {e}")

    # NOTE: test_constraints_match_original was removed with the pre-refactor
    # snapshot `graph_db/neo4j_client copy.py`; the DDL lists are now validated by
    # test_all_ddl_lists_non_empty / test_all_ddl_idempotent above.


# ─── BASE MIXIN TESTS (mocked neo4j) ─────────────────────────────────────────

class TestBaseMixin(unittest.TestCase):
    def _make_client(self, node_count=5):
        mock_record = MagicMock()
        mock_record.__getitem__ = MagicMock(
            side_effect=lambda k: node_count if k in ("deleted_count", "deleted", "cleaned") else 0
        )
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.run.return_value.single.return_value = mock_record

        mock_driver = MagicMock()
        mock_driver.session.return_value = mock_session
        mock_driver.close = MagicMock()

        client = _base.BaseMixin.__new__(_base.BaseMixin)
        client.driver = mock_driver
        client._mock_session = mock_session
        return client

    def test_clear_project_data_returns_stats_dict(self):
        client = self._make_client()
        result = client.clear_project_data("user1", "proj1")
        self.assertIsInstance(result, dict)
        self.assertIn("nodes_deleted", result)

    def test_clear_project_data_uses_detach_delete(self):
        client = self._make_client()
        client.clear_project_data("user1", "proj1")
        calls = str(client._mock_session.run.call_args_list)
        self.assertIn("DETACH DELETE", calls)

    def test_clear_project_data_passes_tenant(self):
        client = self._make_client()
        client.clear_project_data("alice", "project-99")
        calls = str(client._mock_session.run.call_args_list)
        self.assertIn("alice", calls)
        self.assertIn("project-99", calls)

    def test_clear_gvm_data_keys(self):
        client = self._make_client()
        result = client.clear_gvm_data("user1", "proj1")
        self.assertEqual(
            set(result.keys()),
            {"vulnerabilities_deleted", "cves_deleted", "technologies_deleted",
             "technologies_cleaned", "traceroutes_deleted", "certificates_deleted",
             "exploits_gvm_deleted", "relationships_deleted"}
        )

    def test_close_calls_driver_close(self):
        client = self._make_client()
        client.close()
        client.driver.close.assert_called_once()

    def test_verify_connection_true_on_success(self):
        client = self._make_client()
        client._mock_session.run.return_value.single.return_value = {"test": 1}
        self.assertTrue(client.verify_connection())

    def test_verify_connection_false_on_exception(self):
        client = self._make_client()
        client.driver.session.return_value.__enter__.side_effect = Exception("refused")
        self.assertFalse(client.verify_connection())



class TestSubdomainEdgesArePaired(unittest.TestCase):
    """Domain <-> Subdomain must be a symmetric pair.

    Every place that MERGEs `(d)-[:HAS_SUBDOMAIN]->(s)` must also MERGE the reverse
    `(s)-[:BELONGS_TO]->(d)` in the same query, and vice versa. The URLScan
    discovery path in osint_mixin.py created only HAS_SUBDOMAIN, so 13
    enrichment-discovered subdomains in a multi-domain scan had no BELONGS_TO edge
    back to their domain - reachable one way, invisible to a Subdomain->Domain
    traversal. This pins the invariant so a future write site cannot regress it.
    """

    _MIXINS = [
        "graph_db/mixins/osint_mixin.py",
        "graph_db/mixins/recon/domain_mixin.py",
        "graph_db/mixins/recon/user_input_mixin.py",
        "graph_db/mixins/recon/vhost_sni_mixin.py",
    ]

    _MERGE_HAS = re.compile(r"MERGE\s*\([^)]*\)\s*-\[:HAS_SUBDOMAIN")
    _MERGE_BEL = re.compile(r"MERGE\s*\([^)]*\)\s*-\[:BELONGS_TO")

    def test_has_subdomain_and_belongs_to_are_created_together(self):
        unpaired = []
        for rel in self._MIXINS:
            src = open(os.path.join(_REPO, rel)).read()
            # Each Cypher literal is a triple-quoted block; check per block so a
            # HAS_SUBDOMAIN create and a BELONGS_TO create in DIFFERENT queries do
            # not mask a genuinely one-directional write.
            for block in re.findall(r'"""(.*?)"""', src, re.S):
                has = self._MERGE_HAS.search(block) is not None
                bel = self._MERGE_BEL.search(block) is not None
                if has != bel:
                    unpaired.append(f"{rel}: HAS_SUBDOMAIN={has} BELONGS_TO={bel}")
        self.assertEqual(unpaired, [], "one-directional Domain/Subdomain write(s): " + "; ".join(unpaired))

    def test_the_urlscan_discovery_path_creates_both_edges(self):
        # The exact site that regressed: update_graph_from_urlscan_discovery.
        src = open(os.path.join(_REPO, "graph_db/mixins/osint_mixin.py")).read()
        start = src.index("def update_graph_from_urlscan_discovery")
        end = src.index("\n    def ", start + 1)
        body = src[start:end]
        self.assertIn("HAS_SUBDOMAIN", body)
        self.assertIn("BELONGS_TO", body)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestSyntax, TestMethodPresence, TestNeo4jClientOrchestrator,
                TestCpeResolver, TestSchema, TestBaseMixin,
                TestSubdomainEdgesArePaired]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
