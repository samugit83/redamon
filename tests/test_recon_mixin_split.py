"""
Identity tests for the recon_mixin.py split refactor.

Proves that the split of graph_db/mixins/recon_mixin.py into a package of
topical sub-mixins is a pure code-move (zero behavioral change) by comparing
every method's normalized AST against the pre-refactor snapshot in
tests/fixtures/recon_mixin_snapshot.json.

Run with:
    python3 tests/test_recon_mixin_split.py
    # or:
    python3 -m pytest tests/test_recon_mixin_split.py -v
"""
import ast
import json
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SNAPSHOT = os.path.join(_REPO, "tests", "fixtures", "recon_mixin_snapshot.json")

# Expected split: each method -> sub-mixin file it should live in
EXPECTED_PLACEMENT = {
    "update_graph_from_domain_discovery": "graph_db/mixins/recon/domain_mixin.py",
    "update_graph_from_ip_recon":         "graph_db/mixins/recon/domain_mixin.py",
    "update_graph_from_port_scan":        "graph_db/mixins/recon/port_mixin.py",
    "update_graph_from_nmap":             "graph_db/mixins/recon/port_mixin.py",
    "update_graph_from_http_probe":       "graph_db/mixins/recon/http_mixin.py",
    "_find_cwes_with_capec":              "graph_db/mixins/recon/vuln_mixin.py",
    "_process_cwe_with_capec":            "graph_db/mixins/recon/vuln_mixin.py",
    "update_graph_from_vuln_scan":        "graph_db/mixins/recon/vuln_mixin.py",
    "update_graph_from_resource_enum":    "graph_db/mixins/recon/resource_mixin.py",
    "update_graph_from_js_recon":         "graph_db/mixins/recon/js_recon_mixin.py",
    "create_user_input_node":             "graph_db/mixins/recon/user_input_mixin.py",
    "update_user_input_status":           "graph_db/mixins/recon/user_input_mixin.py",
    "update_graph_from_partial_discovery":"graph_db/mixins/recon/user_input_mixin.py",
    "get_graph_inputs_for_tool":          "graph_db/mixins/recon/user_input_mixin.py",
}

SUB_MIXIN_FILES = sorted(set(EXPECTED_PLACEMENT.values()))


def _load_snapshot():
    with open(_SNAPSHOT) as f:
        return json.load(f)


def _methods_in_file(relpath):
    """Return {method_name: ast.dump(method)} for every FunctionDef inside any ClassDef in the file."""
    path = os.path.join(_REPO, relpath)
    if not os.path.exists(path):
        return {}
    tree = ast.parse(open(path).read())
    out = {}
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for node in cls.body:
            if isinstance(node, ast.FunctionDef):
                out[node.name] = ast.dump(node, annotate_fields=True, include_attributes=False)
    return out


def _all_new_methods():
    """Union of methods across all sub-mixin files. Asserts no duplicates."""
    merged = {}
    duplicates = []
    for f in SUB_MIXIN_FILES:
        for name, dump in _methods_in_file(f).items():
            if name in merged:
                duplicates.append((name, merged[name + "__file"], f))
            merged[name] = dump
            merged[name + "__file"] = f
    return merged, duplicates


class TestSnapshotIntegrity(unittest.TestCase):
    """The snapshot fixture must exist and contain all 14 original methods."""

    def test_snapshot_exists(self):
        self.assertTrue(os.path.exists(_SNAPSHOT),
                        f"Snapshot missing: {_SNAPSHOT}. "
                        "Run the snapshot script before the refactor.")

    def test_snapshot_has_all_methods(self):
        snap = _load_snapshot()
        self.assertEqual(set(snap.keys()), set(EXPECTED_PLACEMENT.keys()),
                         "Snapshot method set differs from EXPECTED_PLACEMENT")


class TestSubMixinFilesExist(unittest.TestCase):
    """After the refactor, every sub-mixin file must exist."""

    def test_package_init_exists(self):
        init = os.path.join(_REPO, "graph_db/mixins/recon/__init__.py")
        self.assertTrue(os.path.exists(init),
                        f"Package init missing: {init}")

    def test_all_submixin_files_exist(self):
        for f in SUB_MIXIN_FILES:
            with self.subTest(file=f):
                path = os.path.join(_REPO, f)
                self.assertTrue(os.path.exists(path),
                                f"Sub-mixin file missing: {f}")

    def test_all_submixin_files_parse(self):
        for f in SUB_MIXIN_FILES:
            with self.subTest(file=f):
                src = open(os.path.join(_REPO, f)).read()
                try:
                    ast.parse(src)
                except SyntaxError as e:
                    self.fail(f"Syntax error in {f}: {e}")


class TestMethodIdentity(unittest.TestCase):
    """Every pre-refactor method must appear in its expected sub-mixin with
    a byte-identical AST dump. This proves a pure code-move."""

    def test_all_methods_present_in_expected_sub_mixin(self):
        snap = _load_snapshot()
        for name, expected_file in EXPECTED_PLACEMENT.items():
            with self.subTest(method=name):
                methods = _methods_in_file(expected_file)
                self.assertIn(name, methods,
                              f"Method {name} missing from {expected_file}")
                self.assertEqual(
                    methods[name], snap[name],
                    f"AST mismatch for {name} in {expected_file} - "
                    f"method body was MODIFIED during the move (refactor "
                    f"must be a pure code-move, no edits).")

    def test_no_method_duplicated_across_sub_mixins(self):
        merged, dups = _all_new_methods()
        self.assertEqual(dups, [],
                         f"Methods duplicated across sub-mixins: {dups}")

    def test_method_set_matches_snapshot_exactly(self):
        snap = _load_snapshot()
        merged, _ = _all_new_methods()
        new_method_names = {k for k in merged if not k.endswith("__file")}
        snap_names = set(snap.keys())
        missing = snap_names - new_method_names
        extra = new_method_names - snap_names
        self.assertEqual(missing, set(),
                         f"Methods lost during refactor: {missing}")
        self.assertEqual(extra, set(),
                         f"Unexpected new methods in sub-mixins: {extra}")


class TestCombinatorClass(unittest.TestCase):
    """recon_mixin.py must become a thin combinator that re-exports ReconMixin."""

    def _recon_mixin_src(self):
        return open(os.path.join(_REPO, "graph_db/mixins/recon_mixin.py")).read()

    def test_is_thin(self):
        lines = self._recon_mixin_src().splitlines()
        self.assertLess(len(lines), 80,
                        f"recon_mixin.py has {len(lines)} lines, expected < 80 after split")

    def test_exposes_ReconMixin_class(self):
        tree = ast.parse(self._recon_mixin_src())
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        self.assertIn("ReconMixin", classes,
                      "ReconMixin class missing from recon_mixin.py")

    def test_ReconMixin_inherits_all_sub_mixins(self):
        tree = ast.parse(self._recon_mixin_src())
        cls = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.ClassDef) and n.name == "ReconMixin")
        bases = set()
        for b in cls.bases:
            if isinstance(b, ast.Name):
                bases.add(b.id)
            elif isinstance(b, ast.Attribute):
                bases.add(b.attr)
        required = {"DomainMixin", "PortMixin", "HttpMixin", "VulnMixin",
                    "ResourceMixin", "JsReconMixin", "UserInputMixin"}
        self.assertEqual(bases, required,
                         f"ReconMixin bases mismatch. got={bases} expected={required}")


class TestReconMixinMROResolves(unittest.TestCase):
    """The combined ReconMixin must expose every original method via MRO
    (loaded as a real class with a stubbed neo4j driver)."""

    @classmethod
    def setUpClass(cls):
        # Stub neo4j / dotenv so imports don't require a live DB
        sys.modules.setdefault("neo4j", MagicMock())
        sys.modules.setdefault("dotenv", MagicMock())

        # Ensure repo root is on sys.path
        if _REPO not in sys.path:
            sys.path.insert(0, _REPO)

        # Fresh import - clear any cached recon_mixin modules
        for k in list(sys.modules):
            if k.startswith("graph_db.mixins.recon"):
                del sys.modules[k]

        from graph_db.mixins.recon_mixin import ReconMixin
        cls.ReconMixin = ReconMixin

    def test_all_original_methods_resolvable(self):
        snap = _load_snapshot()
        for name in snap:
            with self.subTest(method=name):
                self.assertTrue(
                    hasattr(self.ReconMixin, name),
                    f"ReconMixin missing method {name} after split")
                self.assertTrue(
                    callable(getattr(self.ReconMixin, name)),
                    f"ReconMixin.{name} is not callable")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for c in [TestSnapshotIntegrity, TestSubMixinFilesExist,
              TestMethodIdentity, TestCombinatorClass,
              TestReconMixinMROResolves]:
        suite.addTests(loader.loadTestsFromTestCase(c))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
