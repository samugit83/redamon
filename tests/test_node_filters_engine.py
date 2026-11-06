"""Node filters: the catalog, the rule parser, the evaluator and the Cypher builder.

Everything here is pure: the catalog is the committed catalog.json, the rule
documents are synthetic, and no graph is touched. The sweep itself, against a
fake driver, is in test_node_filter_mixin.py; against a real Neo4j, in
test_node_filters_graph_live.py.

Fixtures use only example.com, 192.0.2.0/24 and 2001:db8::/32.

Run: ./redamon.sh test unit   (root-agent section)
"""
import copy
import json
import os
import random
import string
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from graph_db.node_filters import build  # noqa: E402
from graph_db.node_filters import catalog as C  # noqa: E402
from graph_db.node_filters.cypher import (  # noqa: E402
    ident, mute_query, projection_query, restamp_query, selector_clause, unmute_query,
)
from graph_db.node_filters.evaluate import compile as compile_rules  # noqa: E402
from graph_db.node_filters.model import LIMITS, OPERATORS, parse, valid_rule_name  # noqa: E402
from graph_db.node_filters.normalize import NORMALIZERS, field_value  # noqa: E402

FIXTURES = _REPO / "graph_db" / "node_filters" / "fixtures"
CAT = C.load_catalog()


def rule(rid="k3f9a2", name="A rule", conds=None, **kw):
    return {"id": rid, "name": name, "enabled": kw.pop("enabled", True),
            "all": conds if conds is not None else [], **kw}


def doc(kind, *rules, enabled=True):
    return {"version": 1, "kinds": {kind: {"enabled": enabled, "action": "mute", "rules": list(rules)}}}


def filterset(kind, *rules, mode="denylist", now=None):
    cfg = parse(doc(kind, *rules), mode, CAT)
    return compile_rules(cfg, CAT, now=now), cfg


def one(kind, cond, value, mode="denylist"):
    """Does a single-condition rule filter a node whose field has `value`?"""
    fs, cfg = filterset(kind, rule(conds=[cond]), mode=mode)
    assert cfg.kinds[kind].active, cfg.kinds[kind].errors
    return fs.decide(kind, {cond["field"]: value})[0]


class TestTheCatalog(unittest.TestCase):
    def test_the_committed_catalog_is_built_from_the_yaml_and_passes_every_check(self):
        # build.py --check: an undeclared prop, an overlapping selector, an
        # unclaimed source or a stale webapp copy all fail here.
        self.assertEqual(build.main(["--check"]), 0)

    def test_phase_one_covers_the_planned_kinds(self):
        self.assertEqual(set(CAT.kinds_for_enabled_phases()), {
            "vuln.nuclei", "vuln.security_check", "vuln.waf_bypass", "vuln.nmap_nse",
            "vuln.takeover", "vuln.vhost_sni", "vuln.cache_poisoning", "vuln.graphql",
            "vuln.ai_surface", "vuln.passive_cve", "vuln.osv", "vuln.serialized_scan",
            "vuln.route_exposure", "vuln.urlscan", "js.finding", "secret", "malpackage",
        })

    def test_the_muteable_labels_match_the_triage_mixin(self):
        from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
        self.assertEqual(set(C.MUTEABLE), set(MUTEABLE_LABELS))

    def test_every_kind_keys_on_its_uniqueness_constraint(self):
        self.assertEqual(CAT.kind("malpackage")["key"], "finding_id")
        for kind_id, kind in CAT.kinds.items():
            if kind["graph_label"] != "MalPackageFinding":
                self.assertEqual(kind["key"], "id", kind_id)

    def test_selectors_on_one_label_never_overlap(self):
        vulns = [(k, v) for k, v in CAT.kinds.items() if v["graph_label"] == "Vulnerability"]
        for i, (a, ka) in enumerate(vulns):
            for b, kb in vulns[i + 1:]:
                self.assertTrue(C.selectors_disjoint(ka["select"], kb["select"]), f"{a} vs {b}")

    def test_waf_bypass_is_split_off_security_check_by_type(self):
        sc, wb = CAT.kind("vuln.security_check"), CAT.kind("vuln.waf_bypass")
        self.assertIn({"prop": "type", "not_eq": "waf_bypass"}, sc["select"])
        self.assertIn({"prop": "type", "eq": "waf_bypass"}, wb["select"])

    def test_every_unfiltered_source_says_why(self):
        for source, reason in {**CAT.data["unfiltered_sources"], **CAT.data["asset_sources"]}.items():
            self.assertTrue(reason.strip(), source)

    def test_operators_and_limits_ship_with_the_catalog(self):
        # The webapp validator reads them from catalog.json, so the two sides
        # cannot offer different operators.
        self.assertEqual(CAT.data["operators"], {t: list(o) for t, o in OPERATORS.items()})
        self.assertEqual(CAT.data["limits"], LIMITS)

    def test_the_webapp_copy_is_identical(self):
        engine = (_REPO / "graph_db/node_filters/catalog.json").read_text()
        webapp = _REPO / "webapp/src/lib/nodeFilters/catalog.json"
        if not webapp.exists():
            self.skipTest("webapp tree not mounted")
        self.assertEqual(engine, webapp.read_text())


class TestTheCatalogCheckRejects(unittest.TestCase):
    """Each check, on a deliberately broken copy of the real catalog."""

    NORMALIZERS = {n: inputs for n, (_f, inputs) in NORMALIZERS.items()}

    def _check(self, mutate, **kw):
        data = copy.deepcopy(CAT.data)
        mutate(data)
        declared = build.label_properties
        return C.check(data, lambda label: set(declared(label)), self.NORMALIZERS, **kw)

    def test_an_undeclared_property(self):
        def m(d):
            d["kinds"]["vuln.nuclei"]["fields"]["template_id"]["prop"] = "tmpl_identifier"
        self.assertTrue(any("not a declared" in e for e in self._check(m)))

    def test_a_property_that_is_not_an_identifier(self):
        def m(d):
            d["kinds"]["vuln.nuclei"]["fields"]["template_id"]["prop"] = "x) DETACH DELETE n //"
        self.assertTrue(any("not an identifier" in e for e in self._check(m)))

    def test_a_label_that_is_not_an_identifier(self):
        def m(d):
            d["kinds"]["vuln.nuclei"]["graph_label"] = "Vulnerability`) DETACH DELETE n //"
        self.assertTrue(any("graph_label" in e for e in self._check(m)))

    def test_a_label_that_cannot_be_muted(self):
        def m(d):
            d["kinds"]["secret"]["graph_label"] = "IP"
        self.assertTrue(any("cannot be muted" in e for e in self._check(m)))

    def test_an_unknown_normalizer(self):
        def m(d):
            d["kinds"]["vuln.nuclei"]["fields"]["port"]["normalizer"] = "port_guess"
        self.assertTrue(any("unknown normalizer" in e for e in self._check(m)))

    def test_two_kinds_claiming_the_same_nodes(self):
        def m(d):
            d["kinds"]["vuln.takeover"]["select"] = [{"prop": "source", "in": ["nuclei", "takeover_scan"]}]
            d["kinds"]["vuln.takeover"]["sources"] = ["nuclei", "takeover_scan"]
        self.assertTrue(any("overlaps" in e for e in self._check(m)))

    def test_a_source_nobody_claims(self):
        errors = self._check(lambda d: None, known_sources={"nuclei", "brand_new_scanner"})
        self.assertEqual([e for e in errors if "brand_new_scanner" in e][:1],
                         ["source 'brand_new_scanner' is in no kind and not listed under "
                          "unfiltered_sources or asset_sources, with a reason"])

    def test_an_overlap_naming_a_missing_setting_or_tab(self):
        errors = self._check(lambda d: None, registry_keys={"nucleiSeverity"}, tab_ids={"vuln"})
        self.assertTrue(any("nucleiExcludeTags" in e for e in errors))
        self.assertTrue(any("not a settings tab" in e for e in errors))

    def test_a_catalog_that_fails_its_check_does_not_load(self):
        data = copy.deepcopy(CAT.data)
        data["kinds"]["vuln.nuclei"]["graph_label"] = "Nope Nope"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
        try:
            with self.assertRaises(C.CatalogError):
                C.load_catalog(f.name)
        finally:
            os.unlink(f.name)

    def test_an_unreadable_catalog_does_not_load(self):
        with self.assertRaises(C.CatalogError):
            C.load_catalog("/nonexistent/catalog.json")


class TestTheSharedFixtures(unittest.TestCase):
    """The same synthetic documents the webapp validator is tested against."""

    def test_there_are_fixtures(self):
        self.assertGreaterEqual(len(list(FIXTURES.glob("*.json"))), 25)

    def test_every_fixture_parses_as_expected(self):
        for path in sorted(FIXTURES.glob("*.json")):
            case = json.loads(path.read_text())
            cfg = parse(case["rules"], case["mode"], CAT)
            errors = len(cfg.errors) + sum(len(k.errors) for k in cfg.kinds.values())
            got = {"ok": cfg.ok, "active": sorted(cfg.active_kinds()), "errors": errors}
            with self.subTest(fixture=path.name, what=case["description"]):
                self.assertEqual(got, case["expect"])


class TestFailClosed(unittest.TestCase):
    BAD = rule("p81c0d", "Bad", [{"field": "nope", "op": "in", "value": ["x"]}])
    GOOD = rule("k3f9a2", "Good", [{"field": "severity", "op": "in", "value": ["info"]}])

    def test_denylist_skips_the_invalid_rule_and_runs_the_rest(self):
        cfg = parse(doc("vuln.nuclei", self.GOOD, self.BAD), "denylist", CAT)
        self.assertTrue(cfg.kinds["vuln.nuclei"].active)
        self.assertEqual([r.id for r in cfg.kinds["vuln.nuclei"].rules], ["k3f9a2"])

    def test_allowlist_deactivates_the_whole_kind(self):
        # Dropping a broken KEEP rule would mute exactly what it was meant to keep.
        cfg = parse(doc("vuln.nuclei", self.GOOD, self.BAD), "allowlist", CAT)
        self.assertFalse(cfg.kinds["vuln.nuclei"].active)
        self.assertIn("deactivates the whole kind", " ".join(cfg.kinds["vuln.nuclei"].errors))

    def test_an_unparseable_document_filters_nothing(self):
        for bad in ("{not json", b"\xff\xfe", 42, [1, 2], {"version": 7}):
            with self.subTest(bad=repr(bad)[:20]):
                self.assertFalse(parse(bad, "denylist", CAT).ok)

    def test_an_oversized_document_filters_nothing(self):
        big = doc("vuln.nuclei", rule(conds=[{"field": "name", "op": "eq", "value": "x"}]))
        big["padding"] = "x" * (LIMITS["document_bytes"] + 1)
        self.assertFalse(parse(big, "denylist", CAT).ok)
        self.assertFalse(parse(json.dumps(big), "denylist", CAT).ok)

    def test_parse_raises_on_overflow_and_recursion(self):
        # parse() promises never to raise. A number too big for a float raised
        # OverflowError, and a deeply nested string document RecursionError:
        # a 500 on a preview, a failed sweep at scan time.
        huge = doc("vuln.nuclei", rule(conds=[{"field": "cvss", "op": "gt", "value": 10 ** 400}]))
        cfg = parse(huge, "denylist", CAT)
        self.assertFalse(cfg.kinds["vuln.nuclei"].active)
        self.assertTrue(cfg.kinds["vuln.nuclei"].errors)
        # 60 KB: under the 64 KB cap, so it is the nesting that must be caught.
        nested = "[" * 30_000 + "]" * 30_000
        self.assertLess(len(nested), LIMITS["document_bytes"])
        self.assertFalse(parse(nested, "denylist", CAT).ok)

    def test_an_unknown_mode_filters_nothing(self):
        self.assertFalse(parse(doc("vuln.nuclei", self.GOOD), "maybe", CAT).ok)

    def test_no_document_is_no_rules_not_an_error(self):
        cfg = parse(None, "denylist", CAT)
        self.assertTrue(cfg.ok)
        self.assertEqual(cfg.active_kinds(), [])

    def test_more_rules_than_the_limit(self):
        rules = [rule(f"r{i:05d}", f"Rule {i}", [{"field": "name", "op": "eq", "value": "x"}])
                 for i in range(LIMITS["rules_per_kind"] + 1)]
        cfg = parse(doc("vuln.nuclei", *rules), "denylist", CAT)
        self.assertFalse(cfg.kinds["vuln.nuclei"].active)

    def test_rule_names(self):
        for ok in ("Informational templates", "Tech/SSL (low): 1.0 + more", "Modèle già visto"):
            self.assertTrue(valid_rule_name(ok), ok)
        for bad in ("", " padded", "x" * 81, "<b>", "=cmd", "a'b", 'a"b', "tab\there", "new\nline", None, 7):
            self.assertFalse(valid_rule_name(bad), repr(bad))

    def test_names_are_kept_even_for_disabled_and_invalid_rules(self):
        cfg = parse(doc("vuln.nuclei", self.GOOD, {**self.BAD, "enabled": False}), "denylist", CAT)
        self.assertEqual(cfg.rule_name("vuln.nuclei", "p81c0d"), "Bad")


class TestOperators(unittest.TestCase):
    N = "vuln.nuclei"

    def test_number(self):
        c = lambda op, v: {"field": "cvss", "op": op, "value": v}  # noqa: E731
        self.assertTrue(one(self.N, c("lt", 4), 3.9))
        self.assertFalse(one(self.N, c("lt", 4), 4))
        self.assertTrue(one(self.N, c("lte", 4), 4))
        self.assertTrue(one(self.N, c("gt", 4), 4.1))
        self.assertTrue(one(self.N, c("gte", 4), "4"))  # a numeric string still compares
        self.assertTrue(one(self.N, c("eq", 5), 5.0))
        self.assertTrue(one(self.N, c("between", [4, 6.9]), 6.9))
        self.assertTrue(one(self.N, c("between", [4, 6.9]), 4))
        self.assertFalse(one(self.N, c("between", [4, 6.9]), 7))
        self.assertFalse(one(self.N, c("gt", 1), "high"))

    def test_long_text_truncation_flips_negative_operators(self):
        # Text was cut to 2,048 characters before every comparison. A needle
        # past the cut made `not_contains` match (a denylist muted a finding it
        # should not) and `contains` / `ends_with` miss (an allowlist muted
        # what it should have kept).
        long_output = "x" * 3000 + " VULNERABLE: CVE-2024-0001"
        nse = "vuln.nmap_nse"
        c = lambda op, v: {"field": "output", "op": op, "value": v}  # noqa: E731
        self.assertFalse(one(nse, c("not_contains", "vulnerable"), long_output))
        self.assertTrue(one(nse, c("contains", "vulnerable"), long_output))
        self.assertTrue(one(nse, c("ends_with", "cve-2024-0001"), long_output))
        self.assertTrue(one(nse, c("glob", "*vulnerable*"), long_output))
        self.assertTrue(one(nse, c("glob", "x*cve-202?-0001"), long_output))
        self.assertFalse(one(nse, c("not_glob", "*vulnerable*"), long_output))

    def test_ordinal(self):
        c = lambda op, v: {"field": "severity", "op": op, "value": v}  # noqa: E731
        self.assertTrue(one(self.N, c("lte", "low"), "info"))
        self.assertTrue(one(self.N, c("lte", "low"), "low"))
        self.assertFalse(one(self.N, c("lte", "low"), "medium"))
        self.assertTrue(one(self.N, c("gte", "high"), "critical"))
        self.assertTrue(one(self.N, c("in", ["info", "low"]), "info"))
        self.assertTrue(one(self.N, c("not_in", ["info"]), "low"))
        # Off the scale is neither above nor below anything.
        self.assertFalse(one(self.N, c("lt", "critical"), "unknown"))
        self.assertFalse(one(self.N, c("gt", "info"), "unknown"))

    def test_the_cache_tier_scale(self):
        c = {"field": "confidence_tier", "op": "lt", "value": "Confirmed"}
        self.assertTrue(one("vuln.cache_poisoning", c, "Strong"))
        self.assertTrue(one("vuln.cache_poisoning", c, "tentative"))
        self.assertFalse(one("vuln.cache_poisoning", c, "Confirmed"))

    def test_enum_is_case_insensitive(self):
        c = {"field": "state", "op": "in", "value": ["LIKELY VULNERABLE"]}
        self.assertTrue(one("vuln.nmap_nse", c, "likely vulnerable"))
        self.assertFalse(one("vuln.nmap_nse", c, "VULNERABLE"))

    def test_text(self):
        f = lambda op, v: {"field": "template_id", "op": op, "value": v}  # noqa: E731
        self.assertTrue(one(self.N, f("eq", "Tech-Detect"), "tech-detect"))
        self.assertTrue(one(self.N, f("not_eq", "a"), "b"))
        self.assertTrue(one(self.N, f("contains", "DETECT"), "tech-detect"))
        self.assertTrue(one(self.N, f("not_contains", "ssl"), "tech-detect"))
        self.assertTrue(one(self.N, f("starts_with", "tech"), "tech-detect"))
        self.assertTrue(one(self.N, f("ends_with", "detect"), "tech-detect"))
        self.assertTrue(one(self.N, f("glob", "tech-*"), "TECH-DETECT"))
        self.assertTrue(one(self.N, f("not_glob", "ssl-*"), "tech-detect"))

    def test_glob_anchors_the_whole_value(self):
        c = {"field": "host", "op": "glob", "value": "*.example.com"}
        self.assertTrue(one(self.N, c, "api.example.com"))
        self.assertFalse(one(self.N, c, "api.example.com.attacker.test"))
        self.assertFalse(one(self.N, c, "example.com"))

    def test_glob_brackets_are_literal_classes_not_regex(self):
        c = {"field": "template_id", "op": "glob", "value": "cve-202[34]-*"}
        self.assertTrue(one(self.N, c, "cve-2023-1234"))
        self.assertFalse(one(self.N, c, "cve-2021-1234"))
        # A regex metacharacter in a glob is a literal.
        c = {"field": "template_id", "op": "glob", "value": "a.b"}
        self.assertFalse(one(self.N, c, "axb"))

    def test_the_fast_glob_path_agrees_with_fnmatch(self):
        # `*`-only patterns skip the regex; they must still mean what fnmatch means.
        import fnmatch as _fn
        from graph_db.node_filters.evaluate import _glob
        rng = random.Random(3)
        alphabet = "ab.-*"
        for _ in range(3000):
            pattern = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 7)))
            value = "".join(rng.choice("ab.-") for _ in range(rng.randint(0, 9)))
            with self.subTest(pattern=pattern, value=value):
                self.assertEqual(_glob(pattern)(value), _fn.fnmatchcase(value, pattern))

    def test_a_pathological_glob_returns_quickly(self):
        c = {"field": "template_id", "op": "glob", "value": "*a" * 16 + "b"}
        start = time.monotonic()
        self.assertFalse(one(self.N, c, "a" * 2048))
        self.assertLess(time.monotonic() - start, 1.0)

    def test_cidr_v4_and_v6(self):
        c = {"field": "matched_ip", "op": "in_cidr", "value": ["192.0.2.0/24", "2001:db8::/32"]}
        self.assertTrue(one(self.N, c, "192.0.2.10"))
        self.assertTrue(one(self.N, c, "2001:db8::1"))
        self.assertFalse(one(self.N, c, "198.51.100.1"))
        self.assertFalse(one(self.N, c, "api.example.com"))
        c = {"field": "matched_ip", "op": "not_in_cidr", "value": ["192.0.2.0/24"]}
        self.assertTrue(one(self.N, c, "198.51.100.1"))
        self.assertFalse(one(self.N, c, "not-an-ip"))

    def test_bool(self):
        self.assertTrue(one(self.N, {"field": "is_dast_finding", "op": "is_true"}, True))
        self.assertTrue(one(self.N, {"field": "is_dast_finding", "op": "is_true"}, "true"))
        self.assertTrue(one(self.N, {"field": "is_dast_finding", "op": "is_false"}, False))
        self.assertFalse(one(self.N, {"field": "is_dast_finding", "op": "is_false"}, None))

    def test_list(self):
        c = lambda op, v: {"field": "tags", "op": op, "value": v}  # noqa: E731
        self.assertTrue(one(self.N, c("contains_any", ["SSL"]), ["tech", "ssl"]))
        self.assertTrue(one(self.N, c("contains_all", ["tech", "ssl"]), ["ssl", "tech", "x"]))
        self.assertFalse(one(self.N, c("contains_all", ["tech", "ssl"]), ["tech"]))
        self.assertTrue(one(self.N, c("not_contains_any", ["cve"]), ["tech"]))
        self.assertTrue(one(self.N, c("not_contains_any", ["cve"]), []))
        self.assertTrue(one(self.N, {"field": "tags", "op": "is_empty"}, []))
        self.assertTrue(one(self.N, {"field": "tags", "op": "is_empty"}, None))
        self.assertFalse(one(self.N, {"field": "tags", "op": "is_empty"}, ["x"]))

    def test_date(self):
        now = datetime(2026, 9, 23, tzinfo=timezone.utc)
        old = (now - timedelta(days=100)).isoformat()
        fs, _ = filterset(self.N, rule(conds=[{"field": "updated_at", "op": "older_than_days", "value": 90}]), now=now)
        self.assertTrue(fs.decide(self.N, {"updated_at": old})[0])
        self.assertFalse(fs.decide(self.N, {"updated_at": now.isoformat()})[0])
        # The ISO string a restored graph carries, with nanoseconds and a Z.
        self.assertTrue(fs.decide(self.N, {"updated_at": "2026-01-02T03:04:05.123456789Z"})[0])
        fs, _ = filterset(self.N, rule(conds=[{"field": "updated_at", "op": "before", "value": "2026-01-01"}]))
        self.assertTrue(fs.decide(self.N, {"updated_at": "2025-12-31T23:00:00Z"})[0])
        self.assertFalse(fs.decide(self.N, {"updated_at": "not a date"})[0])


class TestMissingValues(unittest.TestCase):
    N = "vuln.nuclei"

    def test_missing_matches_absent_null_and_empty(self):
        c = {"field": "template_id", "op": "missing"}
        for value in (None, "", "  "):
            self.assertTrue(one(self.N, c, value), repr(value))
        self.assertFalse(one(self.N, c, "x"))

    def test_every_other_operator_is_false_on_a_missing_value(self):
        for cond in (
            {"field": "template_id", "op": "not_eq", "value": "x"},
            {"field": "template_id", "op": "not_contains", "value": "x"},
            {"field": "template_id", "op": "not_glob", "value": "x*"},
            {"field": "severity", "op": "not_in", "value": ["info"]},
            {"field": "cvss", "op": "lt", "value": 99},
            {"field": "matched_ip", "op": "not_in_cidr", "value": ["192.0.2.0/24"]},
            {"field": "tags", "op": "not_contains_any", "value": ["x"]},
        ):
            with self.subTest(op=cond["op"]):
                self.assertFalse(one(self.N, cond, None))

    def test_in_allowlist_a_node_without_the_field_is_not_kept(self):
        keep = rule(conds=[{"field": "severity", "op": "gte", "value": "high"}])
        fs, _ = filterset(self.N, keep, mode="allowlist")
        self.assertEqual(fs.decide(self.N, {"severity": None}), (True, []))
        self.assertEqual(fs.decide(self.N, {"severity": "critical"}), (False, ["k3f9a2"]))


class TestModes(unittest.TestCase):
    N = "vuln.nuclei"
    INFO = rule("k3f9a2", "Info", [{"field": "severity", "op": "in", "value": ["info"]}])
    SSL = rule("p81c0d", "SSL", [{"field": "tags", "op": "contains_any", "value": ["ssl"]}])

    def test_denylist_is_or_across_rules_and_attributes_the_first(self):
        fs, _ = filterset(self.N, self.INFO, self.SSL)
        self.assertEqual(fs.decide(self.N, {"severity": "info", "tags": ["ssl"]}), (True, ["k3f9a2", "p81c0d"]))
        self.assertEqual(fs.decide(self.N, {"severity": "high", "tags": ["ssl"]}), (True, ["p81c0d"]))
        self.assertEqual(fs.decide(self.N, {"severity": "high", "tags": []}), (False, []))

    def test_and_within_a_rule(self):
        both = rule(conds=[{"field": "severity", "op": "in", "value": ["info"]},
                           {"field": "tags", "op": "contains_any", "value": ["ssl"]}])
        fs, _ = filterset(self.N, both)
        self.assertTrue(fs.decide(self.N, {"severity": "info", "tags": ["ssl"]})[0])
        self.assertFalse(fs.decide(self.N, {"severity": "info", "tags": []})[0])

    def test_allowlist_keeps_what_any_rule_matches(self):
        fs, _ = filterset(self.N, self.INFO, self.SSL, mode="allowlist")
        self.assertFalse(fs.decide(self.N, {"severity": "info", "tags": []})[0])
        self.assertTrue(fs.decide(self.N, {"severity": "high", "tags": []})[0])

    def test_an_inactive_kind_is_never_filtered(self):
        fs, cfg = filterset(self.N, {**self.INFO, "enabled": False})
        self.assertFalse(cfg.kinds[self.N].active)
        self.assertFalse(fs.is_active(self.N))
        self.assertFalse(fs.is_active("secret"))

    def test_match_all(self):
        fs, cfg = filterset("vuln.osv", rule(match_all=True))
        self.assertTrue(fs.decide("vuln.osv", {})[0])
        _fs, cfg = filterset("vuln.osv", rule(match_all=True), mode="allowlist")
        self.assertFalse(cfg.kinds["vuln.osv"].active)

    def test_the_projection_is_only_what_the_rules_read(self):
        fs, _ = filterset(self.N, rule(conds=[{"field": "port", "op": "eq", "value": 443},
                                             {"field": "cvss", "op": "gt", "value": 5}]))
        self.assertEqual(fs.props_needed(self.N), {"matched_at", "cvss_score", "cvss"})


class TestNormalizers(unittest.TestCase):
    """One synthetic node per source shape."""

    def _v(self, kind, field, props):
        return field_value(CAT.kind(kind)["fields"][field], props)

    def test_severity_is_lowercased(self):
        self.assertEqual(self._v("vuln.nuclei", "severity", {"severity": "HIGH"}), "high")
        self.assertIsNone(self._v("vuln.nuclei", "severity", {"severity": ""}))

    def test_cvss_prefers_cvss_score_then_cvss(self):
        self.assertEqual(self._v("vuln.nuclei", "cvss", {"cvss_score": 7.5, "cvss": 1}), 7.5)
        self.assertEqual(self._v("vuln.passive_cve", "cvss", {"cvss": "9.8"}), 9.8)
        self.assertIsNone(self._v("vuln.osv", "cvss", {}))

    def test_cve_ids_from_every_writer_shape(self):
        cases = {
            "nuclei list": ({"cves": ["CVE-2021-44228"]}, ["CVE-2021-44228"]),
            "gvm list": ({"cve_ids": ["cve-2020-1234"]}, ["CVE-2020-1234"]),
            "nmap string": ({"cve_id": "CVE-2019-0708"}, ["CVE-2019-0708"]),
            "osv aliases": ({"aliases": ["GHSA-xxxx", "CVE-2022-0001"]}, ["CVE-2022-0001"]),
            "netlas id": ({"id": "CVE-2023-4567"}, ["CVE-2023-4567"]),
            "shodan id is not a CVE": ({"id": "shodan-CVE-2023-4567-192.0.2.1"}, []),
            "empty nmap cve": ({"cve_id": ""}, []),
        }
        for what, (props, want) in cases.items():
            with self.subTest(what):
                self.assertEqual(self._v("vuln.nuclei", "cve_ids", props), want)

    def test_cve_year_is_the_newest(self):
        props = {"cve_ids": ["CVE-2014-0160", "CVE-2021-44228", "CVE-2021-45046"]}
        self.assertEqual(self._v("vuln.nuclei", "cve_year", props), 2021)
        self.assertTrue(self._v("vuln.nuclei", "has_cve", props))
        self.assertFalse(self._v("vuln.nuclei", "has_cve", {}))

    def test_name_falls_back_to_the_graphql_title(self):
        self.assertEqual(self._v("vuln.graphql", "name", {"title": "Introspection"}), "Introspection")

    def test_port_from_the_nuclei_url(self):
        f = lambda url: self._v("vuln.nuclei", "port", {"matched_at": url})  # noqa: E731
        self.assertEqual(f("https://api.example.com:8443/x"), 8443)
        self.assertEqual(f("https://api.example.com/x"), 443)
        self.assertEqual(f("http://api.example.com"), 80)
        self.assertEqual(f("api.example.com:8080"), 8080)
        self.assertIsNone(f(""))
        self.assertIsNone(f("http://[::1"))

    def test_advisory_prefix(self):
        f = lambda a: self._v("vuln.osv", "advisory_prefix", {"advisory_id": a})  # noqa: E731
        self.assertEqual(f("GHSA-abcd-efgh"), "GHSA")
        self.assertEqual(f("pysec-2021-1"), "PYSEC")
        self.assertIsNone(f(None))

    def test_incident_catalog_presence(self):
        self.assertTrue(self._v("malpackage", "in_incident_catalog", {"incident_id": "inc-1"}))
        self.assertFalse(self._v("malpackage", "in_incident_catalog", {"incident_id": None}))


class TestTheCypherBuilder(unittest.TestCase):
    NUCLEI = CAT.kind("vuln.nuclei")

    def test_identifiers_must_be_safe(self):
        for bad in ("a b", "a`", "1a", "a)", "", None, "a-b"):
            with self.assertRaises(C.CatalogError):
                ident(bad)
        self.assertEqual(ident("template_id"), "`template_id`")

    def test_selector_values_are_parameters(self):
        clause, params = selector_clause(CAT.kind("vuln.security_check")["select"])
        self.assertIn("n.`source` IN $sel0", clause)
        self.assertIn("coalesce(n.`type`, '') <> $sel1", clause)
        self.assertEqual(params, {"sel0": ["security_check"], "sel1": "waf_bypass"})
        self.assertNotIn("waf_bypass", clause)

    def test_the_projection_is_tenant_scoped_and_keyset_paged(self):
        q, _ = projection_query(self.NUCLEI, {"severity"})
        self.assertIn("n.user_id = $uid AND n.project_id = $pid", q)
        self.assertIn("n.`id` > $after", q)
        self.assertIn("ORDER BY n.`id` LIMIT $page", q)
        self.assertIn("n {.`severity`} AS props", q)
        self.assertNotIn("elementId", q)

    def test_scan_scope_reads_restored_string_timestamps(self):
        q, _ = projection_query(self.NUCLEI, set(), touched=True, sources=True)
        self.assertIn("datetime(toString(n.updated_at)) >= datetime($touched_since)", q)
        self.assertIn("n.source IN $sources", q)
        self.assertIn("{} AS props", q)

    def test_an_inactive_kind_only_reads_rule_mutes(self):
        q, params = projection_query(self.NUCLEI, set(), rule_muted_only=True)
        self.assertIn("n:Muted AND coalesce(n.muted_by, '') STARTS WITH $rule_prefix", q)
        self.assertEqual(params["rule_prefix"], "rule:")

    def test_a_rule_field_never_reaches_cypher(self):
        # Property-based: whatever field names and values a document carries,
        # the queries are built from catalog props only.
        rng = random.Random(7)
        for _ in range(50):
            junk = "".join(rng.choice(string.ascii_lowercase + "_") for _ in range(12))
            payload = f"{junk}`) DETACH DELETE n //"
            cfg = parse(doc("vuln.nuclei", rule(conds=[
                {"field": junk, "op": "eq", "value": payload},
                {"field": "template_id", "op": "eq", "value": payload},
            ])), "denylist", CAT)
            fs = compile_rules(cfg, CAT)
            q, params = projection_query(self.NUCLEI, fs.props_needed("vuln.nuclei"))
            for text in (q, mute_query(self.NUCLEI), unmute_query(self.NUCLEI), restamp_query(self.NUCLEI)):
                self.assertNotIn(junk, text)
                self.assertNotIn("DETACH", text)
            self.assertNotIn(payload, json.dumps(params))

    def test_no_write_touches_updated_at(self):
        for q in (mute_query(self.NUCLEI), unmute_query(self.NUCLEI), restamp_query(self.NUCLEI)):
            self.assertNotIn("updated_at", q)

    def test_the_mute_write_rechecks_the_guards_and_the_current_state(self):
        q = mute_query(self.NUCLEI)
        self.assertIn("WHERE NOT n:Muted", q)
        self.assertIn("coalesce(n.triage_source, '') <> 'human'", q)
        self.assertIn("coalesce(n.triage_status, '') <> 'confirmed'", q)
        self.assertIn("n.triage_proof IS NULL", q)
        self.assertIn("NOT EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) }", q)
        self.assertIn("{`id`: row.key, user_id: $uid, project_id: $pid}", q)

    def test_guard_check_before_lock_race(self):
        # Neo4j reads a WHERE under read committed, before the SET takes the
        # node's write lock. A person's mute or a verdict committed in between
        # was overwritten. The writes now lock the node first, then check.
        for q in (mute_query(self.NUCLEI), restamp_query(self.NUCLEI)):
            lock = q.index("SET n._node_filter_lock = true")
            self.assertLess(lock, q.index("REMOVE n._node_filter_lock"))
            self.assertLess(lock, q.index("coalesce(n.triage_source, '') <> 'human'"))
            self.assertLess(lock, q.index("n.muted_by = row.muted_by"))
        self.assertLess(mute_query(self.NUCLEI).index("SET n._node_filter_lock"),
                        mute_query(self.NUCLEI).rindex("NOT n:Muted"))
        # The unmute too: a person re-muting a rule-muted node in between would
        # otherwise lose that mute to this REMOVE.
        q = unmute_query(self.NUCLEI)
        self.assertLess(q.index("SET n._node_filter_lock"), q.rindex("STARTS WITH 'rule:'"))
        self.assertLess(q.rindex("STARTS WITH 'rule:'"), q.index("REMOVE n:Muted"))

    def test_the_unmute_write_only_releases_rule_mutes(self):
        q = unmute_query(self.NUCLEI)
        self.assertIn("STARTS WITH 'rule:'", q)
        self.assertIn(":Muted {`id`: key, user_id: $uid, project_id: $pid}", q)

    def test_malpackage_is_matched_on_finding_id(self):
        q = mute_query(CAT.kind("malpackage"))
        self.assertIn("MalPackageFinding` {`finding_id`: row.key", q)


class TestPerformance(unittest.TestCase):
    def test_100k_nodes_by_40_rules_under_5_seconds(self):
        rules = []
        for i in range(40):
            rules.append(rule(f"r{i:05d}", f"Rule {i}", [
                {"field": "template_id", "op": "glob", "value": f"*tmpl-{i}-*"},
                {"field": "severity", "op": "lte", "value": "medium"},
                {"field": "tags", "op": "contains_any", "value": [f"t{i}", "x"]},
            ]))
        fs, cfg = filterset("vuln.nuclei", *rules)
        self.assertTrue(cfg.kinds["vuln.nuclei"].active)
        rng = random.Random(1)
        nodes = [{"template_id": f"tmpl-{rng.randint(0, 80)}-{i}", "severity": rng.choice(["info", "high"]),
                  "tags": [f"t{rng.randint(0, 60)}"]} for i in range(100_000)]
        start = time.monotonic()
        muted = sum(1 for values in nodes if fs.decide("vuln.nuclei", values)[0])
        elapsed = time.monotonic() - start
        self.assertGreater(muted, 0)
        self.assertLess(elapsed, 5.0, f"{elapsed:.2f}s")


if __name__ == "__main__":
    unittest.main()


class TestSecretPublicClientKey(unittest.TestCase):
    """Plan 05.2: a mute rule on `public_client_key` matches what every reader
    calls public, including a node written before the flag existed."""

    def _decide(self, props):
        fs, cfg = filterset("secret", rule(conds=[{"field": "public_client_key", "op": "is_true"}]))
        self.assertTrue(cfg.kinds["secret"].active, cfg.kinds["secret"].errors)
        return fs.decide("secret", fs.values("secret", props))[0]

    def test_the_field_reads_the_flag_and_the_name(self):
        fs, _ = filterset("secret", rule(conds=[{"field": "public_client_key", "op": "is_true"}]))
        self.assertEqual(fs.props_needed("secret"), {"public_client_key", "secret_type"})

    def test_a_flagged_key_is_muted(self):
        self.assertTrue(self._decide({"public_client_key": True, "secret_type": "Pusher Key"}))

    def test_a_key_written_before_the_flag_is_muted_by_its_name(self):
        self.assertTrue(self._decide({"secret_type": "GCP API Key"}))
        self.assertTrue(self._decide({"public_client_key": False, "secret_type": "sentry dsn"}))

    def test_a_secret_key_is_not(self):
        self.assertFalse(self._decide({"public_client_key": False, "secret_type": "Stripe Secret Key"}))
        self.assertFalse(self._decide({}))

    def test_the_name_list_is_the_score_models(self):
        sys.path.insert(0, str(_REPO / "agentic"))
        try:
            from cypherfix_triage import score_model as sm
        except ImportError as e:  # pragma: no cover - the agent image has it
            self.skipTest(f"score_model is not importable here: {e}")
        from graph_db.node_filters import normalize
        self.assertEqual(set(normalize.PUBLIC_CLIENT_KEY_TYPES), set(sm.PUBLIC_CLIENT_KEY_TYPES))


class TestLegacyValidationStatusAlias(unittest.TestCase):
    """Plan 05.7: js_recon writes 'rejected' (and 'format_invalid') where it
    wrote 'invalid'. A saved rule, a user preset, an imported bundle or an MCP
    write that names 'invalid' keeps matching them, with no data migration;
    'unknown' (no verdict) is never caught by it."""

    def _mutes(self, op, values, stored):
        cond = {"field": "validation_status", "op": op, "value": values}
        fs, cfg = filterset("secret", rule(conds=[cond]))
        self.assertTrue(cfg.kinds["secret"].active, cfg.kinds["secret"].errors)
        return fs.decide("secret", {"validation_status": stored})[0]

    def test_a_rule_on_invalid_mutes_the_new_dead_statuses(self):
        for stored in ("invalid", "rejected", "REJECTED", "format_invalid"):
            with self.subTest(stored=stored):
                self.assertTrue(self._mutes("in", ["invalid"], stored))

    def test_it_never_mutes_a_key_nobody_could_check(self):
        for stored in ("unknown", "validated", "unvalidated", "skipped", None):
            with self.subTest(stored=stored):
                self.assertFalse(self._mutes("in", ["invalid"], stored))

    def test_not_in_invalid_leaves_them_out_too(self):
        self.assertFalse(self._mutes("not_in", ["invalid"], "rejected"))
        self.assertTrue(self._mutes("not_in", ["invalid"], "unknown"))

    def test_the_alias_is_one_way(self):
        # A legacy 'invalid' node may hide a timeout, so a rule on the new word
        # does not reach back to it.
        self.assertFalse(self._mutes("in", ["rejected"], "invalid"))

    def test_the_catalog_lists_the_new_values_and_keeps_invalid(self):
        field = CAT.kind("secret")["fields"]["validation_status"]
        for value in ("validated", "rejected", "unknown", "format_invalid", "invalid"):
            self.assertIn(value, field["values"])
        self.assertEqual(field["aliases"], {"invalid": ["rejected", "format_invalid"]})

    def test_the_shipped_example_names_the_new_value_too(self):
        examples = {e["name"]: e for e in CAT.kind("secret")["examples"]}
        cond = examples["Keys that failed validation"]["all"][0]
        self.assertEqual(sorted(cond["value"]), ["format_invalid", "invalid", "rejected"])

    def test_an_alias_naming_an_unlisted_value_fails_the_catalog_check(self):
        bad = copy.deepcopy(CAT.data)
        bad["kinds"]["secret"]["fields"]["validation_status"]["aliases"] = {"invalid": ["nope"]}
        problems = C.check(bad, C._declared_props(), {n: i for n, (_f, i) in NORMALIZERS.items()})
        self.assertTrue(any("alias" in p for p in problems), problems)
