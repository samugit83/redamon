"""Multi mute: which findings are "the same type" as the seed (plan §3, §7.1).

The kind decides the whole pool, so the dangerous failure is silent: a new
catalog kind, or a FINDING_QUERIES change, quietly retypes a seed and the pool
becomes a different set of findings. Two guards here fail loudly instead:

- a row per muteable label, and a check that every catalog finding kind has a
  row (plan §19: "a kind test per muteable label that fails when the catalog
  gains a kind for that label without a matching test row");
- the fallback source expression re-derived from the FINDING_QUERIES text.

Run: ./agentic/run_tests.sh tests/test_multi_mute_kind.py
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.fact_queries import FINDING_QUERIES  # noqa: E402
from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS  # noqa: E402
from graph_db.node_filters.catalog import load_catalog  # noqa: E402
from multi_mute import kind as K  # noqa: E402

CATALOG = load_catalog()

# (label, seed props, expected kind id). Every catalog finding kind must appear
# as an expected id, and every muteable label but ExploitGvm must have a row.
KIND_ROWS = [
    ("Vulnerability", {"source": "nuclei"}, "vuln.nuclei"),
    ("Vulnerability", {"source": "security_check", "type": "missing_header"}, "vuln.security_check"),
    ("Vulnerability", {"source": "security_check"}, "vuln.security_check"),
    ("Vulnerability", {"source": "security_check", "type": "waf_bypass"}, "vuln.waf_bypass"),
    ("Vulnerability", {"source": "origin_discovery", "type": "waf_bypass"}, "vuln.waf_bypass"),
    ("Vulnerability", {"source": "nmap_nse"}, "vuln.nmap_nse"),
    ("Vulnerability", {"source": "takeover_scan"}, "vuln.takeover"),
    ("Vulnerability", {"source": "vhost_sni_enum"}, "vuln.vhost_sni"),
    ("Vulnerability", {"source": "cache_poisoning"}, "vuln.cache_poisoning"),
    ("Vulnerability", {"source": "serialized_scan"}, "vuln.serialized_scan"),
    ("Vulnerability", {"source": "route_exposure", "exposure_kind": "env_file"}, "vuln.route_exposure"),
    ("Vulnerability", {"source": "graphql_scan"}, "vuln.graphql"),
    ("Vulnerability", {"source": "graphql_cop"}, "vuln.graphql"),
    ("Vulnerability", {"source": "ai_surface_recon"}, "vuln.ai_surface"),
    ("Vulnerability", {"source": "shodan"}, "vuln.passive_cve"),
    ("Vulnerability", {"source": "internetdb"}, "vuln.passive_cve"),
    ("Vulnerability", {"source": "osv"}, "vuln.osv"),
    ("Vulnerability", {"source": "urlscan_leak", "type": "leaked_one_time_link"}, "vuln.urlscan"),
    # No kind yet (planned): label + the projected source.
    ("Vulnerability", {"source": "gvm"}, "Vulnerability:gvm"),
    ("Vulnerability", {"source": "garak"}, "Vulnerability:garak"),
    ("Vulnerability", {"source": "origin_discovery", "type": "origin_ip"}, "Vulnerability:origin_discovery"),
    ("Vulnerability", {}, "Vulnerability:"),
    ("JsReconFinding", {"finding_type": "endpoint"}, "js.finding"),
    ("JsReconFinding", {}, "js.finding"),
    ("Secret", {"source": "jsluice"}, "secret"),
    ("Secret", {"source": "urlscan"}, "secret"),
    ("Secret", {}, "secret"),
    ("MalPackageFinding", {"source_tool": "guarddog"}, "malpackage"),
    ("MultiscannerFinding", {"source": "noseyparker"}, "MultiscannerFinding:noseyparker"),
    ("MultiscannerFinding", {"source_type": "gitleaks"}, "MultiscannerFinding:gitleaks"),
    ("MultiscannerFinding", {}, "MultiscannerFinding:trufflehog"),
    ("GithubSecret", {"secret_type": "aws"}, "GithubSecret:github_hunt"),
    ("GithubSensitiveFile", {"path": "config/.env"}, "GithubSensitiveFile:github_hunt"),
]

#: Labels that have a Mute Rules kind today. When GVM, GitHub or the secret
#: multiscanner gain one, this set and the fallback rows above must change
#: together, deliberately.
LABELS_WITH_A_KIND = {"Vulnerability", "JsReconFinding", "Secret", "MalPackageFinding"}


def _finding_kinds():
    return {kid: k for kid, k in CATALOG.kinds.items() if k.get("behaviour", "finding") == "finding"}


@pytest.mark.parametrize("label,props,expected", KIND_ROWS,
                         ids=[f"{r[0]}-{r[2]}" for r in KIND_ROWS])
def test_resolve_kind_per_label(label, props, expected):
    kind = K.resolve_kind(label, props, CATALOG)
    assert kind.id == expected
    assert kind.label == label
    if expected in CATALOG.kinds:
        assert kind.selector is not None and kind.source_expr is None
        assert kind.display == CATALOG.kinds[expected]["label"]
    else:
        assert kind.selector is None
        assert kind.source_expr == K.fallback_source_expr(label)


class TestCatalogGuard:
    def test_every_catalog_finding_kind_has_a_test_row(self):
        covered = {expected for _, _, expected in KIND_ROWS}
        missing = sorted(set(_finding_kinds()) - covered)
        assert not missing, f"catalog kinds with no resolve_kind test row: {missing}"

    def test_labels_with_a_kind_are_exactly_the_expected_set(self):
        labels = {k["graph_label"] for k in _finding_kinds().values()}
        assert labels == LABELS_WITH_A_KIND

    def test_every_muteable_label_but_exploitgvm_has_a_row(self):
        rows = {label for label, _, _ in KIND_ROWS}
        assert rows == set(MUTEABLE_LABELS) - {"ExploitGvm"}

    def test_every_catalog_source_resolves_to_its_own_kind(self):
        for kind_id, entry in _finding_kinds().items():
            for source in entry.get("sources") or []:
                props = {"source": source}
                if kind_id == "vuln.waf_bypass":
                    props["type"] = "waf_bypass"
                resolved = K.resolve_kind(entry["graph_label"], props, CATALOG)
                assert resolved.id == kind_id, (kind_id, source)


def _projected_source_expr(label: str) -> str:
    """The `... AS source` expression of a FINDING_QUERIES entry, over `n`."""
    entry = next(e for e in FINDING_QUERIES if e["label"] == label)
    query = re.sub(r"//[^\n]*", "", entry["query"])
    var = re.search(r"\((\w+):" + label + r"\b", query).group(1)
    end = re.search(r"\bAS\s+source\b(?!\w)", query).start()
    head, depth, i = query[:end], 0, end - 1
    while i >= 0:
        ch = head[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        i -= 1
    expr = head[i + 1:].strip()
    expr = re.sub(r"^RETURN\s+", "", expr)
    expr = re.sub(r"\b" + var + r"\.", "n.", expr)
    return re.sub(r"\s+", " ", expr)


class TestFallbackSource:
    @pytest.mark.parametrize("label", [l for l in MUTEABLE_LABELS if l != "ExploitGvm"])
    def test_fallback_expr_is_the_finding_queries_projection(self, label):
        assert K.fallback_source_expr(label) == _projected_source_expr(label)

    def test_multiscanner_coalesces_like_the_query(self):
        assert K.seed_source("MultiscannerFinding", {"source": None, "source_type": "gitleaks"}) == "gitleaks"
        assert K.seed_source("MultiscannerFinding", {}) == "trufflehog"
        # A pool row carries the projected, already coalesced `source`.
        assert K.seed_source("MultiscannerFinding", {"source": "noseyparker"}) == "noseyparker"

    def test_malpackage_reads_source_tool_or_the_projected_source(self):
        assert K.seed_source("MalPackageFinding", {"source_tool": "guarddog"}) == "guarddog"
        assert K.seed_source("MalPackageFinding", {"source": "guarddog"}) == "guarddog"
        assert K.seed_source("MalPackageFinding", {}) == "osv"

    def test_constant_source_labels_ignore_a_stray_source_property(self):
        assert K.seed_source("GithubSecret", {"source": "something_else"}) == "github_hunt"

    def test_fallback_when_the_catalog_has_no_kind_for_the_label(self):
        kind = K.resolve_kind("Vulnerability", {"source": "nuclei"}, {"kinds": {}})
        assert kind.id == "Vulnerability:nuclei"
        assert kind.selector is None
        assert kind.display == "Vulnerabilities (nuclei)"

    def test_malpackage_fallback_uses_the_projected_source(self):
        kind = K.resolve_kind("MalPackageFinding", {"source": "guarddog"}, {"kinds": {}})
        assert (kind.id, kind.source_value) == ("MalPackageFinding:guarddog", "guarddog")


class TestNotMuteable:
    def test_exploitgvm_is_refused(self):
        with pytest.raises(K.SeedNotMuteable):
            K.resolve_kind("ExploitGvm", {"source": "gvm"}, CATALOG)

    def test_js_file_container_is_refused(self):
        with pytest.raises(K.SeedNotMuteable):
            K.resolve_kind("JsReconFinding", {"finding_type": "js_file"}, CATALOG)

    @pytest.mark.parametrize("label", ["Endpoint", "IP", "CVE", "", "vulnerability"])
    def test_a_label_that_is_not_a_finding_is_refused(self, label):
        with pytest.raises(K.SeedNotMuteable):
            K.resolve_kind(label, {}, CATALOG)

    def test_it_is_a_value_error(self):
        assert issubclass(K.SeedNotMuteable, ValueError)


class TestKindWhere:
    def test_selector_kind_uses_selector_clause_parameters(self):
        where, params = K.kind_where(K.resolve_kind("Vulnerability", {"source": "nuclei"}, CATALOG))
        assert where == "n.`source` IN $sel0"
        assert params == {"sel0": ["nuclei"]}

    def test_two_item_selector_is_anded(self):
        kind = K.resolve_kind("Vulnerability", {"source": "security_check"}, CATALOG)
        where, params = K.kind_where(kind)
        assert where == "n.`source` IN $sel0 AND coalesce(n.`type`, '') <> $sel1"
        assert params == {"sel0": ["security_check"], "sel1": "waf_bypass"}

    def test_empty_selector_is_the_whole_label(self):
        assert K.kind_where(K.resolve_kind("Secret", {}, CATALOG)) == ("true", {})

    def test_fallback_compares_the_coalesced_source_as_a_parameter(self):
        kind = K.resolve_kind("Vulnerability", {"source": "gvm"}, CATALOG)
        where, params = K.kind_where(kind)
        assert where == "coalesce(n.source, '') = $mm_source"
        assert params == {"mm_source": "gvm"}

    def test_fallback_value_never_reaches_the_query_text(self):
        hostile = "x' OR 1=1 //"
        kind = K.resolve_kind("Vulnerability", {"source": hostile}, CATALOG)
        where, params = K.kind_where(kind)
        assert hostile not in where
        assert params["mm_source"] == hostile


class TestMatches:
    def test_selector_kind(self):
        nuclei = K.resolve_kind("Vulnerability", {"source": "nuclei"}, CATALOG)
        assert K.matches(nuclei, {"label": "Vulnerability", "source": "nuclei"})
        assert not K.matches(nuclei, {"label": "Vulnerability", "source": "osv"})
        assert not K.matches(nuclei, {"label": "Secret", "source": "nuclei"})

    def test_not_eq_admits_a_missing_property_like_the_cypher(self):
        checks = K.resolve_kind("Vulnerability", {"source": "security_check"}, CATALOG)
        assert K.matches(checks, {"label": "Vulnerability", "source": "security_check"})
        assert not K.matches(checks, {"label": "Vulnerability", "source": "security_check",
                                      "type": "waf_bypass"})

    def test_eq_and_in_never_admit_a_missing_property(self):
        assert not K.selector_matches([{"prop": "source", "in": ["nuclei"]}], {})
        assert not K.selector_matches([{"prop": "type", "eq": "waf_bypass"}], {"type": None})

    def test_fallback_kind(self):
        gvm = K.resolve_kind("Vulnerability", {"source": "gvm"}, CATALOG)
        assert K.matches(gvm, {"label": "Vulnerability", "source": "gvm"})
        assert not K.matches(gvm, {"label": "Vulnerability", "source": "nuclei"})

    def test_kind_is_immutable(self):
        kind = K.resolve_kind("Secret", {}, CATALOG)
        with pytest.raises(Exception):
            kind.id = "other"
