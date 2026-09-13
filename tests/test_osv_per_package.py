"""One OSV advisory node per PACKAGE, and the fields that make it actionable.

WHY THE SPLIT
An advisory was keyed on its id alone, so one node hung off up to ELEVEN
packages in the dev graph. Nothing true could then be said about it:

- its reachability was whichever package happened to be looked at first;
- muting it muted the advisory on every package at once;
- one remediation stood for eleven different upgrades.

Keyed per package instead, each is its own finding with its own facts, and the
board's grouping puts them back together DELIBERATELY under `pkg:<purl>`, where
one upgrade really does fix all of them.

WHY THE FIELDS MATTER
Three were missing, and each one silently disabled something downstream:

- `aliases` (K3): OSV ids are GHSA or PYSEC, so with no CVE alias the whole CVE
  intelligence layer (CISA KEV, EPSS, public proof of concept) was unreachable
  for 94% of the findings in a real graph.
- `fixed_version`: without it a fix item can only say "upgrade this package"
  instead of "upgrade to 4.17.21".
- the name and description: the mixin read `title`/`detail`, which the runner
  never emitted, so every advisory reached the graph named after its own id
  with no description at all.

Run: python -m pytest tests/test_osv_per_package.py
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (_REPO, os.path.join(_REPO, "scanners")):
    if path not in sys.path:
        sys.path.insert(0, path)

from supply_chain_common.osv_runner import (  # noqa: E402
    fixed_version_for_vuln,
    parse_osv_json,
)


def source(relative: str) -> str:
    with open(os.path.join(_REPO, relative)) as handle:
        return handle.read()


class TestOneNodePerPackage(unittest.TestCase):
    SRC = source("graph_db/mixins/supply_chain_mixin.py")

    def test_the_id_carries_the_package_as_well_as_the_advisory(self):
        self.assertIn('vuln_id=f"osv:{purl}:{advisory}"', self.SRC)

    def test_the_merge_keys_on_that_id(self):
        self.assertIn("MERGE (v:Vulnerability {id: $vuln_id, user_id: $uid,", self.SRC)

    def test_the_advisory_id_is_still_stored_so_it_can_be_reported(self):
        self.assertIn("v.advisory_id = $advisory", self.SRC)

    def test_two_packages_with_one_advisory_get_two_different_ids(self):
        first = f"osv:{'pkg:npm/a@1.0.0'}:{'GHSA-xxxx'}"
        second = f"osv:{'pkg:npm/b@2.0.0'}:{'GHSA-xxxx'}"
        self.assertNotEqual(first, second)

    def test_the_board_groups_them_back_together_by_package(self):
        """The split is only safe because grouping puts them back deliberately."""
        sys.path.insert(0, os.path.join(_REPO, "agentic"))
        from cypherfix_triage.grouping import group_key
        one = {"id": "osv:pkg:npm/lodash:GHSA-1", "source": "osv",
               "package_purl": "pkg:npm/lodash"}
        other = {"id": "osv:pkg:npm/lodash:PYSEC-2", "source": "osv",
                 "package_purl": "pkg:npm/lodash"}
        self.assertEqual(group_key(one), group_key(other))


class TestFixedVersion(unittest.TestCase):
    def test_it_reads_the_osv_range_events(self):
        vuln = {"affected": [{"package": {"name": "lodash"},
                              "ranges": [{"events": [{"introduced": "0"},
                                                     {"fixed": "4.17.21"}]}]}]}
        self.assertEqual(fixed_version_for_vuln(vuln, "lodash"), "4.17.21")

    def test_it_ignores_a_different_package_in_the_same_advisory(self):
        """One advisory can cover several packages with different fixes."""
        vuln = {"affected": [
            {"package": {"name": "other"},
             "ranges": [{"events": [{"fixed": "1.0.0"}]}]},
            {"package": {"name": "lodash"},
             "ranges": [{"events": [{"fixed": "4.17.21"}]}]},
        ]}
        self.assertEqual(fixed_version_for_vuln(vuln, "lodash"), "4.17.21")

    def test_an_advisory_with_no_fix_yields_empty_not_a_wrong_version(self):
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        self.assertEqual(fixed_version_for_vuln(vuln, "lodash"), "")

    def test_it_never_raises_on_a_malformed_advisory(self):
        for vuln in (None, {}, {"affected": None}, {"affected": ["junk"]},
                     {"affected": [{"ranges": "not a list"}]},
                     {"affected": [{"ranges": [{"events": [None, 7]}]}]}):
            with self.subTest(vuln=vuln):
                self.assertEqual(fixed_version_for_vuln(vuln), "")

    def test_the_lowest_fix_wins(self):
        """The smallest upgrade that resolves it."""
        vuln = {"affected": [{"ranges": [
            {"events": [{"fixed": "4.17.21"}]},
            {"events": [{"fixed": "3.0.0"}]},
        ]}]}
        self.assertEqual(fixed_version_for_vuln(vuln), "3.0.0")


class TestTheRunnerEmitsWhatTheMixinReads(unittest.TestCase):
    """The exact class of bug this file exists for: the mixin read `title` and
    `detail`, which nothing ever wrote."""

    def _parse(self):
        return parse_osv_json({
            "results": [{"packages": [{
                "package": {"name": "lodash", "version": "4.17.20",
                            "ecosystem": "npm"},
                "vulnerabilities": [{
                    "id": "GHSA-test-0001",
                    "aliases": ["CVE-2021-23337", "not-a-cve"],
                    "summary": "Command injection in lodash",
                    "details": "The template function allows...",
                    "affected": [{"package": {"name": "lodash"},
                                  "ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
                }],
            }]}]
        })

    def test_a_vulnerable_record_carries_every_field_the_mixin_reads(self):
        record = self._parse()["vulnerable"][0]
        for field in ("purl", "name", "version", "ecosystem", "advisory_id",
                      "aliases", "summary", "summary_detail", "severity",
                      "cvss_vector", "fixed_version"):
            with self.subTest(field=field):
                self.assertIn(field, record)

    def test_the_fixed_version_reaches_the_record(self):
        self.assertEqual(self._parse()["vulnerable"][0]["fixed_version"], "4.17.21")

    def test_the_description_reaches_the_record(self):
        self.assertEqual(self._parse()["vulnerable"][0]["summary_detail"],
                         "The template function allows...")

    def test_the_mixin_reads_the_names_the_runner_writes(self):
        mixin = source("graph_db/mixins/supply_chain_mixin.py")
        self.assertIn('vul.get("summary")', mixin)
        self.assertIn('vul.get("summary_detail")', mixin)


class TestCveAliases(unittest.TestCase):
    """K3. Without these, CVE intelligence is unreachable for an OSV finding."""

    def _aliases(self, vul):
        sys.path.insert(0, os.path.join(_REPO, "graph_db", "mixins"))
        from graph_db.mixins.supply_chain_mixin import _cve_aliases
        return _cve_aliases(vul)

    def test_only_real_cve_ids_survive(self):
        self.assertEqual(
            self._aliases({"aliases": ["CVE-2021-23337", "GHSA-x", "PYSEC-1",
                                       "", None, "CVE-BAD"]}),
            ["CVE-2021-23337"])

    def test_they_are_normalised_and_deduplicated(self):
        self.assertEqual(
            self._aliases({"aliases": ["cve-2021-23337", "CVE-2021-23337"]}),
            ["CVE-2021-23337"])

    def test_the_order_is_stable(self):
        ids = ["CVE-2022-20002", "CVE-2021-10001"]
        self.assertEqual(self._aliases({"aliases": ids}),
                         self._aliases({"aliases": ids[::-1]}))

    def test_an_advisory_with_no_alias_yields_an_empty_list(self):
        self.assertEqual(self._aliases({}), [])

    def test_an_injected_alias_cannot_reach_a_cve_lookup(self):
        """These ids are sent to vulnx, so this is the same boundary as
        cypherfix_triage/intel.py, enforced a second time at the source."""
        self.assertEqual(
            self._aliases({"aliases": ["CVE-2021-23337; rm -rf /",
                                       "$(whoami)", "../../etc/passwd"]}),
            [])


if __name__ == "__main__":
    unittest.main()
