"""Two projects scanning the same target must not collide (Phase 0b, G1/G2).

THE DEFECT, IN ONE SENTENCE
Per-project finding labels were unique on `id` ALONE, so one id could exist once
in the entire database. Two projects scanning the same host, the same GitHub
organisation or the same package therefore collided, and the collision went one
of two ways, both of them silent:

  * an id-only MERGE took the OTHER project's node over and re-pointed it, so
    one project's scan mutated another project's graph;
  * a tenant-keyed MERGE hit the global constraint, and the writers catch and
    swallow that exception, so the second project's finding was simply LOST.

It is also why project import deleted the SOURCE project's graph: with globally
unique ids, importing a backup of a project that still existed would collide
with it, so the source had to go. An operator importing a backup lost the
project they took it from.

WHY THERE IS NO DOWNTIME
`(id)` unique -> `(id, user_id, project_id)` unique is a RELAXATION: anything
valid under the old constraint is valid under the new one. So the swap needs no
data migration and no maintenance window. What does need migrating is data that
is already wrong (duplicate nuclei findings), and that lives in the one-shot
script, which is dry-run by default.

THE OTHER HALF OF THE SAME CHANGE
Relaxing the constraint means an id is no longer globally unique, so every
`MATCH (v:Vulnerability {id: $id})` that was safe before can now match another
project's node. Both halves are checked here, because shipping one without the
other is worse than shipping neither.

Run: python -m pytest tests/test_graph_identity.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.schema import CONSTRAINTS, DROP_LEGACY_CONSTRAINTS  # noqa: E402

#: Labels whose nodes belong to ONE project. Anything here must be unique per
#: tenant, never globally.
PER_PROJECT_FINDING_LABELS = (
    "Vulnerability", "ExploitGvm", "Secret", "JsReconFinding", "GithubHunt",
    "GithubRepository", "GithubPath", "GithubSecret", "GithubSensitiveFile",
    "SbomDocument", "UserInput", "MultiscannerFinding",
)

WRITER_FILES = [
    "graph_db/mixins/gvm_mixin.py",
    "graph_db/mixins/osint_mixin.py",
    "graph_db/mixins/secret_mixin.py",
    "graph_db/mixins/supply_chain_mixin.py",
    "graph_db/mixins/graphql_mixin.py",
    "graph_db/mixins/recon/vuln_mixin.py",
    "graph_db/mixins/recon/takeover_mixin.py",
    "graph_db/mixins/recon/vhost_sni_mixin.py",
    "graph_db/mixins/recon/js_recon_mixin.py",
    "graph_db/mixins/recon/resource_mixin.py",
    "graph_db/mixins/recon/user_input_mixin.py",
    "graph_db/mixins/recon/ai_surface_recon_mixin.py",
    "scanners/ai_attack_surface_scan/normalizer.py",
]


def source(relative: str) -> str:
    with open(os.path.join(_REPO, relative)) as handle:
        return handle.read()


def code_only(relative: str) -> str:
    """The file with comments and docstrings removed.

    Several of these tests assert "this pattern does not appear", and the
    comments explaining WHY it must not appear necessarily contain it. Reading
    prose as code made the tests fail on their own documentation.
    """
    import io
    import tokenize

    text = source(relative)
    out = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok_type, tok_str, _, _, _ in tokens:
            if tok_type in (tokenize.COMMENT, tokenize.STRING):
                continue
            out.append(tok_str)
    except tokenize.TokenError:
        return text
    return " ".join(out)


class TestConstraintsAreTenantScoped(unittest.TestCase):
    def test_no_per_project_label_is_unique_on_id_alone(self):
        for statement in CONSTRAINTS:
            for label in PER_PROJECT_FINDING_LABELS:
                if f":{label})" not in statement:
                    continue
                with self.subTest(label=label, statement=statement[:70]):
                    self.assertIn("user_id", statement)
                    self.assertIn("project_id", statement)

    def test_every_per_project_finding_label_has_a_constraint(self):
        """A label with none is unconstrained, which is worse than either."""
        for label in PER_PROJECT_FINDING_LABELS:
            with self.subTest(label=label):
                self.assertTrue(
                    any(f":{label})" in s for s in CONSTRAINTS),
                    f"{label} has no uniqueness constraint")

    def test_the_old_global_constraints_are_dropped_by_name(self):
        """A same-name CREATE ... IF NOT EXISTS against a database that still
        has the old constraint is a SILENT no-op, so the new ones had to be
        renamed and the old ones dropped explicitly."""
        for name in ("vulnerability_unique", "exploitgvm_unique",
                     "githubsecret_unique", "githubsensitivefile_unique",
                     "jsreconfinding_unique", "secret_unique",
                     "sbomdoc_unique", "userinput_unique"):
            with self.subTest(name=name):
                self.assertIn(f"DROP CONSTRAINT {name} IF EXISTS",
                              DROP_LEGACY_CONSTRAINTS)

    def test_a_renamed_constraint_is_not_also_recreated_under_its_old_name(self):
        """The rename is the whole mechanism: a same-name CREATE would be a
        silent no-op and the old GLOBAL constraint would quietly survive."""
        created = {
            re.search(r"CREATE CONSTRAINT (\w+)", s).group(1)
            for s in CONSTRAINTS if "CREATE CONSTRAINT" in s
        }
        for name in ("vulnerability_unique", "exploitgvm_unique",
                     "githubsecret_unique", "githubsensitivefile_unique",
                     "jsreconfinding_unique", "secret_unique",
                     "sbomdoc_unique", "userinput_unique", "exploit_unique"):
            with self.subTest(name=name):
                self.assertNotIn(name, created)

    def test_the_shared_reference_nodes_stay_globally_unique(self):
        """CVE, MitreData and Capec are shared by every project ON PURPOSE.
        Making them per-tenant would give each project its own copy of NVD."""
        for label, prop in (("CVE", "id"), ("MitreData", "id"),
                            ("Capec", "capec_id")):
            statement = next(s for s in CONSTRAINTS if f":{label})" in s)
            with self.subTest(label=label):
                self.assertNotIn("user_id", statement)
                self.assertIn(prop, statement)

    def test_the_unused_exploit_constraint_is_gone(self):
        """K25: the `Exploit` label is constrained but nothing writes one."""
        self.assertIn("DROP CONSTRAINT exploit_unique IF EXISTS",
                      DROP_LEGACY_CONSTRAINTS)
        self.assertFalse(any("(e:Exploit)" in s for s in CONSTRAINTS))


class TestWritersMergeOnTheTriple(unittest.TestCase):
    """A constraint does not stop a writer keying on `id` alone; it just turns
    the collision into an exception the writer then swallows."""

    ID_ONLY_MERGE = re.compile(
        r"MERGE \(\w+:(%s) \{id: \$\w+\}\)" % "|".join(PER_PROJECT_FINDING_LABELS))

    def test_no_writer_merges_a_finding_on_id_alone(self):
        for path in WRITER_FILES:
            found = self.ID_ONLY_MERGE.findall(source(path))
            with self.subTest(file=path):
                self.assertEqual(found, [])

    def test_the_writers_still_merge_those_labels(self):
        """Guards the opposite mistake: deleting the MERGE rather than keying it."""
        joined = " ".join(source(path) for path in WRITER_FILES)
        for label in ("Vulnerability", "GithubSecret", "JsReconFinding"):
            with self.subTest(label=label):
                self.assertIn(f":{label} {{id:", joined)


class TestReadsAreTenantScopedToo(unittest.TestCase):
    """The half that is easy to forget.

    Once an id is no longer globally unique, a MATCH that only knows the id can
    match ANOTHER project's node and link it into this one's graph. Shipping the
    relaxed constraint without this would turn a swallowed error into silent
    cross-project corruption, which is strictly worse.
    """

    ID_ONLY_MATCH = re.compile(
        r"MATCH \(\w+:(%s) \{id: \$\w+\}\)" % "|".join(PER_PROJECT_FINDING_LABELS))

    def test_no_writer_matches_a_finding_on_id_alone(self):
        for path in WRITER_FILES:
            found = self.ID_ONLY_MATCH.findall(source(path))
            with self.subTest(file=path):
                self.assertEqual(found, [])

    def test_the_partial_recon_modules_are_scoped_as_well(self):
        for path in ("recon/partial_recon_modules/web_crawling.py",
                     "recon/partial_recon_modules/port_scanning.py",
                     "recon/partial_recon_modules/parameter_discovery.py",
                     "recon/partial_recon_modules/js_analysis.py",
                     "recon/partial_recon_modules/http_probing.py"):
            found = self.ID_ONLY_MATCH.findall(source(path))
            with self.subTest(file=path):
                self.assertEqual(found, [])


class TestNucleiIdsAreStable(unittest.TestCase):
    """G1. The one place the ids themselves had to change.

    The old id ended in `hash(matched_at) % 10000`. Python's builtin hash() is
    randomised per process unless PYTHONHASHSEED is pinned, and it is pinned in
    exactly one Dockerfile, which is not this one. So the same finding got a
    different id on every scan: a duplicate node each time, while the operator's
    mute, their verdict and the AI's cached review stayed behind on a node
    nothing pointed at any more.
    """

    SRC = source("graph_db/mixins/recon/vuln_mixin.py")
    CODE = code_only("graph_db/mixins/recon/vuln_mixin.py")

    def test_the_id_does_not_use_the_randomised_builtin_hash(self):
        self.assertNotIn("hash ( matched_at )", self.CODE)

    def test_it_is_derived_from_the_natural_key(self):
        self.assertIn('f"{template_id}|{target_host}|{fuzzing_param}|{matched_at}"',
                      self.SRC)

    def test_the_same_finding_hashes_the_same_way_twice(self):
        import hashlib

        def build(template, host, param, matched):
            return "nuclei-" + hashlib.sha1(
                f"{template}|{host}|{param}|{matched}".encode("utf-8", "replace")
            ).hexdigest()[:16]

        first = build("cve-2021-41773", "h1", "", "http://h1/x")
        second = build("cve-2021-41773", "h1", "", "http://h1/x")
        self.assertEqual(first, second)
        self.assertNotEqual(first, build("cve-2021-41773", "h2", "", "http://h1/x"))

    def test_no_graph_writer_still_builds_an_id_from_builtin_hash(self):
        """The same trap in any other writer. Checked against CODE, not prose:
        the comments explaining the trap necessarily name it."""
        import glob
        offenders = []
        for path in sorted(glob.glob(os.path.join(_REPO, "graph_db", "**", "*.py"),
                                     recursive=True)):
            relative = os.path.relpath(path, _REPO)
            if re.search(r"(?<![\w.])hash \(", code_only(relative)):
                offenders.append(relative)
        self.assertEqual(offenders, [])


class TestImportKeepsTheSourceProject(unittest.TestCase):
    """X3. Importing a backup used to delete the project it came from."""

    SRC = source("webapp/src/app/api/projects/import/route.ts")

    def test_the_source_project_graph_is_not_cleared(self):
        self.assertNotIn("clearProjectGraph(session, _oldProjectId)", self.SRC)

    def test_the_new_project_is_still_cleared_first(self):
        """That one is a safety measure and must stay."""
        self.assertIn("clearProjectGraph(session, newProject.id)", self.SRC)


class TestTheMigrationRefusesToRunUnsafely(unittest.TestCase):
    SRC = source("tooling/scripts/triage_graph_migrate.py")

    def test_it_is_a_dry_run_unless_asked(self):
        self.assertIn('"--apply"', self.SRC)
        self.assertIn("DRY RUN", self.SRC)

    def test_it_checks_that_the_writers_are_down(self):
        """A scan running through the merge would re-create what it just
        collapsed."""
        self.assertIn("services_are_up", self.SRC)
        for service in ("agent", "webapp", "recon-orchestrator"):
            with self.subTest(service=service):
                self.assertIn(f'"{service}"', self.SRC)

    def test_a_service_that_answers_with_an_error_still_counts_as_running(self):
        self.assertIn("except urllib.error.HTTPError", self.SRC)

    def test_it_keeps_the_node_a_person_touched(self):
        self.assertIn("muted", self.SRC)
        self.assertIn("triage_source", self.SRC)
        self.assertIn("CARRIED_PROPS", self.SRC)


if __name__ == "__main__":
    unittest.main()
