from pathlib import Path

from graph_seen_inventory import (
    GLOBAL_NODE_EXEMPTIONS,
    SeenViolation,
    find_seen_violations,
    production_writer_files,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "graph_seen_inventory"
    / "unstamped_writer.py"
)


def _write_subject(tmp_path, source):
    path = tmp_path / "inventory_subject.py"
    path.write_text(source, encoding="utf-8")
    return path


def test_inventory_reports_the_deliberately_unstamped_writer():
    violations = find_seen_violations([FIXTURE])

    assert len(violations) == 1
    violation = violations[0]
    assert isinstance(violation, SeenViolation)
    assert violation.path == FIXTURE
    assert violation.line == 2
    assert violation.label == "Endpoint"
    assert violation.alias == "e"
    assert "seen stamping" in violation.reason


def test_inventory_surfaces_an_unresolved_run_query(tmp_path):
    path = _write_subject(
        tmp_path,
        """
query = build_query("MERGE (e:Endpoint {id: $id})")
session.run(query, id="fixture")
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    violation = violations[0]
    assert violation.path == path
    assert violation.line == 3
    assert violation.label == "<unresolved>"
    assert violation.alias == "<unresolved>"
    assert "cannot be statically resolved" in violation.reason


def test_inventory_surfaces_an_unresolved_f_string_clause(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
session.run(
    f"{build_clause()} MATCH (e:Endpoint) RETURN e"
)
''',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unresolved>"


def test_inventory_surfaces_an_unresolved_f_string_inside_a_comment(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
session.run(
    f"// {build_clause()}\\nMATCH (e:Endpoint) RETURN e"
)
''',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unresolved>"


def test_inventory_ignores_match_only_reads(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MATCH (e:Endpoint {id: $id}) RETURN e", id="fixture")\n',
    )

    assert find_seen_violations([path]) == []


def test_inventory_ignores_match_only_comparison_projections(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH (e:Endpoint) RETURN 1, e.status = 'up'"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_inventory_ignores_relationship_only_writes(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH (e:Endpoint), (p:Parameter) MERGE (e)-[:HAS_PARAMETER]->(p)"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_inventory_detects_a_write_to_a_later_match_alias(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH (d:Domain), (e:Endpoint) SET e.status = 'live'"
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "e"


def test_inventory_detects_whole_map_node_replacement(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH (e:Endpoint) SET e = $props",
    props={"status": "live"},
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "e"


def test_inventory_detects_a_node_later_in_a_merge_path(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MERGE (c:CVE {id: $cve})-[:MAPS_TO]->(e:Endpoint {id: $id})"
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "e"


def test_catalogue_exemption_does_not_hide_a_second_project_label(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MERGE (e:CVE:Endpoint {id: $id})", id="fixture")\n',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "e"


def test_inventory_detects_unlabeled_node_creation(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MERGE (e {id: $id})", id="fixture")\n',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unlabeled>"
    assert violations[0].alias == "e"


def test_inventory_detects_unlabeled_create_without_properties(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("CREATE (e)")\n',
    )

    violations = find_seen_violations([path])

    assert violations == [
        SeenViolation(
            path=path,
            line=1,
            label="<unlabeled>",
            alias="e",
            reason=(
                "missing seen stamping: first_seen, first_seen_job_id, "
                "last_seen, last_seen_job_id; missing recon job params"
            ),
        )
    ]


def test_inventory_detects_unlabeled_match_property_mutation(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MATCH (e) SET e.status = \'live\'")\n',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].line == 1
    assert violations[0].label == "<unlabeled>"
    assert violations[0].alias == "e"


def test_inventory_tracks_simple_with_alias_rebinding(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH (e:Endpoint) WITH e AS node SET node.status = 'live'"
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].line == 2
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "node"


def test_relationship_alias_rebinding_remains_relationship_only(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH r AS rel SET rel.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_relationship_identity_survives_with_star(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH * SET r.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_relationship_identity_survives_with_distinct(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH DISTINCT r SET r.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_relationship_identity_survives_with_order_by(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH r ORDER BY r.status SET r.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_relationship_identity_survives_with_limit(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH r LIMIT 1 SET r.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_relationship_identity_survives_with_skip(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    "MATCH ()-[r:REL]->() WITH r SKIP 1 SET r.status = 1"
)
""",
    )

    assert find_seen_violations([path]) == []


def test_node_alias_reused_after_with_scope_reset_is_inventoried(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MATCH ()-[e:REL]->()
    WITH count(*) AS n
    MATCH (e)
    SET e.status = 1
    '''
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unlabeled>"
    assert violations[0].alias == "e"


def test_node_alias_reused_as_relationship_after_with_is_relationship_only(
    tmp_path,
):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MATCH (e:Endpoint)
    WITH count(*) AS n
    MATCH ()-[e:REL]->()
    SET e.status = 1
    '''
)
""",
    )

    assert find_seen_violations([path]) == []


def test_set_targets_are_classified_at_their_own_scope_position(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MATCH (e)
    SET e.status = 'node'
    WITH count(*) AS n
    MATCH ()-[e:REL]->()
    SET e.status = 'relationship'
    '''
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unlabeled>"
    assert violations[0].alias == "e"


def test_inventory_detects_node_label_mutation(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MATCH (e) SET e:Endpoint")\n',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].alias == "e"


def test_inventory_detects_lowercase_node_write_keywords(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("merge (e:Endpoint {id: $id})", id="fixture")\n',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"


def test_inventory_rejects_on_create_only_seen_stamping(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MERGE (e:Endpoint {id: $id})
    ON CREATE SET
        e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
        e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
        e.last_seen = datetime($recon_job_started_at),
        e.last_seen_job_id = $recon_job_id
    ''',
    **self._recon_job_params(),
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert "missing seen stamping" in violations[0].reason


def test_inventory_rejects_stamped_alias_reused_unstamped_after_with(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MERGE (e:Endpoint {id: $first_id})
    SET e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
        e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
        e.last_seen = datetime($recon_job_started_at),
        e.last_seen_job_id = $recon_job_id
    WITH count(e) AS written
    MERGE (e:Endpoint {id: $second_id})
    ''',
    **self._recon_job_params(),
)
""",
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert "reused" in violations[0].reason


def test_global_catalogue_exemption_is_applied_by_label(tmp_path):
    path = _write_subject(
        tmp_path,
        'session.run("MERGE (c:CWE {id: $id})", id="CWE-79")\n',
    )

    assert GLOBAL_NODE_EXEMPTIONS == {
        "CVE": "globally shared reference catalogue",
        "CWE": "globally shared reference catalogue",
        "MitreData": "globally shared reference catalogue",
        "Capec": "globally shared reference catalogue",
    }
    assert find_seen_violations([path]) == []


def test_inventory_resolves_name_bound_f_string_queries(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
label_suffix = "ignored"
query = f"""
MERGE (e:Endpoint {{id: $id}})
SET e.first_seen = coalesce(e.first_seen, datetime($recon_job_started_at)),
    e.first_seen_job_id = coalesce(e.first_seen_job_id, $recon_job_id),
    e.last_seen = datetime($recon_job_started_at),
    e.last_seen_job_id = $recon_job_id
// {label_suffix}
"""
session.run(query=query, **self._recon_job_params())
''',
    )

    assert find_seen_violations([path]) == []


def test_name_bound_queries_are_resolved_within_their_lexical_scope(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
def read(session):
    query = "MATCH (e:Endpoint) RETURN e"
    session.run(query)


def write(session):
    query = "MERGE (e:Endpoint {id: $id})"
    session.run(query, id="fixture")
''',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].line == 9
    assert violations[0].label == "Endpoint"


def test_branch_dependent_name_bound_queries_are_unresolved(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
if flag:
    query = "MERGE (e:Endpoint {id: $id})"
else:
    query = "MATCH (e:Endpoint) RETURN e"
session.run(query)
''',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "<unresolved>"
    assert "cannot be statically resolved" in violations[0].reason


def test_augmented_query_assignment_is_unresolved(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
query = "MATCH (e:Endpoint) RETURN e"
query += build_clause()
session.run(query)
''',
    )

    violations = find_seen_violations([path])

    assert violations == [
        SeenViolation(
            path=path,
            line=4,
            label="<unresolved>",
            alias="<unresolved>",
            reason=(
                "run query cannot be statically resolved; "
                "node-writing status and seen stamping cannot be verified"
            ),
        )
    ]


def test_method_name_resolution_skips_the_class_namespace(tmp_path):
    path = _write_subject(
        tmp_path,
        '''
query = "MERGE (e:Endpoint {id: $id})"


class Writer:
    query = "MATCH (e:Endpoint) RETURN e"

    def write(self, session):
        session.run(query, id="fixture")
''',
    )

    violations = find_seen_violations([path])

    assert len(violations) == 1
    assert violations[0].label == "Endpoint"
    assert violations[0].line == 9


def test_relationship_only_query_ignores_node_shapes_in_string_literals(tmp_path):
    path = _write_subject(
        tmp_path,
        """
session.run(
    '''
    MATCH (d:Domain), (e:Endpoint)
    MERGE (d)-[r:MENTIONS {sample: '(:Vulnerability)'}]->(e)
    // MERGE (:Parameter)
    '''
)
""",
    )

    assert find_seen_violations([path]) == []


def test_complete_production_writer_inventory_has_no_violations():
    files = production_writer_files(ROOT)

    assert ROOT / "graph_db" / "mixins" / "gvm_mixin.py" not in files
    assert ROOT / "graph_db" / "mixins" / "secret_mixin.py" not in files
    assert not find_seen_violations(files)
