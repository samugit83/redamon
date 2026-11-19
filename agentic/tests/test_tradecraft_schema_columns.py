"""Every table and column name the agent uses exists in ``webapp/prisma/schema.prisma``
(D-31), and every INSERT the agent makes can name every column that has no default.

A rename in the schema then fails here, not at the first ingestion on a real install.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import schema_columns as sc  # noqa: E402

SCHEMA = Path(__file__).resolve().parents[2] / "webapp" / "prisma" / "schema.prisma"
APPLY_SCRIPT = Path(__file__).resolve().parents[2] / "webapp" / "scripts" / "apply-tradecraft-search.mjs"

_MODEL = re.compile(r"^model\s+(\w+)\s*\{(.*?)^\}", re.MULTILINE | re.DOTALL)
_FIELD = re.compile(r'^(\w+)\s+(Unsupported\("[^"]*"\)\??|\w+(?:\[\])?\??)(.*)$')


def _strip_comment(line: str) -> str:
    quoted = False
    for i, c in enumerate(line):
        if c == '"':
            quoted = not quoted
        elif not quoted and line.startswith("//", i):
            return line[:i]
    return line


def parse_schema(text: str) -> dict[str, dict]:
    """table -> {column: {"type", "attrs"}} for scalar columns (relation fields dropped)."""
    raw: dict[str, tuple[str, list[tuple[str, str, str]]]] = {}
    for name, body in _MODEL.findall(text):
        table = name
        fields = []
        for line in body.splitlines():
            line = _strip_comment(line).strip()
            if not line:
                continue
            if line.startswith("@@"):
                m = re.match(r'@@map\("([^"]+)"\)', line)
                if m:
                    table = m.group(1)
                continue
            m = _FIELD.match(line)
            assert m, f"cannot read a field of {name}: {line}"
            fields.append(m.groups())
        raw[name] = (table, fields)
    models = set(raw)
    out: dict[str, dict] = {}
    for _name, (table, fields) in raw.items():
        columns = {}
        for field, ftype, attrs in fields:
            if ftype.rstrip("?").removesuffix("[]") in models:
                continue
            m = re.search(r'@map\("([^"]+)"\)', attrs)
            columns[m.group(1) if m else field] = {"type": ftype, "attrs": attrs}
        out[table] = columns
    return out


@pytest.fixture(scope="module")
def schema() -> dict[str, dict]:
    if not SCHEMA.exists():
        pytest.skip("webapp/prisma/schema.prisma is not mounted next to agentic/")
    return parse_schema(SCHEMA.read_text(encoding="utf-8"))


def test_every_table_exists(schema):
    for table in sc.COLUMNS:
        assert table in schema, table


def test_every_column_exists_on_its_table(schema):
    missing = {
        table: sorted(set(columns) - set(schema[table]))
        for table, columns in sc.COLUMNS.items()
        if set(columns) - set(schema[table])
    }
    assert missing == {}


def test_secret_columns_stay_out_of_the_tuple_the_agent_selects(schema):
    """The agent builds SQL from RESOURCES: a secret column there would read the owner's logins
    outside the catalog's rules (TD-9)."""
    for column in sc.RESOURCE_SECRET_COLUMNS:
        assert column in schema[sc.TABLE_RESOURCES], column
        assert column not in sc.RESOURCES, column


def test_inserts_name_every_column_without_a_default(schema):
    for table in sc.AGENT_INSERTS:
        required = {
            col for col, f in schema[table].items()
            if not f["type"].endswith("?") and "@default" not in f["attrs"] and "@updatedAt" not in f["attrs"]
        }
        assert required - set(sc.COLUMNS[table]) == set(), table


def test_agent_insert_tables_default_updated_at_in_the_database(schema):
    for table in sc.AGENT_INSERTS:
        updated = schema[table].get("updated_at")
        if updated is not None:
            assert "@default(now())" in updated["attrs"], table


def test_search_vectors_are_declared_and_filled_by_the_trigger(schema):
    for table in sc.SEARCH_VECTOR_FUNCTIONS:
        assert schema[table]["search_vector"]["type"] == 'Unsupported("tsvector")?', table
    if not APPLY_SCRIPT.exists():
        pytest.skip("webapp/scripts is not mounted next to agentic/")
    script = APPLY_SCRIPT.read_text(encoding="utf-8")
    assert sc.SEARCH_VECTOR_FILLED_BY == "trigger"
    for function in sc.SEARCH_VECTOR_FUNCTIONS.values():
        assert f"'{function}'" in script, function
    assert f"TEXT_SEARCH_CONFIG = '{sc.TEXT_SEARCH_CONFIG}'" in script
    assert f"VECTOR_INPUT_MAX_CHARS = {sc.SEARCH_VECTOR_INPUT_MAX_CHARS}" in script


def test_the_parser_drops_relations_and_reads_maps():
    parsed = parse_schema(
        'model A {\n  id String @id\n  bId String @map("b_id")\n  b B @relation(fields: [bId], references: [id])\n'
        '  v Unsupported("tsvector")? @map("v_col") // note\n  @@map("a_table")\n}\n'
        'model B {\n  id String @id\n  as A[]\n}\n'
    )
    assert set(parsed["a_table"]) == {"id", "b_id", "v_col"}
    assert set(parsed["B"]) == {"id"}
