"""The Tradecraft 2.0 end-to-end library (T10.2): build, snapshot and restore, with no stack.

The snapshot's tables against the schema, its queries run on an in-memory SQLite library of
two accounts (the owner's rows only, the live generation only, no claim, no token), the
restore script's one transaction and its sequences, the stamp's ingestion-code check, the
psql stream, library.yaml against scenarios.yaml and the presets, and the build against a
scripted webapp. No Docker, no network, no model, no real clock.

Run (the root-agent section's image):
  docker run --rm -v "$PWD:/repo" -w /repo -e PYTHONPATH=/repo --entrypoint python \
    redamon-agent:latest -m pytest tests/test_tradecraft_matrix_library.py
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tooling.scripts.tradecraft_e2e import library, report, runner  # noqa: E402

SCN = runner.load_scenarios()
LIB = library.load_library()
SCHEMA_TEXT = library.SCHEMA.read_text(encoding="utf-8")
OWNER = "cowner0000000000000000001"
OTHER = "cother0000000000000000002"
SERIAL = {"tradecraft_page_ids", "tradecraft_entries", "tradecraft_sections", "tradecraft_tree_nodes"}

# The columns a snapshot reads, per table: enough of each to hold the rules (the real lists
# come from the database's catalog at snapshot time).
COLUMNS = {
    "user_tradecraft_resources": ["id", "user_id", "slug", "url", "generation", "active_job_id", "github_token_override",
                                  "credentials", "has_login"],
    "tradecraft_page_ids": ["id", "resource_id", "url"],
    "tradecraft_entries": ["id", "user_id", "resource_id", "generation", "page_id", "url", "title", "stored_text",
                           "search_vector"],
    "tradecraft_sections": ["id", "entry_id", "resource_id", "user_id", "generation", "ord", "heading", "text",
                            "search_vector"],
    "tradecraft_tree_nodes": ["id", "resource_id", "user_id", "generation", "path", "label"],
    "tradecraft_curations": ["id", "resource_id", "url", "blocked", "created_by_id"],
    "tradecraft_project_choices": ["project_id", "resource_id", "created_by_id"],
    "tradecraft_user_settings": ["id", "user_id", "v2_enabled", "search"],
}


def _models(schema: str) -> dict:
    """The Prisma models' bodies by their table name."""
    out = {}
    for body in re.findall(r"^model \w+ \{\n(.*?)^\}", schema, re.S | re.M):
        m = re.search(r'@@map\("([a-z0-9_]+)"\)', body)
        if m:
            out[m.group(1)] = body
    return out


# --------------------------------------------------------------------------------------
# What a snapshot holds
# --------------------------------------------------------------------------------------

def test_every_tradecraft_table_but_the_jobs_is_in_the_snapshot():
    tables = library.tradecraft_tables(SCHEMA_TEXT)
    assert "tradecraft_ingestion_jobs" in tables and "user_tradecraft_resources" in tables
    assert library.uncovered_tables(SCHEMA_TEXT) == []
    assert set(library.NOT_SNAPSHOT) == {"tradecraft_ingestion_jobs"}
    assert {t.name for t in library.TABLES} == set(tables) - {"tradecraft_ingestion_jobs"}
    # A new tradecraft table fails it until the snapshot list names it.
    grown = SCHEMA_TEXT + '\nmodel TradecraftNewThing {\n  id Int @id\n\n  @@map("tradecraft_new_things")\n}\n'
    assert library.uncovered_tables(grown) == ["tradecraft_new_things"]


def test_the_snapshot_moves_every_autoincrement_sequence_of_the_schema():
    models = _models(SCHEMA_TEXT)
    autoinc = {name for name, body in models.items()
               if name in {t.name for t in library.TABLES} and re.search(r"^\s*id\s+\w+\s+@id @default\(autoincrement\(\)\)", body, re.M)}
    assert autoinc == SERIAL == {t.name for t in library.TABLES if t.serial}


def test_written_and_derived_columns_exist_in_the_schema():
    # A renamed column would leave a claim or a token in the snapshot without a failure.
    models = _models(SCHEMA_TEXT)
    for table in library.TABLES:
        body = models[table.name]
        for col in list(table.written) + list(table.derived) + list(table.owner_columns) + list(table.person_columns):
            assert f'@map("{col}")' in body or re.search(rf"^\s*{col}\s", body, re.M), (table.name, col)


def _sqlite_library() -> sqlite3.Connection:
    """Two accounts with the same URL (R-3), each with two generations, a claim and a token."""
    db = sqlite3.connect(":memory:")
    for name, cols in COLUMNS.items():
        db.execute(f"CREATE TABLE {name} ({', '.join(cols)})")
    db.execute("CREATE TABLE projects (id)")
    db.execute("INSERT INTO projects VALUES ('p-owner')")
    for user, rid, base in ((OWNER, "r-owner", 1), (OTHER, "r-other", 100)):
        db.execute("INSERT INTO user_tradecraft_resources VALUES (?, ?, 'hacktricks', 'https://example.invalid/', 2, "
                   "'job-claim', 'ghp_fake_token_value', '{}', 0)", (rid, user))
        db.execute("INSERT INTO tradecraft_page_ids VALUES (?, ?, 'https://example.invalid/a')", (base, rid))
        for gen in (1, 2):
            eid = base * 10 + gen
            db.execute("INSERT INTO tradecraft_entries VALUES (?, ?, ?, ?, ?, 'u', 't', 'text', 'vec')",
                       (eid, user, rid, gen, base))
            db.execute("INSERT INTO tradecraft_sections VALUES (?, ?, ?, ?, ?, 0, 'h', 'x', 'vec')",
                       (eid, eid, rid, user, gen))
            db.execute("INSERT INTO tradecraft_tree_nodes VALUES (?, ?, ?, ?, '/', 'root')", (eid, rid, user, gen))
        db.execute("INSERT INTO tradecraft_curations VALUES (?, ?, 'u', 1, ?)", (f"c-{rid}", rid, user))
        db.execute("INSERT INTO tradecraft_project_choices VALUES ('p-owner', ?, ?)", (rid, user))
        db.execute("INSERT INTO tradecraft_user_settings VALUES (?, ?, 1, '{}')", (f"s-{user}", user))
    return db


def test_the_snapshot_queries_read_the_owners_live_rows_only_without_claim_or_token():
    db = _sqlite_library()
    for table in library.TABLES:
        sql = library.select_sql(table, COLUMNS[table.name], OWNER)
        assert f"user_id = '{OWNER}'" in sql and OTHER not in sql
        cur = db.execute(sql)
        names = [d[0] for d in cur.description]
        rows = [dict(zip(names, r)) for r in cur.fetchall()]
        assert rows, table.name
        assert "search_vector" not in names
        for row in rows:
            assert OTHER not in json.dumps(row) and "r-other" not in json.dumps(row)
            if "generation" in row:
                assert row["generation"] == 2  # the live generation only
        if table.name == "user_tradecraft_resources":
            assert rows[0]["active_job_id"] is None and rows[0]["github_token_override"] == ""
            assert rows[0]["id"] == "r-owner"


def test_snapshot_script_is_one_read_only_transaction_guarded_against_running_jobs():
    script = library.snapshot_script(COLUMNS, OWNER)
    lines = script.strip().splitlines()
    assert lines[0] == "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;" and lines[-1] == "COMMIT;"
    assert lines[1] == library.guard_sql(OWNER)
    assert "status IN ('queued', 'running') AND lease_until > now()" in lines[1]
    assert library.UNFINISHED_JOB in lines[1]
    # No job is copied, and every table once, after its marker.
    assert "COPY (SELECT" in script and "FROM tradecraft_ingestion_jobs t" not in script
    marks = [ln for ln in lines if ln.startswith("SELECT '\\.tc-e2e-table ")]
    assert [m.split()[-1].rstrip("';") for m in marks] == [t.name for t in library.TABLES]
    assert script.count(" TO STDOUT;") == len(library.TABLES)


# --------------------------------------------------------------------------------------
# The psql stream and the snapshot's files
# --------------------------------------------------------------------------------------

def test_the_splitter_cuts_one_file_per_table(tmp_path):
    split = library.Splitter(tmp_path)
    split.line(library.MARK_B + b"user_tradecraft_resources\n")
    split.line(b"r1\tcowner\n")
    split.line(b"r2\tcowner\n")
    split.line(library.MARK_B + b"tradecraft_page_ids\n")
    split.line(b"\\\\.tc-e2e-table looks like a marker but is escaped data\n")
    split.close()
    assert split.problem == ""
    assert (tmp_path / "user_tradecraft_resources.copy").read_bytes() == b"r1\tcowner\nr2\tcowner\n"
    meta = split.meta["user_tradecraft_resources"]
    assert meta["rows"] == 2 and meta["sha256"] == hashlib.sha256(b"r1\tcowner\nr2\tcowner\n").hexdigest()
    assert split.meta["tradecraft_page_ids"]["rows"] == 1
    assert oct((tmp_path / "user_tradecraft_resources.copy").stat().st_mode & 0o777) == "0o600"

    bad = library.Splitter(tmp_path / "x")
    (tmp_path / "x").mkdir()
    bad.line(b"rows before any marker\n")
    assert bad.problem
    bad2 = library.Splitter(tmp_path / "x")
    bad2.line(library.MARK_B + b"tradecraft_ingestion_jobs\n")
    assert "unexpected" in bad2.problem


def test_psql_streams_both_ways_and_names_the_first_error():
    lines = []

    def cat(argv, **kw):
        assert argv[:3] == ["docker", "exec", "-i"] and "ON_ERROR_STOP=1" in argv[-1]
        return subprocess.Popen(["cat"], **kw)

    code, err = library.Psql(popen=cat).run([b"a\n", b"b\n" * 50000], on_line=lines.append)
    assert code == 0 and err == "" and len(lines) == 50001

    def fails(argv, **kw):
        return subprocess.Popen(["sh", "-c", "cat >/dev/null; echo 'psql:<stdin>:2: ERROR:  tc_e2e_unfinished_job' >&2; "
                                             "echo 'CONTEXT:  row value secret-page-text' >&2; exit 3"], **kw)

    code, err = library.Psql(popen=fails).run([b"BEGIN;\n"])
    assert code == 3 and err.startswith("tc_e2e_unfinished_job") and "unfinished ingestion job" in err
    assert "secret-page-text" not in err  # never a CONTEXT or DETAIL line


def test_psql_json_reads_json_agg_over_several_lines():
    # psql prints json_agg with one element per line, as Postgres 16 does for every answer of
    # more than one row: the whole output is the value, not its last line.
    out = '[{"table_name":"a","column_name":"id"}, \n {"table_name":"a","column_name":"url"}]\n'

    def psql(argv, **kw):
        return subprocess.Popen(["sh", "-c", f"cat >/dev/null; printf '%s' '{out}'"], **kw)

    assert library.Psql(popen=psql).json("SELECT 1") == [
        {"table_name": "a", "column_name": "id"}, {"table_name": "a", "column_name": "url"}]


def test_psql_refuses_names_it_would_splice():
    with pytest.raises(ValueError):
        library.Psql(db="x; drop")
    with pytest.raises(ValueError):
        library.Psql(container="a b")
    argv = library.Psql("redamon-tc-pgtest", "tctest", "tc_s15").argv()
    assert "TC_PGUSER=tctest" in argv and "TC_PGDB=tc_s15" in argv


class FakePsql(library.Psql):
    """A database that answers the catalog and owner queries and replays a COPY stream."""

    def __init__(self, *, out_lines=(), code=0, err="", owner=OWNER, columns=None):
        super().__init__()
        self.out_lines, self.code, self.err, self.owner = list(out_lines), code, err, owner
        self.columns = COLUMNS if columns is None else columns
        self.scripts: list = []
        self.queries: list = []

    def json(self, sql):
        self.queries.append(sql)
        if "FROM users" in sql:
            return [{"id": self.owner}] if self.owner else []
        if "information_schema.columns" in sql:
            return [{"table_name": t, "column_name": c} for t, cols in self.columns.items() for c in cols]
        return [{"slug": "hacktricks", "resource_type": "mkdocs-wiki", "storage_mode": "live", "entries": 2}]

    def run(self, chunks, on_line=None):
        self.scripts.append(b"".join(chunks))
        for line in self.out_lines:
            on_line(line)
        return self.code, self.err


def _stream(rows_per_table=2):
    out = []
    for t in library.TABLES:
        out.append(library.MARK_B + t.name.encode() + b"\n")
        out += [f"{t.name}-{i}\t{OWNER}\n".encode() for i in range(rows_per_table)]
    return out


def test_snapshot_writes_the_files_and_the_stamp(tmp_path):
    folder = tmp_path / "library"
    logs = []
    code = library.snapshot(FakePsql(out_lines=_stream()), "tc-e2e-owner@e2e.local", folder=folder, log=logs.append,
                            commit="abc123", code_hash="h1")
    assert code == library.EXIT_OK, logs
    stamp = library.read_stamp(folder)
    assert stamp["owner_id"] == OWNER and stamp["commit"] == "abc123" and stamp["ingest_hash"] == "h1"
    assert set(stamp["tables"]) == {t.name for t in library.TABLES}
    assert "search_vector" not in stamp["tables"]["tradecraft_entries"]["columns"]
    assert all(m["rows"] == 2 for m in stamp["tables"].values())
    assert library.file_problems(stamp, folder) == []
    assert oct(folder.stat().st_mode & 0o777) == "0o700"


def test_snapshot_has_no_claim_and_no_job(tmp_path):
    folder = tmp_path / "library"
    library.snapshot(FakePsql(out_lines=_stream()), "o@e2e.local", folder=folder, log=lambda s: None,
                     commit="c1", code_hash="h1")
    before = sorted(p.name for p in folder.iterdir())
    # A running job refuses the snapshot, and the previous one stays as it was.
    fake = FakePsql(out_lines=_stream()[:3], code=3, err="tc_e2e_unfinished_job: the e2e owner has an unfinished ingestion job")
    logs = []
    assert library.snapshot(fake, "o@e2e.local", folder=folder, log=logs.append, commit="c2", code_hash="h2") == library.EXIT_FAILED
    assert "unfinished ingestion job" in logs[-1] and "previous snapshot is kept" in logs[-1]
    assert sorted(p.name for p in folder.iterdir()) == before and library.read_stamp(folder)["commit"] == "c1"
    script = fake.scripts[0].decode()
    assert "NULL AS \"active_job_id\"" in script and "'' AS \"github_token_override\"" in script
    assert "tradecraft_ingestion_jobs t" not in script
    assert not (tmp_path / ".library.new").exists()


def test_a_snapshot_missing_a_table_section_is_refused(tmp_path):
    stream = _stream()
    cut = [ln for ln in stream if not ln.startswith(library.MARK_B + b"tradecraft_user_settings")]
    logs = []
    code = library.snapshot(FakePsql(out_lines=cut), "o@e2e.local", folder=tmp_path / "library", log=logs.append,
                            commit="c", code_hash="h")
    assert code == library.EXIT_FAILED and not (tmp_path / "library").exists()


# --------------------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------------------

def _snapshot(tmp_path, owner=OWNER):
    folder = tmp_path / "library"
    library.snapshot(FakePsql(out_lines=_stream(), owner=owner), "o@e2e.local", folder=folder, log=lambda s: None,
                     commit="c", code_hash="h")
    return folder, library.read_stamp(folder)


def _sql(parts):
    return "".join(p for p in parts if isinstance(p, str))


def test_restore_runs_in_one_transaction(tmp_path):
    folder, stamp = _snapshot(tmp_path)
    parts = library.restore_parts(stamp, OWNER, folder)
    sql = _sql(parts)
    assert sql.startswith("BEGIN;\n") and sql.endswith("COMMIT;\n")
    control = re.findall(r"^(BEGIN|COMMIT|ROLLBACK|END|ABORT|SAVEPOINT|RELEASE|START)\b", sql, re.M)
    assert control == ["BEGIN", "COMMIT"]
    assert "-v ON_ERROR_STOP=1" in library.Psql().argv()[-1]
    # The user's rows go first (the resources' rows cascade), then every file is copied back.
    assert sql.index(f"DELETE FROM user_tradecraft_resources WHERE user_id = '{OWNER}'") < sql.index("COPY ")
    assert sql.index(library.guard_sql(OWNER)) < sql.index("DELETE FROM")
    for i, part in enumerate(parts):
        if isinstance(part, Path):
            assert parts[i - 1].startswith("COPY tc_e2e_restore_") and parts[i - 1].endswith("FROM STDIN;\n")
            assert parts[i + 1] == "\\.\n" and "tc_e2e_rows_differ" in parts[i + 2]
    assert [p.name for p in parts if isinstance(p, Path)] == [f"{t.name}.copy" for t in library.TABLES]
    # A choice of a project that is gone is not restored.
    assert "INSERT INTO tradecraft_project_choices" in sql and "EXISTS (SELECT 1 FROM projects p WHERE p.id = r.project_id)" in sql


def test_restore_moves_sequences(tmp_path):
    folder, stamp = _snapshot(tmp_path)
    sql = _sql(library.restore_parts(stamp, OWNER, folder))
    last_insert = sql.rindex("INSERT INTO ")
    for table in SERIAL:
        block = library.sequence_sql(table)
        assert block in sql and last_insert < sql.index(block) < sql.index("COMMIT;")
        assert f"pg_get_serial_sequence('{table}', 'id')" in block and f"max(id) INTO top FROM {table}" in block
        # Never backwards: only when the largest id reached the sequence.
        assert "IF top IS NOT NULL AND top >= cur THEN PERFORM setval(seq, top)" in block
    assert sql.count("pg_get_serial_sequence") == len(SERIAL)
    assert "tc_e2e_no_search_vector" in sql


def test_restore_moves_the_rows_to_the_owner_of_today(tmp_path):
    folder, stamp = _snapshot(tmp_path, owner="cold00000000000000000000")
    sql = _sql(library.restore_parts(stamp, OWNER, folder))
    for table in library.TABLES:
        for col in table.owner_columns:
            assert f'UPDATE tc_e2e_restore_{table.name} SET "{col}" = \'{OWNER}\';' in sql
        for col in table.person_columns:
            assert (f'UPDATE tc_e2e_restore_{table.name} SET "{col}" = \'{OWNER}\' '
                    f'WHERE "{col}" = \'cold00000000000000000000\';') in sql
    same = _sql(library.restore_parts(stamp, "cold00000000000000000000", folder))
    assert 'SET "created_by_id"' not in same


def test_restore_streams_the_files_and_reports_success(tmp_path):
    folder, _ = _snapshot(tmp_path)
    fake = FakePsql()
    logs = []
    assert library.restore(fake, "o@e2e.local", folder=folder, log=logs.append) == library.EXIT_OK
    sent = fake.scripts[0]
    data = (folder / "tradecraft_entries.copy").read_bytes()
    assert b"COPY tc_e2e_restore_tradecraft_entries" in sent and data in sent
    assert sent.index(data) < sent.index(b"\\.\n", sent.index(data))
    assert "restore:" in logs[-1] and "rows" in logs[-1]


def test_restore_refuses_a_changed_file_before_touching_the_database(tmp_path):
    folder, _ = _snapshot(tmp_path)
    (folder / "tradecraft_sections.copy").write_bytes(b"tampered\n")
    fake = FakePsql()
    logs = []
    assert library.restore(fake, "o@e2e.local", folder=folder, log=logs.append) == library.EXIT_FAILED
    assert fake.scripts == [] and fake.queries == []
    assert "tradecraft_sections.copy does not match" in logs[-1]
    assert library.restore(FakePsql(), "o@e2e.local", folder=tmp_path / "none", log=logs.append) == library.EXIT_NO_SNAPSHOT


def test_restore_refuses_a_column_the_database_no_longer_has(tmp_path):
    folder, _ = _snapshot(tmp_path)
    cols = {k: [c for c in v if c != "title"] for k, v in COLUMNS.items()}
    fake = FakePsql(columns=cols)
    logs = []
    assert library.restore(fake, "o@e2e.local", folder=folder, log=logs.append) == library.EXIT_FAILED
    assert fake.scripts == [] and "no longer has title" in logs[-1]


def test_a_failed_restore_says_nothing_changed(tmp_path):
    folder, _ = _snapshot(tmp_path)
    logs = []
    fake = FakePsql(code=3, err="duplicate key value violates unique constraint")
    assert library.restore(fake, "o@e2e.local", folder=folder, log=logs.append) == library.EXIT_FAILED
    assert "nothing changed" in logs[-1]


# --------------------------------------------------------------------------------------
# The stamp
# --------------------------------------------------------------------------------------

def test_the_stamp_check_warns_when_ingestion_code_changed(tmp_path):
    root = tmp_path / "ingest"
    root.mkdir()
    (root / "pipeline.py").write_text("STAGES = 1\n")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "pipeline.cpython-311.pyc").write_bytes(b"\0")
    stamp = {"commit": "0123456789abcdef", "ingest_hash": library.ingest_hash(root)}
    assert library.stamp_warning(stamp, root) is None
    (root / "__pycache__" / "other.pyc").write_bytes(b"\1")
    assert library.stamp_warning(stamp, root) is None  # bytecode is not code
    (root / "pipeline.py").write_text("STAGES = 2\n")
    warning = library.stamp_warning(stamp, root)
    assert warning and "changed since the library was built" in warning and "0123456789ab" in warning
    (root / "pipeline.py").write_text("STAGES = 1\n")
    (root / "new_stage.py").write_text("")
    assert library.stamp_warning(stamp, root)
    assert library.stamp_warning(None, root) is None


def test_the_snapshot_folder_is_ignored_by_git():
    # D-40: third-party pages never reach a commit.
    rel = library.SNAPSHOT_DIR.relative_to(REPO)
    assert rel.parts[0] == "_local"
    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/_local/" in gitignore or "_local/" in gitignore


# --------------------------------------------------------------------------------------
# library.yaml
# --------------------------------------------------------------------------------------

def test_the_library_is_the_one_the_matrix_reads():
    assert library.scenario_problems(LIB, SCN) == []
    assert len(LIB["resources"]) == 9
    assert LIB["fake_login"] == {"cookie": "cookie=fake-session"}
    assert int(LIB["parallel"]) == 2
    broken = json.loads(json.dumps(LIB))
    broken["resources"][1]["slug"] = broken["resources"][0]["slug"]
    del broken["resources"][2]["expect"]
    problems = library.library_problems(broken)
    assert any("twice" in p for p in problems) and any("has no expect" in p for p in problems)
    moved = json.loads(json.dumps(LIB))
    moved["resources"][0]["storage"] = "stored"
    assert any("Stored resources" in p for p in library.scenario_problems(moved, SCN))


def test_the_library_resources_are_the_presets():
    presets = (REPO / "webapp/src/lib/tradecraft/presets.ts").read_text(encoding="utf-8")
    for spec in LIB["resources"]:
        at = presets.index(f"key: '{spec['preset']}'")
        entry = presets[at:presets.index("}", at)]
        assert f"name: '{spec['name']}'" in entry, spec["slug"]
        assert f"url: '{spec['url']}'" in entry, spec["slug"]
        chip = re.search(r"type: '([a-z-]+)'", entry).group(1)
        # Quick Add forces the type a github.com address or a CVE archive proves, and the
        # Featured websites' (presetSettings).
        forced = {"github-repo": "github-repo", "cve-poc-db": "cve-poc-db"}.get(chip)
        if spec["preset"] in ("web-hacking-techniques-index", "hexbrain-payloads"):
            forced = "agentic-crawl"
        assert spec.get("forcedType") == forced, spec["slug"]
        if spec.get("overrides"):
            # The preset's own settings (SETTINGS_BY_KEY): one entry, up to the next key or the map's end.
            start = presets.index(f"'{spec['preset']}': {{")
            ends = [i for i in (presets.find("\n  '", start + 1), presets.find("\n}", start)) if i != -1]
            block = presets[start:min(ends)]
            for key in spec["overrides"]:
                assert f"'{key}'" in block, (spec["slug"], key)


def test_the_build_sends_what_the_form_sends():
    specs = {s["slug"]: s for s in LIB["resources"]}
    fake = LIB["fake_login"]
    for slug, spec in specs.items():
        body = library.create_body(spec, "model-x", spec.get("overrides") or {}, fake)
        assert body["slug"] == slug and body["presetKey"] == spec["preset"] and body["llmModel"] == "model-x"
        assert body["storageMode"] == spec["storage"] and body["enabled"] is True
        assert "githubTokenOverride" not in body
        assert ("credentials" in body) == (slug == SCN["library"]["login_resource"])
        assert ("focus" in body) == (slug in ("payloadsallthethings", "claude-bughunter"))
    assert library.create_body(specs["ired-team"], "m", {}, fake)["credentials"] == {"cookie": "cookie=fake-session"}
    assert library.check_url_body(specs["ired-team"], fake)["credentials"] == {"cookie": "cookie=fake-session"}
    bug = library.create_body(specs["claude-bughunter"], "m", {}, fake)["focus"]
    assert bug["mode"] == "focused" and bug["topics"] == ["sql_injection", "ssrf"] and bug["kinds"] == ["payloads", "bypasses"]
    # Check URL's CVE pattern fills the archive's path patterns, as the form does, never over a chosen one.
    found = {"ok": True, "cve_pattern": "{year}/{cve}.md"}
    assert library.prefill_from_check(found, {}) == {"type.cve.pathPatterns": ["{year}/{cve}.md"]}
    assert library.prefill_from_check(found, {"type.cve.pathPatterns": ["x"]}) == {"type.cve.pathPatterns": ["x"]}
    assert library.prefill_from_check({"ok": False, "cve_pattern": "y"}, {}) == {}
    # A CVE archive has no page list to focus.
    cve = dict(specs["trickest-cve"], focus={"mode": "tagOnly"})
    assert "focus" not in library.create_body(cve, "m", {}, fake)
    entries = [{"url": f"https://example.invalid/{i}", "title": "t" * 400} for i in range(150)]
    prev = library.preview_body(specs["claude-bughunter"], "m", entries)
    assert len(prev["entries"]) == 100 and len(prev["entries"][0]["title"]) == 300


def test_judge_checks_type_size_storage_readiness_login_and_focus():
    spec = next(s for s in LIB["resources"] if s["slug"] == "claude-bughunter")
    view = {"resourceType": "github-repo", "entryCount": 40, "storageMode": "stored", "hasLogin": False,
            "report": {"stored": {"pages": 30}, "readiness": {"realTitlesPct": 90}, "focus": {"mode": "focused", "dropped": 7}}}
    job = {"status": "succeeded"}
    assert all(c.ok for c in library.judge(spec, view, job))
    bad = dict(view, resourceType="agentic-crawl", entryCount=3, report={"stored": {"pages": 1}})
    failed = {c.name for c in library.judge(spec, bad, {"status": "failed", "errorCode": "fetch_failed"}) if not c.ok}
    assert failed == {"job_succeeded", "type", "map_size", "stored_pages", "readiness", "focus_applied"}
    cve = next(s for s in LIB["resources"] if s["slug"] == "trickest-cve")
    names = {c.name for c in library.judge(cve, {"resourceType": "cve-poc-db", "entryCount": 0, "storageMode": "live"}, job)}
    assert "readiness" not in names and "map_size" in names
    login = next(s for s in LIB["resources"] if s["slug"] == "ired-team")
    no_login = {"resourceType": "gitbook", "entryCount": 99, "storageMode": "live", "hasLogin": False, "report": {"readiness": {"a": 1}}}
    assert [c.name for c in library.judge(login, no_login, job) if not c.ok] == ["login"]


def test_the_build_record_holds_counts_only():
    view = {"report": {"visited": 10, "kept": 9, "stored": {"pages": 9, "bytes": 100}, "errors": [{"code": "x", "count": 1}],
                       "readiness": {"a": 1}, "pageText": "never", "url": "https://example.invalid/?token=1"}}
    out = library.Outcome("s", counts=library.report_counts(view))
    out.checks.append(report.CheckResult("job_succeeded", True, "succeeded"))
    record = library.build_record({"s": out}, model="m", commit="c", started="t")
    text = json.dumps(record)
    assert "never" not in text and "token" not in text and record["resources"]["s"]["ok"] is True


# --------------------------------------------------------------------------------------
# The build against a scripted webapp
# --------------------------------------------------------------------------------------

class FakeWebapp:
    """The routes the build calls, with jobs that end after ``polls`` listings."""

    def __init__(self, *, existing=(), polls=2, never_end=(), providers=(), models=None, wrong_type=None):
        self.calls: list = []
        self.resources: dict = {}  # id -> view
        self.polls, self.never_end = polls, set(never_end)
        self.providers, self.models, self.wrong_type = list(providers), models, wrong_type or {}
        self.running_max = 0
        self._n = 0
        for view in existing:
            self.resources[view["id"]] = view

    def _view(self, body):
        spec = next(s for s in LIB["resources"] if s["slug"] == body["slug"])
        self._n += 1
        rid = f"r{self._n}"
        exp = spec["expect"]
        return {"id": rid, "slug": body["slug"], "url": body["url"], "storageMode": body["storageMode"],
                "resourceType": self.wrong_type.get(body["slug"], exp["type"]),
                "hasLogin": "credentials" in body, "mapVersion": 3,
                "entryCount": max(int(exp.get("min_entries", 1)), 1) + 5,
                "report": {"stored": {"pages": int(exp.get("min_stored_pages") or 0) + 1}, "readiness": {"a": 80},
                           "focus": {"mode": (spec.get("focus") or {}).get("mode", "everything")}},
                "job": {"status": "queued", "stage": "", "progress": {}}, "_left": self.polls}

    def call(self, method, path, body=None, *, headers=None, timeout=None):
        self.calls.append((method, path, body))
        R = runner.Response
        if path.endswith("/llm-providers") and method == "GET":
            return R(200, self.providers)
        if "/llm-providers/" in path and path.endswith("/test"):
            return R(200, {"ok": True})
        if path == "/api/models":
            return R(200, self.models or {})
        if path.endswith("/settings") or path.endswith("/tradecraft-settings"):
            return R(200, {})
        if path.endswith("/check-url"):
            return R(200, {"result": {"ok": True, "error_code": "", "detected_type": "", "sample_entries":
                                      [{"url": "https://example.invalid/a", "title": "A"}], "cve_pattern": None}})
        if path.endswith("/focus-preview"):
            return R(200, {"result": {"kept": 1, "maybe": 0, "dropped": 0, "examples": []}})
        if path.endswith("/tradecraft-resources") and method == "POST":
            view = self._view(body)
            self.resources[view["id"]] = view
            return R(201, {"resource": view, "job": view["job"]})
        if path.endswith("/tradecraft-resources") and method == "GET":
            running = 0
            for view in self.resources.values():
                job = view.get("job") or {}
                if job.get("status") in ("queued", "running"):
                    running += 1
                    if view["slug"] not in self.never_end:
                        view["_left"] -= 1
                        job["status"] = "succeeded" if view["_left"] <= 0 else "running"
            self.running_max = max(self.running_max, running)
            return R(200, [dict(v) for v in self.resources.values()])
        if method == "DELETE" and path.endswith("/jobs"):
            rid = path.split("/")[-2]
            self.resources[rid]["job"]["status"] = "cancelled"
            return R(200, {})
        if method == "DELETE":
            self.resources.pop(path.split("/")[-1], None)
            return R(200, {})
        return R(404, {"code": "not_found"})


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, sec):
        self.t += sec


def _builder(web, clock=None, lib=LIB):
    clock = clock or FakeClock()
    logs = []
    return library.Builder(lib, SCN, web, "u-owner", "model-x", logs.append, clock=clock, sleep=clock.sleep), logs


def test_build_adds_every_resource_two_at_a_time_and_judges_each():
    web = FakeWebapp()
    builder, logs = _builder(web)
    assert builder.prepare() == []
    put = [c for c in web.calls if c[0] == "PUT"]
    assert put[0][2] == {"featureModels": {"tradecraft_librarian": "model-x"}}
    assert put[1][2] == {"search": SCN["owner_search"]}
    outcomes = builder.run()
    assert set(outcomes) == {s["slug"] for s in LIB["resources"]}
    assert all(o.ok for o in outcomes.values()), {s: [c for c in o.checks if not c.ok] for s, o in outcomes.items()}
    adds = [c[2]["slug"] for c in web.calls if c[0] == "POST" and c[1].endswith("/tradecraft-resources")]
    assert adds == [s["slug"] for s in LIB["resources"]]
    assert web.running_max <= 2
    previews = [c for c in web.calls if c[1].endswith("/focus-preview")]
    assert len(previews) == 1 and outcomes["claude-bughunter"].preview == {"kept": 1, "maybe": 0, "dropped": 0}
    # Every add came after its own Check URL.
    order = [(c[1].rsplit("/", 1)[-1], (c[2] or {}).get("url")) for c in web.calls if c[0] == "POST"]
    for spec in LIB["resources"]:
        assert order.index(("check-url", spec["url"])) < order.index(("tradecraft-resources", spec["url"]))


def test_build_resumes_without_adding_twice():
    built = {"id": "old1", "slug": "hacktricks", "url": "https://book.hacktricks.wiki", "storageMode": "live",
             "resourceType": "mkdocs-wiki", "hasLogin": False, "mapVersion": 3, "entryCount": 900,
             "report": {"readiness": {"a": 1}}, "job": {"status": "succeeded"}}
    failed = {"id": "old2", "slug": "mitmproxy-docs", "url": "https://docs.mitmproxy.org/stable/", "mapVersion": 3,
              "job": {"status": "failed", "errorCode": "fetch_failed"}}
    stray = {"id": "old3", "slug": "not-in-the-library", "url": "https://example.invalid/", "job": None}
    web = FakeWebapp(existing=[built, failed, stray])
    builder, _ = _builder(web)
    outcomes = builder.run()
    adds = [c[2]["slug"] for c in web.calls if c[0] == "POST" and c[1].endswith("/tradecraft-resources")]
    assert "hacktricks" not in adds and "mitmproxy-docs" in adds and len(adds) == 8
    deleted = [c[1] for c in web.calls if c[0] == "DELETE"]
    assert any(p.endswith("/old2") for p in deleted) and any(p.endswith("/old3") for p in deleted)
    assert not any(p.endswith("/old1") for p in deleted)
    assert outcomes["hacktricks"].ok and outcomes["hacktricks"].note == "built by an earlier run"


def test_build_cancels_a_job_past_its_limit_and_reports_the_wrong_type():
    web = FakeWebapp(never_end={"hacktricks"}, wrong_type={"mitmproxy-docs": "agentic-crawl"})
    clock = FakeClock()
    builder, logs = _builder(web, clock)
    outcomes = builder.run()
    assert not outcomes["hacktricks"].ok
    assert any(c[0] == "DELETE" and c[1].endswith("/jobs") for c in web.calls)
    assert [c.name for c in outcomes["mitmproxy-docs"].checks if not c.ok] == ["type"]
    cancelled = [c.detail for c in outcomes["hacktricks"].checks if not c.ok]
    assert cancelled == [f"cancelled after {int(LIB['resource_timeout_min'])} min"]
    assert all(o.ok for s, o in outcomes.items() if s not in ("hacktricks", "mitmproxy-docs"))


def test_build_stops_at_mc9_without_a_model_provider():
    web = FakeWebapp(providers=[], models={"Agent in the Loop": [{"id": "loop/claude-code"}]})
    assert "MC-9" in library.provider_problem(web, "u-owner")
    web_own = FakeWebapp(providers=[{"id": "p1"}])
    assert library.provider_problem(web_own, "u-owner") is None
    offered = FakeWebapp(providers=[], models={"Instance": [{"id": "instance/p9/some-model"}]})
    assert library.provider_problem(offered, "u-owner") is None
    logs = []
    with mock.patch.object(library, "_owner_session", return_value=(web, "u-owner")):
        code = library.cmd_build(LIB, SCN, "model-x", logs.append, report.Redactor())
    assert code == library.EXIT_MC9 and "pending (MC-9)" in logs[-1]
    assert not any(c[1].endswith("/tradecraft-resources") or c[0] == "PUT" for c in web.calls)


def test_plan_starts_nothing(capsys):
    with mock.patch.object(runner, "seed_accounts") as seed, mock.patch.object(subprocess, "Popen") as popen:
        assert library.main(["plan", "--model", "model-x"]) == library.EXIT_OK
    assert not seed.called and not popen.called
    out = capsys.readouterr().out
    assert out.count(": Check URL {") == 9 and out.count("focus preview") == 1 and "cookie=fake-session" in out
