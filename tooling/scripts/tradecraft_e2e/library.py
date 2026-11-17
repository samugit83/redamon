#!/usr/bin/env python3
"""The Tradecraft 2.0 end-to-end library (phase 10, T10.2): build it, freeze it, restore it.

Every agent run of the matrix reads one library, the same in every run and offline (Stored
resources answer from their copy): the e2e owner's nine resources of ``library.yaml``, added
from the default presets through the product's own routes, then frozen in a snapshot that
``runner.py``'s preflight restores before each matrix run.

  python3 tooling/scripts/tradecraft_e2e/library.py plan                 # what build would send; starts nothing
  python3 tooling/scripts/tradecraft_e2e/library.py models               # the model ids the e2e owner may pick
  python3 tooling/scripts/tradecraft_e2e/library.py build --model <id>   # the library, through the routes (MC-9)
  python3 tooling/scripts/tradecraft_e2e/library.py snapshot             # its rows, into _local/tradecraft-e2e/library/
  python3 tooling/scripts/tradecraft_e2e/library.py restore              # those rows back, in one transaction
  python3 tooling/scripts/tradecraft_e2e/library.py status               # the stamp; warns when ingestion changed

``build`` signs in as the e2e owner (``runner.seed_accounts``), stops when the account has no
model provider (MC-9), sets the librarian model and the search settings the matrix expects,
then per resource runs Check URL, the focus preview where ``library.yaml`` asks for it, and
Add, waits for the jobs (two at a time, as the agent runs them) and judges each report. It
resumes: a resource already built is judged again, never added twice.

``snapshot`` copies the e2e owner's rows of every tradecraft table but the jobs, in one
read-only transaction, with no claim, no GitHub token and no site login, plus a stamp (the
commit, a hash of the ingestion code, the columns, row counts and checksums). ``restore``
deletes that owner's tradecraft rows and copies the files back in one transaction, writes
the card's fake login back on the S2/S3 resource, then moves the four autoincrement
sequences past the restored ids. Both accept the e2e owner ``tc-e2e-owner@e2e.local`` only,
and replace or remove only a folder they made. The snapshot holds third-party pages: it
stays under ``_local/`` and is never committed (D-40).

Standard library only, host Python 3. The database is reached through ``psql`` in its
container (as ``runner.Db``), the webapp as a person reaches it. Credentials stay inline and
are never printed (``runner.Log`` redacts every line).
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence, Union

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tooling.scripts.tradecraft_e2e import report, runner  # noqa: E402

HERE = Path(__file__).resolve().parent
LIBRARY_YAML = HERE / "library.yaml"
SNAPSHOT_DIR = runner.SNAPSHOT_DIR
BUILD_RECORD = SNAPSHOT_DIR.parent / "library-build.json"
INGEST_DIR = REPO / "agentic" / "tradecraft" / "ingest"
SCHEMA = REPO / "webapp" / "prisma" / "schema.prisma"
PLAN_BRANCH = "refs/heads/feature/tradecraft-2.0"
STAMP = "stamp.json"
STAMP_FORMAT = 1

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_STACK, EXIT_MC9, EXIT_NO_SNAPSHOT = 0, 1, 2, 3, 4, 5

# The one account whose library this script builds, freezes and replaces: restore deletes a
# whole library, so no other address is accepted, whatever scenarios.yaml says.
LIBRARY_OWNER = "tc-e2e-owner@e2e.local"
# The card's fake login of the S2/S3 resource. A snapshot holds no login at all; restore
# writes this one back on that resource, in the shape the add stores (v2/fields.ts).
FAKE_COOKIE = "cookie=fake-session"
FAKE_CREDENTIALS = {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}

# agentContract.ts: SITE_TYPES, STORAGE_MODES, SLUG_RE, the focus modes (focus.ts).
SITE_TYPES = ("mkdocs-wiki", "sphinx-docs", "gitbook", "github-repo", "cve-poc-db", "pdf", "agentic-crawl")
STORAGE_MODES = ("live", "stored")
FOCUS_MODES = ("everything", "focused", "tagOnly")
# The same modes as the agent spells them in its report (ingest/focus.py MODES).
AGENT_FOCUS_MODES = ("everything", "focused", "tag_only")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,199}$")
JOB_ENDED = ("succeeded", "failed", "cancelled")
# Check URL waits for the agent's 60 s deadline, the focus preview for its 120 s, each plus a margin.
CHECK_URL_TIMEOUT = 120
PREVIEW_TIMEOUT = 180
PREVIEW_ENTRIES = 100
LOOP_PREFIX = "loop/"

_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


# --------------------------------------------------------------------------------------
# The tables: what a snapshot holds of one user's library
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Table:
    name: str
    # The user's rows: SQL on alias ``t``; ``{owner}`` is the user's id as a literal.
    where: str
    # Columns that hold the user's id: set to the restoring user's on restore.
    owner_columns: tuple = ()
    # A person's plain id: the snapshot's user becomes the restoring user, anyone else stays.
    person_columns: tuple = ()
    # Column -> the SQL value the snapshot holds instead of the row's.
    written: Mapping[str, str] = field(default_factory=dict)
    # Left out: the database computes them again on insert.
    derived: tuple = ()
    # An autoincrement id: restore moves its sequence past the restored rows.
    serial: bool = False
    # A restored row is inserted only when this holds (alias ``r``).
    keep_if: str = ""


_OWNED = "t.resource_id IN (SELECT o.id FROM user_tradecraft_resources o WHERE o.user_id = {owner})"
# Readers take only the resource's live generation; an older one is being purged.
_LIVE = "t.generation = (SELECT o.generation FROM user_tradecraft_resources o WHERE o.id = t.resource_id)"

TABLES: tuple = (
    # No claim (a restored library never holds one), and no secret: the snapshot is a file, so
    # no GitHub token and no site login (cookies, headers, basic auth) reach it.
    Table("user_tradecraft_resources", "t.user_id = {owner}", owner_columns=("user_id",),
          written={"active_job_id": "NULL", "github_token_override": "''", "credentials": "'{}'",
                   "has_login": "false"}),
    Table("tradecraft_page_ids", _OWNED, serial=True),
    # search_vector is filled by the BEFORE INSERT trigger of apply-tradecraft-search.mjs.
    Table("tradecraft_entries", "t.user_id = {owner} AND " + _LIVE, owner_columns=("user_id",),
          derived=("search_vector",), serial=True),
    Table("tradecraft_sections", "t.user_id = {owner} AND " + _LIVE, owner_columns=("user_id",),
          derived=("search_vector",), serial=True),
    Table("tradecraft_tree_nodes", "t.user_id = {owner} AND " + _LIVE, owner_columns=("user_id",), serial=True),
    Table("tradecraft_curations", _OWNED, person_columns=("created_by_id",)),
    # A project is a run's own: a choice whose project is gone is not restored.
    Table("tradecraft_project_choices", _OWNED, person_columns=("created_by_id",),
          keep_if="EXISTS (SELECT 1 FROM projects p WHERE p.id = r.project_id)"),
    Table("tradecraft_user_settings", "t.user_id = {owner}", owner_columns=("user_id",)),
)

# Every tradecraft table of the schema is in TABLES or here, with the reason.
NOT_SNAPSHOT = {
    "tradecraft_ingestion_jobs": "a job is the record of one ingestion: a restored library holds no job and no claim",
}

# A line COPY's text format never writes (it escapes every backslash): the start of a table.
MARK = "\\.tc-e2e-table "
MARK_B = MARK.encode()

UNFINISHED_JOB = "tc_e2e_unfinished_job"
ERROR_TEXT = {
    UNFINISHED_JOB: "the e2e owner has an unfinished ingestion job: wait for it, or cancel it",
    "tc_e2e_rows_differ": "a snapshot file did not load whole",
    "tc_e2e_no_search_vector": "the search trigger did not fill the restored rows (apply-tradecraft-search.mjs)",
    "tc_e2e_no_sequence": "a restored table has no autoincrement sequence",
    "tc_e2e_no_login_resource": "the login resource of S2 and S3 did not get its fake login",
}


def qi(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"not a plain SQL identifier: {name!r}")
    return f'"{name}"'


def tradecraft_tables(schema_text: str) -> list:
    """The tradecraft tables of a Prisma schema (their ``@@map`` names)."""
    return sorted({m for m in re.findall(r'@@map\("([a-z0-9_]+)"\)', schema_text) if "tradecraft" in m})


def uncovered_tables(schema_text: str) -> list:
    known = {t.name for t in TABLES} | set(NOT_SNAPSHOT)
    return [t for t in tradecraft_tables(schema_text) if t not in known]


def snapshot_columns(table: Table, columns: Sequence[str]) -> list:
    return [c for c in columns if c not in table.derived]


def select_sql(table: Table, columns: Sequence[str], owner_id: str) -> str:
    exprs = [f"{table.written[c]} AS {qi(c)}" if c in table.written else f"t.{qi(c)}"
             for c in snapshot_columns(table, columns)]
    return f"SELECT {', '.join(exprs)} FROM {table.name} t WHERE {table.where.format(owner=runner.lit(owner_id))}"


def guard_sql(owner_id: str) -> str:
    """Refuses while the user has a job that is still running: a lost job (its lease expired)
    no longer writes and does not count."""
    return ("DO $$ BEGIN IF EXISTS (SELECT 1 FROM tradecraft_ingestion_jobs WHERE user_id = "
            f"{runner.lit(owner_id)} AND status IN ('queued', 'running') AND lease_until > now()) "
            f"THEN RAISE EXCEPTION '{UNFINISHED_JOB}'; END IF; END $$;")


def snapshot_script(columns_by_table: Mapping[str, Sequence[str]], owner_id: str) -> str:
    """One read-only transaction, so the tables agree with each other: the job guard, then per
    table a marker line and its COPY."""
    lines = ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;", guard_sql(owner_id)]
    for table in TABLES:
        lines.append(f"SELECT {runner.lit(MARK + table.name)};")
        lines.append(f"COPY ({select_sql(table, columns_by_table[table.name], owner_id)}) TO STDOUT;")
    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"


def _count_check(temp: str, rows: int, table: str) -> str:
    return (f"DO $$ BEGIN IF (SELECT count(*) FROM {temp}) <> {int(rows)} "
            f"THEN RAISE EXCEPTION 'tc_e2e_rows_differ {table}'; END IF; END $$;\n")


def sequence_sql(table: str) -> str:
    """The table's sequence to at least its largest id, never backwards: the restored rows keep
    their ids, and the next ingestion's rows would otherwise collide with them."""
    return (
        f"DO $$ DECLARE seq text := pg_get_serial_sequence('{table}', 'id'); top bigint; cur bigint; BEGIN "
        f"IF seq IS NULL THEN RAISE EXCEPTION 'tc_e2e_no_sequence {table}'; END IF; "
        f"SELECT max(id) INTO top FROM {table}; "
        "EXECUTE 'SELECT last_value FROM ' || seq INTO cur; "
        "IF top IS NOT NULL AND top >= cur THEN PERFORM setval(seq, top); END IF; "
        "END $$;\n")


Part = Union[str, Path]


def login_sql(owner_id: str, slug: str, required: bool) -> str:
    """The card's fake login on the S2/S3 resource, which the snapshot holds without one; when
    the snapshot has that resource, the restore fails unless it got it."""
    o, s = runner.lit(owner_id), runner.lit(slug)
    sql = (f"UPDATE user_tradecraft_resources SET credentials = {runner.lit(json.dumps(FAKE_CREDENTIALS))}::jsonb, "
           f"has_login = true WHERE user_id = {o} AND slug = {s};\n")
    if required:
        sql += (f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM user_tradecraft_resources WHERE user_id = {o} AND slug = {s} "
                "AND has_login) THEN RAISE EXCEPTION 'tc_e2e_no_login_resource'; END IF; END $$;\n")
    return sql


def restore_parts(stamp: Mapping, owner_id: str, folder: Path, login_slug: Optional[str] = None) -> list:
    """The restore as one script for ``psql -f -``: SQL text, and the snapshot's files where a
    ``COPY ... FROM STDIN`` reads its rows. One transaction from BEGIN to COMMIT; with
    ``ON_ERROR_STOP`` any error ends psql before COMMIT, and nothing changes."""
    o = runner.lit(owner_id)
    old = str(stamp.get("owner_id") or "")
    parts: list = [
        "BEGIN;\n",
        "SET LOCAL lock_timeout = '60s';\n",
        guard_sql(owner_id) + "\n",
        # The resources' rows cascade: page ids, entries, sections, tree nodes, curations,
        # project choices and the resources' jobs.
        f"DELETE FROM user_tradecraft_resources WHERE user_id = {o};\n",
        f"DELETE FROM tradecraft_user_settings WHERE user_id = {o};\n",
    ]
    for table in TABLES:
        meta = stamp["tables"][table.name]
        cols = ", ".join(qi(c) for c in meta["columns"])
        temp = f"tc_e2e_restore_{table.name}"
        parts += [
            f"CREATE TEMP TABLE {temp} (LIKE {table.name} INCLUDING DEFAULTS) ON COMMIT DROP;\n",
            f"COPY {temp} ({cols}) FROM STDIN;\n",
            folder / meta["file"],
            "\\.\n",
            _count_check(temp, meta["rows"], table.name),
        ]
        for col in table.owner_columns:
            parts.append(f"UPDATE {temp} SET {qi(col)} = {o};\n")
        if old and old != owner_id:
            for col in table.person_columns:
                parts.append(f"UPDATE {temp} SET {qi(col)} = {o} WHERE {qi(col)} = {runner.lit(old)};\n")
        where = f" WHERE {table.keep_if}" if table.keep_if else ""
        parts.append(f"INSERT INTO {table.name} ({cols}) SELECT {cols} FROM {temp} r{where};\n")
    if login_slug:
        restored = {str(r.get("slug")) for r in stamp.get("resources") or [] if isinstance(r, dict)}
        parts.append(login_sql(owner_id, login_slug, required=login_slug in restored))
    parts += [sequence_sql(t.name) for t in TABLES if t.serial]
    parts.append(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM tradecraft_entries WHERE user_id = " + o + " AND search_vector IS NULL) "
        "OR EXISTS (SELECT 1 FROM tradecraft_sections WHERE user_id = " + o + " AND search_vector IS NULL) "
        "THEN RAISE EXCEPTION 'tc_e2e_no_search_vector'; END IF; END $$;\n")
    parts.append("COMMIT;\n")
    return parts


def stream_parts(parts: Sequence[Part], chunk: int = 1 << 20) -> Iterator[bytes]:
    for part in parts:
        if isinstance(part, Path):
            with part.open("rb") as fh:
                while True:
                    data = fh.read(chunk)
                    if not data:
                        break
                    yield data
        else:
            yield part.encode()


# --------------------------------------------------------------------------------------
# psql in a Postgres container
# --------------------------------------------------------------------------------------

def first_error(stderr: str) -> str:
    """psql's first ERROR line, clipped; never its DETAIL or CONTEXT, which can quote row values."""
    for line in stderr.splitlines():
        if "ERROR:" in line:
            msg = line.split("ERROR:", 1)[1].strip()
            for code, text in ERROR_TEXT.items():
                if msg.startswith(code):
                    return f"{msg[:120]}: {text}"
            return msg[:160]
    return stderr.strip().splitlines()[0][:160] if stderr.strip() else ""


class Psql:
    """``psql`` in a Postgres container, the script on stdin (as ``runner.Db``): by default the
    stack's database; ``user``/``db`` name another one, such as the plan's disposable test
    Postgres (``tooling/scripts/tradecraft_pg_testdb.sh``)."""

    def __init__(self, container: str = runner.POSTGRES_CONTAINER, user: str = "", db: str = "",
                 popen: Callable[..., Any] = subprocess.Popen):
        for value in (user, db):
            if value and not _IDENT.match(value):
                raise ValueError(f"not a plain database or user name: {value!r}")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", container):
            raise ValueError(f"not a container name: {container!r}")
        self.container, self.user, self.db = container, user, db
        self._popen = popen

    def argv(self) -> list:
        return ["docker", "exec", "-i", "-e", f"TC_PGUSER={self.user}", "-e", f"TC_PGDB={self.db}", self.container,
                "sh", "-c", 'exec psql -U "${TC_PGUSER:-$POSTGRES_USER}" -d "${TC_PGDB:-$POSTGRES_DB}" '
                            "-qAtX -v ON_ERROR_STOP=1 -f -"]

    def run(self, chunks: Iterable[bytes], on_line: Optional[Callable[[bytes], None]] = None) -> tuple:
        """Feeds the script; each output line goes to ``on_line``. Returns (exit code, first error)."""
        proc = self._popen(self.argv(), stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE if on_line else subprocess.DEVNULL, stderr=subprocess.PIPE)
        errors: list = []
        threads = [threading.Thread(target=lambda: errors.append(proc.stderr.read()), daemon=True)]
        if on_line:
            def read_out() -> None:
                for line in proc.stdout:
                    on_line(line)
            threads.append(threading.Thread(target=read_out, daemon=True))
        for t in threads:
            t.start()
        try:
            for data in chunks:
                proc.stdin.write(data)
            proc.stdin.close()
        except BrokenPipeError:  # psql stopped on an error: its exit code says so
            pass
        code = proc.wait()
        for t in threads:
            t.join()
        err = b"".join(e for e in errors if e).decode("utf-8", "replace")
        return code, first_error(err) if code else ""

    def json(self, sql: str) -> Any:
        lines: list = []
        script = ("SET default_transaction_read_only = on;\n"
                  f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({sql}) t;\n")
        code, err = self.run([script.encode()], on_line=lines.append)
        if code != 0:
            raise RuntimeError(f"psql failed (exit {code}): {err}")
        # json_agg writes one element per line: the answer is the whole output.
        text = b"".join(lines).decode("utf-8", "replace").strip()
        return json.loads(text) if text else []


def owner_id_of(psql: Psql, email: str) -> Optional[str]:
    rows = psql.json(f"SELECT id FROM users WHERE email = {runner.lit(email)}")
    return str(rows[0]["id"]) if rows else None


def table_columns(psql: Psql) -> dict:
    names = ", ".join(runner.lit(t.name) for t in TABLES)
    rows = psql.json("SELECT table_name, column_name FROM information_schema.columns "
                     f"WHERE table_schema = current_schema() AND table_name IN ({names}) "
                     "ORDER BY table_name, ordinal_position")
    out: dict = {}
    for row in rows:
        out.setdefault(row["table_name"], []).append(row["column_name"])
    return out


def library_summary(psql: Psql, owner_id: str) -> list:
    """Per resource: its type, storage, live entry count and stored pages (counts only)."""
    o = runner.lit(owner_id)
    return psql.json(
        "SELECT r.slug, r.resource_type, r.storage_mode, r.map_version, r.has_login, "
        "(SELECT count(*) FROM tradecraft_entries e WHERE e.resource_id = r.id AND e.generation = r.generation) AS entries, "
        "(SELECT count(*) FROM tradecraft_entries e WHERE e.resource_id = r.id AND e.generation = r.generation "
        "AND e.stored_text IS NOT NULL) AS stored_pages "
        f"FROM user_tradecraft_resources r WHERE r.user_id = {o} ORDER BY r.slug")


# --------------------------------------------------------------------------------------
# The stamp: what the snapshot was built from
# --------------------------------------------------------------------------------------

def hash_files(files: Iterable) -> str:
    """One hash of the ingestion code from (relative path, sha256 hex) pairs, whatever holds the
    files: the running agent's image or a working tree."""
    h = hashlib.sha256()
    for rel, digest in sorted(files):
        h.update(str(rel).encode() + b"\0")
        h.update(str(digest).encode() + b"\n")
    return h.hexdigest()


def ingest_hash(root: Path = INGEST_DIR) -> str:
    """The ingestion code of a working tree (the checkout's HEAD may not even track it)."""
    return hash_files((p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
                      for p in root.rglob("*.py") if "__pycache__" not in p.parts)


# The agent image's ingestion code, listed read-only inside the running container.
AGENT_INGEST_SCRIPT = r"""
import hashlib, json, pathlib
root = pathlib.Path("/app/tradecraft/ingest")
print(json.dumps([[p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()]
                  for p in root.rglob("*.py") if "__pycache__" not in p.parts]))
"""


def running_ingest_hash(run: Callable[..., Any] = subprocess.run, container: str = runner.AGENT_CONTAINER,
                        root: Path = INGEST_DIR) -> tuple:
    """(hash, source): the ingestion code the RUNNING agent holds, which is what built the
    library, never a shared working tree another session may be editing. Only when the agent's
    container cannot be read, the working tree's, and the source says so."""
    try:
        done = run(["docker", "exec", "-i", container, "python", "-c", AGENT_INGEST_SCRIPT], capture_output=True,
                   text=True, timeout=60, check=False)
        files = json.loads((done.stdout or "").strip().splitlines()[-1]) if done.returncode == 0 else None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        files = None
    if isinstance(files, list) and files:
        return hash_files((str(f[0]), str(f[1])) for f in files), f"the running agent ({container})"
    return ingest_hash(root), "the working tree (the agent's container could not be read)"


def plan_commit(run: Callable[..., Any] = subprocess.run) -> str:
    for ref in (PLAN_BRANCH, "HEAD"):
        done = run(["git", "-C", str(REPO), "rev-parse", "--verify", "--quiet", ref], capture_output=True, text=True,
                   check=False, timeout=30)
        if done.returncode == 0 and done.stdout.strip():
            return done.stdout.strip()
    return ""


def read_stamp(folder: Path = SNAPSHOT_DIR) -> Optional[dict]:
    try:
        stamp = json.loads((folder / STAMP).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return stamp if isinstance(stamp, dict) else None


def stamp_warning(stamp: Optional[Mapping], root: Path = INGEST_DIR,
                  current: Optional[Callable[[], tuple]] = None) -> Optional[str]:
    """A warning when the ingestion code the running agent holds differs from the one the
    library was built with: the snapshot then no longer shows what that code would ingest, so
    the library is rebuilt. ``current`` gives (hash, source); by default the running agent's."""
    if not stamp:
        return None
    now, source = (current or (lambda: running_ingest_hash(root=root)))()
    if stamp.get("ingest_hash") != now:
        return (f"the ingestion code of {source} differs from the one the library was built with (commit "
                f"{str(stamp.get('commit', ''))[:12] or '?'}): rebuild it (library.py build, then snapshot)")
    return None


def file_problems(stamp: Mapping, folder: Path) -> list:
    """Each file of the stamp, whole and unchanged: checked before restore touches the database."""
    problems = []
    for table in TABLES:
        meta = (stamp.get("tables") or {}).get(table.name)
        if not isinstance(meta, dict):
            problems.append(f"the snapshot has no {table.name}")
            continue
        path = folder / str(meta.get("file", ""))
        try:
            data = path.read_bytes()
        except OSError:
            problems.append(f"{path.name} is missing")
            continue
        if hashlib.sha256(data).hexdigest() != meta.get("sha256") or data.count(b"\n") != meta.get("rows"):
            problems.append(f"{path.name} does not match the stamp")
    return problems


# --------------------------------------------------------------------------------------
# snapshot, restore
# --------------------------------------------------------------------------------------

class Splitter:
    """Writes psql's one output stream to one file per table, cut at the marker lines."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.meta: dict = {}
        self.problem = ""
        self._fh = None
        self._name = ""
        self._hash = None

    def line(self, raw: bytes) -> None:
        if raw.startswith(MARK_B):
            self._finish()
            name = raw[len(MARK_B):].strip().decode("ascii", "replace")
            if name not in {t.name for t in TABLES} or name in self.meta:
                self.problem = self.problem or f"an unexpected table marker {name!r}"
                return
            self._name, self._hash = name, hashlib.sha256()
            path = self.folder / f"{name}.copy"
            self._fh = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb")
            self.meta[name] = {"file": path.name, "rows": 0, "bytes": 0}
        elif self._fh is None:
            self.problem = self.problem or "rows before the first table marker"
        else:
            self._fh.write(raw)
            self._hash.update(raw)
            self.meta[self._name]["rows"] += 1
            self.meta[self._name]["bytes"] += len(raw)

    def _finish(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self.meta[self._name]["sha256"] = self._hash.hexdigest()
            self._fh = None

    def close(self) -> None:
        self._finish()


SNAPSHOT_FILES = frozenset({STAMP} | {f"{t.name}.copy" for t in TABLES})


def snapshot_folder_problem(folder: Path, *, stamp_required: bool = True) -> Optional[str]:
    """Why ``folder`` may not be replaced or removed, or None. Only a folder this script made may
    be: absent, or holding nothing but a snapshot's files (the snapshot itself also its stamp).
    A parent folder, a checkout or any other folder is refused, whatever ``--dir`` names."""
    if not os.path.lexists(folder):
        return None
    if folder.is_symlink() or not folder.is_dir():
        return f"{folder} is not a folder this script made (a file or a link): nothing was changed"
    foreign = sorted(p.name for p in folder.iterdir() if p.name not in SNAPSHOT_FILES or p.is_symlink() or not p.is_file())
    if foreign:
        more = ", ..." if len(foreign) > 5 else ""
        return f"{folder} holds what a snapshot never writes ({', '.join(foreign[:5])}{more}): nothing was changed"
    if stamp_required:
        stamp = read_stamp(folder)
        if not stamp or stamp.get("format") != STAMP_FORMAT or not isinstance(stamp.get("tables"), dict):
            return f"{folder} holds no stamp of this script: not a snapshot folder, nothing was changed"
    return None


def _work_folders(folder: Path) -> tuple:
    return folder.parent / f".{folder.name}.new", folder.parent / f".{folder.name}.old"


def folders_problem(folder: Path) -> Optional[str]:
    """The snapshot folder and its two working siblings, all checked before anything is written."""
    new, old = _work_folders(folder)
    return (snapshot_folder_problem(folder) or snapshot_folder_problem(new, stamp_required=False)
            or snapshot_folder_problem(old, stamp_required=False))


def _remove(path: Path, *, stamp_required: bool = False) -> None:
    """Removes a folder only when it is one this script made (checked again at the removal)."""
    problem = snapshot_folder_problem(path, stamp_required=stamp_required)
    if problem:
        raise RuntimeError(problem)
    shutil.rmtree(path, ignore_errors=True)


def _private_dir(path: Path) -> None:
    _remove(path)
    path.mkdir(parents=True, mode=0o700)


def _swap_in(new: Path, target: Path) -> None:
    """The new snapshot replaces the old one only once it is whole."""
    _, old = _work_folders(target)
    _remove(old)
    if os.path.lexists(target):
        problem = snapshot_folder_problem(target)
        if problem:
            raise RuntimeError(problem)
        target.rename(old)
    new.rename(target)
    _remove(old)


def library_owner_problem(email: str) -> Optional[str]:
    """Snapshot and restore read or replace one library only: the e2e owner's."""
    if email != LIBRARY_OWNER:
        return f"{email!r} is not the e2e library's owner {LIBRARY_OWNER}: no other account's library is read or replaced"
    return runner.e2e_account_problem(email)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def snapshot(psql: Psql, owner_email: str, *, folder: Path = SNAPSHOT_DIR, log: Callable[[str], None] = print,
             commit: Optional[str] = None, code_hash: Optional[str] = None) -> int:
    # Both before the database is read and before anything on disk is touched.
    problem = library_owner_problem(owner_email) or folders_problem(folder)
    if problem:
        log(f"snapshot: refused: {problem}")
        return EXIT_FAILED
    owner_id = owner_id_of(psql, owner_email)
    if not owner_id:
        log(f"snapshot: no account {owner_email}: build the library first")
        return EXIT_FAILED
    columns = table_columns(psql)
    missing = [t.name for t in TABLES if t.name not in columns]
    if missing:
        log(f"snapshot: the database has no {', '.join(missing)}: is the plan's schema pushed?")
        return EXIT_FAILED
    summary = library_summary(psql, owner_id)
    new, _ = _work_folders(folder)
    hash_source = running_ingest_hash() if code_hash is None else (code_hash, "given")
    _private_dir(new)
    splitter = Splitter(new)
    code, err = psql.run([snapshot_script(columns, owner_id).encode()], on_line=splitter.line)
    splitter.close()
    absent = [t.name for t in TABLES if t.name not in splitter.meta]
    if code != 0 or splitter.problem or absent:
        _remove(new)
        why = err or splitter.problem or f"no rows section for {', '.join(absent)}"
        log(f"snapshot: refused, the previous snapshot is kept: {why}")
        return EXIT_FAILED
    tables = {}
    for t in TABLES:
        tables[t.name] = {**splitter.meta[t.name], "columns": snapshot_columns(t, columns[t.name])}
    stamp = {
        "format": STAMP_FORMAT,
        "taken_at": now_iso(),
        "commit": plan_commit() if commit is None else commit,
        "ingest_hash": code_hash if code_hash is not None else hash_source[0],
        "ingest_hash_of": "given" if code_hash is not None else hash_source[1],
        "owner_email": owner_email,
        "owner_id": owner_id,
        "tables": tables,
        "resources": summary,
    }
    path = new / STAMP
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fh:
        json.dump(stamp, fh, indent=2, sort_keys=True)
    _swap_in(new, folder)
    rows = sum(m["rows"] for m in tables.values())
    size = sum(m["bytes"] for m in tables.values())
    log(f"snapshot: {len(summary)} resources, {rows} rows, {size / 1e6:.1f} MB in {folder}")
    return EXIT_OK


def restore(psql: Psql, owner_email: str, *, folder: Path = SNAPSHOT_DIR, log: Callable[[str], None] = print,
            login_slug: Optional[str] = None) -> int:
    """``login_slug``: the resource that gets the card's fake login back (S2, S3)."""
    problem = library_owner_problem(owner_email)
    if problem:
        log(f"restore: refused: {problem}")
        return EXIT_FAILED
    stamp = read_stamp(folder)
    if stamp is None:
        log(f"restore: no snapshot in {folder}: build the library and snapshot it first")
        return EXIT_NO_SNAPSHOT
    if stamp.get("owner_email") != owner_email:
        log(f"restore: refused: the snapshot is {stamp.get('owner_email')!r}'s library, not {owner_email!r}'s")
        return EXIT_FAILED
    if stamp.get("format") != STAMP_FORMAT:
        log(f"restore: the snapshot's format {stamp.get('format')!r} is not {STAMP_FORMAT}: snapshot again")
        return EXIT_FAILED
    problems = file_problems(stamp, folder)
    if problems:
        log("restore: refused before touching the database: " + "; ".join(problems))
        return EXIT_FAILED
    owner_id = owner_id_of(psql, owner_email)
    if not owner_id:
        log(f"restore: no account {owner_email}: the runner's preflight creates it")
        return EXIT_FAILED
    columns = table_columns(psql)
    for table in TABLES:
        gone = [c for c in stamp["tables"][table.name]["columns"] if c not in columns.get(table.name, [])]
        if gone:
            log(f"restore: {table.name} no longer has {', '.join(gone)}: rebuild the library")
            return EXIT_FAILED
    started = time.monotonic()
    code, err = psql.run(stream_parts(restore_parts(stamp, owner_id, folder, login_slug)))
    if code != 0:
        log(f"restore: failed, nothing changed (exit {code}): {err}")
        return EXIT_FAILED
    rows = sum(int(m["rows"]) for m in stamp["tables"].values())
    log(f"restore: {len(stamp.get('resources') or [])} resources, {rows} rows in {time.monotonic() - started:.0f} s"
        + (" (the owner's id changed since the snapshot: rows moved to the new one)"
           if stamp.get("owner_id") != owner_id else ""))
    return EXIT_OK


# --------------------------------------------------------------------------------------
# library.yaml
# --------------------------------------------------------------------------------------

def library_problems(lib: Any) -> list:
    if not isinstance(lib, dict) or not isinstance(lib.get("resources"), list):
        return ["library.yaml has no resources list"]
    problems = []
    seen = set()
    for i, spec in enumerate(lib["resources"]):
        where = f"resources[{i}]"
        if not isinstance(spec, dict):
            problems.append(f"{where} is not a mapping")
            continue
        for key in ("slug", "preset", "name", "url", "storage", "expect"):
            if key not in spec:
                problems.append(f"{where} has no {key}")
        slug = str(spec.get("slug", ""))
        if not SLUG_RE.match(slug):
            problems.append(f"{where}: {slug!r} is not a resource ID")
        if slug in seen:
            problems.append(f"{where}: {slug} twice")
        seen.add(slug)
        if spec.get("storage") not in STORAGE_MODES:
            problems.append(f"{slug}: storage is live or stored")
        if spec.get("forcedType", "") not in ("",) + SITE_TYPES:
            problems.append(f"{slug}: forcedType {spec.get('forcedType')!r} is not a type")
        if (spec.get("expect") or {}).get("type") not in SITE_TYPES:
            problems.append(f"{slug}: expect.type is not a type")
        focus = spec.get("focus") or {}
        if focus and focus.get("mode") not in FOCUS_MODES:
            problems.append(f"{slug}: focus.mode is one of {', '.join(FOCUS_MODES)}")
        if spec.get("preview") and focus.get("mode") not in ("focused", "tagOnly"):
            problems.append(f"{slug}: a focus preview needs a Focused or Tag only focus")
    if lib.get("fake_login") != {"cookie": FAKE_COOKIE}:
        problems.append(f"library.yaml's fake_login is the card's fake value only: {{cookie: {FAKE_COOKIE}}}")
    return problems


def load_library(path: Path = LIBRARY_YAML) -> dict:
    lib = runner.load_yaml(path.read_text(encoding="utf-8"))
    problems = library_problems(lib)
    if problems:
        raise runner.YamlError(f"{path.name}: " + "; ".join(problems))
    return lib


def scenario_problems(lib: Mapping, scn: Mapping) -> list:
    """library.yaml builds what scenarios.yaml's matrix reads."""
    want = scn["library"]
    slugs = [r["slug"] for r in lib["resources"]]
    problems = []
    if sorted(slugs) != sorted(want["resources"]):
        problems.append(f"the library's slugs {sorted(slugs)} are not scenarios.yaml's {sorted(want['resources'])}")
    stored = sorted(r["slug"] for r in lib["resources"] if r["storage"] == "stored")
    if stored != sorted(want["stored"]):
        problems.append(f"the Stored resources {stored} are not scenarios.yaml's {sorted(want['stored'])}")
    logins = [r["slug"] for r in lib["resources"] if r.get("login")]
    if logins != [want["login_resource"]]:
        problems.append(f"the resources with a login {logins} are not [{want['login_resource']}]")
    return problems


def check_url_body(spec: Mapping, fake_login: Mapping) -> dict:
    body: dict = {"url": spec["url"]}
    if spec.get("forcedType"):
        body["forcedType"] = spec["forcedType"]
    if spec.get("overrides"):
        body["overrides"] = copy.deepcopy(spec["overrides"])
    if spec.get("login"):
        body["credentials"] = dict(fake_login)
    return body


def prefill_from_check(result: Mapping, overrides: Mapping) -> dict:
    """What the form fills from Check URL (ResourceFormV2.prefillFromCheck): the CVE pattern it
    found, when none is set."""
    out = copy.deepcopy(dict(overrides))
    if result.get("ok") and result.get("cve_pattern") and "type.cve.pathPatterns" not in out:
        out["type.cve.pathPatterns"] = [result["cve_pattern"]]
    return out


def resource_type(spec: Mapping) -> str:
    return spec.get("forcedType") or spec["expect"]["type"]


def create_body(spec: Mapping, model: str, overrides: Mapping, fake_login: Mapping) -> dict:
    """The Add form's body (ResourceFormV2's save of a new resource)."""
    body: dict = {
        "name": spec["name"], "url": spec["url"], "llmModel": model, "enabled": True,
        "storageMode": spec["storage"], "slug": spec["slug"], "presetKey": spec["preset"],
    }
    if spec.get("forcedType"):
        body["forcedType"] = spec["forcedType"]
    if overrides:
        body["overrides"] = copy.deepcopy(dict(overrides))
    focus = spec.get("focus") or {}
    # A CVE archive has no page list to focus, and Everything is no focus at all.
    if focus and focus.get("mode") != "everything" and resource_type(spec) != "cve-poc-db":
        body["focus"] = copy.deepcopy(dict(focus))
    if spec.get("login"):
        body["credentials"] = dict(fake_login)
    return body


def preview_body(spec: Mapping, model: str, entries: Sequence[Mapping]) -> dict:
    return {"focus": copy.deepcopy(dict(spec["focus"])), "llmModel": model,
            "entries": [{"url": e["url"], "title": str(e.get("title", ""))[:300]} for e in entries[:PREVIEW_ENTRIES]]}


def focus_mode(raw: Any) -> str:
    """A focus mode as the agent spells it (``ingest/focus.py`` ``mode_of``): the form and the
    database write ``tagOnly``, the agent's report ``tag_only``."""
    key = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    key = "tag_only" if key == "tagonly" else key
    return key if key in AGENT_FOCUS_MODES else "everything"


def judge(spec: Mapping, view: Mapping, job: Optional[Mapping]) -> list:
    """The build's checks on one resource: its job, type, map size, storage, readiness, login
    and focus (counts and names only)."""
    exp = spec["expect"]
    rep = view.get("report") or {}
    status = (job or {}).get("status", "none")
    out = [
        report.CheckResult("job_succeeded", status == "succeeded",
                           f"{status} {(job or {}).get('errorCode', '')}".strip()),
        report.CheckResult("type", view.get("resourceType") == exp["type"],
                           f"{view.get('resourceType')} (expected {exp['type']})"),
        report.CheckResult("map_size", int(view.get("entryCount") or 0) >= int(exp.get("min_entries", 1)),
                           f"{view.get('entryCount')} entries (at least {exp.get('min_entries', 1)})"),
        report.CheckResult("storage", view.get("storageMode") == spec["storage"], str(view.get("storageMode"))),
        report.CheckResult("login", bool(view.get("hasLogin")) == bool(spec.get("login")), f"hasLogin={view.get('hasLogin')}"),
    ]
    if exp.get("min_stored_pages") is not None:
        pages = int(((rep.get("stored") or {}).get("pages")) or 0)
        out.append(report.CheckResult("stored_pages", pages >= int(exp["min_stored_pages"]),
                                      f"{pages} stored (at least {exp['min_stored_pages']})"))
    if exp["type"] != "cve-poc-db":
        readiness = rep.get("readiness") or {}
        out.append(report.CheckResult("readiness", bool(readiness), json.dumps(readiness, sort_keys=True)))
    mode = focus_mode((spec.get("focus") or {}).get("mode"))
    if mode != "everything":
        got = focus_mode((rep.get("focus") or {}).get("mode"))
        out.append(report.CheckResult("focus_applied", got == mode, json.dumps(rep.get("focus") or {}, sort_keys=True)))
    if exp.get("min_dropped") is not None:
        dropped = int(((rep.get("focus") or {}).get("dropped")) or 0)
        out.append(report.CheckResult("focus_dropped", dropped >= int(exp["min_dropped"]),
                                      f"{dropped} entries dropped by the focus (at least {exp['min_dropped']})"))
    return out


def report_counts(view: Mapping) -> dict:
    """The report's numbers for the build record: never a URL, never page text."""
    rep = view.get("report") or {}
    keep = ("visited", "kept", "skipped", "stopReason", "llmCalls", "durationSec", "stored", "focus", "readiness", "errors")
    return {k: rep[k] for k in keep if k in rep}


# --------------------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------------------

@dataclass
class Outcome:
    slug: str
    checks: list = field(default_factory=list)
    resource_id: str = ""
    detected_type: str = ""
    preview: Optional[dict] = None
    counts: dict = field(default_factory=dict)
    entries: int = 0
    seconds: float = 0.0
    note: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def fail(self, name: str, detail: str) -> "Outcome":
        self.checks.append(report.CheckResult(name, False, detail))
        return self


def model_ids(http: runner.Http, uid: str) -> list:
    """The model ids the account may pick (its own providers' and any instance provider's),
    without Agent in the Loop's. The route lists them only for a body naming the account
    (``api/models/route.ts``); it reads the signed-in person's, whatever the id says."""
    res = http.call("POST", "/api/models", {"userId": uid}, timeout=90)
    groups = res.data if res.ok and isinstance(res.data, dict) else {}
    ids = []
    for items in groups.values():
        for item in items if isinstance(items, list) else []:
            mid = str((item or {}).get("id", "")) if isinstance(item, dict) else ""
            if mid and not mid.startswith(LOOP_PREFIX):
                ids.append(mid)
    return ids


def provider_problem(http: runner.Http, uid: str) -> Optional[str]:
    """MC-9: the account has a model provider (its own, tested; or one the install offers it)."""
    providers = http.call("GET", f"/api/users/{uid}/llm-providers")
    own = providers.data if isinstance(providers.data, list) else []
    if own:
        test = http.call("POST", f"/api/users/{uid}/llm-providers/{own[0].get('id')}/test", {}, timeout=120)
        return None if test.ok else f"the account's model provider test answered {test.status} {test.code}"
    if model_ids(http, uid):
        return None
    return "the account has no model provider (MC-9: a person adds one acting as it; nothing copies a key)"


class Builder:
    def __init__(self, lib: Mapping, scn: Mapping, http: runner.Http, uid: str, model: str,
                 log: Callable[[str], None], *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.lib, self.scn, self.http, self.uid, self.model, self.log = lib, scn, http, uid, model, log
        self.clock, self.sleep = clock, sleep
        self.base = f"/api/users/{uid}/tradecraft-resources"
        self.fake_login = dict(lib["fake_login"])
        self.outcomes: dict = {}

    # -- the account ---------------------------------------------------------------------

    def prepare(self) -> list:
        """The librarian model (the add's gate while Librarian use is "Agent decides") and the
        search settings the matrix expects."""
        problems = []
        res = self.http.call("PUT", f"/api/users/{self.uid}/settings",
                             {"featureModels": {"tradecraft_librarian": self.model}})
        if not res.ok:
            problems.append(f"setting the librarian model answered {res.status} {res.code}")
        search = dict(self.scn.get("owner_search") or {})
        res = self.http.call("PUT", f"/api/users/{self.uid}/tradecraft-settings", {"search": search})
        if not res.ok:
            problems.append(f"setting the search settings answered {res.status} {res.code}")
        return problems

    def listing(self) -> dict:
        res = self.http.call("GET", self.base)
        rows = res.data if isinstance(res.data, list) else (res.data or {}).get("resources", []) if isinstance(res.data, dict) else []
        if not res.ok:
            raise RuntimeError(f"the resource list answered {res.status} {res.code}")
        return {str(r.get("slug")): r for r in rows if isinstance(r, dict)}

    def delete(self, view: Mapping, why: str) -> None:
        res = self.http.call("DELETE", f"{self.base}/{view.get('id')}")
        self.log(f"{view.get('slug')}: deleted ({why}): {res.status}")

    # -- one resource --------------------------------------------------------------------

    def start(self, spec: Mapping) -> Optional[str]:
        """Check URL, the preview, Add; the new resource's id, or None (the outcome says why)."""
        slug = spec["slug"]
        out = self.outcomes[slug] = Outcome(slug)
        res = self.http.call("POST", f"{self.base}/check-url", check_url_body(spec, self.fake_login),
                             timeout=CHECK_URL_TIMEOUT)
        result = (res.data or {}).get("result") if isinstance(res.data, dict) else None
        if not res.ok or not isinstance(result, dict) or not result.get("ok"):
            code = (result or {}).get("error_code") or res.code
            out.fail("check_url", f"{res.status} {code}".strip())
            return None
        out.detected_type = str(result.get("detected_type") or "")
        index = result.get("index") or {}
        out.checks.append(report.CheckResult(
            "check_url", True, f"type {out.detected_type or 'auto'}, index {index.get('kind', 'none')} "
                               f"({index.get('count', 0)}), {len(result.get('sample_entries') or [])} sample entries"))
        if spec.get("preview"):
            entries = result.get("sample_entries") or []
            if not entries:
                out.fail("focus_preview", "Check URL found no entries to preview")
            else:
                res = self.http.call("POST", f"{self.base}/focus-preview", preview_body(spec, self.model, entries),
                                     timeout=PREVIEW_TIMEOUT)
                prev = (res.data or {}).get("result", res.data) if isinstance(res.data, dict) else None
                if res.ok and isinstance(prev, dict) and "kept" in prev:
                    out.preview = {k: prev.get(k) for k in ("kept", "maybe", "dropped")}
                    out.checks.append(report.CheckResult("focus_preview", True, json.dumps(out.preview, sort_keys=True)))
                else:
                    out.fail("focus_preview", f"{res.status} {res.code}".strip())
        overrides = prefill_from_check(result, spec.get("overrides") or {})
        res = self.http.call("POST", self.base, create_body(spec, self.model, overrides, self.fake_login), timeout=120)
        view = (res.data or {}).get("resource") if isinstance(res.data, dict) else None
        if res.status != 201 or not isinstance(view, dict) or not view.get("id"):
            out.fail("added", f"{res.status} {res.code}".strip())
            return None
        out.resource_id = str(view["id"])
        self.log(f"{slug}: added ({spec['storage']}, {out.detected_type or resource_type(spec)}); ingesting")
        return out.resource_id

    def finish(self, spec: Mapping, view: Mapping, started: float) -> None:
        out = self.outcomes.setdefault(spec["slug"], Outcome(spec["slug"]))
        out.resource_id = str(view.get("id", out.resource_id))
        out.checks += judge(spec, view, view.get("job"))
        out.counts = report_counts(view)
        out.entries = int(view.get("entryCount") or 0)
        out.seconds = round(self.clock() - started, 1)
        verdict = "ok" if out.ok else "FAILED: " + ", ".join(f"{c.name} ({c.detail})" for c in out.checks if not c.ok)
        self.log(f"{spec['slug']}: {out.entries} entries, {out.counts.get('stored', {}).get('pages', 0)} stored; {verdict}")

    # -- the whole library ---------------------------------------------------------------

    def run(self) -> dict:
        specs = list(self.lib["resources"])
        by_slug = {s["slug"]: s for s in specs}
        existing = self.listing()
        for slug, view in existing.items():
            if slug not in by_slug:
                self.delete(view, "not in library.yaml")
        pending: list = []
        inflight: dict = {}  # slug -> (resource id, started)
        for spec in specs:
            view = existing.get(spec["slug"])
            status = ((view or {}).get("job") or {}).get("status")
            if view is None:
                pending.append(spec)
            elif view.get("url") != spec["url"]:
                self.delete(view, "another URL")
                pending.append(spec)
            elif status == "succeeded" and view.get("mapVersion") == 3:
                self.outcomes[spec["slug"]] = Outcome(spec["slug"], note="built by an earlier run")
                self.finish(spec, view, self.clock())
            elif status in ("queued", "running"):
                self.outcomes[spec["slug"]] = Outcome(spec["slug"], resource_id=str(view["id"]), note="was ingesting")
                inflight[spec["slug"]] = (str(view["id"]), self.clock())
            else:
                self.delete(view, f"its last job {status or 'never ran'}")
                pending.append(spec)
        parallel = max(1, int(self.lib.get("parallel", 2)))
        deadline = self.clock() + float(self.lib.get("timeout_min", 240)) * 60
        per_resource = float(self.lib.get("resource_timeout_min", 120)) * 60
        poll = float(self.lib.get("poll_sec", 20))
        last_progress = 0.0
        while pending or inflight:
            while pending and len(inflight) < parallel and self.clock() < deadline:
                spec = pending.pop(0)
                rid = self.start(spec)
                if rid:
                    inflight[spec["slug"]] = (rid, self.clock())
            if not inflight:
                if pending and self.clock() >= deadline:
                    for spec in pending:
                        self.outcomes[spec["slug"]] = Outcome(spec["slug"]).fail("added", "not started: the build's time ran out")
                    pending = []
                continue
            self.sleep(poll)
            views = {str(v.get("id")): v for v in self.listing().values()}
            now = self.clock()
            for slug, (rid, started) in list(inflight.items()):
                view = views.get(rid)
                job = (view or {}).get("job") or {}
                if view is None:
                    self.outcomes[slug].fail("added", "the resource disappeared")
                    del inflight[slug]
                elif job.get("status") in JOB_ENDED:
                    self.finish(by_slug[slug], view, started)
                    del inflight[slug]
                elif now - started > per_resource or now > deadline:
                    self.http.call("DELETE", f"{self.base}/{rid}/jobs")
                    self.outcomes[slug].fail("job_succeeded", f"cancelled after {(now - started) / 60:.0f} min")
                    del inflight[slug]
            if now - last_progress >= 120 and inflight:
                last_progress = now
                for slug, (rid, started) in inflight.items():
                    job = (views.get(rid) or {}).get("job") or {}
                    prog = job.get("progress") or {}
                    self.log(f"{slug}: {job.get('status')} {job.get('stage', '')} "
                             f"{prog.get('done', 0)}/{prog.get('total', '?')} {prog.get('unit', '')} "
                             f"({(now - started) / 60:.0f} min)")
        return self.outcomes


def build_record(outcomes: Mapping, *, model: str, commit: str, started: str) -> dict:
    return {
        "started": started, "finished": now_iso(), "commit": commit, "model": model,
        "resources": {slug: {
            "ok": o.ok, "note": o.note, "detected_type": o.detected_type, "entries": o.entries,
            "seconds": o.seconds, "preview": o.preview, "report": o.counts,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in o.checks],
        } for slug, o in outcomes.items()},
    }


def _write_private(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


# --------------------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------------------

def _owner_session(scn: Mapping, redact: report.Redactor, log: runner.Log) -> tuple:
    """The e2e owner signed in, after the seed (which refuses any address but the e2e accounts)."""
    problem = library_owner_problem(scn["accounts"]["owner"])
    if problem:
        raise ValueError(problem)
    env = runner.read_env(REPO / ".env", redact)
    stack = runner.Stack(env, redact, log)
    if not runner._wait_http(stack.webapp + "/api/health", 10):
        raise ConnectionError("the webapp does not answer")
    accounts = runner.seed_accounts(scn["accounts"], redact)
    return stack.session(accounts["owner"].email, accounts["owner"].password)


def cmd_plan(lib: Mapping, scn: Mapping, model: str, out: Callable[[str], None] = print) -> int:
    problems = scenario_problems(lib, scn)
    out(f"Tradecraft e2e library: {len(lib['resources'])} resources for {scn['accounts']['owner']} "
        f"(plan: no stack, no network)")
    out(f"  owner search settings: {json.dumps(scn.get('owner_search') or {}, sort_keys=True)}; "
        f"librarian model: {model}")
    fake_login = lib["fake_login"]
    for spec in lib["resources"]:
        body = create_body(spec, model, spec.get("overrides") or {}, fake_login)
        out(f"  {spec['slug']}: Check URL {json.dumps(check_url_body(spec, fake_login), sort_keys=True)}")
        if spec.get("preview"):
            out(f"    focus preview on Check URL's entries: {json.dumps(spec['focus'], sort_keys=True)}")
        out(f"    Add {json.dumps(body, sort_keys=True)}; expect {json.dumps(spec['expect'], sort_keys=True)}")
    stamp = read_stamp()
    out(f"  snapshot: {SNAPSHOT_DIR} " + (f"taken {stamp.get('taken_at')} from {str(stamp.get('commit'))[:12]}"
                                          if stamp else "absent"))
    for p in problems:
        out(f"  PROBLEM: {p}")
    return EXIT_FAILED if problems else EXIT_OK


def cmd_build(lib: Mapping, scn: Mapping, model: str, log: runner.Log, redact: report.Redactor) -> int:
    problems = scenario_problems(lib, scn)
    if problems:
        for p in problems:
            log(f"library.yaml: {p}")
        return EXIT_USAGE
    started = now_iso()
    try:
        http, uid = _owner_session(scn, redact, log)
    except ValueError as exc:
        log(f"build: refused: {exc}")
        return EXIT_USAGE
    except (ConnectionError, RuntimeError) as exc:
        log(f"build: {exc}")
        return EXIT_STACK
    problem = provider_problem(http, uid)
    if problem:
        log(f"build: pending (MC-9): {problem}")
        return EXIT_MC9
    ids = model_ids(http, uid)
    if ids and model not in ids:
        log(f"build: warning: {model} is not among the {len(ids)} models the e2e owner's providers list")
    builder = Builder(lib, scn, http, uid, model, log)
    problems = builder.prepare()
    if problems:
        for p in problems:
            log(f"build: {p}")
        return EXIT_FAILED
    outcomes = builder.run()
    record = build_record(outcomes, model=model, commit=plan_commit(), started=started)
    _write_private(BUILD_RECORD, redact.scrub(record))
    failed = [s for s, o in outcomes.items() if not o.ok]
    log(f"build: {len(outcomes) - len(failed)}/{len(outcomes)} resources passed; record {BUILD_RECORD}"
        + (f"; failed: {', '.join(failed)}" if failed else ""))
    return EXIT_FAILED if failed else EXIT_OK


def cmd_status(out: Callable[[str], None] = print, folder: Path = SNAPSHOT_DIR) -> int:
    stamp = read_stamp(folder)
    if stamp is None:
        out(f"no snapshot in {folder}")
        return EXIT_NO_SNAPSHOT
    rows = sum(int(m.get("rows", 0)) for m in (stamp.get("tables") or {}).values())
    out(f"snapshot taken {stamp.get('taken_at')} from {str(stamp.get('commit'))[:12]}: "
        f"{len(stamp.get('resources') or [])} resources, {rows} rows")
    for r in stamp.get("resources") or []:
        out(f"  {r.get('slug')}: {r.get('resource_type')}, {r.get('storage_mode')}, {r.get('entries')} entries, "
            f"{r.get('stored_pages')} stored")
    problems = file_problems(stamp, folder)
    for p in problems:
        out(f"  PROBLEM: {p}")
    warning = stamp_warning(stamp)
    if warning:
        out(f"  warning: {warning}")
    return EXIT_FAILED if problems else EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=("plan", "models", "build", "snapshot", "restore", "status"))
    ap.add_argument("--model", default="", help="build: the model of every resource and the librarian, one the "
                    "e2e owner's provider serves")
    ap.add_argument("--dir", default=str(SNAPSHOT_DIR), help="snapshot/restore/status: the snapshot folder")
    ap.add_argument("--pg-container", default=runner.POSTGRES_CONTAINER, help="snapshot/restore: the Postgres container")
    ap.add_argument("--pg-user", default="", help="snapshot/restore: the database user (default: the container's)")
    ap.add_argument("--pg-db", default="", help="snapshot/restore: the database (default: the container's)")
    args = ap.parse_args(argv)

    redact = report.Redactor()
    log = runner.Log(redact, prefix="[tc-e2e library]")
    scn = runner.load_scenarios()
    lib = load_library()
    folder = Path(args.dir)
    # Only the e2e owner's library: snapshot and restore refuse any other address.
    owner_email = LIBRARY_OWNER
    if args.command == "plan":
        return cmd_plan(lib, scn, args.model or "<model>", out=lambda s: print(redact(s)))
    if args.command == "status":
        return cmd_status(out=lambda s: print(redact(s)), folder=folder)
    if args.command in ("snapshot", "restore"):
        psql = Psql(args.pg_container, args.pg_user, args.pg_db)
        try:
            if args.command == "snapshot":
                return snapshot(psql, owner_email, folder=folder, log=log)
            return restore(psql, owner_email, folder=folder, log=log, login_slug=scn["library"]["login_resource"])
        except (RuntimeError, OSError) as exc:
            log(f"{args.command}: {type(exc).__name__}: {exc}")
            return EXIT_FAILED
    if args.command == "models":
        try:
            http, uid = _owner_session(scn, redact, log)
        except ValueError as exc:
            log(f"models: refused: {exc}")
            return EXIT_USAGE
        except (ConnectionError, RuntimeError) as exc:
            log(f"models: {exc}")
            return EXIT_STACK
        for mid in model_ids(http, uid):
            print(redact(mid))
        return EXIT_OK
    if not args.model:
        log("build: --model is required: the model of every resource and the librarian")
        return EXIT_USAGE
    return cmd_build(lib, scn, args.model, log, redact)


if __name__ == "__main__":
    sys.exit(main())
