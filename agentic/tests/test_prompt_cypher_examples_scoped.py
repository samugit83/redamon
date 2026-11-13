"""
Every Cypher example the agent prompts teach passes the tenant scoper.

The agent learns its graph queries from these examples, and every query it writes goes through
`graph_db.tenant_filter.scope_query` (agent /graph/exec, MCP query_graph, text-to-Cypher). Since
847b37cb a shared reference node (CVE, MitreData, Capec) is reachable only through a tenant-scoped
node of the same path, and the prompt's "ALL Vulnerabilities" UNION and "All CVEs in the system"
examples, which matched `(c:CVE)` alone, listed every tenant's CVEs and are now refused. An example
the scoper refuses teaches the model a query that fails (or, before the fix, leaked). So every
fenced ```cypher block in agentic/prompts/*.py, split into its queries, and every inline "Good:"
example must pass; the "Bad:" ones stay refused.

Run: ./agentic/run_tests.sh tests/test_prompt_cypher_examples_scoped.py
"""
import re
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
_REPO = _AGENTIC_DIR.parent
for p in (str(_AGENTIC_DIR), str(_REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from graph_db.tenant_filter import TenantScopeError, scope_query
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

_FENCE = re.compile(r"```cypher\n(.*?)```", re.S)
_STARTS_A_QUERY = re.compile(r"^(OPTIONAL\s+MATCH|MATCH|CALL|UNWIND)\b", re.I)


def _queries(block: str):
    """The queries of one fenced block: blank lines separate them, and so does a new MATCH
    after a finished query (a RETURN already seen, not right after UNION). `//` lines dropped.
    A prompt rendered with str.format doubles its braces; the model reads them single."""
    block = block.replace("{{", "{").replace("}}", "}")
    queries, current = [], []

    def flush():
        if current:
            queries.append("\n".join(current))
        current.clear()

    for raw in block.split("\n"):
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("//"):
            continue
        finished = any(re.search(r"\bRETURN\b", q) for q in current)
        after_union = bool(current) and current[-1].upper().startswith("UNION")
        if finished and not after_union and _STARTS_A_QUERY.match(line):
            flush()
        current.append(line)
    flush()
    return queries


def _examples():
    found = []
    for path in sorted((_AGENTIC_DIR / "prompts").glob("*.py")):
        text = path.read_text()
        for match in _FENCE.finditer(text):
            line = text[:match.start()].count("\n") + 1
            for query in _queries(match.group(1)):
                found.append((f"{path.name}:{line}", query))
    return found


def _inline(marker: str):
    found = []
    for path in sorted((_AGENTIC_DIR / "prompts").glob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if f"{marker}:" in line and "MATCH" in line:
                query = line.split(f"{marker}:", 1)[1].split("<-")[0].strip()
                found.append((f"{path.name}:{n}", query))
    return found


@unittest.skipUnless(_HAVE, "graph_db not importable (run in-container)")
class PromptCypherExamplesAreScoped(unittest.TestCase):

    def test_the_scan_finds_the_examples(self):
        self.assertGreaterEqual(len(_examples()), 40, "the fenced-block scan found too few queries")
        self.assertGreaterEqual(len(_inline("Good")), 4)

    def test_every_fenced_example_passes_scope_query(self):
        for where, query in _examples():
            with self.subTest(where=where, query=query[:120]):
                try:
                    scope_query(query, "u", "p")
                except TenantScopeError as e:
                    self.fail(f"{where}: the prompt teaches a query the scoper refuses: {e}")

    def test_every_good_example_passes_and_every_bad_reference_example_is_refused(self):
        for where, query in _inline("Good"):
            with self.subTest(where=where, query=query):
                scope_query(query, "u", "p")
        for where, query in _inline("Bad"):
            if ":CVE" in query:
                with self.subTest(where=where, query=query), self.assertRaises(TenantScopeError):
                    scope_query(query, "u", "p")

    def test_no_example_lists_cves_alone(self):
        for where, query in _examples():
            with self.subTest(where=where):
                self.assertNotRegex(query, r"(?m)^MATCH \(c:CVE\)\s*$", where)


if __name__ == "__main__":
    unittest.main()
