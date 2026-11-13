"""
Tenant-scoping helpers for Cypher queries.

Single source of truth for:
- Inline (user_id, project_id) injection into every node pattern.
- Fail-closed verification that a query really is scoped before it runs.
- Read-only enforcement (write-clause and write-procedure detection).

Imported by both the agent (agentic.tools.Neo4jToolManager) and the
kali-sandbox CLI (mcp/servers/redagraph.py).

Why the scanner instead of one regex: scoping used to be a single
`\\((\\w+):(\\w+)...\\)` substitution, which only recognised `(var:Label)`.
Every other shape the text-to-Cypher LLM can emit - `(n)` with the label
tested in the WHERE, `(n:A:B)`, a backticked label, `(n {prop: 1})` - matched
nothing, so the query ran completely unscoped and returned every tenant's
nodes. That was observed live: an agent asked for "all malicious packages"
reported 4, one of which belonged to a different project.

Injection is therefore best-effort over ALL node-pattern shapes, and
`find_unscoped_node_pattern` is the backstop: anything that still cannot be
proven scoped must not be executed. Callers should use `scope_query`, which
does both.
"""

import bisect
import re
from typing import Iterator, List, Optional, Tuple

_WRITE_CLAUSE_RE = re.compile(
    r'\b(CREATE|MERGE|DELETE|DETACH\s+DELETE|SET|REMOVE|DROP|ALTER|'
    r'LOAD\s+CSV|START\s+DATABASE|STOP\s+DATABASE|GRANT|DENY|REVOKE|'
    r'ENABLE\s+SERVER|DEALLOCATE|REALLOCATE|TERMINATE)\b',
    re.IGNORECASE,
)

_WRITE_PROCEDURE_RE = re.compile(
    r'\bCALL\s+(apoc\.(create|merge|refactor|periodic|trigger|schema|atomic)|'
    r'apoc\.cypher\.(runWrite|doIt)|dbms\.)\b',
    re.IGNORECASE,
)

#: Any `CALL` to a procedure NOT on this list is refused.
#:
#: This is a positive allowlist because the denylist above could not be made to
#: work. Tenant scoping rewrites NODE PATTERNS, and a procedure that takes Cypher
#: as a STRING ARGUMENT carries its query past every pattern-based control:
#:
#:     OPTIONAL MATCH (d:Domain) WITH d LIMIT 1
#:     CALL apoc.cypher.run("MATCH (n) RETURN n.user_id", {}) YIELD value
#:     RETURN value
#:
#: The outer pattern is scoped and the inner string is not even seen - it is a
#: string literal, so `code_positions()` correctly marks it non-code. The result
#: is a full cross-tenant read that every guard approves. `apoc.cypher.runMany`
#: does the same for writes, and `\u0043REATE` inside the literal hides the
#: keyword from `_WRITE_CLAUSE_RE`, which scans raw text. `apoc.load.json` turns
#: the same hole into an SSRF from inside the database container.
#:
#: APOC ships enabled and unrestricted in this deployment
#: (docker-compose.yml NEO4J_PLUGINS / procedures_unrestricted), so none of this
#: is theoretical. No agent or MCP read needs any of it: the legitimate graph
#: queries are MATCH/RETURN over labelled patterns.
_ALLOWED_PROCEDURES = frozenset({
    # The fixed schema op, which is server-controlled and never caller Cypher.
    "db.schema.visualization",
    # Read-only index/constraint introspection used by the schema surfaces.
    "db.labels",
    "db.relationshiptypes",
    "db.propertykeys",
})

_CALL_RE = re.compile(r'\bCALL\s+([A-Za-z_][\w.]*)', re.IGNORECASE)

#: A subquery `CALL { ... }` has no procedure name and is scoped like any other
#: clause, so it is allowed; only a NAMED procedure call is gated.
_CALL_SUBQUERY_RE = re.compile(r'\bCALL\s*\{')


def find_disallowed_procedure(query: str) -> Optional[str]:
    """Return the name of the first CALLed procedure that is not allowlisted.

    Only code positions are inspected, so a procedure name appearing inside a
    string literal is not a false positive. This gates the `CALL <proc>` form;
    `find_disallowed_call` is the broader gate that also covers FUNCTION calls.
    """
    is_code, _ = code_positions(query)
    for m in _CALL_RE.finditer(query):
        # Ignore a match that lies inside a string literal or a comment.
        if not is_code[m.start()]:
            continue
        # `CALL {` subquery: the regex needs a name, so this cannot match, but
        # guard explicitly in case of `CALL  {`.
        if _CALL_SUBQUERY_RE.match(query, m.start()):
            continue
        name = m.group(1)
        if name.lower() not in _ALLOWED_PROCEDURES:
            return name
    return None


#: Built-in FUNCTION namespaces a legitimate read may call. `_ALLOWED_PROCEDURES`
#: covers the fixed schema/introspection PROCEDURES; these are the namespaced
#: functions (temporal, spatial, vector similarity) that appear in real queries.
#: Everything else namespaced-and-called is refused - notably `apoc.*`, whose
#: FUNCTION forms (`apoc.cypher.runFirstColumn*`, `apoc.load.*`) run unscoped
#: Cypher or fetch URLs and are callable ANYWHERE an expression is, never after
#: CALL, so `find_disallowed_procedure` alone never saw them.
_SAFE_CALL_NAMESPACES = frozenset({
    "point", "duration", "date", "time", "datetime", "localtime",
    "localdatetime", "vector",
})

#: A namespaced call: a dotted identifier chain immediately followed by `(`.
#: Matched against `_normalise_calls` output so backticks, whitespace and
#: comments between the parts cannot hide the name.
_NAMESPACED_CALL_RE = re.compile(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(')


def _normalise_calls(cypher: str) -> str:
    """A view of the query for call detection: comments removed, string literals
    blanked, backtick-quoted identifiers unwrapped, and whitespace around `.`
    removed. This defeats `` `apoc`.`cypher`.`run` ``, `apoc . cypher . run` and
    `apoc/**/.cypher.run`, which resolve to the same call but read differently in
    the raw text.
    """
    out: List[str] = []
    n = len(cypher)
    i = 0
    while i < n:
        ch = cypher[i]
        if ch == '/' and i + 1 < n and cypher[i + 1] == '/':
            nl = cypher.find('\n', i)
            i = n if nl == -1 else nl + 1
            out.append(' ')
            continue
        if ch == '/' and i + 1 < n and cypher[i + 1] == '*':
            close = cypher.find('*/', i + 2)
            i = n if close == -1 else close + 2
            out.append(' ')
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            while i < n:
                if cypher[i] == '\\':
                    i += 2
                    continue
                if cypher[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(' ')  # a string literal is data, never a call
            continue
        if ch == '`':
            close = cypher.find('`', i + 1)
            close = n if close == -1 else close
            out.append(cypher[i + 1:close])  # unwrap: the identifier itself
            i = close + 1
            continue
        out.append(ch)
        i += 1
    return re.sub(r'\s*\.\s*', '.', ''.join(out))


def find_disallowed_call(cypher: str) -> Optional[str]:
    """Return the first namespaced procedure OR function call that is not
    allowlisted, or None.

    `find_disallowed_procedure` only gates `CALL <proc>`. APOC exposes the same
    danger as FUNCTIONS, which need no CALL, so this gates every namespaced call
    by the same positive allowlist, on a normalised view of the query.
    """
    for m in _NAMESPACED_CALL_RE.finditer(_normalise_calls(cypher)):
        name = m.group(1)
        root = name.split('.', 1)[0].lower()
        if name.lower() in _ALLOWED_PROCEDURES or root in _SAFE_CALL_NAMESPACES:
            continue
        return name
    return None


#: A relationship carrying `*` (variable length), a quantifier applied to a
#: path/relationship group (`{n,m}`, `{,m}`), or a quantified relationship
#: (`-[:HAS_PORT]->+`, `-->*`, `<--+`). Matched against the code with every space
#: removed: Neo4j accepts whitespace between the parts of an arrow (`- ->+`),
#: and squeezing it out keeps these patterns free of `\s*` runs that backtrack.
_VAR_LENGTH_REL_RE = re.compile(r'\[[^\[\]]*\*[^\[\]]*\]')
_PATH_QUANTIFIER_RE = re.compile(r'[)\]][<>-]*\{[\d,]')
_QUANTIFIED_REL_RE = re.compile(r'(?:\]-+>?|-->?|<--)[+*]')


def _code_only(cypher: str) -> str:
    """The query with string literals, comments and backticked names blanked."""
    is_code, _ = code_positions(cypher)
    return ''.join(c if is_code[i] else ' ' for i, c in enumerate(cypher))


def _relationship_holds_star(squeezed: str) -> bool:
    """True when the brackets of a relationship (`-[ ... ]`) hold a `*`.

    `_VAR_LENGTH_REL_RE` stops at a nested bracket, so a list in the property
    map hid the star: `-[r*1..2 {tags: [1]}]-` is variable-length in Neo4j 5.26.
    One pass with a stack and a running count of stars, so nesting stays linear.
    An unclosed relationship bracket counts as one (fail closed).
    """
    stars_before = [0]
    for char in squeezed:
        stars_before.append(stars_before[-1] + (char == '*'))
    opens: List[int] = []
    for i, char in enumerate(squeezed):
        if char == '[':
            opens.append(i)
        elif char == ']' and opens:
            start = opens.pop()
            if start > 0 and squeezed[start - 1] == '-' and stars_before[i] > stars_before[start]:
                return True
    return any(start > 0 and squeezed[start - 1] == '-' for start in opens)


def has_variable_length_path(cypher: str) -> bool:
    """True when the query uses a variable-length relationship or a quantified
    path pattern.

    Both traverse nodes that are never written as `()` patterns, so
    `inject_tenant_filter` cannot scope them and `find_unscoped_node_pattern`
    cannot see them: a `[*]` hop from an exempt reference node (or between two of
    the caller's own nodes) reaches other tenants' nodes. Refused rather than
    run. Only code positions count, so the same characters inside a string
    literal or comment are ignored.
    """
    squeezed = re.sub(r'\s+', '', _code_only(cypher))
    return bool(
        _VAR_LENGTH_REL_RE.search(squeezed)
        or _relationship_holds_star(squeezed)
        or _PATH_QUANTIFIER_RE.search(squeezed)
        or _QUANTIFIED_REL_RE.search(squeezed)
    )


#: Clauses that read outside the caller's graph rather than through node
#: patterns: `SHOW TRANSACTIONS` lists every session's running query with its
#: parameters (other tenants' ids and search terms), `USE` switches database,
#: `LOAD CSV` fetches a URL from inside the database container. None of them has
#: a pattern to scope. Not after `.`, `:` or `$`: `n.show`, `:Load`, `$use` are
#: a property, a label and a parameter.
_OFF_GRAPH_CLAUSE_RE = re.compile(r'(?<![.:$\w])(SHOW|USE|LOAD)(?!\w)', re.IGNORECASE)


def find_off_graph_clause(cypher: str) -> Optional[str]:
    """Return the first SHOW / USE / LOAD clause keyword (upper case), or None."""
    match = _OFF_GRAPH_CLAUSE_RE.search(_code_only(cypher))
    return match.group(1).upper() if match else None


TENANT_PARAMS = {"tenant_user_id", "tenant_project_id"}
TENANT_PROPS = "user_id: $tenant_user_id, project_id: $tenant_project_id"

#: The label an operator adds to a finding to suppress it as noise. A muted node
#: keeps its functional label and gains this one, so it is still MERGE-able by a
#: re-scan and still un-mutable, but it must be invisible to every agent read.
#:
#: Invisibility is enforced here, at the same chokepoint as tenant isolation and
#: for the same reason: injection touches EVERY node pattern, so there is no
#: query shape - labelled, unlabelled, or a bare `MATCH (n)` - that can reach a
#: muted node. The webapp's Muted-table endpoint is the only legitimate reader,
#: and it does not go through this module.
MUTED_LABEL = "Muted"

#: Labels holding GLOBAL reference data - the public NVD/MITRE catalogue. Each
#: is UNIQUE on its natural id, so there is exactly one node per CVE for the
#: whole database and it carries no tenant property at all. Injecting a tenant
#: filter on one matches nothing, which made the agent blind to every CVE, CWE
#: and CAPEC in the graph.
#:
#: Exempt because they hold no per-tenant data, not because scoping is
#: inconvenient. Two guards keep the exemption from becoming a hole:
#:   - a pattern qualifies only when EVERY label it names is on this list, and
#:     only for a plain `:A` / `:A:B` conjunction. A label EXPRESSION never
#:     qualifies, because `(n:!CVE)` means every node that is NOT a CVE.
#:   - the reference pattern must be joined by relationship patterns to a
#:     tenant-scoped node of the SAME path (`find_unscoped_node_pattern`), so
#:     reference nodes are reachable only by traversing from the caller's own
#:     data. A scoped node elsewhere in the query is no anchor: `MATCH
#:     (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x` would list every
#:     CVE in the database, and which CVEs exist is itself a signal about what
#:     other tenants have scanned.
GLOBAL_REFERENCE_LABELS = frozenset({"CVE", "MitreData", "Capec"})

#: A plain label conjunction and nothing else. Backticks are refused rather than
#: unquoted: a backticked label may contain ':' and would break the split below,
#: and no reference label needs quoting.
_SIMPLE_LABELS_RE = re.compile(r'^(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)+$')

# A Cypher identifier: bare, or backtick-quoted (which may contain spaces).
# The lookahead makes a bare name take its whole word: inside the repeated label
# run below, `aaaa` could otherwise split into idents in 2^n ways, and a failing
# match tried them all (a 30-character label held the agent's event loop for
# minutes).
_IDENT = r'(?:`[^`]*`|[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_]))'

# The inside of a node pattern: optional variable, optional label expression,
# optional inline property map.
#
# The label expression accepts the whole Neo4j 5 grammar - conjunction (`:A:B`,
# `:A&B`), union (`:A|B`), negation (`:!A`) and grouping (`:(A|B)&C`) - rather
# than one operator per label. It has to: mute injection rewrites a label into
# `:X&!Muted`, and `scope_query` re-parses its OWN output through
# `find_unscoped_node_pattern`, so a shape this regex cannot read is reported as
# unscoped and the query is refused. Reading the rewritten form is therefore a
# correctness requirement, not a convenience.
#
# `{` and `}` are deliberately outside the label character set, so the property
# map is never swallowed by the label run.
#
# Whitespace is consumed only BEFORE a token, never on both sides of one: two
# adjacent `\s*` (or `\s*` next to a repeated `\s`) split a run of spaces in
# O(w^2)-O(w^3) ways on a failing match, and `(n` + 600 spaces + `%)` took
# longer than 20 seconds.
_LABEL_EXPR = r'(?:[:|&!()]|' + _IDENT + r'|\s)+'
_LABEL_RUN = r'\s*:(?:\s*(?:[:|&!()]|' + _IDENT + r'))*'
_NODE_INNER_RE = re.compile(
    r'^(?:\s*(?P<var>' + _IDENT + r'))?'
    r'(?P<labels>' + _LABEL_RUN + r')?'
    r'(?:\s*(?P<props>\{.*\}))?\s*$',
    re.DOTALL,
)

# A word as the scanner reads it, Unicode letters included: `MATCH (é)` used to
# hit an ASCII-only regex here and crash with AttributeError, a 500 rather than
# a refusal. Neo4j reads `$` inside a name as a name character, so `AS$p` is
# one variable, not the clause word AS (which ended the pattern region).
_WORD_RE = re.compile(r'[^\W\d][\w$]*')

_MUTED_WORD_RE = re.compile(r'\b' + MUTED_LABEL + r'\b')

# Clauses whose operand is a pattern, and the clauses that end one. Tracking
# this is what tells a node pattern apart from a parenthesised expression:
# `(n)` after MATCH is a node, `(n)` in a RETURN list is not.
_REGION_START = frozenset({'MATCH', 'MERGE', 'CREATE'})
_REGION_END = frozenset({
    'WHERE', 'RETURN', 'WITH', 'UNWIND', 'CALL', 'ORDER', 'SKIP', 'LIMIT',
    'DELETE', 'DETACH', 'SET', 'REMOVE', 'FOREACH', 'UNION', 'YIELD', 'ON',
    'USING', 'AS',
})


#: Words whose `{` opens a subquery. The short forms of the first three hold a
#: bare pattern (`COUNT { (x:Secret) }`), so their brace opens a pattern region.
_PATTERN_SUBQUERY_WORDS = frozenset({'EXISTS', 'COUNT', 'COLLECT'})
_SUBQUERY_WORDS = _PATTERN_SUBQUERY_WORDS | {'CALL'}

#: Words after which `(` opens a pattern or an expression, never a call's
#: arguments: `MATCH(n)` is a node pattern although no space separates them.
#: Mirrors NOT_A_CALL in the webapp's injectProjectFilter.ts.
_NOT_A_CALL = frozenset({
    'MATCH', 'OPTIONAL', 'MERGE', 'CREATE', 'WHERE', 'AND', 'OR', 'XOR', 'NOT',
    'RETURN', 'WITH', 'UNWIND', 'IN', 'AS', 'DISTINCT', 'BY', 'SKIP', 'LIMIT',
    'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'IS', 'UNION', 'CALL', 'YIELD',
    'EXISTS', 'DELETE', 'DETACH', 'SET', 'REMOVE', 'FOREACH', 'ON', 'ANY', 'ALL',
    'SHORTEST', 'PATH', 'PATHS', 'GROUP', 'GROUPS', 'ELEMENTS', 'RELATIONSHIPS',
    'NEXT', 'FILTER', 'LET', 'USE',
})


def names_muted_label(cypher: str) -> bool:
    """True when the query itself mentions the `Muted` label.

    The injection below hides muted nodes, but an agent could still probe for
    them - `MATCH (n) WHERE n:Muted`, or asking for `labels(n)` and filtering.
    Refusing the word outright closes that, and keeps the enforcement honest:
    the agent has no vocabulary for mute at all.

    Only code positions count, so `WHERE n.note CONTAINS 'Muted'` is a string
    literal and stays legal - it cannot leak anything, because the pattern that
    bound `n` already excluded muted nodes. The check is case-sensitive so the
    ordinary property name `muted` is unaffected.
    """
    is_code, _ = code_positions(cypher)
    return any(
        is_code[match.start()] for match in _MUTED_WORD_RE.finditer(cypher)
    )


def find_disallowed_write_operation(cypher: str) -> Optional[str]:
    """Return a disallowed write clause/procedure name, or None for read-only Cypher."""
    proc_match = _WRITE_PROCEDURE_RE.search(cypher)
    if proc_match:
        return proc_match.group(1)

    match = _WRITE_CLAUSE_RE.search(cypher)
    if match:
        return re.sub(r'\s+', ' ', match.group(1).upper())

    return None


class TenantScopeError(Exception):
    """A query could not be proven tenant-scoped and must not be executed.

    Raised by `scope_query`. Callers that regenerate Cypher (the query_graph
    retry loop) should feed the message back to the model; callers that do not
    should surface it as a refusal. Never fall back to running the query.
    """


def code_positions(cypher: str) -> Tuple[List[bool], List[int]]:
    """Per character: is it executable code, and what brace depth is it at.

    Code means outside string literals (', ", `) and outside `//` and `/* */`
    comments, so a keyword or bracket quoted inside a literal is never mistaken
    for syntax. Depth counts `{ }` nesting, which tells a subquery body apart
    from the top level.

    A backslash escapes only inside a string. In a backticked name Neo4j reads it
    literally (a backtick there is escaped by doubling it), so treating `` `x\\` ``
    as an escape ran the name on to the NEXT backtick and hid the clauses in
    between from every check: `WITH d AS `x\\` MATCH (m) RETURN m.name AS `y``
    ran `(m)` unscoped.
    """
    n = len(cypher)
    is_code = [False] * n
    depth = [0] * n
    current_depth = 0
    i = 0
    while i < n:
        ch = cypher[i]
        if ch == '/' and i + 1 < n and cypher[i + 1] == '/':
            newline = cypher.find('\n', i)
            i = n if newline == -1 else newline + 1
            continue
        if ch == '/' and i + 1 < n and cypher[i + 1] == '*':
            close = cypher.find('*/', i + 2)
            i = n if close == -1 else close + 2
            continue
        if ch in ("'", '"', '`'):
            quote = ch
            i += 1
            while i < n:
                if cypher[i] == '\\' and quote != '`':
                    i += 2
                    continue
                if cypher[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == '}':
            current_depth = max(0, current_depth - 1)
        is_code[i] = True
        depth[i] = current_depth
        if ch == '{':
            current_depth += 1
        i += 1
    return is_code, depth


def has_balanced_parens(cypher: str) -> bool:
    """True when every `(` in executable code is closed, and none closes early.

    An unbalanced query is malformed Cypher that Neo4j would reject anyway, but
    it must not reach the scanner: a pattern whose closing paren is missing is
    skipped by `_iter_node_patterns`, so the query can end up with NO patterns to
    scope and sail past the backstop unfiltered. Refusing it keeps the "if it
    cannot be proven scoped it does not run" rule intact.
    """
    is_code, _ = code_positions(cypher)
    depth = 0
    for i, char in enumerate(cypher):
        if not is_code[i]:
            continue
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _paren_pairs(cypher: str, is_code: List[bool]) -> dict:
    """Map each code `(` to the index of its `)`; an unclosed `(` is absent.

    One pass with a stack: scanning forward from every `(` was quadratic, so a
    query of nested parentheses cost seconds per request.
    """
    pairs = {}
    opens: List[int] = []
    for i, char in enumerate(cypher):
        if not is_code[i]:
            continue
        if char == '(':
            opens.append(i)
        elif char == ')' and opens:
            pairs[opens.pop()] = i
    return pairs


def _is_name_char(char: str) -> bool:
    return char.isalnum() or char == '_'


def _is_function_call(cypher: str, open_idx: int, is_code: List[bool]) -> bool:
    """True when the `(` at open_idx opens a call, not a node pattern.

    A call is a name written right against the paren (`count(*)`, `collect(p)`,
    `` `count`(n) ``), while a pattern follows whitespace, an arrow or a clause
    keyword. The keyword case matters: `MATCH(n)` puts MATCH right against the
    paren, and reading it as a function name left the pattern unscoped (a read
    of every tenant's graph). A dotted name (`date.truncate(`) is always a call;
    a number never is, whatever its form (`2e1(n:Domain)` skipped the group).
    """
    if open_idx == 0:
        return False
    prev = cypher[open_idx - 1]
    if not is_code[open_idx - 1]:
        return prev == '`'  # a quoted function name; a comment or string is not a name
    if not _is_name_char(prev):
        return False
    start = open_idx - 1
    while start > 0 and is_code[start - 1] and _is_name_char(cypher[start - 1]):
        start -= 1
    word = cypher[start:open_idx]
    if word[0].isdigit():
        return False
    if start > 0 and is_code[start - 1] and cypher[start - 1] == '.':
        return True
    return word.upper() not in _NOT_A_CALL


_LABEL_GROUP_ONLY_RE = re.compile(r'^' + _LABEL_EXPR + r'$')

_LABEL_TOKEN_RE = re.compile(
    r'\s*(?:(?P<ident>' + _IDENT + r')|(?P<op>[:&|])|(?P<neg>!)'
    r'|(?P<open>\()|(?P<close>\)))'
)


def _is_wellformed_label_expr(labels: str) -> bool:
    """True when `labels` is a label expression Cypher would actually accept.

    `_LABEL_EXPR` is a loose character run, which is right for finding where the
    labels end but wrong for deciding a pattern is understood. It also matches
    the malformed `(n:)`, and injection would then silently "repair" that into
    `(n:!Muted {user_id: .., project_id: ..})` - turning a query Neo4j would have
    rejected outright into one that quietly returns every node in the project.

    So the loose match locates the expression and this validates it: operands and
    operators must alternate, parentheses must balance, and there must be at
    least one actual label. Anything else is reported unparseable and refused,
    which is the fail-closed direction.
    """
    raw = (labels or '').strip()
    if not raw:
        return True
    if not raw.startswith(':'):
        return False

    body = raw[1:]
    pos, depth = 0, 0
    expect_operand = True
    seen_label = False
    while pos < len(body):
        token = _LABEL_TOKEN_RE.match(body, pos)
        if not token:
            return False
        pos = token.end()
        if token.group('ident') is not None:
            if not expect_operand:
                return False
            seen_label = True
            expect_operand = False
        elif token.group('op') is not None:
            if expect_operand:
                return False
            expect_operand = True
        elif token.group('neg') is not None:
            if not expect_operand:  # '!' negates an operand, never follows one
                return False
        elif token.group('open') is not None:
            if not expect_operand:
                return False
            depth += 1
        else:
            if expect_operand or depth == 0:
                return False
            depth -= 1
            expect_operand = False

    return depth == 0 and not expect_operand and seen_label


def _is_label_expression_group(
    cypher: str, open_idx: int, close_idx: int, is_code: List[bool]
) -> bool:
    """True when the `(` at open_idx opens a grouped LABEL expression.

    `MATCH (n:(A|B)&!Muted {...})` contains a parenthesised group that is part of
    the label expression, not a nested node pattern - but the scanner is inside a
    MATCH region and would otherwise yield `(A|B)` as an unscoped pattern and
    refuse the query. That query shape is produced by our own mute injection, so
    without this every union-label query would be rejected.

    Narrow on purpose, so it cannot become a way to smuggle an unscoped pattern
    past the backstop: the group must follow a label operator AND contain nothing
    but label-expression syntax. `{k: (1+2)}` follows a ':' but is not a label
    expression, so it is still reported.
    """
    prev = _prev_code_char(cypher, open_idx, is_code)
    if prev not in (':', '&', '|', '!'):
        return False
    # A label group is never followed by an arrow: `| (y:Secret)-->()` in a list
    # comprehension is a pattern, whatever the character before it.
    if _adjacent_code_char(cypher, close_idx + 1, 1, is_code) in ('-', '<'):
        return False
    return bool(_LABEL_GROUP_ONLY_RE.match(cypher[open_idx + 1:close_idx]))


def _prev_code_char(cypher: str, before: int, is_code: List[bool]) -> Optional[str]:
    for i in range(before - 1, -1, -1):
        if not is_code[i]:
            return '`'  # a backticked identifier ended here
        if not cypher[i].isspace():
            return cypher[i]
    return None


def _adjacent_code_char(cypher: str, start: int, step: int, is_code: List[bool]) -> Optional[str]:
    """The nearest code character from `start` walking by `step` (+1 / -1), past
    whitespace AND anything that is not code. For arrow adjacency: a comment
    between an arrow and its node (`-->/**/(x)`) used to hide the arrow, and a
    pattern comprehension's `(x)` then ran unscoped. Seeing through a string or
    a name as well can only find more arrows, the fail-closed direction.
    """
    i = start
    while 0 <= i < len(cypher):
        if is_code[i] and not cypher[i].isspace():
            return cypher[i]
        i += step
    return None


def _label_run_end(labels: str) -> int:
    """End of the label expression that `labels` (starting with ':') opens.

    Stops at the first token that cannot continue it: `:A WHERE ...` and
    `:A {..}` end after `A`, and so does `:A OR n:B`, a boolean expression.
    """
    pos, expect_operand = 1, True
    while pos < len(labels):
        token = _LABEL_TOKEN_RE.match(labels, pos)
        if not token:
            break
        if token.group('ident') is not None:
            if not expect_operand:
                break
            expect_operand = False
        else:
            expect_operand = token.group('close') is None
        pos = token.end()
    return pos


_VAR_HEAD_RE = re.compile(r'\s*(?:' + _IDENT + r')?\s*')
_WHERE_RE = re.compile(r'WHERE\b', re.IGNORECASE)
#: The GQL label form `(n IS Label)`; `IS NULL`, `IS NOT ...`, `IS :: TYPE`,
#: `IS TYPED` and `IS NORMALIZED` are predicates, not labels.
_IS_LABEL_RE = re.compile(
    r'IS\b(?!\s*(?:NOT|NULL|TYPED|NORMALIZED|NF[CD]|NFK[CD])\b|\s*::)', re.IGNORECASE
)


def _is_node_shaped(inner: str) -> bool:
    """True when a group can only be a node pattern, wherever it stands.

    The pattern-region tracking decides most groups; this is the backstop for a
    pattern somewhere the scanner does not read as a pattern clause (the
    webapp's filter treats every node-looking group this way). `()`,
    `(:Label)`, a property map `(n {..})`, an inline `(n WHERE ..)` and the GQL
    `(n IS Label)` are never expressions. `(n)` and `(n:Label)` are left to the
    region: in a WHERE they are a variable and a label predicate
    (`WHERE (n:A OR n:B)`), and scoping them there would break the query.
    """
    head = _VAR_HEAD_RE.match(inner)
    has_var = bool(inner[:head.end()].strip())
    rest = inner[head.end():]
    if not rest:
        return not has_var
    if rest[0] == '{' or (rest[0] == ':' and not has_var):
        return True
    if rest[0] == ':':
        tail = rest[_label_run_end(rest):].lstrip()
        return tail.startswith('{') or bool(_WHERE_RE.match(tail))
    return has_var and bool(_WHERE_RE.match(rest) or _IS_LABEL_RE.match(rest))


def _prev_code_word(cypher: str, before: int, is_code: List[bool]) -> str:
    """The code word before `before`, past whitespace, comments, strings and
    backticked names, upper-cased. Skipping too much only ever finds a subquery
    word where there is none, and a pattern region is the fail-closed reading."""
    i = before - 1
    while i >= 0 and (not is_code[i] or cypher[i].isspace()):
        i -= 1
    end = i + 1
    while i >= 0 and is_code[i] and _is_name_char(cypher[i]):
        i -= 1
    return cypher[i + 1:end].upper()


def _next_token_char(cypher: str, i: int) -> Optional[str]:
    """The next character from `i` (a code position) past whitespace and
    comments only: a string or a quoted name counts as a token here."""
    n = len(cypher)
    while i < n:
        if cypher[i].isspace():
            i += 1
        elif cypher.startswith('/*', i):
            close = cypher.find('*/', i + 2)
            i = n if close == -1 else close + 2
        elif cypher.startswith('//', i):
            newline = cypher.find('\n', i)
            i = n if newline == -1 else newline + 1
        else:
            return cypher[i]
    return None


def _iter_node_patterns(cypher: str) -> Iterator[Tuple[int, int, str, bool]]:
    """Yield (start, end, inner, is_parseable) for every node-pattern candidate.

    A candidate is a parenthesised group that is not a function call and is
    inside a pattern clause (MATCH / OPTIONAL MATCH / MERGE / CREATE, the short
    `EXISTS { }` / `COUNT { }` subquery), adjacent to a relationship arrow, or
    shaped so it can only be a node (`_is_node_shaped`). `is_parseable` is False
    when the group does not parse as a node pattern - those are never
    rewritten, but they are reported as unscoped so an unrecognised shape fails
    closed instead of silently running unfiltered.

    A clause word ends the pattern region only at clause level: outside any
    bracket, or directly inside a subquery's braces. Inside a pattern it is a
    name or an inline predicate (`-[r WHERE r.x > 1]->`, `{limit: 1}`, a
    variable called `on`), and reading it as a clause used to end the region
    early, so the next comma-separated `(c)` ran unscoped. Every brace restores
    the region at its close, so nothing inside one can change how the rest of
    the query is read. A clause word followed by `=` is a path variable (Neo4j
    5.26 accepts `MATCH where = (m)`), so it does not end the region either:
    no clause is ever followed by `=`.
    """
    is_code, _ = code_positions(cypher)
    pairs = _paren_pairs(cypher, is_code)
    n = len(cypher)
    in_pattern_region = False
    # One entry per open bracket: (kind, region state when it opened).
    stack: List[Tuple[str, bool]] = []
    i = 0
    while i < n:
        if not is_code[i]:
            i += 1
            continue
        ch = cypher[i]
        if ch.isalpha() or ch == '_':
            word_match = _WORD_RE.match(cypher, i)
            word = word_match.group(0).upper()
            at_clause_level = not stack or stack[-1][0] == 'subquery'
            names_a_value = i > 0 and cypher[i - 1] in '.$'
            if word in _REGION_START:
                in_pattern_region = True
            elif (
                word in _REGION_END and at_clause_level and not names_a_value
                and _next_token_char(cypher, word_match.end()) != '='
            ):
                in_pattern_region = False
            i = word_match.end()
            continue
        if ch == '{':
            word = _prev_code_word(cypher, i, is_code)
            opens_subquery = (
                word in _SUBQUERY_WORDS or _adjacent_code_char(cypher, i - 1, -1, is_code) == ')'
            )
            stack.append(('subquery' if opens_subquery else 'map', in_pattern_region))
            if word in _PATTERN_SUBQUERY_WORDS:
                in_pattern_region = True
            i += 1
            continue
        if ch == '}':
            if stack and stack[-1][0] in ('subquery', 'map'):
                in_pattern_region = stack.pop()[1]
            i += 1
            continue
        if ch == '[':
            stack.append(('[', in_pattern_region))
            i += 1
            continue
        if ch in '])':
            if stack and stack[-1][0] == ('[' if ch == ']' else '('):
                stack.pop()
            i += 1
            continue
        if ch == '(':
            close = pairs.get(i)
            if close is not None and _is_label_expression_group(cypher, i, close, is_code):
                i = close + 1
                continue
            if close is not None and not _is_function_call(cypher, i, is_code):
                inner = cypher[i + 1:close]
                prev = _adjacent_code_char(cypher, i - 1, -1, is_code)
                following = _adjacent_code_char(cypher, close + 1, 1, is_code)
                arrow_adjacent = (
                    (prev is not None and prev in '-><]')
                    or (following is not None and following in '-<')
                )
                if in_pattern_region or arrow_adjacent or _is_node_shaped(inner):
                    parsed = _NODE_INNER_RE.match(inner)
                    parseable = bool(parsed) and _is_wellformed_label_expr(
                        parsed.group('labels') or ''
                    )
                    yield (i, close + 1, inner, parseable)
            # Keep scanning INSIDE the group: patterns nest in predicates such
            # as `size((n)-->())`.
            stack.append(('(', in_pattern_region))
            i += 1
            continue
        i += 1


_PLAIN_NAME_RE = re.compile(r'[A-Za-z_]\w*\Z')
_MAP_ENTRY_RE = re.compile(r'\s*([^\W\d][\w$]*)\s*:(?!:)(.*)\Z', re.DOTALL)
_EXACT_TENANT_ENTRIES = [('project_id', '$tenant_project_id'), ('user_id', '$tenant_user_id')]


def _neutral_map_view(props: str) -> str:
    """The property map as Neo4j reads its keys and parameters: comments
    removed, each string literal shown as `0`, a quoted name unwrapped only when
    it is a plain name (`` `project_id` `` is `project_id`). Any other quoted
    name is `quoted_name`: `` `user``_id` `` is the key user`_id to Neo4j, and
    unwrapping it piecewise read it as user_id."""
    out: List[str] = []
    n = len(props)
    i = 0
    while i < n:
        char = props[i]
        if props.startswith('//', i):
            newline = props.find('\n', i)
            i = n if newline == -1 else newline + 1
            out.append(' ')
        elif props.startswith('/*', i):
            close = props.find('*/', i + 2)
            i = n if close == -1 else close + 2
            out.append(' ')
        elif char in ("'", '"'):
            i += 1
            while i < n and props[i] != char:
                i += 2 if props[i] == '\\' else 1
            i += 1
            out.append('0')
        elif char == '`':
            name: List[str] = []
            i += 1
            while i < n:
                if props[i] == '`':
                    if props.startswith('``', i):
                        name.append('`')
                        i += 2
                        continue
                    break
                name.append(props[i])
                i += 1
            i += 1
            text = ''.join(name)
            out.append(text if _PLAIN_NAME_RE.match(text) else 'quoted_name')
        else:
            out.append(char)
            i += 1
    return ''.join(out)


def _map_entries(props: str) -> Optional[List[Tuple[str, str]]]:
    """The top-level `(key, value)` entries of a property map, or None when it
    is not a map of `key: value` pairs (a map projection `{.name}`, two maps)."""
    view = _neutral_map_view(props).strip()
    if not (view.startswith('{') and view.endswith('}')):
        return None
    body = view[1:-1]
    if not body.strip():
        return []
    parts: List[str] = []
    depth, start = 0, 0
    for i, char in enumerate(body):
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
            if depth < 0:
                return None
        elif char == ',' and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    if depth != 0:
        return None
    parts.append(body[start:])
    entries = []
    for part in parts:
        entry = _MAP_ENTRY_RE.match(part)
        if not entry:
            return None
        entries.append((entry.group(1), entry.group(2).strip()))
    return entries


def _tenant_state(inner: str) -> Optional[str]:
    """How the pattern's property map names the tenant: 'none', 'exact' (each
    tenant key once, bound to its tenant parameter) or 'other'; None when the
    map cannot be read.

    Only TOP-LEVEL entries count. A substring test was fooled every way: the
    tokens inside a string literal counted as a filter, a second `project_id:
    'other'` key could outvote the real one, and a tenant map nested inside a
    value (`{name: left('', size(keys({user_id: $tenant_user_id, ...})))}`)
    stood in for the node's own filter while the node matched every tenant.
    """
    match = _NODE_INNER_RE.match(inner)
    if not match:
        return None
    props = match.group('props')
    if props is None:
        return 'none'
    entries = _map_entries(props)
    if entries is None:
        return None
    tenant = sorted(entry for entry in entries if entry[0] in ('user_id', 'project_id'))
    if not tenant:
        return 'none'
    return 'exact' if tenant == _EXACT_TENANT_ENTRIES else 'other'


def _pattern_has_tenant_props(inner: str) -> bool:
    return _tenant_state(inner) == 'exact'


def _is_global_reference_pattern(inner: str) -> bool:
    """True when the pattern names ONLY labels from GLOBAL_REFERENCE_LABELS.

    Strict by design; see the note on GLOBAL_REFERENCE_LABELS. An unlabelled
    pattern, a mixed one such as `(n:CVE:Domain)`, and any label expression
    (`:A|B`, `:!A`, `:A&B`) all fail this and are scoped as normal.
    """
    match = _NODE_INNER_RE.match(inner)
    if not match:
        return False
    raw = (match.group('labels') or '').strip()
    if not raw or not _SIMPLE_LABELS_RE.match(raw):
        return False
    labels = [part.strip() for part in raw.split(':') if part.strip()]
    return bool(labels) and all(label in GLOBAL_REFERENCE_LABELS for label in labels)


def _labels_excluding_muted(labels: str) -> str:
    """Return `labels` as a label expression that also excludes `:Muted`.

    A muted finding keeps its functional label and gains `:Muted`, so excluding
    it is a label-expression term rather than a property filter - there is no
    inline-property way to say "not". This is what makes a muted node
    unmatchable by ANY pattern the agent emits, including a bare `MATCH (n)`.

    Two Cypher rules drive the shape of the output:
      - Neo4j 5 refuses to mix the legacy colon conjunction with the `&|!`
        operators in one pattern, so `:A:B` is re-spelled `:A&B` before the
        `&!Muted` term is appended. `:A:B&!Muted` would be a syntax error.
      - `&` binds tighter than `|`, so a union is parenthesised first:
        `:A|B` becomes `:(A|B)&!Muted`, never `:A|B&!Muted` (which would read as
        `A OR (B AND NOT Muted)` and happily return a muted A).

    A backticked label may itself contain ':' or '|', so it is copied verbatim
    rather than scanned for operators.
    """
    raw = (labels or '').strip()
    body = raw[1:].strip() if raw.startswith(':') else raw
    if not body:
        return f":!{MUTED_LABEL}"

    rewritten = []
    has_union = False
    i, end = 0, len(body)
    while i < end:
        char = body[i]
        if char == '`':
            close = body.find('`', i + 1)
            close = end - 1 if close == -1 else close
            rewritten.append(body[i:close + 1])
            i = close + 1
            continue
        if char == ':':
            rewritten.append('&')
        else:
            has_union = has_union or char == '|'
            rewritten.append(char)
        i += 1

    expr = ''.join(rewritten).strip()
    if has_union:
        expr = f"({expr})"
    return f":{expr}&!{MUTED_LABEL}"


def _labels_exclude_muted(labels: str) -> bool:
    """True for a label expression `_labels_excluding_muted` produced: `:!Muted`,
    or `:X&!Muted` with no top-level `|` in X (a union is parenthesised first)."""
    raw = re.sub(r'\s+', '', labels or '')
    term = f"&!{MUTED_LABEL}"
    if raw == f":!{MUTED_LABEL}":
        return True
    if not raw.startswith(':') or not raw.endswith(term):
        return False
    depth, quoted = 0, False
    for char in raw[1:-len(term)]:
        if char == '`':
            quoted = not quoted
        elif not quoted:
            depth += (char == '(') - (char == ')')
            if char == '|' and depth == 0:
                return False
    return True


def _with_tenant_props(inner: str, add_tenant: bool = True) -> str:
    """The pattern with the `!Muted` exclusion and, unless it already carries
    the exact tenant filter (`add_tenant=False`), the tenant properties."""
    match = _NODE_INNER_RE.match(inner)
    var = (match.group('var') or '').strip()
    labels = (match.group('labels') or '').strip()
    props = match.group('props')

    if not add_tenant:
        new_props = props.strip()
    elif props is not None:
        body = props.strip()[1:-1].strip()
        new_props = f"{{{body}, {TENANT_PROPS}}}" if body else f"{{{TENANT_PROPS}}}"
    else:
        new_props = f"{{{TENANT_PROPS}}}"

    # The label expression always survives as at least `:!Muted`, so the head is
    # never empty - an anonymous `()` endpoint becomes `(:!Muted {...})`.
    head = f"{var}{_labels_excluding_muted(labels)}"
    return f"({head} {new_props})"


def inject_tenant_filter(cypher: str, user_id: str, project_id: str) -> str:
    """
    Inject mandatory user_id and project_id filters into a Cypher query.

    Adds tenant properties directly into each node pattern as inline property
    filters. This ensures filters are always in scope regardless of WITH clauses
    or query structure.

    Example:
        MATCH (d:Domain {name: "example.com"})
    becomes:
        MATCH (d:Domain {name: "example.com", user_id: $tenant_user_id, project_id: $tenant_project_id})

    Every node-pattern shape is covered, including unlabelled `(n)`, multi-label
    `(n:A:B)`, backticked labels and anonymous `()` endpoints. Best-effort by
    design: pair it with `find_unscoped_node_pattern` (or just call
    `scope_query`) so an unparseable pattern is refused rather than run.

    The caller must pass the parameters {"tenant_user_id": user_id,
    "tenant_project_id": project_id} when executing the returned query.
    """
    spans = []
    last_end = -1
    for start, end, inner, parseable in _iter_node_patterns(cypher):
        if not parseable or start < last_end:
            continue
        last_end = end
        # A global reference pattern is left alone: these nodes carry no tenant
        # property, so a filter here matches nothing at all.
        if _is_global_reference_pattern(inner):
            continue
        tenant = _tenant_state(inner)
        if tenant == 'none':
            spans.append((start, end, _with_tenant_props(inner)))
        elif tenant == 'exact':
            # The caller's own exact filter still needs the mute exclusion.
            labels = _NODE_INNER_RE.match(inner).group('labels') or ''
            if not _labels_exclude_muted(labels):
                spans.append((start, end, _with_tenant_props(inner, add_tenant=False)))
        # Otherwise ('other', or a map that is not `key: value` pairs) it is left
        # as written for find_unscoped_node_pattern to refuse: appending the
        # filter would leave two values for one key.

    if not spans:
        return cypher

    out = []
    cursor = 0
    for start, end, rewritten in spans:
        out.append(cypher[cursor:start])
        out.append(rewritten)
        cursor = end
    out.append(cypher[cursor:])
    return ''.join(out)


def _is_relationship_gap(gap: str) -> bool:
    """True when `gap` (code between two node patterns, comments and literals
    blanked) is one fixed-length relationship: `--`, `-->`, `<--`, `<-->`,
    `-[...]-`, `-[...]->`, `<-[...]-`, with the spaces Neo4j allows inside an
    arrow. A `*` in the brackets or a quantifier after them is not one."""
    squeezed = re.sub(r'\s+', '', gap)
    if squeezed.startswith('<'):
        squeezed = squeezed[1:]
    if not squeezed.startswith('-'):
        return False
    rest = squeezed[1:]
    if rest.startswith('['):
        depth = 0
        for close, char in enumerate(rest):
            depth += (char == '[') - (char == ']')
            if depth == 0:
                break
        else:
            return False
        if '*' in rest[:close]:
            return False
        rest = rest[close + 1:]
    return rest in ('-', '->')


def _path_roots(cypher: str, patterns: List[Tuple[int, int, str, bool]]) -> List[int]:
    """For each pattern, a representative of its path: the patterns joined to it
    by relationship patterns (`(a)-[:HAS_PORT]->(b)<--(c)` is one path; a comma, a new
    clause or a UNION starts another). A pattern is joined to the first one that
    starts after it ends, as the webapp's saved-view filter reads it."""
    view = _code_only(cypher)
    starts = [start for start, _, _, _ in patterns]
    parent = list(range(len(patterns)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, (_, end, _, _) in enumerate(patterns):
        nxt = bisect.bisect_left(starts, end, i + 1)
        if nxt < len(patterns) and _is_relationship_gap(view[end:starts[nxt]]):
            parent[root(nxt)] = root(i)
    return [root(i) for i in range(len(patterns))]


_SCOPE_BOUNDARY_WORDS = frozenset({'WITH', 'RETURN', 'UNION', 'CALL'})


def _scope_boundaries(view: str) -> List[int]:
    """Sorted positions after which a variable bound earlier may name another
    node: WITH (not the `STARTS WITH` / `ENDS WITH` operators), RETURN, UNION,
    CALL, and every brace (a subquery's variables are its own). Over-marking
    only refuses more."""
    marks = [i for i, char in enumerate(view) if char in '{}']
    previous = ''
    for match in _WORD_RE.finditer(view):
        word = match.group(0).upper()
        before = view[match.start() - 1] if match.start() else ' '
        if (
            word in _SCOPE_BOUNDARY_WORDS and before not in ('.', ':', '$')
            and not (word == 'WITH' and previous in ('STARTS', 'ENDS'))
        ):
            marks.append(match.start())
        previous = word
    return sorted(marks)


def _pattern_variable(inner: str) -> str:
    match = _NODE_INNER_RE.match(inner)
    var = ((match.group('var') if match else '') or '').strip()
    if var.startswith('`') and _PLAIN_NAME_RE.match(var[1:-1]):
        return var[1:-1]
    return var


def _anchor_rebound_variables(
    cypher: str,
    patterns: List[Tuple[int, int, str, bool]],
    roots: List[int],
    anchored: set,
) -> None:
    """Add to `anchored` the paths that re-match a variable an anchored path
    bound earlier in the same query part.

    `MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) OPTIONAL MATCH
    (c:CVE)-[:HAS_CWE]->(m:MitreData)` is the MCP exploit_paths query and the
    shape the agent prompt teaches: the second `(c:CVE)` is the CVE the first
    path bound, not a fresh one. It counts only when nothing between the two can
    rebind the name (`_scope_boundaries`), and only from a binding at clause
    level: a variable bound inside a comprehension or a subquery is local to it.
    """
    view = _code_only(cypher)
    boundaries = _scope_boundaries(view)
    nesting, depth = [], 0
    for char in view:
        nesting.append(depth)
        if char in '([':
            depth += 1
        elif char in ')]':
            depth = max(0, depth - 1)
    variables = [_pattern_variable(inner) if parseable else '' for _, _, inner, parseable in patterns]
    # Forward propagation is one pass; another catches a path anchored by a
    # member that comes after the pattern re-matching it.
    for _ in range(3):
        changed = False
        latest = {}
        for i, (start, _, _, _) in enumerate(patterns):
            var = variables[i]
            if not var:
                continue
            q = latest.get(var)
            if q is not None and roots[q] in anchored and roots[i] not in anchored:
                q_end = patterns[q][1]
                k = bisect.bisect_left(boundaries, q_end)
                if start >= q_end and (k == len(boundaries) or boundaries[k] >= start):
                    anchored.add(roots[i])
                    changed = True
            if nesting[start] == 0:
                latest[var] = i
        if not changed:
            break


def find_unscoped_node_pattern(cypher: str) -> Optional[str]:
    """Return the first node pattern that is not tenant-scoped, or None.

    Run this on the query AFTER injection. A non-None result means the query
    would read across projects and must not be executed.

    A reference pattern (CVE, MitreData, Capec) with no tenant keys of its own is
    exempt only when a tenant-scoped node of the SAME path anchors it: a
    traversal from the caller's own data (or a re-match of a variable such a
    path bound, `_anchor_rebound_variables`). A scoped node elsewhere in the
    query is no anchor: `MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE)
    RETURN x` hands back every CVE in the database, the union of what every
    tenant has found, whether or not the project has a Domain.
    """
    patterns = list(_iter_node_patterns(cypher))
    tenant = [_tenant_state(inner) if parseable else None for _, _, inner, parseable in patterns]
    reference = [
        parseable and _is_global_reference_pattern(inner)
        for _, _, inner, parseable in patterns
    ]
    roots = _path_roots(cypher, patterns)
    anchored = {
        roots[i] for i in range(len(patterns)) if tenant[i] == 'exact' and not reference[i]
    }
    if anchored and any(reference):
        _anchor_rebound_variables(cypher, patterns, roots, anchored)
    for i, (start, end, _, parseable) in enumerate(patterns):
        if not parseable:
            return cypher[start:end]
        if tenant[i] == 'exact':
            continue
        if tenant[i] == 'none' and reference[i] and roots[i] in anchored:
            continue
        return cypher[start:end]
    return None


def has_labelled_node_pattern(cypher: str) -> bool:
    """True when at least one node pattern declares a label.

    A least-privilege control for the worker-facing /graph/exec endpoint: the
    kali-sandbox must name the labels it wants rather than dumping the graph
    with a bare `MATCH (n)`. Tenant isolation no longer depends on this -
    `scope_query` scopes unlabelled patterns too - so this is defence in depth
    for the least-trusted caller, not the isolation mechanism.
    """
    for _, _, inner, parseable in _iter_node_patterns(cypher):
        if not parseable:
            continue
        match = _NODE_INNER_RE.match(inner)
        if (match.group('labels') or '').strip():
            return True
    return False


def find_disallowed_character(cypher: str) -> Optional[str]:
    """Return the first character in executable code the scanner cannot read the
    way Neo4j does, or None.

    Neo4j's lexer accepts Unicode dashes and arrowheads in a relationship
    (`(a)\u2014[:HAS_PORT]\u2014+(b)` is `(a)-[:HAS_PORT]-+(b)`), reads several control
    characters as whitespace and ignores format characters inside names; this
    scanner reads ASCII punctuation only, so each of those hid an arrow, a
    quantifier or a keyword from it. Rather than mirror the lexer, such a
    character in code is refused. Strings, comments and backticked names are
    not code and keep any character; letters of any script stay legal, and a
    pattern variable that is not ASCII is refused later as unparseable.
    """
    is_code, _ = code_positions(cypher)
    for i, char in enumerate(cypher):
        if not is_code[i] or ' ' <= char <= '~' or char in '\t\n\r':
            continue
        if char > '\x7f' and char.isalpha():
            continue
        return char
    return None


def scope_query(cypher: str, user_id: str, project_id: str) -> str:
    """Inject tenant filters and refuse anything that is still unscoped.

    This is the only entry point callers should use before executing
    LLM-generated or worker-supplied Cypher.

    Raises:
        TenantScopeError: the query cannot be proven scoped to one project, or
            it references the reserved `Muted` label. Every refusal is this
            exception: a parser failure on odd input is converted too, because
            callers catch only TenantScopeError and anything else ended the
            request in a 500.
    """
    try:
        return _scope_query(cypher, user_id, project_id)
    except TenantScopeError:
        raise
    except Exception as exc:  # noqa: BLE001 - unreadable input is a refusal, never a crash
        raise TenantScopeError(
            "Query rejected: it could not be read, so its node patterns could not "
            "be scoped to this project."
        ) from exc


def _scope_query(cypher: str, user_id: str, project_id: str) -> str:
    bad_char = find_disallowed_character(cypher)
    if bad_char is not None:
        raise TenantScopeError(
            f"Query rejected: the character U+{ord(bad_char):04X} outside a string "
            f"literal cannot be read safely. Write Cypher syntax in plain ASCII."
        )

    # Checked BEFORE injection: afterwards every pattern carries our own
    # `!Muted` term, so the query would always look like it names the label.
    if not has_balanced_parens(cypher):
        raise TenantScopeError(
            "Query rejected: unbalanced parentheses, so its node patterns could "
            "not be scoped to this project."
        )

    if names_muted_label(cypher):
        raise TenantScopeError(
            f"Query rejected: the '{MUTED_LABEL}' label is reserved and cannot be "
            f"referenced. Findings an operator has suppressed as noise are not "
            f"visible to the agent and cannot be queried."
        )

    off_graph = find_off_graph_clause(cypher)
    if off_graph:
        raise TenantScopeError(
            f"Query rejected: {off_graph} reads outside this project's graph and "
            f"cannot be scoped to it. Query the graph with MATCH ... RETURN."
        )

    # Checked BEFORE injection, and fail-closed: a procedure that takes Cypher
    # as a STRING argument (apoc.cypher.run/runMany/runTimeboxed) carries its
    # query past tenant injection entirely, because injection rewrites node
    # PATTERNS and the inner query is a string literal. That is a full
    # cross-tenant read and, via runMany, a cross-tenant WRITE. apoc.load.* is
    # the same hole pointed outward, as an SSRF from the database container.
    bad_proc = find_disallowed_procedure(cypher)
    if bad_proc:
        raise TenantScopeError(
            f"Query rejected: the procedure '{bad_proc}' is not permitted. Only "
            f"MATCH/RETURN over labelled node patterns can be proven scoped to "
            f"one project; a procedure that takes a query as an argument cannot."
        )

    # The same danger in FUNCTION form: `apoc.cypher.runFirstColumn*` and
    # `apoc.load.*` are callable anywhere an expression is, with no CALL, so the
    # procedure gate above never sees them.
    bad_call = find_disallowed_call(cypher)
    if bad_call:
        raise TenantScopeError(
            f"Query rejected: the function '{bad_call}' is not permitted. A "
            f"function that takes a query as an argument, or fetches a URL, "
            f"carries its work past tenant scoping."
        )

    # A variable-length or quantified path traverses nodes that are never written
    # as `()` patterns, so they cannot be scoped: `(:CVE)-[*2]-(:CVE)` walks from
    # the exempt reference nodes straight into other projects' data.
    if has_variable_length_path(cypher):
        raise TenantScopeError(
            "Query rejected: variable-length and quantified path patterns "
            "(`[*]`, `{n,m}`) traverse nodes that cannot be scoped to this "
            "project. Use fixed-length hops: one explicit relationship per hop."
        )

    filtered = inject_tenant_filter(cypher, user_id, project_id)
    unscoped = find_unscoped_node_pattern(filtered)
    if unscoped and _is_global_reference_pattern(unscoped.strip()[1:-1]):
        raise TenantScopeError(
            f"Query rejected: the shared reference node {unscoped.strip()} is "
            f"reachable only through a relationship from this project's own node "
            f"in the same pattern, e.g. MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE). "
            f"A separate MATCH, a comma or a UNION does not tie it to this project."
        )
    if unscoped:
        raise TenantScopeError(
            f"Query rejected: node pattern {unscoped.strip()} could not be scoped "
            f"to this project. Give every node pattern an explicit label, e.g. "
            f"MATCH (p:Package), instead of matching (n) and testing the label "
            f"in a WHERE clause."
        )
    return filtered
