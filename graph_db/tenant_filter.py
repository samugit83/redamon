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
#:   - the QUERY must still carry at least one tenant-scoped pattern
#:     (`find_unscoped_node_pattern`), so reference nodes are reachable only by
#:     traversing from the caller's own data. `MATCH (c:CVE) RETURN c` on its
#:     own is still refused: which CVEs exist in the database is itself a weak
#:     signal about what other tenants have scanned.
GLOBAL_REFERENCE_LABELS = frozenset({"CVE", "MitreData", "Capec"})

#: A plain label conjunction and nothing else. Backticks are refused rather than
#: unquoted: a backticked label may contain ':' and would break the split below,
#: and no reference label needs quoting.
_SIMPLE_LABELS_RE = re.compile(r'^(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)+$')

# A Cypher identifier: bare, or backtick-quoted (which may contain spaces).
_IDENT = r'(?:`[^`]*`|[A-Za-z_][A-Za-z0-9_]*)'

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
_LABEL_EXPR = r'(?:[:|&!()]|' + _IDENT + r'|\s)+'
_NODE_INNER_RE = re.compile(
    r'^\s*(?P<var>' + _IDENT + r')?'
    r'\s*(?P<labels>' + _LABEL_EXPR + r')?'
    r'\s*(?P<props>\{.*\})?\s*$',
    re.DOTALL,
)

_WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

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
                if cypher[i] == '\\':
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


def _matching_paren(cypher: str, open_idx: int, is_code: List[bool]) -> Optional[int]:
    """Index of the `)` closing the `(` at open_idx, or None if unbalanced."""
    depth = 0
    for i in range(open_idx, len(cypher)):
        if not is_code[i]:
            continue
        if cypher[i] == '(':
            depth += 1
        elif cypher[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    return None


def _is_function_call(cypher: str, open_idx: int) -> bool:
    """True when the `(` at open_idx opens a call, not a node pattern.

    A call is written with no space before the paren (`count(*)`, `collect(p)`),
    while a pattern always follows whitespace or a relationship arrow. Checking
    the IMMEDIATE previous character rather than the previous token matters:
    `MATCH (n)` is preceded by the keyword MATCH, which would otherwise read as
    a function name and leave the pattern unscoped.
    """
    if open_idx == 0:
        return False
    prev = cypher[open_idx - 1]
    return prev.isalnum() or prev in '_`'


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
    return bool(_LABEL_GROUP_ONLY_RE.match(cypher[open_idx + 1:close_idx]))


def _prev_code_char(cypher: str, before: int, is_code: List[bool]) -> Optional[str]:
    for i in range(before - 1, -1, -1):
        if not is_code[i]:
            return '`'  # a backticked identifier ended here
        if not cypher[i].isspace():
            return cypher[i]
    return None


def _next_code_char(cypher: str, start: int, is_code: List[bool]) -> Optional[str]:
    for i in range(start, len(cypher)):
        if not is_code[i]:
            return '`'
        if not cypher[i].isspace():
            return cypher[i]
    return None


def _iter_node_patterns(cypher: str) -> Iterator[Tuple[int, int, str, bool]]:
    """Yield (start, end, inner, is_parseable) for every node-pattern candidate.

    A candidate is a parenthesised group that is either inside a pattern clause
    (MATCH / OPTIONAL MATCH / MERGE / CREATE) or adjacent to a relationship
    arrow, and is not a function call. `is_parseable` is False when the group
    does not parse as a node pattern - those are never rewritten, but they are
    reported as unscoped so an unrecognised shape fails closed instead of
    silently running unfiltered.
    """
    is_code, _ = code_positions(cypher)
    n = len(cypher)
    in_pattern_region = False
    i = 0
    while i < n:
        if not is_code[i]:
            i += 1
            continue
        ch = cypher[i]
        if ch.isalpha() or ch == '_':
            word_match = _WORD_RE.match(cypher, i)
            word = word_match.group(0).upper()
            if word in _REGION_START:
                in_pattern_region = True
            elif word in _REGION_END:
                in_pattern_region = False
            i = word_match.end()
            continue
        if ch == '(':
            close = _matching_paren(cypher, i, is_code)
            if close is None:
                i += 1
                continue
            if _is_label_expression_group(cypher, i, close, is_code):
                i = close + 1
                continue
            prev = _prev_code_char(cypher, i, is_code)
            is_call = _is_function_call(cypher, i)
            following = _next_code_char(cypher, close + 1, is_code)
            arrow_adjacent = (
                (prev is not None and prev in '-><]')
                or (following is not None and following in '-<')
            )
            if not is_call and (in_pattern_region or arrow_adjacent):
                inner = cypher[i + 1:close]
                parsed = _NODE_INNER_RE.match(inner)
                parseable = bool(parsed) and _is_wellformed_label_expr(
                    parsed.group('labels') or ''
                )
                yield (i, close + 1, inner, parseable)
            # Keep scanning INSIDE the group: patterns nest in predicates such
            # as `size((n)-->())`.
            i += 1
            continue
        i += 1


def _pattern_has_tenant_props(inner: str) -> bool:
    return "$tenant_user_id" in inner and "$tenant_project_id" in inner


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


def _with_tenant_props(inner: str) -> str:
    match = _NODE_INNER_RE.match(inner)
    var = (match.group('var') or '').strip()
    labels = (match.group('labels') or '').strip()
    props = match.group('props')

    if props is not None:
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
        # A global reference pattern is left alone: these nodes carry no tenant
        # property, so a filter here matches nothing at all.
        if _pattern_has_tenant_props(inner) or _is_global_reference_pattern(inner):
            last_end = end
            continue
        spans.append((start, end, inner))
        last_end = end

    if not spans:
        return cypher

    out = []
    cursor = 0
    for start, end, inner in spans:
        out.append(cypher[cursor:start])
        out.append(_with_tenant_props(inner))
        cursor = end
    out.append(cypher[cursor:])
    return ''.join(out)


def find_unscoped_node_pattern(cypher: str) -> Optional[str]:
    """Return the first node pattern that is not tenant-scoped, or None.

    Run this on the query AFTER injection. A non-None result means the query
    would read across projects and must not be executed.
    """
    patterns = list(_iter_node_patterns(cypher))
    # Reference nodes are readable only from a query that is ITSELF anchored to
    # the caller's data. Without this, `MATCH (c:CVE) RETURN c.id` would hand
    # back every CVE in the database - no asset, no project, but still the union
    # of what every tenant has found.
    has_tenant_anchor = any(
        parseable and _pattern_has_tenant_props(inner)
        for _, _, inner, parseable in patterns
    )
    for start, end, inner, parseable in patterns:
        if not parseable:
            return cypher[start:end]
        if _pattern_has_tenant_props(inner):
            continue
        if has_tenant_anchor and _is_global_reference_pattern(inner):
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


def scope_query(cypher: str, user_id: str, project_id: str) -> str:
    """Inject tenant filters and refuse anything that is still unscoped.

    This is the only entry point callers should use before executing
    LLM-generated or worker-supplied Cypher.

    Raises:
        TenantScopeError: the query cannot be proven scoped to one project, or
            it references the reserved `Muted` label.
    """
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

    filtered = inject_tenant_filter(cypher, user_id, project_id)
    unscoped = find_unscoped_node_pattern(filtered)
    if unscoped:
        raise TenantScopeError(
            f"Query rejected: node pattern {unscoped.strip()} could not be scoped "
            f"to this project. Give every node pattern an explicit label, e.g. "
            f"MATCH (p:Package), instead of matching (n) and testing the label "
            f"in a WHERE clause."
        )
    return filtered
