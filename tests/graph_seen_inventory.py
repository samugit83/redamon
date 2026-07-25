import ast
import re
from dataclasses import dataclass
from pathlib import Path


PROJECT_LABELS = frozenset({
    "UserInput", "Domain", "Subdomain", "IP", "DNSRecord", "Port",
    "Service", "BaseURL", "Endpoint", "Parameter", "Header",
    "Certificate", "Technology", "Vulnerability", "ExternalDomain",
})

GLOBAL_NODE_EXEMPTIONS = {
    "CVE": "globally shared reference catalogue",
    "CWE": "globally shared reference catalogue",
    "MitreData": "globally shared reference catalogue",
    "Capec": "globally shared reference catalogue",
}

_DYNAMIC = "__GRAPH_SEEN_DYNAMIC__"
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"


@dataclass(frozen=True)
class SeenViolation:
    path: Path
    line: int
    label: str
    alias: str
    reason: str


def production_writer_files(root):
    root = Path(root)
    paths = [
        *(root / "graph_db" / "mixins" / "recon").glob("*.py"),
        root / "graph_db" / "mixins" / "graphql_mixin.py",
        root / "graph_db" / "mixins" / "osint_mixin.py",
        root / "graph_db" / "mixins" / "cache_mixin.py",
        *(root / "recon" / "partial_recon_modules").glob("*.py"),
    ]
    return tuple(sorted(path for path in paths if path.is_file()))


def _node_pattern(keyword, alias, label):
    return re.compile(
        rf"\b{keyword}\s*\(\s*{re.escape(alias)}\s*:\s*{re.escape(label)}\b",
        re.IGNORECASE,
    )


def _set_clause_bodies(query):
    return [
        clause.group("body")
        for clause in re.finditer(
        r"\bSET\b(?P<body>.*?)(?="
        r"\b(?:OPTIONAL\s+MATCH|MATCH|MERGE|CREATE|WITH|RETURN|REMOVE|"
        r"DELETE|DETACH|UNWIND|CALL|FOREACH|ON\s+(?:CREATE|MATCH)\s+SET)"
        r"\b|$)",
        query,
        re.IGNORECASE | re.DOTALL,
        )
    ]


def _alias_has_set(query, alias):
    assignment = re.compile(
        rf"(?:^|,)\s*{re.escape(alias)}"
        rf"(?:\.\w+\s*(?:\+?=)|\s*(?:\+?=)|\s*:\s*{_IDENTIFIER})",
        re.IGNORECASE,
    )
    return any(
        assignment.search(body) is not None
        for body in _set_clause_bodies(query)
    )


def _query_constants(tree, source):
    constants = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = _query_text(node.value, source, constants)
        if value is None:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value
    return constants


def _query_text(arg, source, constants):
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return constants.get(arg.id)
    if isinstance(arg, ast.JoinedStr):
        parts = []
        for value in arg.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                formatted = _query_text(value.value, source, constants)
                parts.append(formatted if formatted is not None else _DYNAMIC)
            else:
                parts.append(_DYNAMIC)
        return "".join(parts)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left = _query_text(arg.left, source, constants)
        right = _query_text(arg.right, source, constants)
        if left is not None and right is not None:
            return left + right
    return None


_LEXICAL_SCOPES = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
)


def _parent_map(tree):
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _lexical_scope(node, parents):
    current = node
    while not isinstance(current, _LEXICAL_SCOPES):
        current = parents[current]
    return current


def _outer_scope(scope, parents):
    current = parents.get(scope)
    while current is not None and not isinstance(current, _LEXICAL_SCOPES):
        current = parents.get(current)
    if (
        isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        and isinstance(current, ast.ClassDef)
    ):
        return _outer_scope(current, parents)
    return current


def _assignment_values(tree, parents):
    assignments = {}
    for node in ast.walk(tree):
        unsafe = False
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
            value = None
            unsafe = True
        else:
            continue
        if value is None and not unsafe:
            continue
        scope = _lexical_scope(node, parents)
        for target in targets:
            if isinstance(target, ast.Name):
                assignments.setdefault((scope, target.id), []).append(
                    (node.lineno, value)
                )
    return assignments


def _scope_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    return {
        argument.arg
        for argument in [
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
        ]
    } | ({args.vararg.arg} if args.vararg else set()) | (
        {args.kwarg.arg} if args.kwarg else set()
    )


def _query_text_at(
    arg,
    source,
    assignments,
    parents,
    scope,
    before_line,
    resolving=frozenset(),
):
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.JoinedStr):
        parts = []
        for value in arg.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                formatted = _query_text_at(
                    value.value,
                    source,
                    assignments,
                    parents,
                    scope,
                    before_line,
                    resolving,
                )
                parts.append(formatted if formatted is not None else _DYNAMIC)
            else:
                parts.append(_DYNAMIC)
        return "".join(parts)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left = _query_text_at(
            arg.left,
            source,
            assignments,
            parents,
            scope,
            before_line,
            resolving,
        )
        right = _query_text_at(
            arg.right,
            source,
            assignments,
            parents,
            scope,
            before_line,
            resolving,
        )
        if left is not None and right is not None:
            return left + right
        return None
    if not isinstance(arg, ast.Name):
        return None

    current_scope = scope
    while current_scope is not None:
        key = (current_scope, arg.id)
        if key in resolving:
            return None
        candidates = assignments.get(key, [])
        preceding = [
            (line, value) for line, value in candidates
            if line < before_line
        ]
        if preceding:
            possible_values = {
                _query_text_at(
                    value,
                    source,
                    assignments,
                    parents,
                    current_scope,
                    line,
                    resolving | {key},
                )
                for line, value in preceding
            }
            if len(possible_values) == 1:
                return possible_values.pop()
            return None
        if candidates or arg.id in _scope_parameter_names(current_scope):
            return None
        current_scope = _outer_scope(current_scope, parents)
    return None


def _run_calls(path):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    parents = _parent_map(tree)
    assignments = _assignment_values(tree, parents)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            continue
        query_arg = node.args[0] if node.args else None
        if query_arg is None:
            query_arg = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "query"
                ),
                None,
            )
        query = None
        if query_arg is not None:
            query = _query_text_at(
                query_arg,
                source,
                assignments,
                parents,
                _lexical_scope(node, parents),
                node.lineno,
            )
        call_source = ast.get_source_segment(source, node) or ""
        yield query, call_source, node.lineno


def _session_run_queries(path):
    for query, call_source, line in _run_calls(path):
        if query is not None:
            yield query, call_source, line


def _unresolved_session_run_calls(path):
    for query, call_source, line in _run_calls(path):
        if query is None:
            yield call_source, line


def _label_aliases(query, labels):
    aliases = []
    labels_pattern = "|".join(re.escape(label) for label in labels)
    pattern = re.compile(
        rf"\b(?:MERGE|CREATE|MATCH|OPTIONAL MATCH)\s*"
        rf"\(\s*(\w+)\s*:\s*({labels_pattern})\b"
    )
    for alias, label in pattern.findall(query):
        aliases.append((label, alias))
    return aliases


def _all_label_aliases(query):
    node_pattern = re.compile(
        rf"\(\s*(?P<alias>{_IDENTIFIER})?"
        rf"(?P<labels>(?:\s*:\s*`?{_IDENTIFIER}`?)+)",
        re.IGNORECASE,
    )
    label_pattern = re.compile(rf":\s*`?(?P<label>{_IDENTIFIER})`?")
    aliases = []
    for node in node_pattern.finditer(query):
        alias = node.group("alias") or "<anonymous>"
        aliases.extend(
            (label.group("label"), alias)
            for label in label_pattern.finditer(node.group("labels"))
        )
    return aliases


def _unlabeled_write_aliases(query):
    pattern = re.compile(
        rf"\b(?:MERGE|CREATE)\s*\(\s*(?P<alias>{_IDENTIFIER})\s*"
        rf"(?=(?:\{{|\)(?!\s*[-<])))",
        re.IGNORECASE,
    )
    return [
        ("<unlabeled>", match.group("alias"))
        for match in pattern.finditer(query)
    ]


def _structural_clauses(query):
    pattern = re.compile(
        r"\b(?P<kind>OPTIONAL\s+MATCH|MATCH|MERGE|CREATE|WITH|SET|WHERE|"
        r"ORDER\s+BY|SKIP|LIMIT|RETURN|REMOVE|DELETE|DETACH|UNWIND|CALL|"
        r"FOREACH)\b",
        re.IGNORECASE,
    )
    matches = list(pattern.finditer(query))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(query)
        yield (
            re.sub(r"\s+", " ", match.group("kind").upper()),
            match.start(),
            query[match.end():end],
        )


def _node_binding_events(body):
    node_pattern = re.compile(
        rf"\(\s*(?P<alias>{_IDENTIFIER})"
        rf"(?P<labels>(?:\s*:\s*`?{_IDENTIFIER}`?)*)"
        rf"(?=\s*(?:\{{|\)))",
        re.IGNORECASE,
    )
    label_pattern = re.compile(rf":\s*`?(?P<label>{_IDENTIFIER})`?")
    relationship_pattern = re.compile(
        rf"\[\s*(?P<alias>{_IDENTIFIER})\s*(?=[:{{\]])",
        re.IGNORECASE,
    )
    events = []
    for node in node_pattern.finditer(body):
        labels = {
            label.group("label")
            for label in label_pattern.finditer(node.group("labels"))
        }
        events.append((node.start(), "node", node.group("alias"), labels))
    events.extend(
        (relationship.start(), "relationship", relationship.group("alias"), set())
        for relationship in relationship_pattern.finditer(body)
    )
    return sorted(events)


def _with_projection_state(body, state):
    body = re.sub(r"^\s*DISTINCT\b", "", body, flags=re.IGNORECASE)
    projection = re.compile(
        rf"^(?P<source>{_IDENTIFIER})"
        rf"(?:\s+AS\s+(?P<target>{_IDENTIFIER}))?$",
        re.IGNORECASE,
    )
    projected = {}
    for item in (part.strip() for part in body.split(",")):
        if item == "*":
            projected.update(state)
            continue
        match = projection.fullmatch(item)
        if match is None or match.group("source") not in state:
            continue
        projected[match.group("target") or match.group("source")] = state[
            match.group("source")
        ]
    return projected


def _set_body_targets(body):
    target_pattern = re.compile(
        rf"(?:^|,)\s*(?P<alias>{_IDENTIFIER})(?="
        rf"(?:\.\w+\s*(?:\+?=)|\s*(?:\+?=)|\s*:\s*{_IDENTIFIER}))",
        re.IGNORECASE,
    )
    return [match.group("alias") for match in target_pattern.finditer(body)]


def _set_body_labels(body):
    mutation_pattern = re.compile(
        rf"(?:^|,)\s*(?P<alias>{_IDENTIFIER})"
        rf"(?P<labels>(?:\s*:\s*`?{_IDENTIFIER}`?)+)",
        re.IGNORECASE,
    )
    label_pattern = re.compile(rf":\s*`?(?P<label>{_IDENTIFIER})`?")
    return [
        (label.group("label"), mutation.group("alias"))
        for mutation in mutation_pattern.finditer(body)
        for label in label_pattern.finditer(mutation.group("labels"))
    ]


def _positioned_set_writer_aliases(query):
    state = {}
    label_aliases = []
    for kind, _position, body in _structural_clauses(query):
        if kind in {"MATCH", "OPTIONAL MATCH", "MERGE", "CREATE"}:
            for _offset, binding, alias, labels in _node_binding_events(body):
                state[alias] = (binding, labels)
            continue
        if kind == "WITH":
            state = _with_projection_state(body, state)
            continue
        if kind != "SET":
            continue

        for label, alias in _set_body_labels(body):
            binding, labels = state.get(alias, ("node", set()))
            if binding != "relationship":
                state[alias] = ("node", {*labels, label})
                label_aliases.append((label, alias))

        for alias in _set_body_targets(body):
            binding, labels = state.get(alias, ("node", set()))
            if binding == "relationship":
                continue
            label_aliases.extend(
                (label, alias)
                for label in (labels or {"<unlabeled>"})
            )
    return label_aliases


def _writer_label_aliases(query):
    node_clause_aliases = [
        (label, alias)
        for label, alias in _all_label_aliases(query)
        if _is_node_clause_write(query, label, alias)
    ]
    return [
        *node_clause_aliases,
        *_unlabeled_write_aliases(query),
        *_positioned_set_writer_aliases(query),
    ]


def _cypher_structure(query):
    characters = list(query)
    length = len(query)
    index = 0

    def blank(start, end):
        for position in range(start, end):
            if characters[position] not in "\r\n":
                characters[position] = " "

    while index < length:
        if query.startswith("//", index):
            end = query.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue
        if query.startswith("/*", index):
            close = query.find("*/", index + 2)
            end = length if close == -1 else close + 2
            blank(index, end)
            index = end
            continue
        if query[index] not in {"'", '"'}:
            index += 1
            continue

        quote = query[index]
        start = index
        index += 1
        while index < length:
            if query[index] == "\\" and index + 1 < length:
                index += 2
                continue
            if query[index] == quote:
                if index + 1 < length and query[index + 1] == quote:
                    index += 2
                    continue
                index += 1
                break
            index += 1
        blank(start, index)

    return "".join(characters)


def _is_node_clause_write(query, label, alias):
    if label == "<unlabeled>":
        return True
    write_clauses = re.finditer(
        r"\b(?:MERGE|CREATE)\b(?P<body>.*?)(?="
        r"\b(?:OPTIONAL\s+MATCH|MATCH|MERGE|CREATE|SET|WITH|RETURN|REMOVE|"
        r"DELETE|DETACH|UNWIND|CALL|FOREACH|ON\s+(?:CREATE|MATCH))\b|$)",
        query,
        re.IGNORECASE | re.DOTALL,
    )
    alias_pattern = (
        ""
        if alias == "<anonymous>"
        else re.escape(alias)
    )
    written_node = re.compile(
        rf"\(\s*{alias_pattern}"
        rf"(?:\s*:\s*`?{_IDENTIFIER}`?)*"
        rf"\s*:\s*`?{re.escape(label)}`?\b",
        re.IGNORECASE,
    )
    if any(
        written_node.search(clause.group("body")) is not None
        for clause in write_clauses
    ):
        return True
    return False


def _is_node_write(query, label, alias):
    if _is_node_clause_write(query, label, alias):
        return True
    if alias == "<anonymous>":
        return False
    return _alias_has_set(query, alias)


def _has_unsafe_dynamic_segment(query):
    if _DYNAMIC not in query:
        return False
    safe_dynamic = re.sub(
        rf"(\b(?:OPTIONAL\s+)?MATCH\s*\(\s*{_IDENTIFIER}?\s*:\s*)"
        rf"{re.escape(_DYNAMIC)}\b",
        rf"\1__STATIC_MATCH_LABEL__",
        query,
        flags=re.IGNORECASE,
    )
    safe_dynamic = re.sub(
        rf"(\[\s*(?:{_IDENTIFIER}\s*)?:\s*){re.escape(_DYNAMIC)}\b",
        rf"\1__STATIC_RELATIONSHIP_TYPE__",
        safe_dynamic,
        flags=re.IGNORECASE,
    )
    return _DYNAMIC in safe_dynamic


def _assert_seen_stamped(
    query, call_source, path, line, label, alias, *, exact_once=False
):
    fields = {
        "first_seen": (
            f"{alias}.first_seen = coalesce("
            f"{alias}.first_seen, datetime($recon_job_started_at))"
        ),
        "first_seen_job_id": (
            f"{alias}.first_seen_job_id = coalesce("
            f"{alias}.first_seen_job_id, $recon_job_id)"
        ),
        "last_seen": (
            f"{alias}.last_seen = datetime($recon_job_started_at)"
        ),
        "last_seen_job_id": f"{alias}.last_seen_job_id = $recon_job_id",
    }
    for field, assignment in fields.items():
        count = query.count(assignment)
        if exact_once:
            assert count == 1, (
                f"{path}:{line} expected exactly one {field} assignment for "
                f"{label} alias {alias}, found {count}"
            )
        else:
            assert count >= 1, (
                f"{path}:{line} missing {field} for {label} alias {alias}"
            )
    assert (
        "_recon_job_params()" in call_source
    ), f"{path}:{line} does not pass recon job params for {label} alias {alias}"


def _seen_stamp_problems(query, call_source, alias):
    if alias == "<anonymous>":
        return ["node-writing query uses an anonymous node"]

    stamp_query = _without_on_create_set_bodies(query)
    assignments = {
        "first_seen": (
            f"{alias}.first_seen = coalesce("
            f"{alias}.first_seen, datetime($recon_job_started_at))"
        ),
        "first_seen_job_id": (
            f"{alias}.first_seen_job_id = coalesce("
            f"{alias}.first_seen_job_id, $recon_job_id)"
        ),
        "last_seen": (
            f"{alias}.last_seen = datetime($recon_job_started_at)"
        ),
        "last_seen_job_id": f"{alias}.last_seen_job_id = $recon_job_id",
    }
    missing = [
        field for field, assignment in assignments.items()
        if assignment not in stamp_query
    ]
    problems = []
    if missing:
        problems.append("missing seen stamping: " + ", ".join(missing))
    if alias in _reused_node_writer_aliases(query):
        problems.append(
            "node-writing alias is reused across clauses; "
            "seen stamping cannot be proven for every occurrence"
        )
    if "_recon_job_params()" not in call_source:
        problems.append("missing recon job params")
    return problems


def _without_on_create_set_bodies(query):
    clauses = list(_structural_clauses(query))
    characters = list(query)
    for index, (kind, position, _body) in enumerate(clauses):
        if kind != "SET":
            continue
        if re.search(r"\bON\s+CREATE\s*$", query[:position], re.IGNORECASE) is None:
            continue
        end = clauses[index + 1][1] if index + 1 < len(clauses) else len(query)
        for offset in range(position, end):
            if characters[offset] not in "\r\n":
                characters[offset] = " "
    return "".join(characters)


def _reused_node_writer_aliases(query):
    occurrences = {}
    for kind, position, body in _structural_clauses(query):
        if kind not in {"MERGE", "CREATE"}:
            continue
        clause = f"{kind} {body}"
        aliases = {
            alias
            for _label, alias in [
                *_all_label_aliases(clause),
                *_unlabeled_write_aliases(clause),
            ]
            if alias != "<anonymous>"
        }
        for alias in aliases:
            occurrences.setdefault(alias, []).append(position)
    return {
        alias
        for alias, positions in occurrences.items()
        if len(positions) > 1
    }


def _unresolved_violation(path, line):
    return SeenViolation(
        path=path,
        line=line,
        label="<unresolved>",
        alias="<unresolved>",
        reason=(
            "run query cannot be statically resolved; "
            "node-writing status and seen stamping cannot be verified"
        ),
    )


def find_seen_violations(paths):
    violations = []
    for path in map(Path, paths):
        for query, call_source, line in _run_calls(path):
            if query is None:
                violations.append(_unresolved_violation(path, line))
                continue

            if _has_unsafe_dynamic_segment(query):
                violations.append(_unresolved_violation(path, line))
                continue

            structure = _cypher_structure(query)
            label_aliases = _writer_label_aliases(structure)

            for label, alias in dict.fromkeys(label_aliases):
                if label == _DYNAMIC:
                    if _is_node_write(structure, label, alias):
                        violations.append(_unresolved_violation(path, line))
                    continue
                if label in GLOBAL_NODE_EXEMPTIONS:
                    continue
                if not _is_node_write(structure, label, alias):
                    continue
                problems = _seen_stamp_problems(
                    structure,
                    call_source,
                    alias,
                )
                if problems:
                    violations.append(
                        SeenViolation(
                            path=path,
                            line=line,
                            label=label,
                            alias=alias,
                            reason="; ".join(problems),
                        )
                    )
    return sorted(
        set(violations),
        key=lambda violation: (
            str(violation.path),
            violation.line,
            violation.label,
            violation.alias,
            violation.reason,
        ),
    )
