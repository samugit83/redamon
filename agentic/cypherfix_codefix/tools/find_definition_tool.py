"""FindDefinition tool: locate where a symbol is defined."""

import logging
from .repo_paths import RepoPathError, resolve_in_repo
from .symbols_tool import EXT_TO_LANG, _get_parser, DEFINITION_TYPES, _extract_name

logger = logging.getLogger(__name__)

SKIP_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', '.tox', 'venv', '.venv', 'dist', 'build'}


async def github_find_definition(state, symbol: str, scope: str = None) -> str:
    """Find where a symbol is defined across the repo."""
    try:
        base = resolve_in_repo(state.repo_path, scope)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not base.exists():
        return f"Error: Directory not found: {scope or '.'}"

    results = []
    for ext, lang in EXT_TO_LANG.items():
        parser = _get_parser(lang)
        if not parser:
            continue

        def_types = DEFINITION_TYPES.get(lang, [])
        for file_path in base.rglob(f"*{ext}"):
            if any(skip in file_path.parts for skip in SKIP_DIRS):
                continue
            try:
                content = file_path.read_bytes()
                tree = parser.parse(content)
                _find_defs_in_tree(
                    tree.root_node, symbol, def_types,
                    file_path, state.repo_path, results,
                )
            except Exception:
                continue

            if len(results) >= 50:
                break
        if len(results) >= 50:
            break

    if not results:
        return f"No definition found for '{symbol}'. Try github_grep for a text search."

    lines = [f"Definitions of '{symbol}' ({len(results)} found):", ""]
    for r in results:
        lines.append(f"  {r['file']}:{r['line']}  ({r['kind']})")
        if r.get('signature'):
            lines.append(f"    {r['signature']}")
    return '\n'.join(lines)


def _find_defs_in_tree(node, symbol, def_types, file_path, repo_path, results):
    """Recursively search for definition nodes matching the symbol."""
    for child in node.children:
        if child.type in def_types:
            name = _extract_name(child)
            if name == symbol:
                rel = str(file_path.relative_to(repo_path))
                line = child.start_point[0] + 1
                kind = child.type.replace('_definition', '').replace('_declaration', '')
                sig_line = child.text.decode('utf-8', errors='replace').split('\n')[0][:200]
                results.append({
                    'file': rel, 'line': line, 'kind': kind, 'signature': sig_line,
                })
        _find_defs_in_tree(child, symbol, def_types, file_path, repo_path, results)
