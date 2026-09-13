"""FindReferences tool: find all usages of a symbol."""

import logging
from .repo_paths import RepoPathError, resolve_in_repo
from .symbols_tool import EXT_TO_LANG, _get_parser, DEFINITION_TYPES

logger = logging.getLogger(__name__)

SKIP_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', '.tox', 'venv', '.venv', 'dist', 'build'}


async def github_find_references(state, symbol: str, file_path: str = None) -> str:
    """Find all usages of a symbol."""
    if file_path:
        try:
            files = [resolve_in_repo(state.repo_path, file_path, allow_root=False)]
        except RepoPathError as exc:
            return f"Error: {exc}"
    else:
        files = []
        for ext in EXT_TO_LANG:
            for f in state.repo_path.rglob(f"*{ext}"):
                if any(skip in f.parts for skip in SKIP_DIRS):
                    continue
                files.append(f)

    results = []
    for fp in files:
        ext = fp.suffix
        lang = EXT_TO_LANG.get(ext)
        if not lang:
            continue
        parser = _get_parser(lang)
        if not parser:
            continue

        try:
            content = fp.read_bytes()
            text_lines = content.decode('utf-8', errors='replace').splitlines()
            tree = parser.parse(content)
            _find_refs_in_tree(
                tree.root_node, symbol, lang,
                fp, state.repo_path, text_lines, results,
            )
        except Exception:
            continue

        if len(results) >= 100:
            break

    if not results:
        return f"No references found for '{symbol}'."

    lines = [f"References to '{symbol}' ({len(results)} found):", ""]
    for r in results:
        lines.append(f"  {r['file']}:{r['line']}  {r['context']}")
    return '\n'.join(lines)


def _find_refs_in_tree(node, symbol, lang, file_path, repo_path, text_lines, results):
    """Walk AST to find identifier nodes matching the symbol."""
    if node.type == 'identifier' and node.text.decode('utf-8') == symbol:
        # Skip if this is a definition
        parent = node.parent
        def_types = DEFINITION_TYPES.get(lang, [])
        if parent and parent.type not in def_types:
            line = node.start_point[0] + 1
            rel = str(file_path.relative_to(repo_path))
            ctx = text_lines[line - 1].strip()[:200] if line <= len(text_lines) else ""
            results.append({'file': rel, 'line': line, 'context': ctx})

    for child in node.children:
        if len(results) >= 100:
            return
        _find_refs_in_tree(child, symbol, lang, file_path, repo_path, text_lines, results)
