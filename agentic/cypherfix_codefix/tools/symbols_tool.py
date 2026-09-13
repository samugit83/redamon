"""Symbols tool: tree-sitter AST — list definitions in a file."""

import logging
from pathlib import Path

from .repo_paths import RepoPathError, resolve_in_repo

logger = logging.getLogger(__name__)

# Language detection from file extension
EXT_TO_LANG = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.jsx': 'javascript', '.java': 'java', '.go': 'go', '.rs': 'rust',
    '.rb': 'ruby', '.php': 'php', '.c': 'c', '.cpp': 'cpp', '.cs': 'c_sharp',
    '.kt': 'kotlin', '.swift': 'swift', '.scala': 'scala',
}

# Node types that represent definitions per language
DEFINITION_TYPES = {
    'python': ['function_definition', 'class_definition', 'decorated_definition'],
    'javascript': ['function_declaration', 'class_declaration', 'method_definition',
                    'arrow_function', 'variable_declarator'],
    'typescript': ['function_declaration', 'class_declaration', 'method_definition',
                    'arrow_function', 'variable_declarator', 'interface_declaration',
                    'type_alias_declaration'],
    'java': ['class_declaration', 'method_declaration', 'interface_declaration'],
    'go': ['function_declaration', 'method_declaration', 'type_declaration'],
    'rust': ['function_item', 'impl_item', 'struct_item', 'enum_item', 'trait_item'],
    'ruby': ['method', 'class', 'module', 'singleton_method'],
    'php': ['function_definition', 'class_declaration', 'method_declaration'],
    'c': ['function_definition', 'struct_specifier'],
    'cpp': ['function_definition', 'class_specifier', 'struct_specifier'],
    'c_sharp': ['class_declaration', 'method_declaration', 'interface_declaration'],
}


def _get_parser(lang: str):
    """Get a tree-sitter parser for the given language."""
    try:
        from tree_sitter_languages import get_parser
        return get_parser(lang)
    except Exception as e:
        logger.debug(f"tree-sitter not available for {lang}: {e}")
        return None


def _extract_name(node):
    """Extract the name from a definition node."""
    for child in node.children:
        if child.type in ('identifier', 'name', 'property_identifier', 'type_identifier'):
            return child.text.decode('utf-8')
    return None


def _walk_definitions(node, lang, depth=0, parent_name=None):
    """Walk AST and extract definitions."""
    definitions = []
    def_types = DEFINITION_TYPES.get(lang, [])

    for child in node.children:
        if child.type in def_types:
            name = _extract_name(child)
            if name:
                start_line = child.start_point[0] + 1
                end_line = child.end_point[0] + 1
                kind = child.type.replace('_definition', '').replace('_declaration', '').replace('_item', '')
                scope = f"{parent_name} > " if parent_name else ""
                definitions.append({
                    'name': name,
                    'kind': kind,
                    'start_line': start_line,
                    'end_line': end_line,
                    'scope': scope,
                    'depth': depth,
                })
                # Recurse for nested definitions
                definitions.extend(_walk_definitions(child, lang, depth + 1, name))
        else:
            definitions.extend(_walk_definitions(child, lang, depth, parent_name))

    return definitions


async def github_symbols(state, file_path: str) -> str:
    """List all definitions in a file using tree-sitter."""
    try:
        full_path = resolve_in_repo(state.repo_path, file_path, allow_root=False)
    except RepoPathError as exc:
        return f"Error: {exc}"

    if not full_path.exists():
        return f"Error: File not found: {file_path}. Use github_glob to find the correct path."

    ext = Path(file_path).suffix
    lang = EXT_TO_LANG.get(ext)
    if not lang:
        return f"Error: Unsupported language for {ext}. Supported: {', '.join(EXT_TO_LANG.keys())}"

    parser = _get_parser(lang)
    if not parser:
        return f"Error: tree-sitter parser not available for {lang}. Use github_read instead."

    try:
        content = full_path.read_bytes()
        tree = parser.parse(content)
        definitions = _walk_definitions(tree.root_node, lang)

        if not definitions:
            return f"No definitions found in {file_path}."

        lines = [f"Symbols in {file_path} ({len(definitions)} definitions):", ""]
        for d in definitions[:500]:
            indent = "  " * d['depth']
            lines.append(
                f"{indent}{d['kind']} {d['scope']}{d['name']}  "
                f"[{d['start_line']}-{d['end_line']}]"
            )

        return '\n'.join(lines)
    except Exception as e:
        return f"Error parsing {file_path}: {e}. Use github_read instead."
