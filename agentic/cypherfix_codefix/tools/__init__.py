"""CodeFix tool definitions for LLM."""

CODEFIX_TOOLS = [
    {
        "name": "github_glob",
        "description": "Fast file pattern matching. Returns file paths sorted by modification time.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Glob pattern to match files"},
                "path": {"type": "string", "description": "Directory to search in (default: repo root)"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "github_grep",
        "description": "Search file contents using regex (ripgrep). Output modes: 'files_with_matches' (default), 'content', 'count'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "path": {"type": "string", "description": "File or directory to search"},
                "glob": {"type": "string", "description": "Filter files by glob"},
                "type": {"type": "string", "description": "File type filter (e.g., 'py', 'js')"},
                "output_mode": {"type": "string", "enum": ["files_with_matches", "content", "count"]},
                "context": {"type": "integer", "description": "Lines of context around matches"},
                "case_insensitive": {"type": "boolean"},
                "multiline": {"type": "boolean"},
                "head_limit": {"type": "integer", "description": "Max results (default: 50)"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "github_read",
        "description": "Read a file with line numbers. ALWAYS read a file before editing it.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path relative to repo root"},
                "offset": {"type": "integer", "description": "Start line (1-indexed)"},
                "limit": {"type": "integer", "description": "Number of lines to read"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "github_edit",
        "description": "Exact string replacement in a file. old_string must be UNIQUE. You MUST read the file first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "old_string": {"type": "string", "description": "Exact text to replace"},
                "new_string": {"type": "string", "description": "Replacement text"},
                "replace_all": {"type": "boolean", "description": "Replace all occurrences (default: false)"},
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    },
    {
        "name": "github_write",
        "description": "Create a new file, or replace a whole file. The whole file is shown to the user for review, like an edit. Prefer github_edit for modifications.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "content": {"type": "string", "description": "File content to write"},
            },
            "required": ["file_path", "content"],
        },
    },
    {
        "name": "github_bash",
        "description": "Run a shell command in the repo directory. Full runtimes available: node/npm/yarn/pnpm, python3/pip, go, java/mvn, ruby/bundler, php/composer, dotnet, make/gcc/g++. Use for tests, linters, builds, dependency installs, and project tooling.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer", "description": "Timeout in milliseconds (default: 120000)"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "github_list_dir",
        "description": "List directory contents with type indicators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path (default: repo root)"},
            },
        },
    },
    {
        "name": "github_symbols",
        "description": "List all functions, classes, methods in a file with line ranges. Use BEFORE reading a file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "github_find_definition",
        "description": "Find where a symbol is defined. More precise than grep — returns only definitions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Name of function/class/method"},
                "scope": {"type": "string", "description": "Directory to search in"},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "github_find_references",
        "description": "Find all usages of a symbol across the codebase. Skips comments and strings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string"},
                "file_path": {"type": "string", "description": "Limit search to this file"},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "github_repo_map",
        "description": "High-level codebase map: files with function/class signatures ranked by importance. Use FIRST on unfamiliar repos.",
        "input_schema": {
            "type": "object",
            "properties": {
                "max_tokens": {"type": "integer", "description": "Token budget (default: 2000)"},
                "focus_paths": {"type": "array", "items": {"type": "string"}, "description": "Directories to focus on"},
            },
        },
    },
]
