"""State models for the CodeFix agent."""

from typing import Optional
from pathlib import Path
from pydantic import BaseModel


class DiffBlock(BaseModel):
    block_id: str
    file_path: str
    language: str
    old_code: str
    new_code: str
    context_before: str
    context_after: str
    start_line: int
    end_line: int
    description: str
    status: str = "pending"  # pending | accepted | rejected


class CodeFixSettings(BaseModel):
    github_token: str = ""
    github_repo: str = ""
    default_branch: str = "main"
    branch_prefix: str = "cypherfix/"
    require_approval: bool = True
    model: str = "gpt-4o"
    max_iterations: int = 100
    tool_output_max_chars: int = 20000
    model_context_window: int = 200000


class CodeFixState:
    """Minimal state tracking. The real state is in the messages array."""

    def __init__(self):
        self.remediation_id: str = ""
        self.remediation_title: str = ""
        self.user_id: str = ""
        self.project_id: str = ""
        self.session_id: str = ""
        # Identifies the per-job CodeFix build sandbox (T6/E10). Set in
        # CodeFixOrchestrator.run(); used to route github_bash into the sandbox.
        self.job_id: str = ""
        self.repo_path: Optional[Path] = None
        self.repo_url: str = ""
        self.branch_name: str = ""
        self.base_branch: str = "main"
        self.files_read: set = set()
        self.files_modified: set = set()
        self.diff_blocks: list = []
        self.pending_approval: bool = False
        self.pending_block_id: Optional[str] = None
        # block_id -> (file_path, content before the edit, was the file already
        # in files_modified). A rejected block has to be undone on disk: only
        # approved changes may reach the commit in _finalize.
        self.block_backups: dict = {}
        self.settings: CodeFixSettings = CodeFixSettings()
        self.streaming_callback = None
        self.iteration: int = 0
        self.status: str = "initializing"
