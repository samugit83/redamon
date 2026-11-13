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
    # The owner's CodeFix model from "Models by feature". Empty means none was
    # chosen, and the session refuses to start rather than guess one.
    model: str = ""
    max_iterations: int = 100
    tool_output_max_chars: int = 20000
    model_context_window: int = 200000


class CodeFixState:
    """Minimal state tracking. The real state is in the messages array."""

    def __init__(self):
        self.remediation_id: str = ""
        self.remediation_title: str = ""
        self.user_id: str = ""
        #: The person who runs the fix (the ticket's `sub`) and the admin acting as them
        #: (`act`); `user_id` is the project's tenant. A push is asked for them (step 5.4).
        self.actor_user_id: str = ""
        self.real_actor_user_id: Optional[str] = None
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
        # Every file a change was written to, pending ones included. The commit
        # uses `committable`, not this.
        self.files_modified: set = set()
        # Repo-relative path -> the content the PR carries: what a person
        # accepted (or, with approval off, what the edit tools wrote). Only
        # tools/review_gate.py writes it, and _finalize commits exactly this.
        self.committable: dict = {}
        self.diff_blocks: list = []
        self.pending_approval: bool = False
        self.pending_block_id: Optional[str] = None
        # block_id -> review_gate.ProposedChange, for the change awaiting a
        # person's decision; a rejected one is undone on disk.
        self.block_backups: dict = {}
        self.settings: CodeFixSettings = CodeFixSettings()
        self.streaming_callback = None
        self.iteration: int = 0
        self.status: str = "initializing"
