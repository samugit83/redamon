"""
Output-offload helper.

After a tool runs, route its output through `maybe_offload()`. If policy says
"always" - or "auto" + size exceeds threshold - write the full output to
/workspace/<projectId>/tool-outputs/<utc-iso>-<tool>.txt and return a head/tail
stub. Otherwise return the output unchanged.

Per-call override: the executor sniffs `output_mode` out of tool_args (via
`strip_output_mode()`) BEFORE dispatching, so MCP servers never see it. The
returned override wins over the per-tool policy.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import workspace_fs
from tool_offload_policy import get_offload_mode, OFFLOAD_THRESHOLD

logger = logging.getLogger(__name__)

WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))

HEAD_LINES = 80
TAIL_LINES = 40
# Char caps protect against tools that emit huge single-line output
# (base64 blobs, minified JSON) - without these, head/tail join would
# render the entire output and defeat the offload.
HEAD_CHAR_CAP = 4000
TAIL_CHAR_CAP = 2000


_OFFLOAD_OVERRIDE_VALUES = {"inline", "file", "auto"}


def strip_output_mode(tool_args) -> tuple:
    """
    Pop `output_mode` from tool_args ONLY when its value is an offload override
    (`inline` | `file` | `auto`), and return (cleaned_args, override).

    Tools like `fs_grep` own a native `output_mode` param with a different
    vocabulary (`files_with_matches` | `content` | `count`). Stripping it
    unconditionally would silently revert those calls to the default and
    swallow caller intent — bug observed: fs_grep(output_mode="content")
    returned just the filename because the param was eaten before reaching
    the tool. Now the strip only fires for the offload tokens.

    Called by PhaseAwareToolExecutor BEFORE invoking the tool so MCP servers
    never see the offload override. Returns the original args dict (unchanged)
    and None when no override is set OR the value belongs to the tool.
    """
    if not isinstance(tool_args, dict) or "output_mode" not in tool_args:
        return tool_args, None
    value = tool_args.get("output_mode")
    if value not in _OFFLOAD_OVERRIDE_VALUES:
        return tool_args, None
    cleaned = {k: v for k, v in tool_args.items() if k != "output_mode"}
    return cleaned, value


def _resolve_mode(tool_name: str, override: Optional[str]) -> str:
    """
    Return one of: "inline" (never offload), "offload" (always offload),
    or "auto" (size-driven).

    Override values are the user-facing ones: "inline" | "file" | "auto".
    Policy values are the registry ones: "never" | "always" | "auto".
    This function normalises both into the three internal decision modes.
    """
    if override == "inline":
        return "inline"
    if override == "file":
        return "offload"
    if override == "auto":
        return "auto"
    # unknown override (or None) -> fall through to per-tool policy
    pol = get_offload_mode(tool_name)
    if pol == "never":
        return "inline"
    if pol == "always":
        return "offload"
    return "auto"


def maybe_offload(
    project_id: str,
    tool_name: str,
    output,
    *,
    override: Optional[str] = None,
    job_id: Optional[str] = None,
) -> str:
    """
    Possibly write `output` to disk and return a head/tail stub; else return
    `output` unchanged.

    Args:
        project_id: required - decides which /workspace/<projectId>/tool-outputs/ dir.
        tool_name: used for the policy lookup + filename.
        output: tool output (str or anything coercible).
        override: per-call override stripped from tool_args by the executor.
        job_id: if set, file is named "<job_id>-<tool>.log" instead of timestamp.
    """
    if output is None:
        return ""
    if not isinstance(output, str):
        output = str(output)
    if not project_id:
        # No project scope - can't safely offload. Return as-is.
        return output

    mode = _resolve_mode(tool_name, override)
    if mode == "inline":
        return output
    if mode == "auto" and len(output) <= OFFLOAD_THRESHOLD:
        return output
    # else: mode == "offload", or mode == "auto" and over threshold

    # tool-outputs/ is written by every sandbox of the project, and the names below
    # are predictable: the folder is created and the file written through
    # workspace_fs's pinned folder, as a new file only, so a link planted at the
    # folder or at the next name is never written through (FU, STRIDE T4).
    project_root = WORKSPACE_ROOT / project_id
    outputs_dir = project_root / "tool-outputs"
    try:
        workspace_fs._validate_project_id(project_id)
        project_root.mkdir(parents=True, exist_ok=True)
        with workspace_fs._pinned_parent(outputs_dir, project_root) as (dir_fd, name):
            with contextlib.suppress(FileExistsError):
                os.mkdir(name, 0o777, dir_fd=dir_fd)
    except Exception as e:
        logger.error(f"offload: cannot create {outputs_dir}: {e}")
        return output

    tool = re.sub(r"[^A-Za-z0-9_.-]", "_", str(tool_name)) or "tool"
    if job_id:
        filename = f"{job_id}-{tool}.log"
    else:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        filename = f"{ts}-{tool}.txt"
    try:
        # Inside the try: a lone surrogate (json.loads lets "\ud800" through) fails
        # the encode, and the output then stays inline instead of being lost.
        data = output.encode("utf-8")
        try:
            workspace_fs._write_file(outputs_dir / filename, project_root, data, create_only=True)
        except FileExistsError:
            # Taken: a second offload in the same second, or a name planted ahead.
            stem, ext = os.path.splitext(filename)
            filename = f"{stem}-{uuid.uuid4().hex[:8]}{ext}"
            workspace_fs._write_file(outputs_dir / filename, project_root, data, create_only=True)
    except Exception as e:
        logger.error(f"offload: failed to write {outputs_dir / filename}: {e}")
        return output

    return _format_stub(output, filename, len(output))


def _format_stub(output: str, filename: str, byte_len: int) -> str:
    lines = output.splitlines()
    head = "\n".join(lines[:HEAD_LINES])
    if len(head) > HEAD_CHAR_CAP:
        head = head[:HEAD_CHAR_CAP] + "\n[head truncated]"
    has_tail = len(lines) > HEAD_LINES
    tail = "\n".join(lines[-TAIL_LINES:]) if has_tail else ""
    if len(tail) > TAIL_CHAR_CAP:
        tail = "[tail truncated]\n" + tail[-TAIL_CHAR_CAP:]
    parts = [
        f"[Output offloaded: {byte_len} chars -> tool-outputs/{filename}]",
        f"[Head {HEAD_LINES} lines / Tail {TAIL_LINES} lines below. "
        f"Use fs_read for full output; fs_grep over tool-outputs/ to search.]",
        "--- head ---",
        head,
    ]
    if tail:
        parts.append("--- tail ---")
        parts.append(tail)
    return "\n".join(parts)
