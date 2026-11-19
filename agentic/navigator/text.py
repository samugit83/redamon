"""Model content to plain text: providers answer a string or a list of content blocks."""
from __future__ import annotations


def message_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") in (None, "text") and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "".join(parts)
    return ""
