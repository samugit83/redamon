import hashlib
import re
import logging

logger = logging.getLogger(__name__)


def _load_chunking_defaults() -> tuple[int, int]:
    """
    Load (max_tokens, preferred_tokens) from kb_config with a safe fallback.

    The chunker is coupled to the embedder's max sequence length: max_tokens
    must stay below the embedder's hard cap or the embedder silently truncates.
    Reading from kb_config means swapping to a longer-context embedder is a
    one-line YAML edit instead of a code change.

    Falls back to (480, 256) — sized for e5-large-v2 — if config loading
    fails for any reason (missing yaml, import error during early bootstrap,
    corrupted config). The fallback values match the historical hardcoded
    constants so behavior is unchanged when no config is available.
    """
    try:
        from knowledge_base.kb_config import load_kb_config
        cfg = load_kb_config()
        return cfg.chunking.max_tokens, cfg.chunking.preferred_tokens
    except Exception:
        return 480, 256


_MAX_TOKENS, _PREFERRED_TOKENS = _load_chunking_defaults()


class ChunkStrategy:
    """
    Content-aware chunking that respects document structure.

    MAX_CHUNK_TOKENS and PREFERRED_CHUNK_TOKENS are loaded at class
    definition time from kb_config (chunking.max_tokens and
    chunking.preferred_tokens). They remain class-level constants for
    backward compatibility with code that imports them directly via
    ``ChunkStrategy.MAX_CHUNK_TOKENS``.
    """

    MAX_CHUNK_TOKENS = _MAX_TOKENS
    PREFERRED_CHUNK_TOKENS = _PREFERRED_TOKENS

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Fast token count estimate (chars / 4)."""
        return len(text) // 4

    @staticmethod
    def generate_chunk_id(source: str, unique_key: str) -> str:
        """
        Generate a deterministic chunk_id from source + unique key.

        Args:
            source: Source identifier (e.g., 'nvd', 'gtfobins').
            unique_key: Unique key within the source (e.g., CVE ID, binary name).

        Returns:
            16-character hex string.
        """
        raw = f"{source}:{unique_key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def chunk_structured(self, entries: list[dict]) -> list[dict]:
        """
        Chunk atomic entries — each entry becomes one chunk.

        Used for: CVEs, GTFOBins, LOLBAS, Nuclei templates, ExploitDB descriptions,
        tool flag groups.

        Each entry dict must have at least a 'content' key.
        If content exceeds MAX_CHUNK_TOKENS, it is truncated.

        Returns:
            The same list with content potentially truncated.
        """
        result = []
        for entry in entries:
            content = entry.get("content", "")
            estimated = self.estimate_tokens(content)
            if estimated > self.MAX_CHUNK_TOKENS:
                # Truncate to approximate MAX_CHUNK_TOKENS chars
                max_chars = self.MAX_CHUNK_TOKENS * 4
                content = content[:max_chars].rsplit(" ", 1)[0] + "..."
                entry = {**entry, "content": content}
                logger.debug(
                    f"Truncated chunk from ~{estimated} to ~{self.estimate_tokens(content)} tokens"
                )
            result.append(entry)
        return result

    def chunk_markdown(self, text: str, split_on: str = "##") -> list[dict]:
        """
        Chunk markdown text by splitting on headers.

        Used for: OWASP test cases, tool reference docs, exploit writeups.

        Strategy:
        1. Split on the specified header level (default: ##)
        2. Merge sections smaller than 128 tokens with the next section
        3. Split sections larger than MAX_CHUNK_TOKENS at paragraph boundaries

        Args:
            text: Markdown text to chunk.
            split_on: Header prefix to split on (e.g., '##', '###').

        Returns:
            List of dicts with 'content' and 'title' keys.
        """
        if not text.strip():
            return []

        # Split on header pattern (keep the header with its section)
        pattern = rf"(?=^{re.escape(split_on)}\s)",
        sections = re.split(rf"(?m)(?=^{re.escape(split_on)}\s)", text)

        # Remove empty sections
        sections = [s.strip() for s in sections if s.strip()]

        if not sections:
            return []

        # Extract title from first line of each section
        parsed = []
        for section in sections:
            lines = section.split("\n", 1)
            title = lines[0].lstrip("#").strip()
            body = lines[1].strip() if len(lines) > 1 else ""
            full_content = section.strip()
            parsed.append({"title": title, "content": full_content, "body": body})

        # Merge small sections
        merged = []
        buffer = None
        for item in parsed:
            estimated = self.estimate_tokens(item["content"])
            if buffer is not None:
                combined_content = buffer["content"] + "\n\n" + item["content"]
                combined_est = self.estimate_tokens(combined_content)
                if combined_est <= self.MAX_CHUNK_TOKENS:
                    buffer = {
                        "title": buffer["title"],
                        "content": combined_content,
                    }
                    continue
                else:
                    merged.append(buffer)
                    buffer = None

            if estimated < 128:
                buffer = {"title": item["title"], "content": item["content"]}
            else:
                merged.append({"title": item["title"], "content": item["content"]})

        if buffer is not None:
            merged.append(buffer)

        # Split oversized sections at paragraph boundaries
        result = []
        for item in merged:
            estimated = self.estimate_tokens(item["content"])
            if estimated <= self.MAX_CHUNK_TOKENS:
                result.append(item)
            else:
                sub_chunks = self._split_at_paragraphs(
                    item["content"], item["title"]
                )
                result.extend(sub_chunks)

        return result

    def _split_at_paragraphs(self, text: str, base_title: str) -> list[dict]:
        """
        Split oversized text at paragraph boundaries (\n\n).

        Tries to keep each chunk under PREFERRED_CHUNK_TOKENS.
        Falls back to MAX_CHUNK_TOKENS as hard ceiling.
        """
        paragraphs = re.split(r"\n\n+", text)
        chunks = []
        current_content = ""
        part = 1

        for para in paragraphs:
            candidate = (current_content + "\n\n" + para).strip() if current_content else para
            if self.estimate_tokens(candidate) > self.MAX_CHUNK_TOKENS and current_content:
                chunks.append({
                    "title": f"{base_title} (part {part})" if part > 1 or len(paragraphs) > 1 else base_title,
                    "content": current_content.strip(),
                })
                current_content = para
                part += 1
            else:
                current_content = candidate

        if current_content.strip():
            chunks.append({
                "title": f"{base_title} (part {part})" if part > 1 else base_title,
                "content": current_content.strip(),
            })

        return chunks
