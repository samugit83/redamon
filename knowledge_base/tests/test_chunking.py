import pytest
from knowledge_base.chunking import ChunkStrategy


@pytest.fixture
def strategy():
    return ChunkStrategy()


class TestChunkStructured:

    def test_atomic_entries_stay_whole(self, strategy):
        entries = [
            {"content": "Short entry about python SUID", "title": "python"},
            {"content": "Another entry about vim file-read", "title": "vim"},
        ]
        result = strategy.chunk_structured(entries)
        assert len(result) == 2
        assert result[0]["content"] == "Short entry about python SUID"
        assert result[1]["content"] == "Another entry about vim file-read"

    def test_oversized_entry_truncated(self, strategy):
        # Create content that exceeds MAX_CHUNK_TOKENS (450 tokens ≈ 1800 chars)
        long_content = "word " * 500  # ~2500 chars ≈ 625 tokens
        entries = [{"content": long_content, "title": "big"}]
        result = strategy.chunk_structured(entries)
        assert len(result) == 1
        assert result[0]["content"].endswith("...")
        assert strategy.estimate_tokens(result[0]["content"]) <= strategy.MAX_CHUNK_TOKENS + 10

    def test_empty_input(self, strategy):
        assert strategy.chunk_structured([]) == []

    def test_preserves_extra_fields(self, strategy):
        entries = [{"content": "test", "title": "t", "cve_id": "CVE-2021-44228"}]
        result = strategy.chunk_structured(entries)
        assert result[0]["cve_id"] == "CVE-2021-44228"


class TestChunkMarkdown:

    def test_splits_on_headers(self, strategy):
        # The chunker auto-merges adjacent sections when the combined
        # size fits in MAX_CHUNK_TOKENS AND the first section is under
        # 128 tokens (the small-section merge threshold in
        # chunk_markdown). To actually exercise header-based splitting,
        # each section must be >= 128 tokens (~512 chars) so the merger
        # leaves them as standalone chunks.
        filler = "Paragraph content for this section. " * 40  # ~1480 chars ≈ 370 tokens
        text = f"## Section One\n{filler}\n\n## Section Two\n{filler}"
        result = strategy.chunk_markdown(text)
        assert len(result) == 2
        assert result[0]["title"] == "Section One"
        assert result[1]["title"] == "Section Two"

    def test_merges_small_sections(self, strategy):
        # Two very small sections should be merged
        text = "## A\nTiny.\n\n## B\nAlso tiny."
        result = strategy.chunk_markdown(text)
        # Both are < 128 tokens, so should be merged into one chunk
        assert len(result) == 1
        assert "Tiny." in result[0]["content"]
        assert "Also tiny." in result[0]["content"]

    def test_splits_oversized_at_paragraphs(self, strategy):
        # Create a section that exceeds MAX_CHUNK_TOKENS
        big_para_1 = "First paragraph. " * 100  # ~1700 chars ≈ 425 tokens
        big_para_2 = "Second paragraph. " * 100
        text = f"## Big Section\n{big_para_1}\n\n{big_para_2}"
        result = strategy.chunk_markdown(text)
        assert len(result) >= 2
        assert "part" in result[1]["title"].lower()

    def test_empty_input(self, strategy):
        assert strategy.chunk_markdown("") == []
        assert strategy.chunk_markdown("   ") == []

    def test_no_headers_returns_nothing(self, strategy):
        # Text without ## headers — no split points
        text = "Just some text without headers."
        result = strategy.chunk_markdown(text)
        # The whole text becomes one section (no ## to split on)
        # Since it's < 128 tokens, it may be a single chunk or empty depending on impl
        # It should be returned as-is since there's no split
        assert len(result) <= 1

    def test_custom_split_on(self, strategy):
        text = "### Sub One\nContent.\n\n### Sub Two\nMore content."
        result = strategy.chunk_markdown(text, split_on="###")
        assert len(result) >= 1


class TestEstimateTokens:

    def test_basic_estimate(self, strategy):
        text = "a" * 400  # 400 chars ≈ 100 tokens
        assert strategy.estimate_tokens(text) == 100

    def test_empty_string(self, strategy):
        assert strategy.estimate_tokens("") == 0


class TestGenerateChunkId:

    def test_deterministic(self):
        id1 = ChunkStrategy.generate_chunk_id("nvd", "CVE-2021-44228")
        id2 = ChunkStrategy.generate_chunk_id("nvd", "CVE-2021-44228")
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        id1 = ChunkStrategy.generate_chunk_id("nvd", "CVE-2021-44228")
        id2 = ChunkStrategy.generate_chunk_id("nvd", "CVE-2021-41773")
        assert id1 != id2

    def test_different_sources_different_ids(self):
        id1 = ChunkStrategy.generate_chunk_id("nvd", "CVE-2021-44228")
        id2 = ChunkStrategy.generate_chunk_id("exploitdb", "CVE-2021-44228")
        assert id1 != id2

    def test_length(self):
        cid = ChunkStrategy.generate_chunk_id("test", "key")
        assert len(cid) == 16
