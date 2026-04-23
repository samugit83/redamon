from abc import ABC, abstractmethod
from typing import Any


class BaseClient(ABC):
    """
    Base interface for knowledge base data source clients.

    Each client is responsible for:
    1. Fetching raw data from its source (API, CSV, GitHub, etc.)
    2. Converting raw data into chunk dicts ready for embedding + Neo4j storage.

    Chunk dict contract — every chunk must include:
        - chunk_id: str — deterministic hash (use ChunkStrategy.generate_chunk_id)
        - content: str — text to embed
        - title: str — human-readable title
        - source: str — must match cls.SOURCE
    Plus any source-specific fields matching the NODE_LABEL schema.
    """

    SOURCE: str = ""  # e.g., "nvd", "gtfobins", "tool_docs"
    NODE_LABEL: str = ""  # e.g., "NVDChunk", "GTFOBinsChunk", "ToolDocChunk"

    @abstractmethod
    def fetch(self, **kwargs) -> list[dict]:
        """
        ownload or read raw data from the source.

        Returns:
            List of raw data dicts (source-specific structure).
        """

    @abstractmethod
    def to_chunks(self, raw_data: list[dict]) -> list[dict]:
        """
        Convert raw data into chunk dicts.

        Each chunk dict must satisfy the contract described above.

        Args:
            raw_data: Output from fetch().

        Returns:
            List of chunk dicts ready for embedding and Neo4j storage.
        """
