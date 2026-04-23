"""Round-robin API key rotation to avoid rate limits."""

import logging

logger = logging.getLogger(__name__)


class KeyRotator:
    """Rotates through a pool of API keys every N calls."""

    def __init__(self, keys: list[str], rotate_every_n: int = 10):
        self.keys = [k for k in keys if k]
        self.rotate_every_n = max(1, rotate_every_n)
        self._call_count = 0
        self._index = 0

    @property
    def current_key(self) -> str:
        if not self.keys:
            return ''
        return self.keys[self._index % len(self.keys)]

    def tick(self):
        """Call after each API request to advance the rotation counter."""
        if len(self.keys) <= 1:
            return
        self._call_count += 1
        if self._call_count >= self.rotate_every_n:
            self._call_count = 0
            old_idx = self._index
            self._index = (self._index + 1) % len(self.keys)
            logger.debug("Key rotation: switched from key index %d to %d (pool size %d)",
                         old_idx, self._index, len(self.keys))

    @property
    def has_keys(self) -> bool:
        return len(self.keys) > 0

    @property
    def pool_size(self) -> int:
        return len(self.keys)
