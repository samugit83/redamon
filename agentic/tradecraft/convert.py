"""Converting an account's 1.x resources to 2.0 (phase 9, T9.1).

Until T9.1 fills it the router answers 501 ``not_implemented``.
"""

from __future__ import annotations


async def convert_user(user_id: str) -> int:
    """Queues the conversion of the user's 1.x resources; returns how many were queued."""
    raise NotImplementedError("The conversion arrives with T9.1")
