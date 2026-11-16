"""Read now (phase 6, T6.7): one page of a resource read for the person, from the store or live.

Until T6.7 fills it the router answers 501 ``not_implemented``. The router ends the call at
the contract's deadline (``contract.DEADLINES_SEC["read_now"]``) with ``timeout``.
"""

from __future__ import annotations

from tradecraft.contract import ReadNowRequest, ReadNowResult


async def read_now(request: ReadNowRequest) -> ReadNowResult:
    raise NotImplementedError("Read now arrives with T6.7")
