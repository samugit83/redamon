"""The focus preview (phase 5, T5.3): how a focus would sort a sample of the map.

Until T5.3 fills it the router answers 501 ``not_implemented``. The router ends the call at
the contract's deadline (``contract.DEADLINES_SEC["preview_focus"]``) with ``timeout``.
"""

from __future__ import annotations

from tradecraft.contract import PreviewRequest, PreviewResult


async def preview_focus(request: PreviewRequest) -> PreviewResult:
    raise NotImplementedError("The focus preview arrives with T5.3")
