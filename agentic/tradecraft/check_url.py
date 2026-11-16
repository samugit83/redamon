"""Check URL (phase 4, T4.1): what a URL is before a resource is saved.

Until T4.1 fills it the router answers 501 ``not_implemented``. The router ends the call at
the contract's deadline (``contract.DEADLINES_SEC["check_url"]``) with ``timeout``.
"""

from __future__ import annotations

from tradecraft.contract import CheckUrlRequest, CheckUrlResult


async def check_url(request: CheckUrlRequest) -> CheckUrlResult:
    raise NotImplementedError("Check URL arrives with T4.1")
