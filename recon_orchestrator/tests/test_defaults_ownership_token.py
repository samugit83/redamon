"""
L-16: `/defaults` never serves a domain-ownership token.

The ProjectForm seeds a new project from this payload and POSTs it back, so a
token here became the token of every project created through the form: the
same published value for all of them. The create paths generate one per
project instead.

The route coroutine is called directly (the image has no httpx for TestClient).

Run: python -m pytest tests/test_defaults_ownership_token.py -v
"""
import asyncio
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for path in (str(REPO), str(REPO / "recon")):
    if path not in sys.path:
        sys.path.insert(0, path)

import api  # noqa: E402


def _defaults() -> dict:
    return asyncio.run(api.get_defaults())


def test_defaults_carry_no_ownership_token():
    assert "ownershipToken" not in _defaults()


def test_defaults_keep_the_rest_of_the_ownership_block():
    """The prefix and the switch are real defaults a new form needs."""
    payload = _defaults()
    assert payload["ownershipTxtPrefix"] == "_redamon-verify"
    assert payload["verifyDomainOwnership"] is False
