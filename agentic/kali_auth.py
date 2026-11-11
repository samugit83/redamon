"""The credential the agent presents to the Kali sandbox's own HTTP servers.

Every Kali server (the MCP SSE ports, the Metasploit session manager on :8013, the
Hydra progress stream on :8014, the terminal on :8016) refuses a request without
``Authorization: Bearer <MCP_AUTH_TOKEN>``, and refuses everything when its token
is unset. The token is read at call time, as the MCP clients' ``BearerAuth`` does.
"""
import logging
import os

logger = logging.getLogger(__name__)


def kali_auth_headers() -> dict:
    """The bearer header, or none when MCP_AUTH_TOKEN is unset (never an empty bearer)."""
    token = os.environ.get("MCP_AUTH_TOKEN", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def note_kali_refusal(status_code: int, what: str) -> bool:
    """Log a Kali 401 (the agent's token is missing or differs from kali-sandbox's)."""
    if status_code != 401:
        return False
    logger.warning(
        "[rbac] kali-sandbox refused the agent's bearer on %s: MCP_AUTH_TOKEN is "
        "unset in the agent or differs from kali-sandbox's", what)
    return True
