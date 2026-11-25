"""The credential the agent presents to a Kali sandbox's own HTTP servers.

Every Kali server (the MCP SSE ports, the Metasploit session manager on :8013, the
Hydra progress stream on :8014, the terminal on :8016) refuses a request without
the bearer of its own instance, and refuses everything when its token is unset. Each
sandbox has its own token, which the agent gets from the sandbox router's handle.
"""
import logging

logger = logging.getLogger(__name__)


def kali_auth_headers_for(token) -> dict:
    """The bearer header for one sandbox instance's own token, or none for an empty or
    malformed one: never an empty bearer, never a value a CR/LF could split into a
    second header."""
    if isinstance(token, str) and token and token.isascii() and token.isprintable() and " " not in token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def note_kali_refusal(status_code: int, what: str) -> bool:
    """Log a Kali 401 (the sandbox refused the instance token the agent holds for it)."""
    if status_code != 401:
        return False
    logger.warning("[rbac] a Kali sandbox refused the agent's bearer on %s (its instance token)", what)
    return True
