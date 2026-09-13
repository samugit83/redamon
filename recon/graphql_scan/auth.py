"""
Authentication Module for GraphQL Testing

GraphQL keeps its own typed auth triple (GRAPHQL_AUTH_TYPE/VALUE/HEADER); the
headers are built by the shared project AuthProfile builder so both paths get
the same sanitizing.
"""

from typing import Dict

from recon.helpers.auth_profile import build_auth_headers as _build_profile_headers
from recon.helpers.auth_profile import mask_auth_value  # noqa: F401  (public re-export)


def build_auth_headers(settings: dict) -> Dict[str, str]:
    """Build GraphQL request auth headers from the project settings."""
    return _build_profile_headers({
        'authType': settings.get('GRAPHQL_AUTH_TYPE', ''),
        'authValue': settings.get('GRAPHQL_AUTH_VALUE', ''),
        'authHeaderName': settings.get('GRAPHQL_AUTH_HEADER', ''),
    }, log_prefix='[GraphQL]')
