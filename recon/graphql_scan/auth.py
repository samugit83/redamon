"""
Authentication Module for GraphQL Testing

Handles different authentication types for GraphQL endpoints.
"""

from typing import Dict, Optional
import base64


def build_auth_headers(settings: dict) -> Dict[str, str]:
    """
    Build authentication headers based on project settings.

    Args:
        settings: Project settings containing auth configuration

    Returns:
        Dict of headers to include in requests
    """
    headers = {}

    auth_type = settings.get('GRAPHQL_AUTH_TYPE', '').lower()
    auth_value = settings.get('GRAPHQL_AUTH_VALUE', '')

    if not auth_type or not auth_value:
        return headers

    # Bearer token authentication
    if auth_type == 'bearer':
        headers['Authorization'] = f'Bearer {auth_value}'
        masked_value = mask_auth_value(auth_value, auth_type)
        print(f"[*][GraphQL] Using Bearer token authentication: {masked_value}")

    # Cookie authentication
    elif auth_type == 'cookie':
        headers['Cookie'] = auth_value
        masked_value = mask_auth_value(auth_value, auth_type)
        print(f"[*][GraphQL] Using Cookie authentication: {masked_value}")

    # Custom header authentication
    elif auth_type == 'header':
        header_name = settings.get('GRAPHQL_AUTH_HEADER', 'X-Auth-Token')
        headers[header_name] = auth_value
        masked_value = mask_auth_value(auth_value, auth_type)
        print(f"[*][GraphQL] Using custom header authentication: {header_name} = {masked_value}")

    # Basic authentication
    elif auth_type == 'basic':
        # Expect auth_value in format "username:password"
        if ':' in auth_value:
            encoded = base64.b64encode(auth_value.encode()).decode()
            headers['Authorization'] = f'Basic {encoded}'
            masked_value = mask_auth_value(auth_value, auth_type)
            print(f"[*][GraphQL] Using Basic authentication: {masked_value}")
        else:
            print("[!][GraphQL] Basic auth value should be in format 'username:password'")

    # API Key authentication (common variations)
    elif auth_type == 'apikey':
        # Try common API key header names
        header_name = settings.get('GRAPHQL_AUTH_HEADER', 'X-API-Key')
        headers[header_name] = auth_value
        masked_value = mask_auth_value(auth_value, auth_type)
        print(f"[*][GraphQL] Using API key authentication: {header_name} = {masked_value}")

    else:
        print(f"[!][GraphQL] Unknown auth type: {auth_type}")

    return headers


def mask_auth_value(auth_value: str, auth_type: str = '') -> str:
    """
    Mask authentication values for safe logging.

    Args:
        auth_value: The authentication value to mask
        auth_type: Type of authentication

    Returns:
        Masked version of the auth value
    """
    if not auth_value:
        return ''

    # For basic auth, mask after the username
    if auth_type == 'basic' and ':' in auth_value:
        username, _ = auth_value.split(':', 1)
        return f"{username}:***"

    # For other types, show first few and last few characters
    if len(auth_value) > 10:
        return f"{auth_value[:4]}...{auth_value[-4:]}"
    elif len(auth_value) > 4:
        return f"{auth_value[:2]}***"
    else:
        return "***"