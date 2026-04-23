"""
GraphQL Introspection Module

Tests for exposed GraphQL introspection and extracts schema if available.
"""

import json
import time
from typing import Dict, Optional, Tuple
import requests
from requests.exceptions import RequestException, Timeout


def _build_type_ref_fragment(depth: int) -> str:
    """Render the recursive TypeRef fragment with N levels of ofType nesting.

    GraphQL type references are singly-linked chains (e.g. NON_NULL → LIST → NON_NULL → NAMED).
    Fixed 3-level fragments truncate info on deeply-wrapped types. GRAPHQL_DEPTH_LIMIT
    lets users match their schema's actual wrapping depth.
    """
    depth = max(1, min(20, depth))  # clamp 1-20 to avoid server-side query rejection
    indent = "    "
    parts = ["kind", "name"]
    tail_close = ""
    for _ in range(depth):
        parts.append("ofType {")
        parts.append(indent + "kind")
        parts.append(indent + "name")
        tail_close += "}\n"
    fragment_body = "\n  ".join(parts)
    return "fragment TypeRef on __Type {\n  " + fragment_body + "\n" + tail_close.strip() + "\n}"


def build_introspection_query(depth_limit: int = 3) -> str:
    """Compose the full introspection query with configurable TypeRef depth."""
    return f"""
query IntrospectionQuery {{
  __schema {{
    queryType {{ name }}
    mutationType {{ name }}
    subscriptionType {{ name }}
    types {{
      ...FullType
    }}
  }}
}}

fragment FullType on __Type {{
  kind
  name
  description
  fields(includeDeprecated: true) {{
    name
    description
    args {{
      ...InputValue
    }}
    type {{
      ...TypeRef
    }}
    isDeprecated
    deprecationReason
  }}
  inputFields {{
    ...InputValue
  }}
  interfaces {{
    ...TypeRef
  }}
  enumValues(includeDeprecated: true) {{
    name
    description
    isDeprecated
    deprecationReason
  }}
  possibleTypes {{
    ...TypeRef
  }}
}}

fragment InputValue on __InputValue {{
  name
  description
  type {{ ...TypeRef }}
  defaultValue
}}

{_build_type_ref_fragment(depth_limit)}
"""


# Default depth=3 query (matches historical behavior when no depth passed)
INTROSPECTION_QUERY = build_introspection_query(3)

# Simpler introspection query for testing
SIMPLE_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
  }
}
"""


def test_introspection(endpoint: str, headers: Dict[str, str] = None,
                      timeout: int = 30, verify_ssl: bool = True,
                      session: Optional[requests.Session] = None,
                      depth_limit: int = 3) -> Tuple[bool, Optional[dict], Optional[str]]:
    """
    Test if GraphQL introspection is enabled at the endpoint.

    Args:
        endpoint: The GraphQL endpoint URL
        headers: Optional headers including authentication
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        session: Optional pre-built requests.Session with retry adapter.
            Falls back to bare requests.post when None (back-compat for tests).
        depth_limit: TypeRef fragment depth for the full introspection query.

    Returns:
        Tuple of (is_enabled, schema_data, error_message)
    """
    if headers is None:
        headers = {}

    # Add content-type if not present
    if 'content-type' not in headers and 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/json'

    # Route through the retry-enabled session when provided.
    _post = session.post if session is not None else requests.post

    # Try simple introspection first
    print(f"[*][GraphQL] Testing introspection at: {endpoint}")

    try:
        # First, verify it's a GraphQL endpoint with a simple query
        test_payload = {
            "query": "{ __typename }"
        }

        response = _post(
            endpoint,
            json=test_payload,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )

        if response.status_code != 200:
            return False, None, f"Non-200 status code: {response.status_code}"

        try:
            result = response.json()
        except json.JSONDecodeError:
            return False, None, "Response is not valid JSON"

        # Check if it's a GraphQL response
        if 'data' not in result and 'errors' not in result:
            return False, None, "Not a GraphQL endpoint"

        # Now test introspection
        introspection_payload = {
            "query": SIMPLE_INTROSPECTION_QUERY
        }

        response = _post(
            endpoint,
            json=introspection_payload,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )

        if response.status_code != 200:
            return False, None, f"Introspection returned status: {response.status_code}"

        result = response.json()

        # Check for introspection data
        if 'data' in result and result['data'] and '__schema' in result['data']:
            print(f"[+][GraphQL] Introspection ENABLED at: {endpoint}")

            # Full introspection query with user-configured depth
            full_payload = {
                "query": build_introspection_query(depth_limit)
            }

            try:
                full_response = _post(
                    endpoint,
                    json=full_payload,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False
                )

                if full_response.status_code == 200:
                    # Check response size to prevent memory issues
                    content_length = len(full_response.content)
                    if content_length > 10 * 1024 * 1024:  # 10MB limit
                        print(f"[!][GraphQL] Schema too large ({content_length} bytes), using simple introspection")
                        return True, result['data'], None

                    full_result = full_response.json()
                    if 'data' in full_result and full_result['data']:
                        return True, full_result['data'], None
            except (RequestException, json.JSONDecodeError, KeyError, TypeError):
                # If full introspection fails, return simple result
                pass

            return True, result['data'], None

        # Check if introspection is explicitly disabled
        if 'errors' in result:
            error_messages = ' '.join([e.get('message', '') for e in result['errors']])
            if any(msg in error_messages.lower() for msg in
                   ['introspection', 'disabled', 'not allowed', 'forbidden']):
                print(f"[-][GraphQL] Introspection DISABLED at: {endpoint}")
                return False, None, "Introspection explicitly disabled"

        return False, None, "No introspection data in response"

    except Timeout:
        return False, None, f"Request timeout after {timeout}s"
    except RequestException as e:
        return False, None, f"Request error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error: {str(e)}"


def extract_operations(schema_data: dict) -> Dict[str, list]:
    """
    Extract queries, mutations, and subscriptions from schema.

    Args:
        schema_data: The GraphQL schema data

    Returns:
        Dict with lists of operations
    """
    operations = {
        'queries': [],
        'mutations': [],
        'subscriptions': []
    }

    if not schema_data or '__schema' not in schema_data:
        return operations

    schema = schema_data['__schema']
    types = {t['name']: t for t in schema.get('types', [])}

    # Extract queries
    query_type = schema.get('queryType')
    if query_type and query_type['name'] in types:
        query_fields = types[query_type['name']].get('fields', [])
        operations['queries'] = [f['name'] for f in query_fields if f.get('name')]

    # Extract mutations
    mutation_type = schema.get('mutationType')
    if mutation_type and mutation_type['name'] in types:
        mutation_fields = types[mutation_type['name']].get('fields', [])
        operations['mutations'] = [f['name'] for f in mutation_fields if f.get('name')]

    # Extract subscriptions
    subscription_type = schema.get('subscriptionType')
    if subscription_type and subscription_type['name'] in types:
        subscription_fields = types[subscription_type['name']].get('fields', [])
        operations['subscriptions'] = [f['name'] for f in subscription_fields if f.get('name')]

    return operations


def calculate_schema_hash(schema_data: dict) -> str:
    """
    Calculate a hash of the schema for change detection.

    Args:
        schema_data: The GraphQL schema data

    Returns:
        SHA256 hash of the schema
    """
    import hashlib
    import json

    if not schema_data:
        return ""

    # Sort keys for consistent hashing
    schema_str = json.dumps(schema_data, sort_keys=True)
    return hashlib.sha256(schema_str.encode()).hexdigest()[:16]


def detect_sensitive_fields(schema_data: dict) -> list:
    """
    Detect potentially sensitive fields in the schema.

    Args:
        schema_data: The GraphQL schema data

    Returns:
        List of sensitive field names
    """
    sensitive_keywords = [
        'password', 'secret', 'token', 'key', 'api', 'private',
        'credential', 'auth', 'ssn', 'credit', 'card', 'payment',
        'bank', 'account', 'pin', 'cvv', 'salary', 'medical'
    ]

    sensitive_fields = []

    if not schema_data or '__schema' not in schema_data:
        return sensitive_fields

    # Check all types and fields
    for type_def in schema_data['__schema'].get('types', []):
        if type_def.get('fields'):
            for field in type_def['fields']:
                field_name = field.get('name', '').lower()
                if any(keyword in field_name for keyword in sensitive_keywords):
                    sensitive_fields.append(f"{type_def['name']}.{field['name']}")

    return sensitive_fields