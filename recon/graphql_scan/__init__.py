"""
GraphQL Security Scanner Package for RedAmon

This package provides GraphQL security testing capabilities including:
- Endpoint discovery from multiple sources
- Introspection query detection and schema extraction
- Mutation security testing for business logic flaws
- GraphQL-to-REST proxy vulnerability detection

Phase 1 (MVP) includes:
- Endpoint discovery
- Introspection detection
- Basic vulnerability reporting
"""

from .scanner import run_graphql_scan, run_graphql_scan_isolated
from .discovery import discover_graphql_endpoints

__all__ = [
    'run_graphql_scan',
    'run_graphql_scan_isolated',
    'discover_graphql_endpoints'
]