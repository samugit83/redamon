"""
Output Normalization Module

Normalizes findings from different GraphQL security scanners
to a consistent format for storage and reporting.
"""

from typing import Dict, List, Any
from datetime import datetime, timezone


def normalize_finding(
    endpoint: str,
    vulnerability_type: str,
    severity: str,
    title: str,
    description: str,
    evidence: Dict[str, Any] = None,
    remediation: str = None
) -> Dict[str, Any]:
    """
    Create a normalized vulnerability finding.

    Args:
        endpoint: The affected GraphQL endpoint
        vulnerability_type: Type of vulnerability (e.g., 'graphql_introspection_enabled')
        severity: Severity level (critical, high, medium, low, info)
        title: Short title of the finding
        description: Detailed description
        evidence: Optional evidence dict with payload/response
        remediation: Optional remediation advice

    Returns:
        Normalized finding dictionary
    """
    finding = {
        'endpoint': endpoint,
        'vulnerability_type': vulnerability_type,
        'severity': severity.lower(),
        'title': title,
        'description': description,
        'source': 'graphql_scan',
        'discovered_at': datetime.now(timezone.utc).isoformat(),
    }

    if evidence:
        finding['evidence'] = evidence

    if remediation:
        finding['remediation'] = remediation

    return finding


def normalize_introspection_finding(
    endpoint: str,
    schema_data: dict = None,
    operations: Dict[str, list] = None,
    sensitive_fields: List[str] = None
) -> Dict[str, Any]:
    """
    Normalize introspection-specific findings.

    Args:
        endpoint: The GraphQL endpoint
        schema_data: Extracted schema data
        operations: Dict of queries/mutations/subscriptions
        sensitive_fields: List of detected sensitive field names

    Returns:
        Normalized introspection finding
    """
    severity = 'info'
    description = "GraphQL introspection is enabled, exposing the entire API schema."

    # Increase severity based on what's exposed
    if operations and operations.get('mutations'):
        mutation_count = len(operations['mutations'])
        if mutation_count > 20:
            severity = 'medium'
            description += f" Found {mutation_count} mutations that could modify data."
        elif mutation_count > 0:
            description += f" Found {mutation_count} mutations."

    if sensitive_fields:
        severity = 'medium'
        description += f" Detected {len(sensitive_fields)} potentially sensitive fields."

    evidence = {
        'introspection_enabled': True
    }

    if operations:
        evidence['operations_count'] = {
            'queries': len(operations.get('queries', [])),
            'mutations': len(operations.get('mutations', [])),
            'subscriptions': len(operations.get('subscriptions', []))
        }

    if sensitive_fields and len(sensitive_fields) <= 10:
        # Only include sample if not too many
        evidence['sensitive_fields_sample'] = sensitive_fields[:5]

    remediation = (
        "Disable GraphQL introspection in production environments. "
        "This can typically be done by setting the 'introspection' option to false "
        "in your GraphQL server configuration."
    )

    return normalize_finding(
        endpoint=endpoint,
        vulnerability_type='graphql_introspection_enabled',
        severity=severity,
        title='GraphQL Introspection Enabled',
        description=description,
        evidence=evidence,
        remediation=remediation
    )


def severity_to_score(severity: str) -> int:
    """Convert severity to numeric score for sorting."""
    scores = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }
    return scores.get(severity.lower(), 0)


def aggregate_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate findings into summary statistics.

    Args:
        findings: List of normalized findings

    Returns:
        Summary dictionary
    """
    summary = {
        'total_findings': len(findings),
        'by_severity': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'by_type': {}
    }

    for finding in findings:
        severity = finding.get('severity', 'info')
        vuln_type = finding.get('vulnerability_type', 'unknown')

        # Count by severity
        if severity in summary['by_severity']:
            summary['by_severity'][severity] += 1

        # Count by type
        if vuln_type not in summary['by_type']:
            summary['by_type'][vuln_type] = 0
        summary['by_type'][vuln_type] += 1

    return summary