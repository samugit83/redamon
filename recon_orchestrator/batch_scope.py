"""
Domain batch: which domains a project would actually scan.

Kept OUT of api.py deliberately. This feeds the hard guardrail, the one control an
operator cannot switch off, and api.py cannot be imported without FastAPI and the
Docker client - so the security decision would have been untestable in the unit
tier. Mirrors auth.py, which is standalone for the same reason.

The contract, and why each half matters:

  - a Domain-batch project has an EMPTY targetDomain and keeps its scope in
    domainBatchGroups, so a guardrail that reads targetDomain alone waves every
    batch target through;
  - a root that fails the charset check is DROPPED, never repaired: a repaired
    hostname would be a target the operator never approved;
  - an empty result in batch mode means "cannot determine scope", which the caller
    must treat as a refusal, not as "nothing to check". Fail closed.
"""
from __future__ import annotations

import re

_BATCH_ROOT_CHARSET = re.compile(r'^[a-z0-9.-]+$')


def batch_guardrail_targets(project: dict) -> list[str]:
    """Every root domain a Domain-batch project would scan, deduplicated, in order."""
    groups = project.get('domainBatchGroups')
    if not isinstance(groups, list):
        return []

    roots: list[str] = []
    for entry in groups:
        if not isinstance(entry, dict):
            continue
        root = str(entry.get('rootDomain') or '').strip().lower()
        if not root or not _BATCH_ROOT_CHARSET.match(root) or '..' in root:
            continue
        if root not in roots:
            roots.append(root)
    return roots


def guardrail_targets(project: dict) -> list[str]:
    """Every domain to hard-guardrail before starting a recon, whatever the mode.

    IP mode returns [] (IPs are not hard-blocked; see hard_guardrail.is_hard_blocked).
    Batch mode returns the group roots. Anything else returns the single target.
    """
    if project.get('ipMode', False):
        return []
    if project.get('domainBatchMode', False):
        return batch_guardrail_targets(project)
    target = str(project.get('targetDomain') or '').strip()
    return [target] if target else []
