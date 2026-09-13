"""Deterministic identity key for Certificate graph nodes.

Every writer (httpx/http_probe, Censys, FOFA, GVM, tlsx) must compute the key
the same way, so two scanners observing the SAME certificate produce the SAME
node instead of colliding on `subject_cn` (which is not a certificate identity
and is empty on a growing share of modern certs).

- With a real SHA-256 fingerprint: ``"sha256:" + fingerprint.lower()``.
- Otherwise a surrogate over the fields a writer does have. A surrogate is used
  rather than a null key because Neo4j uniqueness constraints do NOT constrain
  nodes missing the key property, which would silently re-introduce duplicates.
"""

import hashlib
from typing import Optional


def build_cert_key(
    fingerprint_sha256: Optional[str] = None,
    subject_cn: Optional[str] = None,
    issuer: Optional[str] = None,
    not_before: Optional[str] = None,
    not_after: Optional[str] = None,
) -> str:
    """Return the deterministic ``cert_key`` for a certificate.

    ``fingerprint_sha256`` wins when present (the true identity). The surrogate
    is intentionally stable across writers: same subject/issuer/validity -> same
    key, so httpx and FOFA converge even without a fingerprint.
    """
    if fingerprint_sha256:
        fp = fingerprint_sha256.strip().lower()
        if fp:
            return "sha256:" + fp
    surrogate_input = f"{subject_cn or ''}|{issuer or ''}|{not_before or ''}|{not_after or ''}"
    digest = hashlib.sha1(surrogate_input.encode("utf-8", "replace")).hexdigest()[:32]
    return "surrogate:" + digest
