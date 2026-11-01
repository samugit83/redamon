"""Build the evidence bundle the AI review judges, and redact it first.

WHAT THIS IS FOR
The old rationale call showed the model seven fields, none of which was
evidence, and asked it why a finding mattered. It could only paraphrase the
title. The review (Step C) instead shows it the actual proof — the request, the
response excerpt, the file path, the validation result — and asks it to check
the four factors against that. Everything it says must be quoted from this
bundle, and the quote is verified in code.

THREE RULES

1. **Secrets are redacted BEFORE the bundle is built**, from the same value
   fields the group key hashes, so no raw value can reach a prompt. A redacted
   secret still carries what the model needs: its shape, its detector and where
   it was found.
2. **Every field is capped, and the bundle is capped again.** An unbounded
   `raw_response` is both a cost problem and an injection surface.
3. **The whole bundle is wrapped as untrusted.** It is scanner output and target
   response bodies: prompt injection is expected, not exceptional. The wrapper
   is not the defence (the output validation is); it is what makes the boundary
   legible to the model.

THE HASH IS WHAT A REVIEW IS VALID FOR. `bundle_hash` is sha256 over the
normalised, redacted bundle alone, stored as `triage_evidence_hash`. A review
(the built-in AI's, or an external agent's over MCP) records the hash it read
and counts only while the two are equal, so a rescan that changes the evidence
retires it and a rescan that changes only a `Date` header does not.

`build_bundle_legacy` is the pre-v3.2 builder, kept for exactly one job: telling
whether a review a v3.1 run stored still describes the evidence
(`evidence_hash` with `LEGACY_REVIEW_PROMPT_VERSION`).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

#: Per-field caps. `raw_response` is the big one, and the one worth spending on:
#: the difference between "nuclei matched" and "the response is the site's 404
#: page" is in the body.
CAP_RESPONSE = 1500
CAP_DESCRIPTION = 1500
CAP_DETAIL = 1200
CAP_EVIDENCE = 1500
CAP_SHORT = 500

#: Total bundle cap. Roughly 600 tokens, so a batch of 12 stays well inside any
#: provider's context and the cost per finding stays predictable.
CAP_BUNDLE = 2500

#: Paths that usually mean a sample rather than a leak. Surfaced as a FACT for
#: the model to weigh, never applied as an automatic verdict: real credentials
#: do get committed into test fixtures.
_FIXTURE_HINTS = (
    "/test/", "/tests/", "/spec/", "/fixture", "/fixtures/", "/mock", "/mocks/",
    "/example", "/examples/", "/sample", "/samples/", "/__tests__/",
    ".test.", ".spec.", "_test.", "test_", ".example", ".sample", ".dist",
)


def looks_like_a_fixture(path) -> bool:
    text = str(path or "").lower()
    return any(hint in text for hint in _FIXTURE_HINTS)


def redact_secret(value) -> str:
    """First 4 and last 2 characters, and how long it was.

    Enough for the model to tell an AWS key from a UUID from a private IP, and
    for a human reading the board to recognise which secret it is, without the
    value itself ever leaving the graph.
    """
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return f"{text[:1]}***({len(text)} chars)"
    return f"{text[:4]}...{text[-2:]} ({len(text)} chars)"


#: Response and request headers that change on every fetch of the same page.
#: Dropped before hashing, so a rescan that only moves these keeps a review.
_VOLATILE_HEADER_RE = re.compile(
    r"^[ \t]*(?:date|expires|last-modified|age|etag|set-cookie|x-request-id"
    r"|x-amz-(?:[a-z0-9-]*-)?id(?:-\d+)?|cf-ray|server-timing|report-to|nel)"
    r"[ \t]*:.*(?:\r?\n|$)",
    re.IGNORECASE | re.MULTILINE,
)


def normalise_http(text) -> str:
    """A raw request or response without its volatile header lines."""
    return _VOLATILE_HEADER_RE.sub("", str(text or ""))


def _keep4(match_text: str) -> str:
    return f"{match_text[:4]}[REDACTED {len(match_text)} chars]"


#: Secret shapes, each replaced by its first 4 characters and a length. The
#: bundle is shown to the built-in model and to external agents over MCP, and
#: neither needs a live credential to judge whether a finding is real.
_SECRET_SHAPES = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
               re.DOTALL),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"),
)
_BEARER_RE = re.compile(r"(\b(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
# nuclei replays the operator's own session in `raw_request`, and a cookie's
# name says nothing about whether its value is a secret, so every value goes.
_COOKIE_HEADER_RE = re.compile(r"^([ \t]*cookie[ \t]*:)(.*)$", re.IGNORECASE | re.MULTILINE)
_COOKIE_VALUE_RE = re.compile(r"(=)([^;\s]{6,})")
# A scan's auth profile can send a raw token with no scheme (`Authorization:
# 7f3a...`) or in a header of its own (`X-Session:`), which no value shape
# recognises; the header's NAME is what marks it. WWW-Authenticate is kept: its
# realm is evidence of what the server asked for.
_CREDENTIAL_HEADER_RE = re.compile(
    r"^([ \t]*(?!www-authenticate\b)[\w-]*(?:auth|api-?key|apikey|token|session|secret"
    r"|signature|credential|password|csrf|xsrf)[\w-]*[ \t]*:[ \t]*)(\S.{5,})$",
    re.IGNORECASE | re.MULTILINE,
)
_ASSIGNED_SECRET_RE = re.compile(
    r"(\b[A-Za-z_]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token"
    r"|auth[_-]?token|client[_-]?secret)[A-Za-z_]*\b[\"']?\s*[:=]\s*[\"']?)"
    r"([^\s\"'&,;<>]{6,})",
    re.IGNORECASE,
)


def _mask_header_value(value: str) -> str:
    if "[REDACTED" in value:
        return value
    body = value.rstrip("\r")
    return _keep4(body) + value[len(body):]


def redact_secret_shapes(text) -> str:
    """Mask every secret-shaped substring, keeping its first 4 characters."""
    out = str(text or "")
    if not out:
        return ""
    for pattern in _SECRET_SHAPES:
        out = pattern.sub(lambda m: _keep4(m.group(0)), out)
    out = _BEARER_RE.sub(lambda m: m.group(1) + _keep4(m.group(2)), out)
    out = _COOKIE_HEADER_RE.sub(
        lambda m: m.group(1) + _COOKIE_VALUE_RE.sub(
            lambda v: v.group(1) + (v.group(2) if "[REDACTED" in v.group(2) else _keep4(v.group(2))),
            m.group(2)), out)
    out = _CREDENTIAL_HEADER_RE.sub(lambda m: m.group(1) + _mask_header_value(m.group(2)), out)
    out = _ASSIGNED_SECRET_RE.sub(
        lambda m: m.group(1) + (m.group(2) if "[REDACTED" in m.group(2)
                                else _keep4(m.group(2))), out)
    return out


def _clip(value, cap: int, http: bool = False, clean: bool = False) -> str:
    text = str(value or "")
    if clean:
        # Normalise, then redact, then cap: a secret cut in half by the cap
        # would no longer match its shape and would leak its first half.
        if http:
            text = normalise_http(text)
        text = redact_secret_shapes(text)
    text = text.strip()
    if not text:
        return ""
    # Collapse runs of whitespace: a response body padded with newlines would
    # otherwise spend the whole cap on nothing.
    text = re.sub(r"[ \t]{3,}", "  ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text[:cap] + (" [...]" if len(text) > cap else "")


def _line(label: str, value) -> str:
    text = str(value or "").strip()
    return f"{label}: {text}\n" if text else ""


def _trufflehog_facts(finding: dict) -> Optional[dict]:
    """What JS Recon's TruffleHog engine said about a Secret, as evidence
    lines; None for every Secret it did not touch, whose bundle (and so its
    review's hash) stays byte-identical. TruffleHog's "could not confirm" is
    said in words: it is not a verdict that the key is dead."""
    alternate = [str(a)[len("TruffleHog:"):] for a in finding.get("alternate_names") or []
                 if str(a).startswith("TruffleHog:")]
    try:
        info = json.loads(finding.get("validation_info") or "{}") or {}
    except (TypeError, ValueError):
        info = {}
    info = info if isinstance(info, dict) else {}
    th = info.get("trufflehog") if isinstance(info.get("trufflehog"), dict) else {}
    only = finding.get("detection_method") == "trufflehog"
    if not (only or alternate or th):
        return None
    detector = str(th.get("detector") or (alternate[0] if alternate else "") or "").strip()
    who = f"TruffleHog ({detector})" if detector else "TruffleHog"
    facts = {"found_by": who if only else f"JS Recon and {who}"}
    if info.get("checked_by") == "trufflehog" and finding.get("validation_status") == "unknown":
        facts["validation"] = "unknown — TruffleHog could not confirm it, which is not proof it is dead"
    return facts


def build_bundle(finding: dict) -> str:
    """The evidence for one finding, as plain text: normalised, redacted, capped.

    Returns "" when there is nothing worth judging, which is how a finding is
    kept out of the LLM path without a second list of rules.

    The built-in reviewer, `get_finding_evidence` over MCP, the quote check and
    the hash all read THIS text, so a quote is only ever checked against what
    the reviewer was actually shown.
    """
    return _build(finding, clean=True)


def build_bundle_legacy(finding: dict) -> str:
    """The v3.1 bundle, byte for byte: no normalising, no shape redaction.

    Only for adopting a review a v3.1 run stored. Never shown to anyone.
    """
    return _build(finding, clean=False)


def _build(finding: dict, clean: bool) -> str:
    finding = finding or {}
    source = str(finding.get("source") or "").lower()
    label = str(finding.get("label") or "")
    parts: list[str] = []

    parts.append(_line("Finding", finding.get("name")))
    parts.append(_line("Source", source or label))

    if source == "nuclei":
        parts.append(_line("Template", finding.get("template_id")))
        parts.append(_line("Matched at", finding.get("matched_at")))
        # review-v1 bundles never had the matcher, fuzzed-parameter, request,
        # port or solution-type lines filled: the finding queries did not select
        # them. The legacy bundle must stay byte-identical to those, or no v1
        # review could be adopted.
        if clean:
            parts.append(_line("Matcher", finding.get("matcher_name")))
            parts.append(_line("Fuzzed parameter", finding.get("fuzzing_parameter")))
        extracted = finding.get("extracted_results") or []
        if extracted:
            joined = "; ".join(str(x) for x in extracted)
            if clean:
                joined = redact_secret_shapes(joined)
            parts.append(_line("Extracted", joined[:CAP_SHORT]))
        if clean:
            parts.append(_line("Request", _clip(finding.get("raw_request"), CAP_SHORT, http=True, clean=True)))
        parts.append(_line("Response", _clip(finding.get("raw_response"), CAP_RESPONSE, http=True, clean=clean)))

    elif source == "gvm" or label == "ExploitGvm":
        parts.append(_line("Description", _clip(finding.get("description"), CAP_DESCRIPTION, clean=clean)))
        parts.append(_line("Quality of detection",
                           f"{finding.get('qod')} ({finding.get('qod_type')})"))
        parts.append(_line("CVEs", ", ".join(finding.get("cve_ids") or [])))
        if clean:
            parts.append(_line("Port", finding.get("target_port")))
            parts.append(_line("Solution type", finding.get("solution_type")))

    elif source in ("takeover_scan", "cache_poisoning", "graphql_scan",
                    "graphql_cop", "ai_surface_recon", "ai_attack"):
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_EVIDENCE, clean=clean)))
        parts.append(_line("Tool verdict", finding.get("verdict")))
        parts.append(_line("Confidence tier", finding.get("confidence_tier")))
        parts.append(_line("Attack success rate", finding.get("ai_asr")))
        parts.append(_line("Judged by", finding.get("ai_oracle_kind")))

    elif label in ("Secret", "GithubSecret", "GithubSensitiveFile",
                   "MultiscannerFinding"):
        parts.append(_line("Type", finding.get("secret_type")
                           or finding.get("detector_name")))
        parts.append(_line("Detector", finding.get("detector_name")))
        # Only a JS Recon Secret carries what its TruffleHog engine said.
        trufflehog = _trufflehog_facts(finding) if clean and label == "Secret" else None
        if trufflehog:
            parts.append(_line("Found by", trufflehog["found_by"]))
        path = finding.get("path") or finding.get("location") or finding.get("triage_host")
        parts.append(_line("Found in", path))
        parts.append(_line("Validation", (trufflehog or {}).get("validation")
                           or finding.get("validation_status") or "never tested"))
        value = (finding.get("matched_text") or finding.get("sample")
                 or finding.get("raw_secret") or finding.get("secret_value"))
        if value:
            parts.append(_line("Value (redacted)", redact_secret(value)))
        context = finding.get("context")
        if clean and context:
            # The value is masked by name before the shape pass: a secret of no
            # known shape would otherwise reach the reviewer whole. The legacy
            # (v3.1) bundle never had this line, so it gets none.
            text = str(context)
            if value:
                text = text.replace(str(value), redact_secret(value))
            parts.append(_line("Context (redacted)", _clip(text, CAP_SHORT, clean=True)))
        if looks_like_a_fixture(path):
            parts.append("Path note: this path looks like a test or example file.\n")

    elif label == "JsReconFinding":
        parts.append(_line("Kind", finding.get("finding_type")))
        parts.append(_line("Title", finding.get("name")))
        parts.append(_line("Detail", _clip(finding.get("description"), 800, clean=clean)))
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_SHORT, clean=clean)))
        parts.append(_line("Scanner confidence", finding.get("confidence")))

    elif label == "MalPackageFinding":
        parts.append(_line("Verdict", finding.get("verdict")))
        parts.append(_line("Tool", finding.get("source_tool")))
        parts.append(_line("Advisory", finding.get("advisory_id")))
        parts.append(_line("Detail", _clip(finding.get("description"), CAP_DETAIL, clean=clean)))
        if finding.get("soft_error"):
            parts.append("Note: the analyser could not read this package.\n")

    else:
        parts.append(_line("Description", _clip(finding.get("description"), CAP_DESCRIPTION, clean=clean)))
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_EVIDENCE, clean=clean)))

    bundle = "".join(p for p in parts if p)
    if clean:
        # The short fields (names, paths, matched URLs) can carry a token too.
        bundle = redact_secret_shapes(bundle)
    return bundle[:CAP_BUNDLE]


#: Sources whose evidence the model cannot usefully judge, so they never enter
#: the LLM path. On the live dev graph this removes about 95% of findings, which
#: is where the cost is.
#:
#: - security_check findings are FACTS (a header is present or it is not);
#: - an OSV advisory's evidence is the advisory text, not anything about the
#:   target, so the model would be reviewing NVD rather than this project.
#: - serialized_scan candidates are pre-confirmation leads: a thin static
#:   signature bundle, and a false_positive review could wrongly flip a candidate
#:   the agent has not yet confirmed. The agent's proof-typed CONFIRMS edge is the
#:   intended promotion path, not the built-in reviewer.
SKIP_REVIEW_SOURCES = frozenset({"security_check", "osv", "retirejs", "serialized_scan",
                                 "route_exposure"})


def person_decided(status, source) -> bool:
    """Did a person make a decision (Real or False positive) on this finding?

    `unreviewed` is the absence of a decision whatever the source says: a Reset
    before v3.2 left `triage_source = 'human'` behind it. A legacy `ai` source
    is never a decision.
    """
    return (str(status or "") in ("confirmed", "likely_noise")
            and str(source or "") == "human")


def should_review(row: dict) -> bool:
    """Is this finding worth an LLM call?"""
    return not_reviewable_reason(
        state=row.get("state"), proven=bool(row.get("proven")),
        decided=person_decided(row.get("triage_status"), row.get("triage_source")),
        source=row.get("source"), bundle=build_bundle(row.get("_row") or row),
    ) is None


#: Why a finding cannot be reviewed, in the order they are checked. The same
#: words reach an external agent through `get_finding_evidence`.
NOT_REVIEWABLE_REASONS = (
    "out_of_triage_scope", "not_scored", "decided_by_person", "proven",
    "not_open", "source_not_reviewed", "no_evidence",
)


def not_reviewable_reason(*, state, proven: bool, decided: bool, source,
                          bundle: str, scored: bool = True,
                          in_scope: bool = True) -> str | None:
    """None when a review may be written, else the reason it may not."""
    if not in_scope:
        return "out_of_triage_scope"
    if not scored:
        return "not_scored"
    if decided:
        return "decided_by_person"         # a person already decided
    if proven:
        return "proven"                    # proof is not up for discussion
    if state != "open":
        return "not_open"
    if str(source or "").lower() in SKIP_REVIEW_SOURCES:
        return "source_not_reviewed"
    if not bundle:
        return "no_evidence"
    return None


def bundle_hash(bundle: str) -> str:
    """`triage_evidence_hash`: what a review is valid for.

    Over the (normalised, redacted) bundle ALONE. Neither the model nor the
    prompt version is in it: a review is about the evidence, and whether the
    built-in AI should re-read it under a newer model is decided from the
    review's own `triage_ai_model` / `triage_ai_prompt_version`.
    """
    if not bundle:
        return ""
    return hashlib.sha256(bundle.encode("utf-8", "replace")).hexdigest()[:40]


def review_is_current(review_hash, evidence_hash_now) -> bool:
    """A stored review still describes the evidence."""
    return bool(review_hash) and bool(evidence_hash_now) and review_hash == evidence_hash_now


#: Findings whose node is deleted and recreated at every scan of their source,
#: so a review written on one does not survive that scan (TruffleHog findings,
#: GVM exploits). Everything else keeps its review until the evidence changes.
def review_survives_rescan(label, source) -> bool:
    label = str(label or "")
    source = str(source or "").lower()
    if label == "ExploitGvm":
        return False
    if label == "MultiscannerFinding" or source == "trufflehog":
        return False
    return True


def evidence_hash(bundle: str, prompt_version: str, model: str) -> str:
    """The v3.1 review cache key, kept only to recognise a legacy review.

    A v3.1 run stored this as `triage_evidence_hash`. Comparing it against
    `evidence_hash(build_bundle_legacy(row), LEGACY_REVIEW_PROMPT_VERSION,
    model)` tells whether that run's review still describes the evidence.
    """
    material = f"{prompt_version}\x00{model}\x00{bundle}"
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:40]


def normalise_for_quote_check(text: str) -> str:
    """Whitespace-insensitive comparison text.

    A model reliably reproduces the characters of a quote and unreliably
    reproduces its indentation, so comparing raw strings would reject good
    quotes. Everything else must match exactly.
    """
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()
