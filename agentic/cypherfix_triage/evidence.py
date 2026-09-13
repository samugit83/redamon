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

The bundle is also the CACHE KEY. `evidence_hash` is sha256 over the bundle plus
the prompt version plus the model, so a second run over an unchanged finding
costs nothing.
"""

from __future__ import annotations

import hashlib
import re

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


def _clip(value, cap: int) -> str:
    text = str(value or "").strip()
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


def build_bundle(finding: dict) -> str:
    """The evidence for one finding, as plain text, capped and redacted.

    Returns "" when there is nothing worth judging, which is how a finding is
    kept out of the LLM path without a second list of rules.
    """
    finding = finding or {}
    source = str(finding.get("source") or "").lower()
    label = str(finding.get("label") or "")
    parts: list[str] = []

    parts.append(_line("Finding", finding.get("name")))
    parts.append(_line("Source", source or label))

    if source == "nuclei":
        parts.append(_line("Template", finding.get("template_id")))
        parts.append(_line("Matched at", finding.get("matched_at")))
        parts.append(_line("Matcher", finding.get("matcher_name")))
        parts.append(_line("Fuzzed parameter", finding.get("fuzzing_parameter")))
        extracted = finding.get("extracted_results") or []
        if extracted:
            parts.append(_line("Extracted", "; ".join(str(x) for x in extracted)[:CAP_SHORT]))
        parts.append(_line("Request", _clip(finding.get("raw_request"), CAP_SHORT)))
        parts.append(_line("Response", _clip(finding.get("raw_response"), CAP_RESPONSE)))

    elif source == "gvm" or label == "ExploitGvm":
        parts.append(_line("Description", _clip(finding.get("description"), CAP_DESCRIPTION)))
        parts.append(_line("Quality of detection",
                           f"{finding.get('qod')} ({finding.get('qod_type')})"))
        parts.append(_line("CVEs", ", ".join(finding.get("cve_ids") or [])))
        parts.append(_line("Port", finding.get("target_port")))
        parts.append(_line("Solution type", finding.get("solution_type")))

    elif source in ("takeover_scan", "cache_poisoning", "graphql_scan",
                    "graphql_cop", "ai_surface_recon", "ai_attack"):
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_EVIDENCE)))
        parts.append(_line("Tool verdict", finding.get("verdict")))
        parts.append(_line("Confidence tier", finding.get("confidence_tier")))
        parts.append(_line("Attack success rate", finding.get("ai_asr")))
        parts.append(_line("Judged by", finding.get("ai_oracle_kind")))

    elif label in ("Secret", "GithubSecret", "GithubSensitiveFile",
                   "MultiscannerFinding"):
        parts.append(_line("Type", finding.get("secret_type")
                           or finding.get("detector_name")))
        parts.append(_line("Detector", finding.get("detector_name")))
        path = finding.get("path") or finding.get("location") or finding.get("triage_host")
        parts.append(_line("Found in", path))
        parts.append(_line("Validation", finding.get("validation_status") or "never tested"))
        value = (finding.get("matched_text") or finding.get("sample")
                 or finding.get("raw_secret") or finding.get("secret_value"))
        if value:
            parts.append(_line("Value (redacted)", redact_secret(value)))
        if looks_like_a_fixture(path):
            parts.append("Path note: this path looks like a test or example file.\n")

    elif label == "JsReconFinding":
        parts.append(_line("Kind", finding.get("finding_type")))
        parts.append(_line("Title", finding.get("name")))
        parts.append(_line("Detail", _clip(finding.get("description"), 800)))
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_SHORT)))
        parts.append(_line("Scanner confidence", finding.get("confidence")))

    elif label == "MalPackageFinding":
        parts.append(_line("Verdict", finding.get("verdict")))
        parts.append(_line("Tool", finding.get("source_tool")))
        parts.append(_line("Advisory", finding.get("advisory_id")))
        parts.append(_line("Detail", _clip(finding.get("description"), CAP_DETAIL)))
        if finding.get("soft_error"):
            parts.append("Note: the analyser could not read this package.\n")

    else:
        parts.append(_line("Description", _clip(finding.get("description"),
                                                CAP_DESCRIPTION)))
        parts.append(_line("Evidence", _clip(finding.get("evidence"), CAP_EVIDENCE)))

    bundle = "".join(p for p in parts if p)
    return bundle[:CAP_BUNDLE]


#: Sources whose evidence the model cannot usefully judge, so they never enter
#: the LLM path. On the live dev graph this removes about 95% of findings, which
#: is where the cost is.
#:
#: - security_check findings are FACTS (a header is present or it is not);
#: - an OSV advisory's evidence is the advisory text, not anything about the
#:   target, so the model would be reviewing NVD rather than this project.
SKIP_REVIEW_SOURCES = frozenset({"security_check", "osv", "retirejs"})


def should_review(row: dict) -> bool:
    """Is this finding worth an LLM call?"""
    if row.get("state") != "open":
        return False
    if row.get("proven"):
        return False                    # proof is not up for discussion
    if str(row.get("triage_source") or "") == "human":
        return False                    # a person already decided
    if str(row.get("source") or "").lower() in SKIP_REVIEW_SOURCES:
        return False
    return bool(build_bundle(row.get("_row") or row))


def evidence_hash(bundle: str, prompt_version: str, model: str) -> str:
    """The review cache key.

    The prompt version and the model are in it on purpose: the same evidence
    judged by a different model, or under a different prompt, is a different
    answer, and reusing the old one would hide that.
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
