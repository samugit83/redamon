"""P9-P13: the RoE parse prompt is generated, current, and honest about bounds.

The parse path used to hold the same field list in THREE places that nothing
reconciled: a JSON skeleton in `_ROE_PARSE_PROMPT`, a `fieldMap` in
`RoeSection.tsx`, and the registry. Measured before the change, they had NOT
drifted - because two people kept two lists in step by hand. That is the
property that does not survive a codebase adding recon fields weekly, and
"correct today by diligence" is exactly what is worth converting into "correct
by construction" while it is still true.

Three ways it went stale, each silent:

    a column is renamed   the prompt asks for the old name, the model returns
                          it, the handler sets a key that no longer exists
    a field is added      the parser cannot set it whatever the document says
    a bound changes       the model is told one range and judged against
                          another, so the rejection reads as a model error

The third is the nastiest now that parsed values go through the registry
validators, which is why P11 compares what the model is TOLD against what the
validator ENFORCES rather than checking each in isolation.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from recon_settings.loader import fields, load_registry, registry_path
from recon_settings import roe_prompt
from recon_settings.roe_parse_prompt import (
    ROE_PARSE_FIELDS,
    ROE_PARSE_PROMPT,
    ROE_PARSE_REGISTRY_DIGEST,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = REPO_ROOT / "recon_settings" / "roe_parse_prompt.py"


# --- P9: the artifact regenerates byte-identically ------------------------------------

def test_p2_p9_the_committed_prompt_regenerates_byte_for_byte():
    """A hand edit, or a YAML edit that was never built, fails here.

    Part E's P2 and Part H's P9 are the same assertion stated twice; this is it.
    The same treatment `apiReference.ts` already gets, and for the reason its own
    comment gives: the output must be deterministic so the diff is meaningful.
    """
    assert ARTIFACT.read_text(encoding="utf-8") == roe_prompt.render_module()


def test_p9_generation_is_deterministic():
    """No timestamps, no counts a reordering would change."""
    assert roe_prompt.render() == roe_prompt.render()


def test_p9_the_artifact_says_it_is_generated():
    head = ARTIFACT.read_text(encoding="utf-8")[:400]
    assert "GENERATED FILE - DO NOT EDIT" in head
    assert "recon_settings/build.py" in head


# --- P10: every key it names is a real, writable field ---------------------------------

def test_p10_every_named_key_is_a_registry_field():
    unknown = [k for k in ROE_PARSE_FIELDS if k not in fields()]
    assert unknown == []


def test_p10_every_named_key_is_writable_by_the_parse_path():
    """A key the parser is told to return and is then refused for is a trap.

    "Parse-writable" is deliberately WIDER than "MCP-settable", and this is the
    one place the two surfaces are meant to differ. The plan's P2/P10 say
    "settable", which taken literally would stop a document filling the client
    name, the contacts and the dates - the engagement RECORD, which is the thing
    a Rules of Engagement document most obviously IS. The record stays closed to
    MCP and open to the upload, because the upload is the UI.

    What must NOT widen is scope, and that is asserted separately below.
    """
    problems = [
        k for k in ROE_PARSE_FIELDS
        if not roe_prompt.is_parse_writable(k, fields()[k])
    ]
    assert problems == []


def test_p10_parse_writable_is_settable_plus_the_record_and_nothing_else():
    """The exact shape of the widening, so it cannot grow by accident.

    Minus `roe_parse: deny`: the operator settings a document may never set.
    """
    writable = {k for k, f in fields().items() if roe_prompt.is_parse_writable(k, f)}
    settable = {k for k, f in fields().items() if f["mcp"] == "settable"}
    record = {k for k, f in fields().items() if f.get("deny_reason") == "engagement-record"}
    denied = {k for k, f in fields().items() if f.get("roe_parse") == "deny"}
    assert denied
    assert writable == (settable | record) - denied
    # And the record really is closed to MCP, or the widening would be moot.
    assert all(fields()[k]["mcp"] == "never" for k in record)


def test_p10_no_scope_column_is_named():
    """The containment that matters most: a parsed document may not re-point the platform.

    Derived rather than listed: every targeting column is `create_only`, so a new
    one is excluded the day it is classified rather than the day somebody
    remembers to add it here.
    """
    scope = [k for k, f in fields().items() if f["mcp"] == "create_only"]
    assert scope, "no create_only columns at all would make this vacuous"
    assert [k for k in scope if k in ROE_PARSE_FIELDS] == []


def test_p10_no_engagement_limit_is_missing():
    """A document that says "3 requests per second" must be able to say it."""
    limits = [
        k for k, f in fields().items()
        if f.get("group") == "engagement_limits" and f["mcp"] == "settable"
    ]
    assert limits
    assert [k for k in limits if k not in ROE_PARSE_FIELDS] == []


def test_p10_no_engagement_record_column_is_missing():
    """The document IS the contract; parsing it is how the record gets filled."""
    record = [k for k, f in fields().items() if f.get("deny_reason") == "engagement-record"]
    assert record
    assert [k for k in record if k not in ROE_PARSE_FIELDS] == []


def test_p10_a_tools_own_enable_flag_is_reachable():
    """"No directory brute forcing" has to be able to turn ffuf off.

    Before this, the map covered six rate fields, so it could not.
    """
    for key in ["ffufEnabled", "nucleiEnabled", "scanModules", "stealthMode"]:
        assert key in ROE_PARSE_FIELDS, key


# --- P11: told and enforced cannot disagree ---------------------------------------------

def _stated_lines() -> dict[str, str]:
    """field -> the `accepts` clause the prompt states for it."""
    out: dict[str, str] = {}
    for line in ROE_PARSE_PROMPT.split("\n"):
        if line.count(" | ") != 2:
            continue
        name, accepts, _meaning = line.split(" | ", 2)
        if name in fields():
            out[name] = accepts
    return out


def test_p11_the_prompt_states_a_clause_for_every_field_it_names():
    stated = _stated_lines()
    assert sorted(stated) == sorted(ROE_PARSE_FIELDS)


@pytest.mark.parametrize(
    "key",
    sorted(k for k, f in fields().items() if f.get("bounds") and k in set(ROE_PARSE_FIELDS)),
)
def test_p11_a_stated_numeric_range_is_the_enforced_one(key):
    """The bound the model is told is the bound the validator reads.

    Compared against the registry entry directly rather than against a second
    copy: a tightened bound must move both at once, or the rejection it produces
    looks like a model error rather than a stale prompt.
    """
    spec = fields()[key]
    stated = _stated_lines()[key]
    lo, hi = spec["bounds"]["min"], spec["bounds"]["max"]
    assert re.search(rf"\b{lo}\b", stated), f"{key}: stated {stated!r} omits the minimum {lo}"
    assert re.search(rf"\b{hi}\b", stated), f"{key}: stated {stated!r} omits the maximum {hi}"


@pytest.mark.parametrize(
    "key",
    sorted(k for k, f in fields().items() if f.get("values") and k in set(ROE_PARSE_FIELDS)),
)
def test_p11_a_stated_enum_is_the_enforced_one(key):
    stated = _stated_lines()[key]
    for value in fields()[key]["values"]:
        assert value in stated, f"{key}: {value!r} is accepted but never stated"


@pytest.mark.parametrize(
    "key",
    sorted(k for k, f in fields().items()
           if k in set(ROE_PARSE_FIELDS) and not f.get("values") and not f.get("bounds")),
)
def test_p11_a_stated_type_is_the_enforced_one(key):
    """The third thing H4 names, after bounds and enum.

    A field the model is told is "a list of strings" and the validator reads as a
    boolean produces a rejection that looks like a model error. Checked against
    the registry's joined Prisma type - the same one `validateValue` switches on
    - rather than against a second description of it.
    """
    spec = fields()[key]
    stated = _stated_lines()[key]
    if spec.get("roe_parse") == "tighten_only":
        assert stated == "only " + json.dumps(spec["roe_safe_value"]), f"{key}: stated {stated!r}"
        return
    expected = {
        "boolean": "true or false",
        "string-list": "a list of strings",
        "number-list": "a list of whole numbers",
        "json": "a JSON object",
        "datetime": "an ISO 8601 timestamp",
    }.get(spec["type"])
    if expected is None:  # a plain string, with or without a named validator
        assert stated.startswith("a string"), f"{key}: stated {stated!r} for type {spec['type']}"
        if spec.get("validator"):
            assert spec["validator"] in stated, f"{key}: stated {stated!r} omits its validator"
    else:
        assert stated == expected, f"{key}: stated {stated!r}, type is {spec['type']}"


def test_p11_the_validator_half_lives_on_the_typescript_side():
    """H4 asks that a boundary value PASS and one step outside FAIL.

    The validator is TypeScript (`reconSettings/validators.ts`), so that half
    cannot run here. It is asserted, over the same registry entries, by
    `roeParse.test.ts` ("a legal value at each bound is accepted by both") and
    `bounds.test.ts` ("every declared bound is actually enforced at both ends").
    This test fails if either disappears, so the composition cannot be broken by
    deleting one end of it.
    """
    webapp = REPO_ROOT / "webapp" / "src" / "lib" / "reconSettings"
    parse = (webapp / "roeParse.test.ts").read_text(encoding="utf-8")
    bounds = (webapp / "bounds.test.ts").read_text(encoding="utf-8")
    assert "a legal value at each bound is accepted by both" in parse
    assert "every declared bound is actually enforced at both ends" in bounds


def test_p11_an_unlimited_zero_is_flagged_where_it_is_stated():
    """0 is the FASTEST value for several rate fields, not the gentlest.

    A model told "0 to 1000 rps" and nothing else will read 0 as the safe end,
    which is the exact inversion this note exists to prevent.
    """
    stated = _stated_lines()
    unlimited = [
        k for k, f in fields().items()
        if f.get("zero_means") == "unlimited" and k in stated
    ]
    assert unlimited
    for key in unlimited:
        assert "UNLIMITED" in stated[key], key


# --- P13: the digest is the registry's, and a mismatch fails closed ----------------------

def test_p13_the_embedded_digest_is_the_loaded_registrys():
    live = hashlib.sha256(registry_path().read_bytes()).hexdigest()
    assert ROE_PARSE_REGISTRY_DIGEST == live


def test_p13_the_digest_appears_in_the_prompt_text_itself():
    """So a prompt captured from a log can be traced back to a registry."""
    assert ROE_PARSE_REGISTRY_DIGEST in ROE_PARSE_PROMPT


def test_p13_the_endpoint_fails_closed_on_a_mismatch():
    """The skew check answers, and answers with BOTH digests.

    An agent image built last week can hold a prompt generated from last week's
    registry while the orchestrator mounts today's; version skew is the normal
    consequence of three services on three schedules, not a hypothetical. Failing
    closed is deliberate, because a stale prompt does not produce an error - it
    produces a confidently wrong configuration.
    """
    assert roe_prompt.prompt_skew(ROE_PARSE_REGISTRY_DIGEST) is None

    skew = roe_prompt.prompt_skew("0" * 64)
    assert skew is not None
    built_from, live = skew
    assert built_from == "0" * 64
    assert live == hashlib.sha256(registry_path().read_bytes()).hexdigest()


# --- no hand-written field list survives -------------------------------------------------

def test_the_generator_is_the_only_place_a_field_list_is_written():
    """H3: nothing replaces the `fieldMap` that was deleted.

    The generator selects by CLASSIFICATION - a registry query - rather than by
    naming fields, so there is no list left to forget to update. A literal list
    of column names reappearing here is the failure this catches.
    """
    source = (REPO_ROOT / "recon_settings" / "roe_prompt.py").read_text(encoding="utf-8")
    # Strings that are registry column names, outside the docstrings.
    body = re.sub(r'"""[\s\S]*?"""', "", source)
    named = {
        m.group(1) for m in re.finditer(r"""["']([a-z][A-Za-z0-9]{6,})["']""", body)
    } & set(fields())
    assert named == set(), f"the generator names columns literally: {sorted(named)}"


def test_p13_the_endpoint_returns_503_naming_both_digests():
    """A mismatch is refused at the request, not merely detected.

    Asserted against the endpoint's own source rather than by booting the agent,
    which needs the whole LLM stack: what matters is that the guard runs BEFORE
    the model is called and that it returns 503 rather than a parse.
    """
    source = (REPO_ROOT / "agentic" / "api.py").read_text(encoding="utf-8")
    body = source[source.index('async def parse_roe_document'):]
    body = body[:body.index('\n@app.')] if '\n@app.' in body else body

    guard = body.index("_prompt_skew(")
    call = body.index("llm.ainvoke")
    assert guard < call, "the skew check must run before the model is called"

    refusal = body[guard:call]
    assert "status_code=503" in refusal
    assert "promptRegistryDigest" in refusal
    assert "loadedRegistryDigest" in refusal


# --- roe_parse: what an operator may set and a document may not --------------------------

# Validators whose value is free-form enough to carry a host, a URL, a prompt or a
# payload. A field with one of these, or any agent field, must be classified.
_FREE_FORM = {"free_text", "hostname", "hostname_list", "url", "json_object"}


def test_every_agent_or_free_form_field_a_document_could_reach_is_classified():
    """A new agent field cannot silently become document-writable.

    Without this, the next system prompt, callback host or approval gate added to
    the agent would land in the parse catalogue by default, because it is
    `settable` like every other tuning field.
    """
    unclassified = sorted(
        k for k, f in fields().items()
        if (f["mcp"] == "settable" or f.get("deny_reason") == "engagement-record")
        and (f["tool"] == "agent" or f.get("validator") in _FREE_FORM)
        and f.get("roe_parse") not in ("allow", "deny", "tighten_only")
    )
    assert unclassified == []


def test_a_denied_field_is_not_in_the_catalogue():
    denied = {k for k, f in fields().items() if f.get("roe_parse") == "deny"}
    assert denied
    assert sorted(denied & set(ROE_PARSE_FIELDS)) == []


def test_the_controls_a_document_must_never_relax_are_tighten_only():
    """The plan's list, by name, because each is a decision rather than a class."""
    expected = {
        "agentGuardrailEnabled": True,
        "agentRequireApprovalForExploitation": True,
        "agentRequireApprovalForPostExploitation": True,
        "agentRequireToolConfirmation": True,
        "agentKaliInstallEnabled": False,
        "agentNgrokTunnelEnabled": False,
        "agentChiselTunnelEnabled": False,
        "agentActivatePostExplPhase": False,
        # Validation sends every key JS Recon finds to its provider (TruffleHog
        # plan, step 1.14): a document may forbid it, never allow it.
        "jsReconValidateKeys": False,
    }
    actual = {
        k: f.get("roe_safe_value") for k, f in fields().items() if f.get("roe_parse") == "tighten_only"
    }
    assert actual == expected


def test_prompts_callbacks_and_the_model_are_denied():
    for key in [
        "agentInformationalSystemPrompt", "agentExplSystemPrompt", "agentPostExplSystemPrompt",
        "agentLhost", "agentLport", "agentOpenaiModel", "agentToolPhaseMap", "attackSkillConfig",
        "ssrfOobProvider", "ssrfCustomInternalTargets", "katanaScope",
    ]:
        assert fields()[key].get("roe_parse") == "deny", key


def test_the_document_artefacts_are_upload_managed_and_not_parseable():
    """A document cannot describe itself, and a settings save cannot rewrite it."""
    for key in ["roeDocumentData", "roeDocumentName", "roeDocumentMimeType", "roeRawText", "roeParsedJson"]:
        spec = fields()[key]
        assert spec.get("deny_reason") == "upload-managed", key
        assert spec.get("written_by"), key
        assert spec.get("readable") is False, key
        assert key not in ROE_PARSE_FIELDS, key


def test_the_webapp_holds_the_same_digest_for_its_handshake():
    """The agent bakes its registry, so only the webapp can tell it is stale."""
    ts = (REPO_ROOT / "webapp" / "src" / "lib" / "reconSettings" / "registryDigest.generated.ts")
    match = re.search(r"REGISTRY_DIGEST = '([0-9a-f]{64})'", ts.read_text(encoding="utf-8"))
    assert match, "registryDigest.generated.ts has no digest"
    assert match.group(1) == ROE_PARSE_REGISTRY_DIGEST
