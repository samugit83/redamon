"""P18-P21: the published and agent-facing docs do not name what no longer exists,
and (P21) their links, anchors, images and counts still hold.

Deliberately crude. These cannot tell whether a page is well written, only
whether it still names something that was deleted - which is the failure that
actually happens, and the one that is worst where it happens:

  a WIKI page          two of them are mirrored to redamon.org, so a stale claim
                       is public rather than internal
  an AGENT-FACING      the guides under docs/readmes/coding_agent_prompts/ are
  guide                the instructions a coding agent follows. A stale line
                       there does not mislead a reader, it produces wrong code
                       that passes review because the guide said to write it
  a runtime string     playbook.ts is read by the connected agent at run time,
                       so a line naming a deleted tool sends it after something
                       that answers "unknown tool"
"""
from __future__ import annotations

import re
from pathlib import Path

import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WIKI = REPO_ROOT / "redamon.wiki"
PROMPTS = REPO_ROOT / "docs" / "readmes" / "coding_agent_prompts"
SKILLS = REPO_ROOT / "skills"

sys.path.insert(0, str(REPO_ROOT / "tooling" / "scripts"))
from wiki_checkout import SKIP_REASON, wiki_checkout_present  # noqa: E402

# An empty checkout fails the whole file here, at collection, unless allowed.
pytestmark = pytest.mark.skipif(not wiki_checkout_present(WIKI), reason=SKIP_REASON)


def _wiki_pages() -> list[Path]:
    return sorted(WIKI.glob("*.md"))


# --- P18: no wiki page names a deleted tool or disposition -------------------------------

#: Things this programme removed. A page naming one is stale.
_GONE = {
    "tighten_engagement_roe": "the tool was deleted; the limits are ordinary settings now",
    "tighten_only": "the disposition was deleted; there are three, not four",
    "tighten-only": "the disposition was deleted; there are three, not four",
}

#: A deleted name that came back with another meaning. `roe_parse: tighten_only` is a
#: live registry class (the safety switches a RoE document may only turn on), so only a
#: line that does not name `roe_parse` can mean the deleted MCP disposition.
_REUSED_IN = {"tighten_only": "roe_parse"}


def _names_deleted(term: str, line: str) -> bool:
    return term in line and not (term in _REUSED_IN and _REUSED_IN[term] in line)


@pytest.mark.parametrize("term", sorted(_GONE))
def test_p18_no_wiki_page_names_something_that_was_deleted(term):
    offenders = []
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if _names_deleted(term, line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == [], f"{term}: {_GONE[term]}"


@pytest.mark.parametrize(
    ("line", "stale"),
    [
        ("Set the field's disposition to `tighten_only`.", True),
        ("The `tighten-only` direction rule (`roe_parse` aside).", True),
        ("Both lists come from the settings registry (`roe_parse: deny` and `tighten_only`).", False),
    ],
)
def test_p18_the_reused_name_exemption_is_only_for_the_live_class(line, stale):
    """The exemption must not hide the deleted disposition or its hyphenated spelling."""
    assert any(_names_deleted(term, line) for term in _GONE) is stale


def test_p18_no_wiki_page_calls_the_engagement_record_mcp_settable():
    """The record is UI-only, and a page saying otherwise sends somebody to a refusal."""
    claims = re.compile(
        r"roe(ClientName|ClientContact\w*|EmergencyContact|Notes|RawText|EngagementType)"
        r"[^\n]{0,80}(settable|update_recon_settings|writable)",
        re.I,
    )
    offenders = []
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if claims.search(line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == []


def test_p18_the_roe_page_states_the_split():
    """The page's whole subject changed; a page that still describes one concept is stale."""
    text = (WIKI / "Rules-of-Engagement.md").read_text(encoding="utf-8")
    assert "Engagement limits" in text
    assert "Engagement record" in text
    # The claim Part C removes.
    assert "become read-only afterward" not in text


def test_p18_no_page_claims_the_roe_settings_are_fixed_at_creation():
    """They are not. Only the RECORD is; the limits are editable for the project's life."""
    offenders = []
    stale = re.compile(r"RoE settings are (configured|fixed).{0,60}(creation|created)", re.I)
    for page in _wiki_pages():
        for i, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if stale.search(line):
                offenders.append(f"{page.name}:{i}: {line.strip()[:120]}")
    assert offenders == []


# --- P20: no agent-facing guide names a deny reason the registry dropped ------------------

def _agent_facing_files() -> list[Path]:
    out: list[Path] = []
    if PROMPTS.is_dir():
        out += sorted(PROMPTS.glob("*.md"))
    if SKILLS.is_dir():
        out += sorted(SKILLS.rglob("*.md"))
    return out


def _registry_deny_reasons() -> set[str]:
    import json

    schema = json.loads(
        (REPO_ROOT / "recon_settings" / "registry.schema.json").read_text(encoding="utf-8")
    )
    return set(schema["definitions"]["deny_reason"]["enum"])


#: Reasons an earlier model defined and this one does not. `unbounded` is the one
#: that mattered: a guide told an agent to deny a field for having no UI bound,
#: and the field then became unreachable with nothing failing.
_RETIRED_REASONS = ["unbounded", "othertarget", "intrusive", "wordlist", "headers", "egress"]


def test_p20_the_retired_reasons_really_are_retired():
    """If one of these came back, the test below would be asserting the wrong thing."""
    live = _registry_deny_reasons()
    assert [r for r in _RETIRED_REASONS if r in live] == []


#: A line that says a thing does NOT exist is the instruction we want, not the one
#: we are hunting. Without this the guards fail on their own replacement text,
#: which teaches people to delete the guard rather than the stale line.
_NEGATED = re.compile(r"\b(no|not|never|stopped|deleted|removed|replaced|retired)\b", re.I)


@pytest.mark.parametrize("reason", _RETIRED_REASONS)
def test_p20_no_agent_facing_guide_names_a_retired_deny_reason(reason):
    """Matched on the `deny_reason` KEY, not on the bare word.

    `egress` is also the name of a real guard in the capture proxy, and
    `wordlist` is a real thing a tool reads. Only a line that presents one of
    these AS a deny reason is stale.
    """
    pattern = re.compile(rf"deny[ _-]?reason[^\n]{{0,60}}[`\'\"]{reason}[`\'\"]", re.I)
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if pattern.search(line) and not _NEGATED.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:120]}")
    assert offenders == []


# --- P19: no guide tells an agent to hand-edit a generated artifact -----------------------

#: Files a generator owns. Editing one by hand is undone by the next build, and
#: the drift test fails afterwards rather than at the edit. Matched as a substring
#: of a line, so a basename two files share carries its folder.
_GENERATED = [
    "registry.json",
    "registryDigest.generated.ts",
    "roe_parse_prompt.py",
    "graph_db/schema_catalog.py",
    "node_filters/catalog.json",
    "nodeFilters/catalog.json",
    "manifest.schema.json",
    "screen.schema.json",
    "catalog.schema.json",
    "MCP-API-Reference.md",
    "Project-Settings-Registry.md",
    # gen-tradecraft-spec.mjs copies these from webapp/src/lib/tradecraft/, whose
    # vocab.json is the hand-edited source, hence the folder on this one.
    "settings_spec.json",
    "agentic/tradecraft/vocab.json",
    "permissionCatalog.json",
    "routeManifest.json",
    "routeManifest.ts",
    "p3_generated.tsv",
    "p4_generated.tsv",
    "p5_generated.tsv",
]

#: Generated pages that live in the wiki checkout rather than in this repository.
_GENERATED_IN_WIKI = {"MCP-API-Reference.md", "Project-Settings-Registry.md"}


def test_p19_every_generated_artifact_still_exists():
    """A name for a file that no longer exists guards nothing (drift-map #35)."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"], capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    missing = [
        name for name in _GENERATED
        if name not in _GENERATED_IN_WIKI and not any(f.endswith(name) for f in tracked)
    ]
    assert missing == [], f"_GENERATED names files nothing tracks: {missing}"

_EDIT_VERB = re.compile(
    r"\b(edit|add to|update|hand-edit|modify|append to|extend)\b[^\n]{0,80}", re.I
)


@pytest.mark.parametrize("artifact", _GENERATED)
def test_p19_no_guide_instructs_editing_a_generated_artifact(artifact):
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if artifact not in line:
                continue
            # A line that says it is generated, or says NOT to edit it, is the
            # instruction we want rather than the one we are hunting.
            if re.search(r"\b(generated|never edit|do not edit|build artifact|regenerat)", line, re.I):
                continue
            if _EDIT_VERB.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


def test_p19_no_guide_teaches_the_deleted_allow_deny_tables():
    """The positive allowlist was replaced by registry dispositions.

    A guide still teaching "add the column to the ALLOW table" produces code
    against a file that no longer exists.
    """
    # An INSTRUCTION to use one, not a mention of it. "There is no ALLOW/DENY
    # table" is the correction, and flagging it would teach people to delete the
    # guard rather than the stale line.
    pattern = re.compile(
        r"\b(add|put|place|classif\w*|goes|sits|appears)\b[^\n]{0,80}(ALLOW|DENY)[ /]*(or[ ]*DENY)?\s+table",
        re.I,
    )
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if pattern.search(line) and not _NEGATED.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


def test_p19_no_guide_names_the_deleted_tool():
    offenders = []
    for path in _agent_facing_files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if "tighten_engagement_roe" in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()[:140]}")
    assert offenders == []


# --- Links, anchors, images and counts (drift-map guard 13) ----------------------
#
# A heading renamed under an incoming `Page#anchor`, a screenshot that was never
# committed and a count copied into a sentence all go stale with nothing failing.
# Checked: every wiki page link and anchor (from the top-level wiki pages and from
# the repository docs), every same-file and cross-file anchor, every image, every
# link into this repository from the wiki, and the counts below. Whether a relative
# FILE link exists is the path audit's job (drift-audit.sh); here only its anchor.
#
# Wave 3 of the drift-map fix pass corrects the docs, so what is broken today is
# named in tests/fixtures/docs_drift_*.json with its map item, and an entry that no
# longer fails must leave it: the allowlist can only shrink.

_GH = "https://github.com/samugit83/redamon"
_FENCE = re.compile(r"^\s*(```|~~~)")
_LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_IMAGE = re.compile(
    r"!\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)|<img\b[^>]*\bsrc=[\"']([^\"']+)[\"']", re.I)
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_EXPLICIT_ANCHOR = re.compile(r"<a\s+(?:name|id)=[\"']([^\"']+)[\"']", re.I)

#: Repository docs whose links and counts are checked, beside the top-level wiki
#: pages (the subfolders hold session transcripts and per-benchmark patches, and
#: redamon.org copies only the top level).
_REPO_DOC_FILES = ("README.md", "CONTRIBUTING.md", "THIRD-PARTY-LICENSES.md",
                   "testing/guinea_pigs/README.md")
#: Pages that quote stale numbers on purpose, or are generated from code.
_COUNTS_NOT_CHECKED = ("docs/readmes/README.DRIFT_MAP.md", "redamon.wiki/MCP-API-Reference.md",
                       "redamon.wiki/Project-Settings-Registry.md")


def _recon_preset_count() -> int:
    index = (REPO_ROOT / "webapp/src/lib/recon-presets/index.ts").read_text(encoding="utf-8")
    return len(re.findall(r"from '\./presets/", index))


def _mcp_preset_count() -> int:
    text = (REPO_ROOT / "webapp/src/lib/mcp/presets.ts").read_text(encoding="utf-8")
    body = text[text.index("export const MCP_PRESETS"):]
    return len(re.findall(r"^  \{", body[: body.index("\n]\n")], re.M))


def _node_type_count() -> int:
    import importlib.util

    spec = importlib.util.spec_from_file_location("schema_keys", REPO_ROOT / "graph_db" / "schema_keys.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return len(module.LABELS_WITH_KEYS)


def _settings_count() -> int:
    import json

    return len(json.loads((REPO_ROOT / "recon_settings/registry.json").read_text(encoding="utf-8"))["fields"])


def _ts_block(relpath: str, start: str, end: str) -> str:
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    body = text[text.index(start):]
    return re.sub(r"//[^\n]*", "", body[: body.index(end)])


def _permission_count() -> int:
    body = _ts_block("webapp/src/lib/authz/permissions.ts", "const REGISTRY = {", "\n} as const")
    return len(re.findall(r"^  '[a-z_]+:[a-z_]+':", body, re.M))


def _mcp_scope_count() -> int:
    return len(re.findall(r"'([^']+)'", _ts_block("webapp/src/lib/mcpAuth.ts", "export const MCP_SCOPES = [", "\n]")))


def _llm_provider_count() -> int:
    """The built-in providers plus the OpenAI-compatible endpoint, the way the
    AI Model Providers page counts them (Bedrock-custom and Ollama are ways to
    reach those, not providers of their own)."""
    text = (REPO_ROOT / "agentic" / "llm_builder.py").read_text(encoding="utf-8")
    builtins = re.search(r"^_BUILTIN_PROVIDERS\s*=\s*\((.*?)\)", text, re.M | re.S).group(1)
    custom = re.search(r"^CUSTOM_PROVIDER_TYPES\s*=\s*\((.*?)\)", text, re.M | re.S).group(1)
    assert '"openai_compatible"' in custom, "the OpenAI-compatible provider type is gone"
    return len(re.findall(r'"([^"]+)"', builtins)) + 1


def _chat_skill_count() -> int:
    return len(list((REPO_ROOT / "agentic" / "skills").rglob("*.md")))


#: A count the docs spell out ("twelve AI providers"). Only the kinds below that
#: use _N accept words: their noun phrase is specific enough that a spelled-out
#: number is a claim about the whole set, not a subset.
_WORDS = ("two three four five six seven eight nine ten eleven twelve thirteen fourteen "
          "fifteen sixteen seventeen eighteen nineteen twenty").split()
_N = r"(\d+|" + "|".join(_WORDS) + r")"


def _number(text: str) -> int:
    return int(text) if text.isdigit() else _WORDS.index(text.lower()) + 2


#: The claim's block (see _prose_blocks) or its page's name must mention MCP or a
#: token: "32 scopes" is an npm count on the JS recon page.
_MCP_CONTEXT = re.compile(r"\bMCP\b|\btokens?\b", re.I)

#: (kind, pattern, only these files or None, the real number, a context the
#: claim's block must match or None). A claim "N" must equal it; "N+" must be a
#: floor within 10% of it, since "169+ settings" for 741 is true and useless.
#: Prefer "see the generated page" to a number. Each pattern names the set
#: ("built-in presets", "AI providers"), so "at most 200 presets" is no claim.
_COUNT_CLAIMS = [
    ("recon presets", re.compile(r"\b(\d+)(\+?)\s+(?:built-in|recon)\s+presets\b", re.I), None, _recon_preset_count, None),
    ("recon presets", re.compile(r"\b(\d+)(\+?)\s+presets\b", re.I),
     {"Recon-Presets.md", "VHost-and-SNI-Enumeration.md"}, _recon_preset_count, None),
    ("MCP presets", re.compile(r"\b(\d+)(\+?)\s+(?:MCP\s+server\s+)?presets\b", re.I),
     {"MCP-Tool-Plugins.md", "README.md"}, _mcp_preset_count, None),
    ("MCP presets", re.compile(
        r"\b(\d+)(\+?)\s+(?:(?:MCP\s+(?:server\s+)?|prefilled\s+|pre-vetted\s+)presets\b"
        r"|(?:MCP\s+|prefilled\s+)?preset\s+cards\b)", re.I),
     None, _mcp_preset_count, _MCP_CONTEXT),
    ("node types", re.compile(r"\b(\d+)(\+?)\s+node\s+(?:types|labels)\b", re.I), None, _node_type_count, None),
    ("settings", re.compile(r"\b(\d{3,})(\+?)\s+(?:configurable\s+|tunable\s+|project\s+)?(?:settings|parameters)\b(?!\s+mappings)", re.I),
     None, _settings_count, None),
    # Digits after "the", "are" or "registry:" only: "the same 71 permissions" is a
    # set's share and "the three permissions a plugin can ask for" another system.
    ("RBAC permissions", re.compile(r"(?:\bthe|\bare|\bregistry:)\s+\**(\d+)(\+?)\s+permissions\b", re.I),
     None, _permission_count, None),
    ("RBAC permissions", re.compile(r"\b(\d+)(\+?)\s+RBAC\s+permissions\b", re.I), None, _permission_count, None),
    ("MCP scopes", re.compile(rf"\b{_N}(\+?)\s+(?:MCP\s+|token\s+|access\s+)?scopes\b", re.I),
     None, _mcp_scope_count, _MCP_CONTEXT),
    # The token pages call the scopes permissions, paired with the tool count:
    # "51 tools behind 18 permissions", "the tools, the nine permissions".
    ("MCP scopes", re.compile(rf"\btools\b\W{{1,8}}(?:\w+\W+)?{_N}(\+?)\**\s+permissions\b", re.I),
     None, _mcp_scope_count, _MCP_CONTEXT),
    ("MCP scopes", re.compile(rf"\b{_N}(\+?)\s+MCP\s+(?:token\s+)?permissions\b", re.I), None, _mcp_scope_count, None),
    ("LLM providers", re.compile(rf"\b{_N}(\+?)\s+(?:LLM|AI)(?:[\s-]+model)?\s+providers\b", re.I),
     None, _llm_provider_count, None),
    ("LLM providers", re.compile(rf"\bmodels?\**\s+(?:across|from)\s+{_N}(\+?)\s+providers\b", re.I),
     None, _llm_provider_count, None),
    ("LLM providers", re.compile(rf"\b{_N}(\+?)\s+providers\**\s+and\s+\**\d+\+?\s+models\b", re.I),
     None, _llm_provider_count, None),
    ("LLM providers", re.compile(rf"\b{_N}(\+?)\s+providers\s+\((?=[^)]*\b(?:OpenAI|Anthropic)\b)", re.I),
     None, _llm_provider_count, None),
    ("chat skills", re.compile(rf"\b{_N}(\+?)\s+(?:shipped|reference|chat)\s+skills?\b", re.I),
     None, _chat_skill_count, None),
]

#: Claims the patterns match that count something else, by (file, phrase).
_NOT_A_COUNT_OF_THE_SET = {
    ("docs/readmes/README.AGENTIC_SYSTEM.md", "5 node types"): "EvoGraph's own node types",
    ("redamon.wiki/Home.md", "5 node types"): "EvoGraph's own node types",
    ("redamon.wiki/MCP-Tool-Plugins.md", "4 presets"): "the presets that need extra setup",
    ("redamon.wiki/AI-Model-Providers.md", "models from 50+ providers"): "OpenRouter's upstream providers",
}

#: Broken today, fixed by wave 3: (kind, file, target) -> map item. Kept in three
#: files by where the citing doc lives (the wiki, docs/readmes, the rest), so each
#: docs change removes its own entries in the same commit as the fix.
_DOCS_DRIFT_FILES = ("docs_drift_wiki.json", "docs_drift_readmes.json", "docs_drift_root.json")


def _docs_drift() -> dict[tuple[str, str, str], str]:
    import json

    out = {}
    for name in _DOCS_DRIFT_FILES:
        for e in json.loads((REPO_ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))["entries"]:
            out[(e["kind"], e["file"], e["target"])] = e["item"]
    return out


def _prose_lines(text: str):
    """(line number, line) outside fenced code, with inline code blanked."""
    fenced = False
    for i, line in enumerate(text.split("\n"), 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield i, re.sub(r"`[^`]*`", lambda m: " " * len(m.group(0)), line)


_BLOCK_START = re.compile(r"\s*(?:[-*+]\s|\d+[.)]\s|\||#|>)")


def _prose_blocks(text: str):
    """(line number, line, its context) for each prose line. The context is the
    paragraph, list item, table row or quote line the line belongs to, plus the
    heading of its section: a count's subject is read from its own sentence or
    section ("## MCP Tool Plugins" over a list item that never says MCP), never
    from the next row of a table."""
    blocks: list[tuple[str, list[tuple[int, str]]]] = []
    current: list[tuple[int, str]] = []
    heading, last = "", 0
    for lineno, line in _prose_lines(text):
        if not line.strip() or lineno != last + 1 or _BLOCK_START.match(line):
            if current:
                blocks.append((heading, current))
            current = []
        if _HEADING.match(line):
            heading = line
        if line.strip():
            current.append((lineno, line))
        last = lineno
    if current:
        blocks.append((heading, current))
    for section, block in blocks:
        joined = " ".join([section] + [line for _, line in block])
        for lineno, line in block:
            yield lineno, line, joined


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lowercased, punctuation but - and _ dropped,
    each space a hyphen (so " - " becomes "---"). Combining marks survive, so an
    emoji's U+FE0F variation selector stays in the anchor, as GitHub keeps it."""
    import unicodedata

    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    kept = "".join(c for c in text if re.match(r"[\w\- ]", c) or unicodedata.category(c).startswith("M"))
    return kept.replace(" ", "-")


_ANCHORS: dict[Path, set[str]] = {}


def _anchors(path: Path) -> set[str]:
    if path not in _ANCHORS:
        seen: dict[str, int] = {}
        found: set[str] = set()
        fenced = False
        for line in path.read_text(encoding="utf-8", errors="replace").split("\n"):
            if _FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            m = _HEADING.match(line)
            if m:
                base = _slug(m.group(2))
                n = seen.get(base, 0)
                found.add(base if n == 0 else f"{base}-{n}")
                seen[base] = n + 1
            found.update(_EXPLICIT_ANCHOR.findall(line))
        _ANCHORS[path] = found
    return _ANCHORS[path]


def _tracked_paths() -> set[str]:
    import subprocess

    files = subprocess.run(["git", "-C", str(REPO_ROOT), "ls-files"], capture_output=True,
                           text=True, check=True).stdout.split("\n")
    out = {f for f in files if f}
    for f in list(out):
        parent = Path(f).parent
        while str(parent) != ".":
            out.add(str(parent))
            parent = parent.parent
    return out


def _docs_findings() -> dict[tuple[str, str, str], str]:
    """(kind, file, target) -> what is wrong, for every check above."""
    import shutil
    from urllib.parse import unquote

    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    tracked = _tracked_paths()
    pages = {p.stem: p for p in WIKI.rglob("*.md") if ".git" not in p.parts}
    top_pages = sorted(WIKI.glob("*.md"))
    repo_docs = [REPO_ROOT / f for f in sorted(tracked)
                 if f.endswith(".md") and (f in _REPO_DOC_FILES or f.startswith("docs/readmes/"))]
    findings: dict[tuple[str, str, str], str] = {}

    def wiki_target_error(page: str, anchor: str) -> str | None:
        page = unquote(page)
        if page not in pages:
            return f"no wiki page {page}"
        if anchor and unquote(anchor).lower() not in _anchors(pages[page]):
            return f"no anchor #{anchor} in wiki page {page}"
        return None

    for doc in repo_docs + top_pages:
        rel = str(doc.relative_to(REPO_ROOT))
        in_wiki = doc.parent == WIKI
        text = doc.read_text(encoding="utf-8", errors="replace")
        for lineno, line in _prose_lines(text):
            for m in _IMAGE.finditer(line):
                target = (m.group(1) or m.group(2) or "").split("#")[0]
                if target and not re.match(r"^(https?:|data:)", target) \
                        and not (doc.parent / unquote(target)).resolve().exists():
                    findings[("image", rel, target)] = f"{rel}:{lineno}: image {target} does not exist"
            for m in _LINK.finditer(line):
                target = m.group(1)
                page_part, _, anchor = target.partition("#")
                wiki_url = re.match(re.escape(_GH) + r"/wiki/?([^#?]*)", target)
                repo_url = re.match(re.escape(_GH) + r"/(?:blob|tree)/[^/]+/([^#?]+)", target)
                if wiki_url:
                    error = wiki_target_error(wiki_url.group(1) or "Home", anchor)
                    if error:
                        findings[("wiki-link", rel, target)] = f"{rel}:{lineno}: {error}"
                elif repo_url:
                    path = unquote(repo_url.group(1)).strip("/")
                    if path not in tracked:
                        findings[("repo-url", rel, target)] = \
                            f"{rel}:{lineno}: {repo_url.group(1)} is not in the repository"
                    # GitHub renders a blob .md with the same heading slugs as
                    # the wiki; #L<n> addresses only its plain view.
                    elif anchor and "/blob/" in target and path.endswith(".md") \
                            and (REPO_ROOT / path).is_file() \
                            and not re.fullmatch(r"L\d+(-L\d+)?", anchor) \
                            and unquote(anchor).lower() not in _anchors(REPO_ROOT / path):
                        findings[("repo-url", rel, target)] = f"{rel}:{lineno}: no anchor #{anchor} in {path}"
                elif re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                    continue
                elif target == "#":
                    findings[("anchor", rel, target)] = f"{rel}:{lineno}: an empty link"
                elif not page_part:
                    if anchor and unquote(anchor).lower() not in _anchors(doc):
                        findings[("anchor", rel, target)] = f"{rel}:{lineno}: no anchor #{anchor} in this file"
                elif in_wiki and "/" not in page_part and "." not in page_part:
                    error = wiki_target_error(page_part, anchor)
                    if error:
                        findings[("wiki-link", rel, target)] = f"{rel}:{lineno}: {error}"
                else:
                    dest = (doc.parent / unquote(page_part)).resolve()
                    if anchor and dest.suffix == ".md" and dest.exists() \
                            and unquote(anchor).lower() not in _anchors(dest):
                        findings[("anchor", rel, target)] = f"{rel}:{lineno}: no anchor #{anchor} in {page_part}"
        if rel in _COUNTS_NOT_CHECKED:
            continue
        for lineno, line, block in _prose_blocks(text):
            for kind, pattern, only_in, real, context in _COUNT_CLAIMS:
                if only_in and doc.name not in only_in:
                    continue
                if context and not (context.search(block) or context.search(doc.stem)):
                    continue
                for m in pattern.finditer(line):
                    if re.search(r"\btop\s+$", line[: m.start()], re.I) \
                            or (rel, m.group(0)) in _NOT_A_COUNT_OF_THE_SET:
                        continue
                    claimed, floor, truth = _number(m.group(1)), bool(m.group(2)), real()
                    if not (truth * 0.9 <= claimed <= truth if floor else claimed == truth):
                        findings[("count", rel, f"{kind}:{m.group(1)}{m.group(2)}")] = \
                            f"{rel}:{lineno}: '{m.group(0)}', but there are {truth} {kind}"
    return findings


def test_p21_docs_links_anchors_images_and_counts_hold():
    findings, drift = _docs_findings(), _docs_drift()
    new = sorted(msg for key, msg in findings.items() if key not in drift)
    assert new == [], "\n".join(new)


def test_p21_the_docs_drift_allowlist_only_shrinks():
    """An entry the docs no longer break must leave the drift files, or the guard
    would excuse a regression at the same place later."""
    findings = _docs_findings()
    fixed = sorted(f"{key} ({item})" for key, item in _docs_drift().items() if key not in findings)
    assert fixed == [], "no longer broken, drop from tests/fixtures/docs_drift_*.json:\n" + "\n".join(fixed)


def test_p21_the_counts_are_read_from_the_code():
    """A count source that reads zero would make every claim check meaningless."""
    assert _recon_preset_count() > 20
    assert _mcp_preset_count() > 20
    assert _node_type_count() > 30
    assert _settings_count() > 500
    assert _permission_count() > 50
    assert _mcp_scope_count() > 10
    assert _llm_provider_count() > 5
    assert _chat_skill_count() > 20
