"""
Build `registry.json` from `registry.yaml`, joining Prisma for type and default.

Run it after editing the YAML:

    python3 recon_settings/build.py           # write both artifacts
    python3 recon_settings/build.py --check   # fail if either is stale

`--check` is what the drift tests run, so a hand edit to a generated file, or a
YAML edit that was never built, fails the gate rather than reaching a scan.

Two artifacts, one source. A scan container mounts `recon/` but never `webapp/`,
and the webapp build tree cannot import across its own root, so the same bytes
are written to both places and the drift test compares them to each other.

Determinism is a requirement, not a nicety: no timestamps, no version strings,
sorted keys throughout. A generated diff that changes on every run is one people
learn to ignore, which is the failure mode `apiReference.ts` already documents.

The validator is deliberately hand-written rather than `jsonschema`: this module
is imported inside the recon image and the agent image, and a registry that
fails to load is a scan that must not start. A dependency that might not be
installed there would turn the fail-closed rule into a fail-at-runtime one.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
YAML_PATH = HERE / "registry.yaml"
SCHEMA_PATH = HERE / "registry.schema.json"
JSON_PATH = HERE / "registry.json"
WEBAPP_JSON_PATH = REPO_ROOT / "webapp" / "src" / "lib" / "reconSettings" / "registry.json"
ROE_PROMPT_PATH = HERE / "roe_parse_prompt.py"
DIGEST_TS_PATH = REPO_ROOT / "webapp" / "src" / "lib" / "reconSettings" / "registryDigest.generated.ts"
NODE_MAPPING_TS = REPO_ROOT / "webapp" / "src" / "components" / "projects" / "ProjectForm" / "nodeMapping.ts"

#: Registry tools whose partial-recon section in SECTION_NODE_MAP has another name.
SECTION_ALIASES = {
    "gvm": "GvmScan",
    "graphql": "GraphqlScan",
    "openapi_recon": "OpenAPI",
    "takeover": "SubdomainTakeover",
    "zap": "ZapAjaxSpider",
}

sys.path.insert(0, str(REPO_ROOT / "tooling" / "scripts"))


class RegistryError(Exception):
    """A registry that does not build. Always fatal: never fall back."""


# --- a small JSON Schema subset ----------------------------------------------------

def _type_ok(value, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise RegistryError(f"unsupported schema type {expected!r}")


def _resolve(schema: dict, root: dict) -> dict:
    ref = schema.get("$ref")
    if not ref:
        return schema
    if not ref.startswith("#/"):
        raise RegistryError(f"unsupported $ref {ref!r}")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _validate(value, schema: dict, root: dict, path: str, errors: list[str]) -> None:
    schema = _resolve(schema, root)

    if "enum" in schema:
        if value not in schema["enum"]:
            errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
        return

    expected = schema.get("type")
    if expected is not None:
        options = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, o) for o in options):
            errors.append(f"{path}: expected {expected}, got {type(value).__name__}")
            return

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']} characters")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                _validate(item, item_schema, root, f"{path}[{i}]", errors)
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key '{key}'")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties")
        for key, item in sorted(value.items()):
            sub = f"{path}.{key}" if path else key
            if key in props:
                _validate(item, props[key], root, sub, errors)
            elif isinstance(extra, dict):
                _validate(item, extra, root, sub, errors)
            elif extra is False:
                errors.append(f"{path}: unknown key '{key}'")


def validate(document: dict, schema: dict | None = None) -> None:
    schema = schema or json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    _validate(document, schema, schema, "", errors)
    if errors:
        shown = "\n  ".join(errors[:40])
        more = "" if len(errors) <= 40 else f"\n  ... and {len(errors) - 40} more"
        raise RegistryError(f"registry.yaml does not match its schema:\n  {shown}{more}")


# --- the build --------------------------------------------------------------------

def load_yaml() -> dict:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - only without PyYAML
        raise RegistryError(
            "PyYAML is required to BUILD the registry. Reading the built registry.json "
            "needs nothing but the standard library."
        ) from exc
    return yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))


#: The one MCP read refusal that is not the owner's secret: the owner's id names the owner,
#: which every project read returns anyway.
SHAREABLE_READ_DENY_REASONS = frozenset({"other_user"})


#: Groups whose every field decides what the engagement targets or permits: `share: scope`,
#: which a collaborator narrows only as a co-owner and widens never (or `secret`, the
#: ownership token).
SCOPE_GROUPS = frozenset({"scope", "engagement_limits"})


def check_share_classes(fields: dict) -> None:
    """Absent `share` means ordinary, which a collaborator reads and an editor writes, so a
    column added without a class must not be one that needs more:

    - a column withheld from MCP reads is withheld from collaborators too (`share: secret`),
      or a credential column added with `readable: false` would reach every collaborator;
    - a `roe_parse: tighten_only` switch is a safety gate (`share: gate`), or an editor could
      loosen it;
    - a field of a scope group is `share: scope`, or an editor could widen the engagement.
    """
    leaks = sorted(
        name for name, f in fields.items()
        if f.get("readable") is False
        and f.get("read_deny_reason") not in SHAREABLE_READ_DENY_REASONS
        and f.get("share") != "secret"
    )
    if leaks:
        raise RegistryError(
            "a column withheld from MCP reads must also be share: secret, or a collaborator "
            "reads it: " + ", ".join(leaks)
        )
    open_gates = sorted(
        name for name, f in fields.items()
        if f.get("roe_parse") == "tighten_only" and f.get("share") != "gate"
    )
    if open_gates:
        raise RegistryError(
            "a roe_parse: tighten_only switch must also be share: gate, or an editor loosens "
            "it: " + ", ".join(open_gates)
        )
    open_scope = sorted(
        name for name, f in fields.items()
        if f.get("group") in SCOPE_GROUPS and f.get("share") not in ("scope", "secret")
    )
    if open_scope:
        raise RegistryError(
            "a field of the scope or engagement_limits group must be share: scope, or an "
            "editor widens the engagement: " + ", ".join(open_scope)
        )


def build(document: dict | None = None) -> dict:
    """Validate the YAML and join Prisma's type and default onto every field."""
    from prisma_project_columns import project_columns

    doc = document if document is not None else load_yaml()
    validate(doc)
    check_share_classes(doc["fields"])

    columns = project_columns()
    fields = doc["fields"]

    missing = sorted(set(columns) - set(fields))
    ghosts = sorted(set(fields) - set(columns))
    if missing:
        raise RegistryError(
            f"{len(missing)} Prisma Project column(s) have no registry entry: "
            f"{', '.join(missing[:10])}{' ...' if len(missing) > 10 else ''}"
        )
    if ghosts:
        raise RegistryError(
            f"{len(ghosts)} registry entr(ies) name a column Prisma does not have: "
            f"{', '.join(ghosts[:10])}{' ...' if len(ghosts) > 10 else ''}"
        )

    unpaired = sorted(
        name for name, f in fields.items()
        if (f.get("roe_parse") == "tighten_only") != ("roe_safe_value" in f)
    )
    if unpaired:
        raise RegistryError(
            "roe_safe_value must be set on every roe_parse: tighten_only field and on no other: "
            + ", ".join(unpaired)
        )

    tool_sections = {name: tool.get("form_section") for name, tool in doc["tools"].items()}

    out_fields: dict[str, dict] = {}
    for name in sorted(fields):
        col = columns[name]
        entry = dict(fields[name])
        # A field is rendered beside the other settings of the tool it configures,
        # so the section is the TOOL's unless the field names its own. An explicit
        # null survives the join and means "no input anywhere", which is what the
        # parity test reads to tell a deliberate omission from a forgotten one.
        if "form_section" not in entry:
            entry["form_section"] = tool_sections.get(entry["tool"])
        entry["type"] = col.kind
        entry["prisma_type"] = col.type + ("[]" if col.is_list else "")
        entry["optional"] = col.optional
        entry["default"] = col.default_value
        entry["has_default"] = col.default_raw is not None
        out_fields[name] = {k: entry[k] for k in sorted(entry)}

    tools = {name: {k: v for k, v in sorted(_with_produces(name, tool).items())}
             for name, tool in sorted(doc["tools"].items())}
    runtime = {name: {k: v for k, v in sorted(r.items())} for name, r in sorted(doc["runtime_only"].items())}

    return {
        "version": doc["version"],
        "fields": out_fields,
        "runtime_only": runtime,
        "tools": tools,
    }


def _section_node_map() -> dict[str, list[str]]:
    """SECTION_NODE_MAP in nodeMapping.ts: the node labels each partial-recon
    section writes, as the workflow view draws them."""
    import re

    text = NODE_MAPPING_TS.read_text(encoding="utf-8")
    body = re.search(r"export const SECTION_NODE_MAP[^=]*=\s*\{(.*?)\n\}", text, re.S)
    if not body:
        raise RegistryError(f"SECTION_NODE_MAP not found in {NODE_MAPPING_TS.relative_to(REPO_ROOT)}")
    return {m.group(1): re.findall(r"'([^']+)'", m.group(2))
            for m in re.finditer(r"^\s*(\w+):\s*\[([^\]]*)\]", body.group(1), re.M)}


_SECTIONS: dict[str, list[str]] | None = None


def _with_produces(name: str, tool: dict) -> dict:
    """A tool's `produces` is its section's SECTION_NODE_MAP entry, derived at
    build time so it cannot drift from the view; a tool that runs inside another
    section (dns, crtsh) has none of its own."""
    global _SECTIONS
    if "produces" in tool:
        raise RegistryError(
            f"tools.{name}.produces is derived from SECTION_NODE_MAP "
            f"({NODE_MAPPING_TS.relative_to(REPO_ROOT)}); remove it from registry.yaml")
    if _SECTIONS is None:
        _SECTIONS = _section_node_map()
    unknown = sorted(a for a in SECTION_ALIASES.values() if a not in _SECTIONS)
    if unknown:
        raise RegistryError(f"SECTION_ALIASES names sections SECTION_NODE_MAP lacks: {unknown}")
    norm = name.replace("_", "").lower().rstrip("s")
    section = SECTION_ALIASES.get(name) or next(
        (key for key in _SECTIONS if key.lower().rstrip("s") == norm), None)
    if section is None:
        return dict(tool)
    return {**tool, "produces": _SECTIONS[section]}


HEADER = (
    "GENERATED FILE - DO NOT EDIT. Source: recon_settings/registry.yaml. "
    "Rebuild with: python3 recon_settings/build.py"
)


def serialise(registry: dict) -> str:
    return json.dumps({"_generated": HEADER, **registry}, indent=1, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    try:
        text = serialise(build())
    except RegistryError as exc:
        print(f"registry build FAILED: {exc}", file=sys.stderr)
        return 2

    targets = {JSON_PATH: text, WEBAPP_JSON_PATH: text, DIGEST_TS_PATH: _digest_module(text)}

    # The prompt is generated from the registry AS JUST BUILT, not from whatever
    # registry.json happens to be on disk, so one run cannot leave the two
    # artifacts describing different field sets.
    if check:
        stale = [p for p, body in targets.items()
                 if not p.exists() or p.read_text(encoding="utf-8") != body]
        prompt_text = _prompt_from(text, write=False)
        if not ROE_PROMPT_PATH.exists() or ROE_PROMPT_PATH.read_text(encoding="utf-8") != prompt_text:
            stale.append(ROE_PROMPT_PATH)
        if stale:
            names = ", ".join(str(p.relative_to(REPO_ROOT)) for p in stale)
            print(
                f"registry artifact is STALE: {names}\n"
                f"Run: python3 recon_settings/build.py",
                file=sys.stderr,
            )
            return 1
        print("registry artifacts are up to date")
        return 0

    for path, body in targets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    ROE_PROMPT_PATH.write_text(_prompt_from(text, write=True), encoding="utf-8")

    registry = json.loads(text)
    print(
        f"wrote {len(targets) + 1} artifact(s): "
        f"{len(registry['fields'])} fields, {len(registry['tools'])} tools, "
        f"{len(registry['runtime_only'])} runtime-only keys"
    )
    return 0


def _digest_module(registry_text: str) -> str:
    """The registry digest as a TypeScript constant, for the webapp's handshake.

    The agent image COPY-bakes `recon_settings/`, so it compares its prompt with
    its OWN registry and the two always agree: a stale agent parses with an old
    catalogue and reports no skew at all. The webapp is the side that knows the
    current registry, so it compares the digest the agent returns with this one.
    """
    digest = hashlib.sha256(registry_text.encode("utf-8")).hexdigest()
    return (
        "// GENERATED FILE - DO NOT EDIT. Source: recon_settings/registry.yaml.\n"
        "// Rebuild with: python3 recon_settings/build.py\n"
        "//\n"
        "// SHA-256 of the built registry.json. The RoE parse route refuses an agent\n"
        "// whose prompt was generated from any other registry.\n"
        f"export const REGISTRY_DIGEST = '{digest}'\n"
    )


def _prompt_from(registry_text: str, *, write: bool) -> str:
    """Render the prompt against the registry text this run produced.

    The loader caches, and it reads the file, so a build that wrote a new
    registry and then rendered would otherwise render from the PREVIOUS bytes on
    the first run after a change. Writing the registry first and dropping the
    cache is what keeps the digest in the prompt equal to the digest of the file
    beside it. `--check` must not write anything, so it renders from a temporary
    copy through the loader's override instead.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from recon_settings.loader import reload_registry  # noqa: PLC0415
    from recon_settings.roe_prompt import render_module  # noqa: PLC0415

    if write:
        JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        JSON_PATH.write_text(registry_text, encoding="utf-8")
        reload_registry()
        return render_module()

    previous = os.environ.get("RECON_SETTINGS_REGISTRY")
    with tempfile.TemporaryDirectory() as tmp:
        candidate = Path(tmp) / "registry.json"
        candidate.write_text(registry_text, encoding="utf-8")
        os.environ["RECON_SETTINGS_REGISTRY"] = str(candidate)
        try:
            reload_registry()
            return render_module()
        finally:
            if previous is None:
                os.environ.pop("RECON_SETTINGS_REGISTRY", None)
            else:
                os.environ["RECON_SETTINGS_REGISTRY"] = previous
            reload_registry()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
