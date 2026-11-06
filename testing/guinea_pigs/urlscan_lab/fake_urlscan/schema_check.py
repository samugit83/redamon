"""A JSON-schema subset validator, stdlib only.

Shared by check_fixtures.py, the lab's unit test and the live format test, so
the fake urlscan and the real one are held to the same file
(urlscan_search.schema.json).

Supported keywords: type (a name or a list of names), required, enum, pattern
(re.search, as JSON Schema does), properties, items (one schema, or a list for
positional items), minItems, maxItems, minimum, $ref (only "#/definitions/<name>")
and definitions. Any other keyword raises SchemaError instead of being ignored,
so nobody reads a keyword as enforced when it is not.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "urlscan_search.schema.json"

_ANNOTATIONS = {"$schema", "$id", "$comment", "title", "description", "definitions", "examples"}
_KEYWORDS = {"type", "required", "enum", "pattern", "properties", "items", "minItems",
             "maxItems", "minimum", "$ref"} | _ANNOTATIONS
_PY_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


class SchemaError(ValueError):
    """The schema itself uses something this subset does not implement."""


def load_schema(path: Path | str | None = None) -> dict:
    return json.loads(Path(path or SCHEMA_PATH).read_text(encoding="utf-8"))


def _is_type(value, name: str) -> bool:
    # bool is an int subclass in Python; JSON keeps them apart.
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name not in _PY_TYPES:
        raise SchemaError(f"unsupported type {name!r}")
    return isinstance(value, _PY_TYPES[name])


def _resolve(root: dict, ref: str) -> dict:
    prefix = "#/definitions/"
    if not ref.startswith(prefix):
        raise SchemaError(f"unsupported $ref {ref!r}")
    try:
        return root["definitions"][ref[len(prefix):]]
    except KeyError:
        raise SchemaError(f"unknown $ref {ref!r}") from None


def errors(instance, schema: dict, root: dict | None = None, path: str = "$") -> list[str]:
    """Every violation of `schema` by `instance`, as "<json path>: <reason>"."""
    root = schema if root is None else root
    unknown = set(schema) - _KEYWORDS
    if unknown:
        raise SchemaError(f"{path}: unsupported keyword(s) {sorted(unknown)}")
    if "$ref" in schema:
        return errors(instance, _resolve(root, schema["$ref"]), root, path)

    out: list[str] = []
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(instance, n) for n in names):
            got = "null" if instance is None else type(instance).__name__
            return [f"{path}: expected {'|'.join(names)}, got {got}"]
    if "enum" in schema and instance not in schema["enum"]:
        out.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "pattern" in schema and isinstance(instance, str) and not re.search(schema["pattern"], instance):
        out.append(f"{path}: {instance!r} does not match {schema['pattern']!r}")
    if "minimum" in schema and _is_type(instance, "number") and instance < schema["minimum"]:
        out.append(f"{path}: {instance} < minimum {schema['minimum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                out.append(f"{path}: missing required {key!r}")
        for key, sub in schema.get("properties", {}).items():
            if key in instance:
                out.extend(errors(instance[key], sub, root, f"{path}.{key}"))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            out.append(f"{path}: {len(instance)} items < minItems {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            out.append(f"{path}: {len(instance)} items > maxItems {schema['maxItems']}")
        items = schema.get("items")
        if isinstance(items, list):
            for i, (value, sub) in enumerate(zip(instance, items)):
                out.extend(errors(value, sub, root, f"{path}[{i}]"))
        elif isinstance(items, dict):
            for i, value in enumerate(instance):
                out.extend(errors(value, items, root, f"{path}[{i}]"))
    return out


def check_search(body: dict, schema: dict | None = None) -> list[str]:
    """Violations of a 200 search answer."""
    schema = schema or load_schema()
    return errors(body, schema)


def check_error(body: dict, schema: dict | None = None) -> list[str]:
    """Violations of an error answer (400, 403, 429)."""
    schema = schema or load_schema()
    return errors(body, {"$ref": "#/definitions/error"}, schema)
