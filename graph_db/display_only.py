"""The properties that hold a secret or a URL with its secret in it, for display.

Recon keeps a secret's value and every link that carries one (a leaked reset
link, a token in a query string) so the operator can read, copy and open them
in the UI. They sit beside the masked fields, which stay the identities and the
inputs of every request list: no reader that turns graph data into a request
names these, and the agent's generic graph output drops them
(`strip_display_only`), so RedAmon never replays someone's token by itself.

The webapp mirrors this set in webapp/src/lib/secrets/secretProps.ts; a test
keeps the two equal.
"""
from __future__ import annotations

import re
from typing import Any

#: A secret itself.
SECRET_VALUE_PROPS = frozenset({
    "secret_value",    # the full secret (Secret, JsReconFinding)
    "paired_secret",   # the other half of a key pair (an AWS secret access key)
    "secret_values",   # the secrets a response body held (route_exposure Vulnerability)
})

#: A URL or text with a secret left in it.
UNMASKED_PROPS = frozenset({
    "unmasked_url",                  # newest full link of the finding or endpoint
    "unmasked_urls",                 # its distinct full links, newest first
    "unmasked_start_url",            # a urlscan redirect visit's start URL
    "unmasked_redirect_from_url",
    "unmasked_redirect_from_urls",   # ExternalDomain
    "raw_context",                   # the code around a key, nothing masked
})

DISPLAY_ONLY_PROPS = SECRET_VALUE_PROPS | UNMASKED_PROPS

_NAMED = re.compile(r"\b(" + "|".join(sorted(DISPLAY_ONLY_PROPS, key=len, reverse=True)) + r")\b")

REFUSAL = ("The query names {names}: a property that holds a secret, or a full link with its "
           "secret in it, which RedAmon keeps for the operator's UI and never returns to an agent. "
           "Query the masked fields instead (masked_url, sample, value_length, value_hmac, url, "
           "matched_at), or ask the operator.")


def display_only_named(cypher: str) -> list:
    """The display-only property names a Cypher text mentions, sorted. An alias
    (`RETURN s.secret_value AS v`) hides the name from the rows, never from
    the query, so the check is made on the query."""
    return sorted(set(_NAMED.findall(cypher or "")))


def refusal_for(names: list) -> str:
    return REFUSAL.format(names=", ".join(names))


def strip_display_only(value: Any) -> Any:
    """`value` with every display-only key removed from each dict in it, at any
    depth. Lists and tuples are rebuilt; anything else is returned as is."""
    if isinstance(value, dict):
        return {k: strip_display_only(v) for k, v in value.items() if k not in DISPLAY_ONLY_PROPS}
    if isinstance(value, list):
        return [strip_display_only(v) for v in value]
    if isinstance(value, tuple):
        return tuple(strip_display_only(v) for v in value)
    return value
