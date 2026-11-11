"""A prefix secret rule does not fire inside a longer identifier (S-12d).

Most JS Recon rules for vendor tokens are a literal prefix plus a body
(`sk_live_…`, `ghp_…`, `xoxb-…`, `AKIA…`, `glpat-…`). Without a left boundary,
`foosk_live_<body>` or `xghp_<body>` was reported as a Stripe or GitHub token:
the match started mid-identifier, so the "key" was a fragment of a longer
string, never a token the vendor issued.

Only a letter or digit right before the prefix blocks the match. `_`, quotes,
punctuation and an escape (`\\n`, `%22`, `\\x22`, `\\u0022`) are boundaries, so
a key inside an encoded string still fires; `_` counting as a boundary is a
product decision (a token glued to `cfg_` still fires).

Calls the real scan_js_content on synthetic, generated token bodies.
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path

import pytest

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers.js_recon.patterns import scan_js_content  # noqa: E402

_RNG = random.Random(20261111)
HEX = "0123456789abcdef"


def _body(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def _uuid_not_v4() -> str:
    # The third group never starts with `4`, so the UUID v4 rule stays out.
    return f"{_body(8, HEX)}-{_body(4, HEX)}-a{_body(3, HEX)}-{_body(4, HEX)}-{_body(12, HEX)}"


TOKENS = {
    "Stripe Secret Key": "sk_live_" + _body(28),
    "GitHub Token Classic": "ghp_" + _body(36),
    "Slack Bot Token": "xoxb-" + _body(12, string.digits) + "-" + _body(12, string.digits) + "-" + _body(24),
    "AWS Access Key ID": "AKIA" + _body(16, string.ascii_uppercase + string.digits),
    "GitLab PAT": "glpat-" + _body(20),
    # A prefix written as an alternation or a class: `(?:ghu|ghs)_`, `xox[os]-`.
    "GitHub App Token": "ghs_" + _body(36),
    "Slack Legacy Token": "xoxs-" + _body(12, string.digits) + "-" + _body(24),
    # A case-insensitive rule.
    "LaunchDarkly SDK Key": "sdk-" + _uuid_not_v4(),
    "JWT Token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + _body(43),
}

URL = "https://app.example.test/static/main.js"


def _findings(js: str) -> list:
    return scan_js_content(js, URL)[0]


def _named(findings: list, name: str) -> list:
    return [f for f in findings if f.get("name") == name or name in (f.get("alternate_names") or [])]


def _inside(findings: list, text: str) -> list:
    return [f.get("matched_text") for f in findings if f.get("matched_text") and f["matched_text"] in text]


@pytest.mark.parametrize("name", sorted(TOKENS))
def test_control_the_standalone_token_is_found(name):
    hits = _named(_findings(f'const cfg = {{k: "{TOKENS[name]}"}};'), name)
    assert [h["matched_text"] for h in hits] == [TOKENS[name]], name


@pytest.mark.parametrize("name", sorted(TOKENS))
@pytest.mark.parametrize("glue", ["foo", "x", "9"])
def test_the_token_shape_inside_a_longer_identifier_is_no_finding(name, glue):
    glued = glue + TOKENS[name]
    hits = _inside(_findings(f'const cfg = {{k: "{glued}"}};'), glued)
    assert hits == [], f"{name} fired mid-identifier: {hits}"


def test_stripe_shaped_tail_fires_as_no_sibling_rule():
    # sk_live_ is also Clerk's and WorkOS's prefix: every rule sharing it is bounded.
    token = "sk_live_" + _body(40)
    assert _inside(_findings(f'x="foo{token}"'), "foo" + token) == []
    names = {n for f in _findings(f'x="{token}"') for n in [f["name"], *(f.get("alternate_names") or [])]}
    assert {"Stripe Secret Key", "Clerk Secret Key", "WorkOS API Key"} <= names


@pytest.mark.parametrize("before", [
    "\\n",       # a JS escape: `"line\nsk_live_..."`
    "\\t",
    "%22",       # URL-encoded quote
    "%3D",       # URL-encoded `=`
    "\\x22",
    "\\u0022",
    "_",         # product decision: `_` is a boundary
    "cfg_",
    "'", "=", "/", ":", " ", "+",
])
@pytest.mark.parametrize("name", ["Stripe Secret Key", "GitHub Token Classic", "AWS Access Key ID",
                                  "Slack Bot Token", "GitLab PAT"])
def test_a_token_after_an_escape_or_punctuation_still_fires(name, before):
    js = f'const s = "head{before}{TOKENS[name]}";'
    hits = _named(_findings(js), name)
    assert [h["matched_text"] for h in hits] == [TOKENS[name]], (name, before)


def test_a_token_at_the_start_of_the_file_fires():
    token = TOKENS["GitHub Token Classic"]
    assert [h["matched_text"] for h in _named(_findings(token), "GitHub Token Classic")] == [token]


def test_the_case_insensitive_rule_is_bounded_in_any_case():
    token = "SDK-" + _uuid_not_v4()
    assert _named(_findings(f'k="{token}"'), "LaunchDarkly SDK Key")
    assert _inside(_findings(f'k="X{token}"'), "X" + token) == []
