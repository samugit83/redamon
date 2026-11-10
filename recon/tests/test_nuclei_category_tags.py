"""L-8: a Nuclei finding's category comes from whole tags, not from substrings.

`parse_nuclei_finding` matched its category keys with `key in tag`, so the tags
`source`, `bruteforce`, `ecommerce` and `salesforce` gave category `rce`,
`sqlite` gave `sqli` and `fintech` gave `technology`. The Priority Board reads
the stored category (`score_model.classify`), so those findings ranked as
exploitable injections. A key now matches a tag only as a whole word of it:
the tag itself, or a run of its `-`/`_`-separated words, so `time-based-sqli`
is still SQL injection and `open-redirect` still an open redirect.

Run: ./redamon.sh test unit   (recon section)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.nuclei_helpers import parse_nuclei_finding  # noqa: E402


def _category(tags) -> str:
    return parse_nuclei_finding({
        "template-id": "t",
        "info": {"name": "n", "severity": "info", "tags": tags},
    })["category"]


@pytest.mark.parametrize("tags, expected", [
    # A key inside another word is not that key.
    (["source"], "general"),
    (["bruteforce"], "general"),
    (["ecommerce"], "general"),
    (["woocommerce", "wp-plugin"], "general"),
    (["salesforce", "misconfig"], "misconfiguration"),
    (["fintech"], "general"),
    (["sqlite", "exposure"], "exposure"),
    (["mixpanel", "token"], "general"),
    (["nextcloud", "panel"], "exposed_panel"),
    (["starttls"], "general"),
    (["codoso"], "general"),
    (["dockerhub", "tech"], "technology"),
    # Whole tags.
    (["rce"], "rce"),
    (["sqli"], "sqli"),
    (["XSS"], "xss"),
    (["misconfig"], "misconfiguration"),
    (["misconfiguration"], "misconfiguration"),
    (["default-login"], "authentication"),
    (["auth-bypass"], "authentication"),
    (["file-upload"], "file_upload"),
    (["docker"], "cloud"),
    (["tls"], "ssl_tls"),
    # A key that is a whole word of a hyphenated tag.
    (["time-based-sqli", "cve", "cve2023"], "sqli"),
    (["open-redirect"], "open_redirect"),
    (["hostheader-injection"], "injection"),
    (["exposed-panel"], "exposed_panel"),
    (["osint", "osint-tech"], "technology"),
    # The first tag that matches decides, as before.
    (["cve", "cve2021", "rce"], "cve"),
    (["vuln", "panel", "xss"], "exposed_panel"),
    ([], "general"),
])
def test_category_from_tags(tags, expected):
    assert _category(tags) == expected


def test_a_comma_separated_tag_string_is_split_into_tags():
    assert _category("ecommerce, wordpress, exposure") == "exposure"


def test_the_parsed_finding_keeps_its_tags_unchanged():
    parsed = parse_nuclei_finding({"template-id": "t",
                                   "info": {"tags": ["ecommerce", "time-based-sqli"]}})
    assert parsed["tags"] == ["ecommerce", "time-based-sqli"]
    assert parsed["category"] == "sqli"
