"""HD-27: the registry names the project columns that stay the owner's when a project is shared.

`share: secret` is what `projectReadView` (webapp/src/lib/authz/projectReadView.ts) removes
from every project read by someone who is not the owner. It is a different question from
`readable` (the MCP read boundary) and from `deny_reason: secret` (an MCP write refusal): the
custom request-header lists are readable and settable through an owner's token, yet a header
list is where an operator puts an API key, so a collaborator never receives one.

The build refuses a column withheld from MCP reads as a credential, third-party personal data
or the RoE document that is not also `share: secret`, so a credential column added later cannot
reach a collaborator because nobody thought of sharing. The owner's id is the one withheld column
that stays: it names the owner, which the project read returns anyway.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "recon_settings"))

import build  # noqa: E402

REGISTRY = json.loads((REPO / "recon_settings" / "registry.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((REPO / "recon_settings" / "registry.schema.json").read_text(encoding="utf-8"))
FIELDS = REGISTRY["fields"]

# By name, not by count: each entry is a decision someone made.
WITHHELD_FROM_MCP_READS = {
    "cypherfixGithubToken", "graphqlAuthValue", "openapiSources", "ownershipToken",
    "phishingSmtpConfig", "roeClientContactEmail", "roeClientContactName",
    "roeClientContactPhone", "roeClientName", "roeDocumentData", "roeDocumentMimeType",
    "roeDocumentName", "roeEmergencyContact", "roeParsedJson", "roeRawText",
}
CUSTOM_HEADER_LISTS = {
    "httpxCustomHeaders", "katanaCustomHeaders", "zapAjaxSpiderCustomHeaders",
    "hakrawlerCustomHeaders", "jsReconEndpointCustomHeaders", "ffufCustomHeaders",
    "arjunCustomHeaders", "kiterunnerHeaders",
}
SHARE_SECRET = WITHHELD_FROM_MCP_READS | CUSTOM_HEADER_LISTS


def _minimal_document(**field_overrides) -> dict:
    """A registry the schema accepts, with one field to vary."""
    entry = {
        "tool": "t", "runtime_key": None, "unit": "none", "phase": "standalone",
        "traffic": "none", "roe_capped": False, "mcp": "never",
        "meaning": "A field that exists only for this test.",
    }
    entry.update(field_overrides)
    return {
        "version": 1,
        "tools": {"t": {"title": "T", "phase": "standalone", "traffic": "none"}},
        "fields": {"someField": entry},
        "runtime_only": {},
    }


class TestTheShareKeyIsDeclared(unittest.TestCase):
    def test_the_schema_declares_share_with_ordinary_and_secret(self):
        spec = SCHEMA["definitions"]["field"]["properties"]["share"]
        self.assertEqual(spec["enum"], ["ordinary", "secret"])
        self.assertEqual(spec.get("default"), "ordinary")

    def test_a_field_without_share_validates(self):
        build.validate(_minimal_document())

    def test_each_declared_value_validates(self):
        for value in ("ordinary", "secret"):
            build.validate(_minimal_document(share=value))

    def test_an_unknown_value_fails_the_build(self):
        with self.assertRaises(build.RegistryError) as raised:
            build.validate(_minimal_document(share="public"))
        self.assertIn("share", str(raised.exception))


class TestTheBuildKeepsTheOwnersSecrets(unittest.TestCase):
    def test_a_withheld_credential_not_marked_secret_fails(self):
        fields = {"someToken": {"readable": False, "read_deny_reason": "credential"}}
        with self.assertRaises(build.RegistryError) as raised:
            build.check_share_classes(fields)
        self.assertIn("someToken", str(raised.exception))

    def test_every_withheld_reason_but_the_owners_id_needs_secret(self):
        for reason in ("credential", "third_party_pii", "document_blob"):
            with self.subTest(reason=reason), self.assertRaises(build.RegistryError):
                build.check_share_classes({"x": {"readable": False, "read_deny_reason": reason}})
        build.check_share_classes({"x": {"readable": False, "read_deny_reason": "other_user"}})

    def test_a_withheld_column_with_no_reason_needs_secret(self):
        with self.assertRaises(build.RegistryError):
            build.check_share_classes({"x": {"readable": False}})

    def test_the_marked_withheld_credential_passes(self):
        build.check_share_classes(
            {"someToken": {"readable": False, "read_deny_reason": "credential", "share": "secret"}})

    def test_build_runs_the_check(self):
        # build() validates, then checks the share classes before joining Prisma: drop one
        # column's mark from the real document and the build refuses it by name.
        doc = copy.deepcopy(build.load_yaml())
        del doc["fields"]["cypherfixGithubToken"]["share"]
        with self.assertRaises(build.RegistryError) as raised:
            build.build(doc)
        self.assertIn("cypherfixGithubToken", str(raised.exception))


class TestTheBuiltRegistry(unittest.TestCase):
    def test_exactly_the_named_columns_are_secret(self):
        actual = {k for k, f in FIELDS.items() if f.get("share") == "secret"}
        self.assertEqual(sorted(actual), sorted(SHARE_SECRET))

    def test_every_other_field_is_ordinary(self):
        # Absent means ordinary; nothing writes the default out, so a stray value shows here.
        stray = {k: f["share"] for k, f in FIELDS.items()
                 if "share" in f and f["share"] not in ("ordinary", "secret")}
        self.assertEqual(stray, {})

    def test_every_readable_false_field_except_userId_is_secret(self):
        withheld = {k for k, f in FIELDS.items() if f.get("readable") is False}
        self.assertEqual(withheld - {"userId"}, WITHHELD_FROM_MCP_READS)
        missing = sorted(k for k in withheld - {"userId"} if FIELDS[k].get("share") != "secret")
        self.assertEqual(missing, [])

    def test_the_owners_id_stays_readable(self):
        self.assertNotEqual(FIELDS["userId"].get("share"), "secret")

    def test_custom_header_lists_are_secret(self):
        for key in sorted(CUSTOM_HEADER_LISTS):
            with self.subTest(field=key):
                self.assertEqual(FIELDS[key].get("share"), "secret")
                self.assertEqual(FIELDS[key]["validator"], "http_header")

    def test_header_names_and_attribution_values_stay_ordinary(self):
        # graphqlAuthHeader holds a header NAME (its value is graphqlAuthValue, secret);
        # engagementIdentityHeader is the attribution header the client asked for.
        for key in ("graphqlAuthHeader", "engagementIdentityHeader"):
            with self.subTest(field=key):
                self.assertNotEqual(FIELDS[key].get("share"), "secret")

    def test_every_header_list_column_is_named(self):
        # A new custom-header list must be classed on purpose: every string-list column
        # validated as http_header is in the secret list.
        header_lists = {k for k, f in FIELDS.items()
                        if f.get("validator") == "http_header" and f["type"] == "string-list"}
        self.assertEqual(sorted(header_lists), sorted(CUSTOM_HEADER_LISTS))


if __name__ == "__main__":
    unittest.main()
