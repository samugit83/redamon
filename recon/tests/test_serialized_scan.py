"""Unit tests for the serialized_scan recon module (plan §5, §14).

Hermetic: no network, no DB. Covers every family signature, the bomb-safe
decoder (depth/size caps), the scanner over a synthetic in-memory corpus, the
_isolated wrapper's no-mutate contract, the never-raise contract, and the
render-safe evidence snippet.
"""

import base64
import contextlib
import copy
import gzip
import io
import unittest
from unittest import mock

from recon.serialized_scan import (
    decoders,
    normalizers,
    signatures,
    run_serialized_scan,
    run_serialized_scan_isolated,
)


def _latin1(b: bytes) -> str:
    """Carry raw bytes through a str field the way a cookie/param would."""
    return b.decode("latin-1")


class TestFamilySignatures(unittest.TestCase):
    """Each family's representative marker must yield its deser_format (§3)."""

    TEXT_CASES = [
        ("rO0ABXNy", "native_java"),
        ("aced0005cafebabe", "native_java"),
        ('{"@class":"java.util.HashMap"}', "jackson_json"),
        ('{"@type":"com.sun.rowset.JdbcRowSetImpl"}', "fastjson"),
        ('<java version="1.8"><object class="java.lang.Runtime">', "xmldecoder"),
        ("<org.apache.commons.collections.functors.ChainedTransformer>", "xstream"),
        ("!!javax.script.ScriptEngineManager [[!!java.net.URL []]]", "snakeyaml"),
        ('O:4:"User":1:{s:4:"name";s:3:"bob";}', "php_serialize"),
        ("phar:///tmp/evil.phar/x", "phar"),
        ("gASVlAAAAAAAAAB9", "python_pickle"),
        ("gAJ9cQ", "python_pickle"),
        ("AAEAAAD/////AQAAAAAAAAAM", "dotnet_binaryformatter"),
        ("__VIEWSTATE", "viewstate"),
    ]

    BYTE_CASES = [
        (b"\xac\xed\x00\x05sr\x00", "native_java"),
        (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01", "dotnet_binaryformatter"),
        (b"\x80\x04\x95\x10", "python_pickle"),
        (b"\x80\x02}q\x00", "python_pickle"),
        (b"\x04\x08{\x06", "ruby_marshal"),
    ]

    HEADER_CASES = [
        ("application/x-java-serialized-object", "native_java"),
        ("application/x-hessian", "hessian"),
    ]

    def test_text_signatures(self):
        for value, fmt in self.TEXT_CASES:
            with self.subTest(fmt=fmt, value=value):
                hits = signatures.scan_text(value)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_byte_signatures(self):
        for raw, fmt in self.BYTE_CASES:
            with self.subTest(fmt=fmt):
                hits = signatures.scan_bytes(raw)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_header_signatures(self):
        for value, fmt in self.HEADER_CASES:
            with self.subTest(fmt=fmt):
                hits = signatures.scan_header_value(value)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_benign_text_has_no_hits(self):
        for benign in ("hello world", "id=42&page=3", "application/json",
                       "a normal sentence with class names"):
            with self.subTest(benign=benign):
                self.assertEqual(signatures.scan_text(benign), [])

    def test_benign_bytes_have_no_hits(self):
        self.assertEqual(signatures.scan_bytes(b"ordinary cookie value"), [])


class TestDecoders(unittest.TestCase):
    def test_base64_layer_is_peeled(self):
        inner = b"\xac\xed\x00\x05payload"
        value = base64.b64encode(inner).decode()
        out = decoders.decode_layers(value)
        self.assertIn("base64", out["encoding_chain"])
        # the inner Java stream is reachable on a decoded layer
        self.assertTrue(any(l["raw"].startswith(b"\xac\xed") for l in out["layers"]))

    def test_base64_gzip_double_layer(self):
        inner = b"\xac\xed\x00\x05" + b"X" * 50
        value = base64.b64encode(gzip.compress(inner)).decode()
        out = decoders.decode_layers(value)
        self.assertEqual(out["encoding_chain"][:2], ["base64", "gzip"])
        self.assertFalse(out["truncated"])
        self.assertTrue(any(l["raw"].startswith(b"\xac\xed") for l in out["layers"]))

    def test_decompression_bomb_is_aborted_and_flagged(self):
        """An oversized gzip value is flagged truncated, never expanded (§3.1)."""
        bomb = gzip.compress(b"A" * (3 * 1024 * 1024))  # 3 MiB > 1 MiB cap
        value = _latin1(bomb)
        out = decoders.decode_layers(value)
        self.assertTrue(out["truncated"])
        # only the raw layer survives; the bomb was never decompressed
        self.assertEqual(len(out["layers"]), 1)
        self.assertNotIn("gzip", out["encoding_chain"])
        for layer in out["layers"]:
            self.assertLessEqual(len(layer["raw"]), decoders.MAX_CUMULATIVE_BYTES)

    def test_depth_cap_flags_truncated(self):
        # base64 four times over a still-decodable blob hits the 4-layer cap
        payload = b"\xac\xed\x00\x05" + b"Y" * 40
        wrapped = payload
        for _ in range(6):
            wrapped = base64.b64encode(wrapped)
        out = decoders.decode_layers(wrapped.decode())
        self.assertLessEqual(len(out["encoding_chain"]), decoders.MAX_LAYERS)
        self.assertTrue(out["truncated"])

    def test_empty_and_nonstring(self):
        self.assertEqual(decoders.decode_layers("")["layers"], [])
        self.assertEqual(decoders.decode_layers(None)["layers"], [])


def _corpus():
    """A synthetic in-memory combined_result spanning transports/families."""
    return {
        "metadata": {"user_id": "u1", "project_id": "p1"},
        "http_probe": {
            "by_url": {
                "https://t.example.com/app": {
                    "url": "https://t.example.com/app",
                    "status_code": 200,
                    "content_type": "application/x-java-serialized-object",
                    "headers": {
                        "set_cookie": "sess=rO0ABXNyABByZW1lbWJlck1l; Path=/",
                        "x_powered_by": "ASP.NET",
                    },
                },
                "https://t.example.com/hessian": {
                    "url": "https://t.example.com/hessian",
                    "status_code": 200,
                    "content_type": "application/x-hessian",
                    "headers": {},
                },
            }
        },
        # The REAL recon-corpus shape (the shape resource_mixin reads):
        # endpoints carry `methods` (a list); parameters are keyed by POSITION
        # ("query"/"body"), each a list of param dicts with name + sample_values.
        "resource_enum": {
            "by_base_url": {
                "https://t.example.com": {
                    "endpoints": {
                        "/login": {
                            "methods": ["POST"],
                            "parameters": {
                                "query": [
                                    {"name": "__VIEWSTATE",
                                     "sample_values": ["AAEAAAD/////AQAAAA"]},
                                ],
                                "body": [
                                    {"name": "data",
                                     "sample_values": ['O:4:"User":1:{s:1:"a";i:1;}']},
                                ],
                            },
                        },
                    }
                }
            }
        },
    }


class TestScanner(unittest.TestCase):
    def test_disabled_returns_untouched(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": False})
        self.assertNotIn("serialized_scan", out)

    def test_finds_every_transport(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        findings = out["serialized_scan"]["findings"]
        formats = {f["deser_format"] for f in findings}
        self.assertIn("native_java", formats)       # cookie + header
        self.assertIn("hessian", formats)            # content-type header
        self.assertIn("viewstate", formats)          # param name
        self.assertIn("dotnet_binaryformatter", formats)  # param value
        self.assertIn("php_serialize", formats)      # param value
        transports = {f["deser_transport"] for f in findings}
        self.assertIn("cookie", transports)
        self.assertIn("header", transports)
        self.assertIn("param", transports)

    def test_param_method_comes_from_methods_list(self):
        # F2: endpoints carry `methods` (list); a param candidate must take the
        # real method so its Endpoint attach matches (not a hardcoded GET).
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        param_findings = [f for f in out["serialized_scan"]["findings"]
                          if f["deser_transport"] == "param"]
        self.assertTrue(param_findings)
        self.assertTrue(all(f["http_method"] == "POST" for f in param_findings))

    def test_positional_param_shape_scans_names_and_values(self):
        # F1 regression: the real {"query":[{name,sample_values}]} shape must
        # scan BOTH the parameter name and each sample value.
        cr = {"resource_enum": {"by_base_url": {"https://t": {"endpoints": {
            "/y": {"methods": ["GET"], "parameters": {
                "query": [{"name": "__VIEWSTATE",
                           "sample_values": ["gASVlAAAAAAAAAB9"]}]}}}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("viewstate", fmts)        # from the param NAME
        self.assertIn("python_pickle", fmts)    # from the sample_value (gASV)

    def test_flat_param_shape_still_handled(self):
        # Partial recon / a hand-built flat {name: {value}} shape is tolerated.
        cr = {"resource_enum": {"by_base_url": {"https://t": {"endpoints": {
            "/x": {"method": "GET",
                   "parameters": {"q": {"value": "rO0ABXNy"}}}}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)

    def test_string_form_response_headers_are_scanned(self):
        # F3: httpx sometimes stores headers as one CRLF-joined string; the
        # Set-Cookie blob must still be detected, not silently skipped.
        cr = {"http_probe": {"by_url": {"https://t/": {
            "url": "https://t/", "content_type": "text/html",
            "headers": "Set-Cookie: sess=rO0ABXNy; Path=/\nServer: nginx"}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)

    @staticmethod
    def _form(found_at="https://t.example.test/account", action="/save", method="post", inputs=None):
        return {"found_at": found_at, "action": action, "method": method,
                "enctype": "application/x-www-form-urlencoded",
                "inputs": inputs if inputs is not None else [
                    {"name": "__VIEWSTATE", "type": "hidden", "value": "/wEPDwUKLTE5ODk="},
                    {"name": "data", "type": "hidden",
                     "value": '{"@class":"com.example.Widget","name":"x"}'},
                    {"name": "q", "type": "text", "value": "plain"}]}

    def test_hidden_form_fields_are_scanned(self):
        # Live E2E finding: the crawler keeps forms with their field values, and the
        # by_base_url endpoints keep none, so forms were a blind spot.
        cr = {"resource_enum": {"forms": [self._form()]}}
        found = {(f["deser_format"], f["deser_location"]): f
                 for f in run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
                 ["serialized_scan"]["findings"]}
        self.assertIn(("viewstate", "__VIEWSTATE"), found)
        self.assertIn(("jackson_json", "data"), found)
        f = found[("jackson_json", "data")]
        self.assertEqual(f["endpoint_url"], "https://t.example.test/save")   # action, resolved
        self.assertEqual(f["http_method"], "POST")
        self.assertEqual(f["deser_transport"], "param")                      # the declared vocabulary
        self.assertEqual((f["baseurl"], f["path"]), ("https://t.example.test", "/save"))
        self.assertNotIn("q", {loc for _, loc in found})                      # plain field: no hit

    def test_form_action_resolves_against_the_page_it_was_found_on(self):
        cases = [("https://t.example.test/a/b/page", "next", "https://t.example.test/a/b/next"),
                 ("https://t.example.test/a/page", "", "https://t.example.test/a/page"),
                 ("https://t.example.test/x", "https://u.example.test/y", "https://u.example.test/y")]
        for found_at, action, expected in cases:
            with self.subTest(action=action):
                cr = {"resource_enum": {"forms": [self._form(found_at=found_at, action=action)]}}
                urls = {f["endpoint_url"] for f in run_serialized_scan(
                    cr, {"SERIALIZED_SCAN_ENABLED": True})["serialized_scan"]["findings"]}
                self.assertEqual(urls, {expected})

    def test_a_field_named_like_a_sink_flags_even_when_empty(self):
        cr = {"resource_enum": {"forms": [self._form(inputs=[
            {"name": "__VIEWSTATE", "type": "hidden", "value": ""}])]}}
        fmts = {f["deser_format"] for f in run_serialized_scan(
            cr, {"SERIALIZED_SCAN_ENABLED": True})["serialized_scan"]["findings"]}
        self.assertEqual(fmts, {"viewstate"})

    def test_the_same_form_on_two_pages_is_one_candidate_per_field(self):
        cr = {"resource_enum": {"forms": [
            self._form(found_at="https://t.example.test/one"),
            self._form(found_at="https://t.example.test/two")]}}
        findings = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})["serialized_scan"]["findings"]
        keys = [normalizers.dedup_key(f) for f in findings]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(sum(1 for f in findings if f["deser_location"] == "data"), 1)

    def test_forms_respect_the_roe_exclusions(self):
        cr = {"resource_enum": {"forms": [self._form()]}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True, "ROE_ENABLED": True,
                                       "ROE_EXCLUDED_HOSTS": ["t.example.test"]})
        self.assertEqual(out["serialized_scan"]["findings"], [])

    def test_malformed_forms_never_raise(self):
        for forms in ["not-a-list", {"a": 1}, [None, "x", 3],
                      [{"found_at": 5, "action": None, "inputs": "nope"}],
                      [{"found_at": "relative/only", "action": "", "inputs": []}],
                      [self._form(inputs=[None, "x", {"name": 7}, {"name": "", "value": "rO0ABXNy"},
                                          {"name": "v", "value": ["rO0AB"]}])]]:
            with self.subTest(forms=str(forms)[:40]):
                out = run_serialized_scan({"resource_enum": {"forms": forms}},
                                          {"SERIALIZED_SCAN_ENABLED": True})
                self.assertEqual(out["serialized_scan"]["findings"], [])

    def test_candidate_shape(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        for f in out["serialized_scan"]["findings"]:
            self.assertEqual(f["source"], "serialized_scan")
            self.assertEqual(f["vulnerability_type"], "insecure_deserialization")
            self.assertIs(f["needs_agent_confirmation"], True)
            self.assertEqual(f["severity"], "info")
            self.assertTrue(f["endpoint_url"])
            self.assertIn("deser_language", f)
            self.assertIsInstance(f["deser_encoding_layers"], list)
            # evidence must be flat, printable, bounded
            self.assertLessEqual(len(f["evidence_snippet"]), 120)
            self.assertTrue(all(32 <= ord(c) < 127 for c in f["evidence_snippet"]))

    def test_dedup(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        keys = [normalizers.dedup_key(f) for f in out["serialized_scan"]["findings"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_roe_excludes_host(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {
            "SERIALIZED_SCAN_ENABLED": True,
            "ROE_ENABLED": True,
            "ROE_EXCLUDED_HOSTS": ["t.example.com"],
        })
        self.assertEqual(out["serialized_scan"]["findings"], [])

    def test_no_findings_on_benign_corpus(self):
        cr = {
            "http_probe": {"by_url": {"https://x/": {
                "url": "https://x/", "content_type": "text/html",
                "headers": {"server": "nginx"}}}},
            "resource_enum": {"by_base_url": {"https://x": {"endpoints": {
                "/": {"method": "GET", "parameters": {"q": {"value": "search"}}}}}}},
        }
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        self.assertEqual(out["serialized_scan"]["findings"], [])
        self.assertEqual(out["serialized_scan"]["summary"]["total_findings"], 0)

    def test_never_raises_on_malformed_corpus(self):
        for bad in ({"http_probe": "nope"}, {"resource_enum": 5},
                    {"http_probe": {"by_url": {"u": "notadict"}}}, {}):
            with self.subTest(bad=bad):
                out = run_serialized_scan(dict(bad), {"SERIALIZED_SCAN_ENABLED": True})
                self.assertIn("serialized_scan", out)
                self.assertIn("findings", out["serialized_scan"])

    def test_isolated_wrapper_does_not_mutate(self):
        cr = _corpus()
        snapshot = copy.deepcopy(cr)
        payload = run_serialized_scan_isolated(cr, {"SERIALIZED_SCAN_ENABLED": True})
        self.assertEqual(cr, snapshot)              # input untouched
        self.assertIn("findings", payload)
        self.assertNotIn("serialized_scan", cr)     # not written back onto input

    def test_one_value_is_one_candidate_per_format(self):
        # Live E2E finding: base64 Java matched as `rO0AB` text AND as the decoded
        # AC ED 00 05 bytes, so one param became two candidates, and confirming one
        # left its twin pending. The byte signature wins, with the layers peeled to
        # reach it. Each blob is 27 bytes, so its base64 needs no padding, with
        # varied bytes: the decoder skips a low-entropy base64 run.
        java = b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayList"
        cases = [
            (base64.b64encode(java).decode(), "native_java", "AC ED 00 05 (Java stream)", ["base64"]),
            (java.hex(), "native_java", "AC ED 00 05 (Java stream)", ["hex"]),
            (base64.b64encode(gzip.compress(java)).decode(), "native_java",
             "AC ED 00 05 (Java stream)", ["base64", "gzip"]),
            (base64.b64encode(b"\x80\x04\x95" + bytes(range(65, 89))).decode(), "python_pickle",
             "80 04 (pickle proto 4)", ["base64"]),
            (base64.b64encode(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff" + bytes(range(97, 115))).decode(),
             "dotnet_binaryformatter", "00 01 00 00 00 FF FF FF FF (BinaryFormatter)", ["base64"]),
        ]
        for value, fmt, magic, layers in cases:
            with self.subTest(fmt=fmt, magic=magic):
                cr = {"resource_enum": {"by_base_url": {"https://t.example.test": {"endpoints": {
                    "/load": {"methods": ["GET"], "parameters": {
                        "query": [{"name": "data", "sample_values": [value]}]}}}}}}}
                findings = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})[
                    "serialized_scan"]["findings"]
                self.assertEqual([(f["deser_format"], f["deser_magic"], f["deser_encoding_layers"])
                                  for f in findings], [(fmt, magic, layers)])

    @staticmethod
    def _probe(headers, content_type="text/html"):
        return {"http_probe": {"by_url": {"https://t.example.test/": {
            "url": "https://t.example.test/", "content_type": content_type, "headers": headers}}}}

    @staticmethod
    def _seen(cr):
        return [(f["deser_format"], f["deser_transport"], f["deser_location"], f["deser_encoding_layers"])
                for f in run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})["serialized_scan"]["findings"]]

    JAVA_B64 = base64.b64encode(b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayList").decode()

    def test_a_cookie_candidate_sits_at_its_name_with_the_layers_its_value_needs(self):
        # The cookie's own name is what the agent tampers with, not the Set-Cookie
        # header that carried it; the whole header decodes to nothing, the value does.
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}; Path=/; HttpOnly"})
        self.assertEqual(self._seen(cr), [("native_java", "cookie", "sess", ["base64"])])

    def test_every_cookie_a_header_sets_is_scanned_and_attributes_are_not_cookies(self):
        b64 = self.JAVA_B64
        as_list = self._probe({"set_cookie": [f"sess={b64}; Path=/",
                                              f"prefs={b64}; Expires=Wed, 21 Oct 2026 07:28:00 GMT"]})
        as_string = self._probe(f"Set-Cookie: sess={b64}; Path=/\nSet-Cookie: prefs={b64}; HttpOnly")
        for cr in (as_list, as_string):
            with self.subTest(shape=type(cr["http_probe"]["by_url"]["https://t.example.test/"]["headers"])):
                self.assertEqual([loc for _, _, loc, _ in self._seen(cr)], ["sess", "prefs"])

    def test_an_unrelated_escape_elsewhere_in_a_header_never_decides_the_layers(self):
        # A %2F in another query param url-decodes the whole header; the blob in
        # `state=` is base64, and that is what the agent must re-apply.
        cr = self._probe({"location": f"https://t.example.test/cb?next=%2Fhome&state={self.JAVA_B64}"})
        self.assertEqual(self._seen(cr), [("native_java", "header", "location", ["base64"])])

    def test_one_header_spelled_three_ways_is_one_candidate(self):
        # The probe's content_type field and httpx's content_type header are the
        # same Content-Type: two spellings made two candidates.
        ct = "application/x-java-serialized-object"
        self.assertEqual(self._seen(self._probe({"content_type": ct}, content_type=ct)),
                         [("native_java", "header", "content-type", [])])

    def test_two_samples_of_one_sink_are_one_candidate(self):
        # The matched marker is evidence, not identity: base64 and gzip Java, or a
        # PHP object and a PHP array, at one parameter are one sink each.
        java = b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayList"
        cases = {"java": [base64.b64encode(java).decode(), base64.b64encode(gzip.compress(java)).decode()],
                 "php": ['O:4:"User":1:{s:1:"a";i:1;}', 'a:1:{i:0;s:1:"b";}']}
        for name, samples in cases.items():
            with self.subTest(name):
                cr = {"resource_enum": {"by_base_url": {"https://t.example.test": {"endpoints": {"/load": {
                    "methods": ["GET"], "parameters": {"query": [{"name": "data", "sample_values": samples}]}}}}}}}
                self.assertEqual([loc for _, _, loc, _ in self._seen(cr)], ["data"])

    def test_a_marker_readable_as_is_records_no_layers(self):
        # The %2F url-decodes the whole header, but the JSON needs no decoding: the
        # layers are the ones peeled to reach the hit, not the value's whole chain.
        cr = self._probe({"location": 'x=%2Fhome&y={"@class":"a.B"}'})
        self.assertEqual(self._seen(cr), [("jackson_json", "header", "location", [])])

    def test_the_viewstate_neighbours_are_not_viewstates(self):
        # __VIEWSTATEGENERATOR and __VIEWSTATEENCRYPTED ride beside every ViewState.
        cr = {"resource_enum": {"forms": [self._form(inputs=[
            {"name": "__VIEWSTATE", "value": ""}, {"name": "__VIEWSTATEGENERATOR", "value": "CA0B0334"},
            {"name": "__VIEWSTATEENCRYPTED", "value": ""}])]}}
        self.assertEqual(self._seen(cr), [("viewstate", "param", "__VIEWSTATE", [])])

    def test_a_pickle_prefix_counts_only_at_the_start_of_a_base64_run(self):
        # Inside a long random run (a ViewState) "gAJ" + one char turns up by chance.
        noise = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(3000))).decode()
        inside = noise[:500] + "gAJx" + noise[504:]
        at_start = base64.b64encode(b"\x80\x02}q\x00(X\x01").decode()
        for value, fmts in ((inside, []), (at_start, ["python_pickle"])):
            with self.subTest(at_start=value is at_start):
                cr = {"resource_enum": {"forms": [self._form(inputs=[{"name": "blob", "value": value}])]}}
                self.assertEqual([f for f, *_ in self._seen(cr)], fmts)

    def test_a_malformed_form_action_costs_that_form_only(self):
        # urljoin/urlparse raise on a bad IPv6 host; it used to empty the whole
        # result, and print the host (which read as a port scan to the drawer).
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
        cr["resource_enum"] = {"forms": [self._form(action="https://[port-scan]/x")]}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            seen = self._seen(cr)
        self.assertEqual(seen, [("native_java", "cookie", "sess", ["base64"])])
        self.assertNotIn("port-scan", out.getvalue())

    def test_regression_an_error_keeps_every_earlier_candidate_out_of_the_prune(self):
        # R-23: the empty result alone read as "every candidate is gone", and the
        # prune deleted them, including ones an agent was about to confirm. The
        # failed parts said nothing about any host, so the whole source is kept.
        from recon.helpers import circuit_breaker as cb
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
        out = io.StringIO()
        with mock.patch("recon.serialized_scan.scanner._scan_forms",
                        side_effect=RuntimeError("https://portal-scan.example.test")), \
                contextlib.redirect_stdout(out):
            result = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        self.assertEqual(result["serialized_scan"]["findings"], [])
        self.assertIn("RuntimeError", out.getvalue())
        self.assertNotIn("example.test", out.getvalue())
        report = cb.coverage_report()
        self.assertEqual(report.degraded_sources, frozenset({"serialized_scan"}))
        gap, = report.gaps
        self.assertRegex(gap["source"], r"^[a-z0-9_]{1,64}$")
        self.assertEqual((gap["source"], gap["module"]), ("serialized_scan", "serialized_scan"))
        self.assertIn("RuntimeError", gap["reason"])
        self.assertNotIn("example.test", gap["reason"])

    def test_a_failed_input_phase_keeps_the_candidates_and_still_scans(self):
        # resource_enum's endpoints and forms, and http_probe's headers, are the
        # corpus: a phase that raised gave none, so its candidates were never re-read.
        from recon.helpers import circuit_breaker as cb
        for phase in ("resource_enum", "http_probe"):
            with self.subTest(phase=phase):
                cb.reset_registry()
                cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
                cr["metadata"] = {"phase_errors": {phase: "boom"}}
                self.assertEqual(len(self._seen(cr)), 1)
                report = cb.coverage_report()
                self.assertIn("serialized_scan", report.degraded_sources)
                self.assertIn(phase, report.gaps[0]["reason"])

    def test_a_clean_scan_and_an_unrelated_phase_error_note_nothing(self):
        from recon.helpers import circuit_breaker as cb
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
        cr["metadata"] = {"phase_errors": {"nmap": "boom"}}
        self.assertEqual(len(self._seen(cr)), 1)
        self.assertFalse(cb.coverage_report().degraded)

    def test_switched_off_it_notes_nothing(self):
        from recon.helpers import circuit_breaker as cb
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
        cr["metadata"] = {"phase_errors": {"resource_enum": "boom"}}
        run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": False})
        self.assertNotIn("serialized_scan", cr)
        self.assertFalse(cb.coverage_report().degraded)

    def test_a_failing_jev_pass_never_costs_the_candidates(self):
        cr = self._probe({"set_cookie": f"sess={self.JAVA_B64}"})
        with mock.patch("recon.helpers.ai_planner.serialized_assess.run_for_scan",
                        side_effect=RuntimeError("wiring")):
            self.assertEqual(len(self._seen(cr)), 1)

    def test_two_formats_in_one_value_stay_two_candidates(self):
        cr = {"resource_enum": {"forms": [self._form(inputs=[
            {"name": "data", "type": "hidden", "value": '{"@class":"a.B","x":{"@type":"c.D"}}'}])]}}
        fmts = sorted(f["deser_format"] for f in run_serialized_scan(
            cr, {"SERIALIZED_SCAN_ENABLED": True})["serialized_scan"]["findings"])
        self.assertEqual(fmts, ["fastjson", "jackson_json"])

    def test_layered_cookie_is_decoded(self):
        inner = b"\xac\xed\x00\x05" + b"Z" * 30
        blob = base64.b64encode(gzip.compress(inner)).decode()
        cr = {"http_probe": {"by_url": {"https://t/": {
            "url": "https://t/", "content_type": "text/html",
            "headers": {"set_cookie": f"s={blob}"}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)
        f = next(f for f in out["serialized_scan"]["findings"]
                 if f["deser_format"] == "native_java")
        self.assertIn("gzip", f["deser_encoding_layers"])


class TestSnippetSafety(unittest.TestCase):
    def test_non_printable_is_hex_escaped(self):
        s = normalizers.safe_snippet(_latin1(b"\xac\xed\x00\x05\x80abc"))
        self.assertTrue(all(32 <= ord(c) < 127 for c in s))
        self.assertIn("\\xac", s)

    def test_length_bounded(self):
        s = normalizers.safe_snippet("A" * 500)
        self.assertLessEqual(len(s), 120)

    def test_backslash_escaped(self):
        self.assertEqual(normalizers.safe_snippet("a\\b"), "a\\\\b")


if __name__ == "__main__":
    unittest.main()
