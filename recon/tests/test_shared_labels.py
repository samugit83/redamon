"""Item 4b-4f: every address gets the same labels, whatever module found it.

4b/B21/B22 the shared rules; 4c GAU and ParamSpider types; 4d OpenAPI
categories and types; 4e ffuf and JS Recon keep their own words in a second
property, readers unchanged; 4f labels from page titles. Hosts are example.test.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.resource_enum import classification as c  # noqa: E402


class TestSharedRules:
    @pytest.mark.parametrize("path", ["/oidc/callback", "/saml/acs", "/openid/x", "/oidc/authorize",
                                      "/saml/login", "/connect/authorize", "/connect/token"])
    def test_login_flows_are_authentication(self, path):
        assert c.classify_endpoint(path, ["GET"], {}) == "authentication"

    @pytest.mark.parametrize("path", ["/.well-known/openid-configuration", "/saml/metadata"])
    def test_public_metadata_documents_are_not(self, path):
        assert c.classify_endpoint(path, ["GET"], {}) != "authentication"

    def test_attach_is_file_access(self):
        assert c.classify_endpoint("/attach/1", ["GET"], {}) == "file_access"

    @pytest.mark.parametrize("name", ["redirect_uri", "redirect_url", "uri", "forward", "forwarded"])
    def test_redirect_names(self, name):
        assert c.classify_parameter(name) == "redirect_params"

    @pytest.mark.parametrize("name", ["to", "tomato", "total"])
    def test_not_redirect_names(self, name):
        assert c.classify_parameter(name) != "redirect_params"

    @pytest.mark.parametrize("value", ["http%3A%2F%2Fa.b", "//a.b/x", "https://a.b/c@d",
                                       "https://a.b/x.html", "http%253A%252F%252Fa.b"])
    def test_b21_url_values_first_and_encoded(self, value):
        assert c.infer_parameter_type("window", [value]) == "url"

    @pytest.mark.parametrize("value,kind", [("5", "integer"), ("about", "string"), ("a@b.c", "email")])
    def test_other_values_keep_their_type(self, value, kind):
        assert c.infer_parameter_type("x", [value]) == kind

    @pytest.mark.parametrize("name,kind", [("video", "string"), ("valid", "string"),
                                           ("next_page_url", "url"), ("videoId", "integer"),
                                           ("page", "integer")])
    def test_b22_whole_word_names(self, name, kind):
        assert c.infer_parameter_type(name, []) == kind

    def test_b22_every_value_counts(self):
        from unittest.mock import patch
        from recon.helpers.resource_enum import endpoint_helpers as eh
        urls = ["https://a.example.test/p?x=5", "https://a.example.test/p?x=https://b.example.test/"]
        with patch.object(eh, "fetch_forms_from_urls", return_value=[]):
            out = eh.organize_endpoints(urls)
        flat = str(out)
        assert "'type': 'url'" in flat


class TestArchiveTypes:
    def test_gau_infers_from_values_never_stores_them(self):
        from recon.helpers.resource_enum.gau_helpers import merge_gau_into_by_base_url
        url = "https://a.example.test/go?next=https://b.example.test/&id=5"
        by_base, _ = merge_gau_into_by_base_url([url], {}, None)
        q = {p["name"]: p for p in by_base["https://a.example.test"]["endpoints"]["/go"]["parameters"]["query"]}
        assert (q["next"]["type"], q["id"]["type"]) == ("url", "integer")
        assert "sample_values" not in q["next"]

    def test_gau_upgrades_a_plain_string(self):
        from recon.helpers.resource_enum.gau_helpers import merge_gau_into_by_base_url
        existing = {"https://a.example.test": {"endpoints": {"/go": {
            "methods": ["GET"], "sources": ["katana"],
            "parameters": {"query": [{"name": "next", "type": "string"}], "body": [], "path": []}}},
            "summary": {"total_endpoints": 1, "total_parameters": 1, "methods": {}, "categories": {}}}}
        by_base, _ = merge_gau_into_by_base_url(["https://a.example.test/go?next=https://b.example.test/"],
                                                existing, None)
        assert by_base["https://a.example.test"]["endpoints"]["/go"]["parameters"]["query"][0]["type"] == "url"

    def test_paramspider_gets_the_name_based_guess(self):
        from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url
        by_base, _ = merge_paramspider_into_by_base_url(["https://a.example.test/go?next=FUZZ&page=FUZZ"], {})
        q = {p["name"]: p for p in by_base["https://a.example.test"]["endpoints"]["/go"]["parameters"]["query"]}
        assert (q["next"]["type"], q["page"]["type"]) == ("string", "integer")


class TestOpenApiLabels:
    def test_category_and_shared_types(self):
        from recon.helpers.resource_enum import openapi_helpers as oh
        assert oh._parameter("redirect_uri", {"schema": {"type": "string"}}, False)["category"] == "redirect_params"
        assert oh._kind({"type": "number"}) == "integer"
        assert oh._kind({"type": "string", "format": "uri"}) == "url"
        assert oh._kind({"type": "string", "format": "date-time"}) == "datetime"
        assert oh._kind({"type": "array"}) == "string"
        assert oh._kind({"type": ["null", "boolean"]}) == "boolean"


class TestOwnWordsMoveAside:
    def test_ffuf_keeps_its_label_in_ffuf_category(self):
        from recon.helpers.resource_enum.ffuf_helpers import merge_ffuf_into_by_base_url
        by_base, _ = merge_ffuf_into_by_base_url(
            [{"url": "https://a.example.test/admin", "status": 403, "content_type": "text/html"}], {})
        ep = by_base["https://a.example.test"]["endpoints"]["/admin"]
        assert (ep["category"], ep["ffuf_category"]) == ("admin", "forbidden")

    def test_an_ffuf_403_still_reaches_route_exposure_as_a_403(self):
        from recon.route_exposure import harvest as h
        combined = {"resource_enum": {"by_base_url": {"https://a.example.test": {"endpoints": {
            "/secret": {"methods": ["GET"], "category": "other", "ffuf_category": "forbidden",
                        "sources": ["ffuf"]}}}}}}
        route = h.harvest(combined).routes[("https://a.example.test", "/secret", "GET")]
        assert route.discovery_status == 403

    def test_js_recon_admin_debug_still_ranks_like_admin(self):
        from recon.route_exposure import harvest as h
        combined = {"js_recon": {"endpoints": [{"type": "rest", "path": "/debug/vars", "method": "GET",
                                                 "category": "other", "js_recon_category": "admin_debug",
                                                 "resolved_url": "https://a.example.test/debug/vars",
                                                 "source_js": "https://a.example.test/app.js"}]},
                    "http_probe": {"by_url": {"https://a.example.test/": {"status_code": 200}}}}
        routes = [r for r in h.harvest(combined).routes.values() if r.path == "/debug/vars"]
        assert routes and routes[0].category == "admin_debug"

    def test_js_recon_endpoints_get_the_shared_word(self):
        from recon.helpers.js_recon.endpoints import extract_endpoints
        eps = extract_endpoints([{"url": "https://a.example.test/app.js",
                                  "content": 'fetch("/admin/debug/stats"); fetch("/api/v2/users")'}], {})
        shared = {"authentication", "admin", "api", "upload", "file_access", "search", "dynamic",
                  "static", "other"}
        assert eps and all(e["category"] in shared for e in eps)
        assert all("js_recon_category" in e for e in eps)


class TestTitles:
    def test_title_rules(self):
        assert c.endpoint_category("/", ["GET"], {}, "Sign in") == "authentication"
        assert c.endpoint_category("/admin/x", ["GET"], {}, "Grafana") == "admin"
        assert c.endpoint_category("/app", ["GET"], {}, "Grafana") == "admin"
        assert c.endpoint_category("/blog/post", ["GET"], {}, "Blog login tips") == "authentication"
        assert c.endpoint_category("/", ["GET"], {}, "Login - Adminer") == "authentication"
        assert c.endpoint_category("/", ["GET"], {}, "Welcome") == "other"
        assert c.is_api_doc_title("Swagger UI") and c.is_api_doc_title("ReDoc")
        assert not c.is_api_doc_title("Swagger UI tips and tricks")

    def test_a_path_rule_always_wins(self):
        assert c.endpoint_category("/api/v1/items", ["GET"], {}, "Sign in") == "api"
