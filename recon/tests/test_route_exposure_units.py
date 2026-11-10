"""Route exposure scan: the pure stages, one rule per test (plan §15)."""

from __future__ import annotations

import json
import zlib
import threading
import warnings
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.route_exposure import (
    catalogs, generators, gitwalk, harvest, normalizers, prober, ranking, riders, scanner,
    seeds, signals, signatures, verdict,
)
from recon.route_exposure.harvest import Corpus, Route

BASE = "http://10.0.0.5"


def zlib_compress(data: bytes) -> bytes:
    return zlib.compress(data)


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()


# ---------------------------------------------------------------------------
# Harvest
# ---------------------------------------------------------------------------

def _combined(endpoints=None, js=None, by_url=None):
    return {"http_probe": {"by_url": by_url if by_url is not None else
                           {BASE: {"url": BASE, "status_code": 200, "technologies": ["Nginx"]}}},
            "resource_enum": {"by_base_url": {BASE: {"endpoints": endpoints or {}}}},
            "js_recon": {"endpoints": js or []}}


def test_harvest_reads_methods_list_and_singular_method():
    c = harvest.harvest(_combined({"/a": {"methods": ["GET"]}, "/b": {"method": "get"},
                                   "/c": {"methods": "HEAD"}, "/d": {}}))
    assert {r.path for r in c.routes.values()} == {"/a", "/b", "/c", "/d"}


@pytest.mark.parametrize("path,reason", [
    ("/users/{id}", "template"), ("/users/:id", "template"), ("/a/*", "template"),
    ("/app.css", "static"), ("/bundle.js", "static"), ("/logo.png", "static"),
    ("/login", "auth"), ("/oauth/token", "auth"), ("/api/forgot-password", "auth"),
    ("/logout", "state_changing"), ("/orders/1/cancel", "state_changing"),
    ("/api/deleteUser", "state_changing"), ("/log-out", "state_changing"),
    ("relative", "template"), ("/" + "a" * 3000, "template"),
])
def test_unsafe_paths_are_never_kept(path, reason):
    assert harvest.unsafe_reason(path) == reason
    c = harvest.harvest(_combined({path: {"methods": ["GET"]}}))
    assert not c.routes and c.unsafe == 1


@pytest.mark.parametrize("path", ["/api/sendgrid/status", "/api/payload", "/api/killers",
                                  "/internal/users/export", "/api/users/me"])
def test_whole_tokens_only_for_state_changing(path):
    assert harvest.unsafe_reason(path) == ""


def test_non_get_only_route_is_skipped_and_counted():
    c = harvest.harvest(_combined({"/api/x": {"methods": ["DELETE", "POST"]},
                                   "/api/y": {"methods": ["POST", "GET"]}}))
    assert set(p for (_b, p, _m) in c.routes) == {"/api/y"} and c.unsafe == 1


def test_openapi_metadata_and_discovery_status_are_kept():
    c = harvest.harvest(_combined({
        "/api/r": {"methods": ["GET"], "declared_only": True, "status_code": 401,
                   "openapi": {"GET": {"security": ["bearer"], "tags": ["internal", 5]}}},
        "/api/s": {"methods": ["GET"], "category": "forbidden"},
        "/api/t": {"methods": ["GET"], "openapi": {"GET": {"security": []}}},
    }))
    r = c.routes[(BASE, "/api/r", "GET")]
    assert r.openapi_security == ["bearer"] and r.openapi_tags == ("internal",)
    assert r.declared_only and r.discovery_status == 401
    assert c.routes[(BASE, "/api/s", "GET")].discovery_status == 403
    assert c.routes[(BASE, "/api/t", "GET")].openapi_security == []
    assert c.api_prefixes[BASE] == {"/api"}


def test_js_routes_resolve_merge_and_mark_js_only():
    js = [{"type": "rest", "method": "GET", "path": "/internal/x", "source_js": BASE + "/a.js"},
          {"type": "rest", "method": "GET", "full_url": BASE + "/api/v2/y"},
          {"type": "rest", "method": "GET", "path": "/api/both", "source_js": BASE + "/a.js"},
          {"type": "rest", "method": "POST", "path": "/api/post", "source_js": BASE + "/a.js"},
          {"type": "rest", "method": "GET", "path": "/api/t/", "parameterized": True, "source_js": BASE + "/a.js"},
          {"type": "websocket", "path": "wss://x/ws"},
          {"type": "route", "method": "GET", "path": "/admin/dashboard", "source_js": BASE + "/a.js"},
          {"type": "rest", "method": "GET", "path": "//cdn.example/x", "source_js": "https://h/a.js"},
          {"type": "rest", "method": "GET", "path": "/no-source"},
          "garbage"]
    c = harvest.harvest(_combined({"/api/both": {"methods": ["GET"], "sources": ["katana"]}}, js))
    paths = {p: r for (_b, p, _m), r in c.routes.items()}
    assert set(paths) == {"/internal/x", "/api/v2/y", "/api/both", "/x"}
    assert paths["/internal/x"].js_only and not paths["/api/both"].js_only
    assert paths["/api/both"].sources == ("katana", "js_recon")
    routed = harvest.harvest(_combined(js=js), routers=True)
    assert routed.routes[(BASE, "/admin/dashboard", "GET")].router


def test_parked_base_is_skipped_entirely():
    by_url = {BASE: {"url": BASE, "page_class": "parked"}, "http://10.0.0.6/": {"url": "http://10.0.0.6/"}}
    c = harvest.harvest({"http_probe": {"by_url": by_url},
                         "resource_enum": {"by_base_url": {BASE: {"endpoints": {"/a": {}}}}}})
    assert c.bases == ["http://10.0.0.6"] and not c.routes


def test_harvest_tolerates_garbage():
    c = harvest.harvest({"http_probe": {"by_url": {"x": "y", "ftp://h": {}}},
                         "resource_enum": {"by_base_url": {"nope": {}, BASE: {"endpoints": {"/a": "x", 3: {}}}}},
                         "js_recon": {"endpoints": "x"}})
    assert not c.routes and c.bases == [BASE]


def test_base_of_and_extension_helpers():
    assert harvest.base_of("https://h:8443/x?y") == "https://h:8443"
    assert harvest.base_of("ftp://h/") == "" and harvest.base_of("http://[bad") == ""
    assert harvest.has_extension("/a/b.PHP") == ".php" and harvest.has_extension("/a/.git/") == ""
    assert Route(BASE, "/x").url == BASE + "/x"


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _corpus(*paths, base=BASE):
    c = Corpus(bases=[base])
    for p in paths:
        c.add(Route(base, p))
    return c


def test_seed_generator_caps_per_host_and_uses_api_prefixes():
    c = _corpus("/api/v1/users")
    c.api_prefixes[BASE] = {"/api/v1"}
    made = generators.generate(c, {"seed_paths": True})
    assert len(made) == seeds.CAP_SEED and all(r.generated_by == "seed" for r in made)
    paths = [r.path for r in made]
    assert paths[0] == "/internal" and "/api/admin/export" in paths and "/console" in paths
    assert "/api/v1/admin" in paths
    seq = generators.seed_paths({"/api"})
    assert seq.index("/api/internal") < seq.index("/api/admin")  # both exist, head first


def test_vcs_generator_covers_root_and_top_directories():
    c = _corpus("/app/index.php", "/app/x.php", "/static/a/b", "/shop/cart")
    made = generators.generate(c, {"vcs_files": True})
    paths = [r.path for r in made]
    assert len(paths) == seeds.CAP_VCS
    assert "/.git/HEAD" in paths and "/app/.git/HEAD" in paths and "/shop/.env" in paths
    assert not any(p.startswith("/static/") for p in paths)


def test_backup_generator_variants_and_root_archives():
    c = _corpus("/config.php", "/index.html", "/x/settings.yml")
    made = generators.generate(c, {"backup_files": True})
    by_path = {r.path: r for r in made}
    assert {"/config.php.bak", "/config.php~", "/.config.php.swp", "/x/.settings.yml.swp",
            "/backup.zip", "/db.sql"} <= set(by_path)
    assert not any(p.startswith("/index.html") for p in by_path)
    assert by_path["/config.php.bak"].variant_of == "/config.php"
    assert by_path["/backup.zip"].variant_of == "" and by_path["/backup.zip"].request == "backup"


def test_backup_generator_cap():
    c = _corpus(*[f"/f{i}.php" for i in range(20)])
    made = generators.generate(c, {"backup_files": True})
    assert len(made) == seeds.CAP_BACKUP


@pytest.mark.parametrize("path,expected", [
    ("/api/v2/orders/42", ["/api/v1/orders/42", "/api/orders/42"]),
    ("/api/v3/x", ["/api/v2/x", "/api/v1/x", "/api/x"]),
    ("/v10/a", ["/v9/a", "/v8/a", "/v7/a"]),
    ("/api/v1/x", ["/api/x"]),
    ("/api/x", []),
])
def test_version_variants(path, expected):
    assert generators.version_variants(path) == expected


def test_version_generator_records_its_source_and_skips_known_routes():
    c = _corpus("/api/v2/orders/42", "/api/orders/42")
    made = generators.generate(c, {"version_variants": True})
    assert [(r.path, r.variant_of) for r in made] == [("/api/v1/orders/42", "/api/v2/orders/42")]


def test_generators_off_generate_nothing():
    assert generators.generate(_corpus("/api/v2/x", "/a.php"), {}) == []


@pytest.mark.parametrize("path,present,absent", [
    ("/api/orders/42", {"/api/orders", "/api/orders/export", "/api/admin/orders/42",
                        "/internal/api/orders/42"}, {"/api/orders/42"}),
    ("/api/orders", {"/api/orders/export", "/api/orders/all", "/api/orders/list",
                     "/api/admin/orders", "/internal/api/orders"}, {"/api/orders"}),
])
def test_siblings(path, present, absent):
    out = set(generators.siblings(path))
    assert present <= out and out.isdisjoint(absent)


def test_sibling_generator_caps_per_route_and_marks_its_source():
    c = _corpus("/api/orders/42")
    made = generators.generate(c, {"siblings": True})
    assert made and all(r.generated_by == "sibling" and r.variant_of == "/api/orders/42" for r in made)
    assert len(made) <= seeds.CAP_SIBLING_PER_ROUTE
    assert "/api/orders" in [r.path for r in made]


def test_siblings_skip_a_non_api_route():
    assert generators.generate(_corpus("/blog/post/hello"), {"siblings": True}) == []


@pytest.mark.parametrize("techs,present,head_only", [
    (["Spring Boot"], "/actuator/env", "/actuator/heapdump"),
    (["PHP 8.1"], "/phpinfo.php", None),
    (["ASP.NET"], "/elmah.axd", None),
])
def test_framework_paths_match_technology_tokens(techs, present, head_only):
    pairs = dict(generators.framework_paths(techs))
    assert present in pairs
    if head_only:
        assert pairs[head_only] is True
    assert generators.framework_paths(["nginx"]) == []


def test_framework_generator_uses_host_technologies_and_head_only_heapdump():
    c = _corpus("/")
    c.technologies[BASE] = {"Spring Boot"}
    made = generators.generate(c, {"framework_seeds": True})
    by_path = {r.path: r for r in made}
    assert "/actuator/env" in by_path and all(r.generated_by == "framework" for r in made)
    assert by_path["/actuator/heapdump"].request == "head"
    assert len(made) <= seeds.CAP_FRAMEWORK


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def test_score_weights_and_hints():
    r = Route("http://admin.example.com", "/internal/export", openapi_security=["k"],
              openapi_tags=("Admin",), declared_only=True, discovery_status=403, category="admin",
              js_only=True)
    assert ranking.score(r) == 5 + 3 + 2 + 3 + 3 + 2 + 1 + 1
    assert r.hints == ["openapi", "openapi_tag", "declared_only", "seen_denied", "path_word", "host_word"]
    assert r.floor
    assert ranking.score(Route(BASE, "/.git/HEAD", generated_by="vcs")) == 5
    v = Route(BASE, "/api/x", generated_by="version")
    assert ranking.score(v) == 2 and not v.floor
    assert ranking.score(Route(BASE, "/api/x", generated_by="sibling")) == 1
    vcs = Route(BASE, "/x", generated_by="vcs")
    ranking.score(vcs)
    assert vcs.floor


def test_budget_floor_first_per_host_cap_and_round_robin():
    routes = [Route("http://b.example", f"/p{i}") for i in range(5)]
    routes += [Route("http://10.0.0.1", f"/q{i}") for i in range(5)]
    routes.append(Route("http://10.0.0.1", "/internal/admin", openapi_security=["k"]))
    chosen, cut = ranking.select(routes, per_host=3, total=4)
    assert cut == len(routes) - 4
    assert chosen[0].path == "/internal/admin"          # the floor, first
    hosts = [ranking._host(r.baseurl) for r in chosen[1:]]
    assert hosts == ["b.example", "10.0.0.1", "b.example"]  # hostnames before IPs
    assert ranking._is_ip("10.0.0.1") and not ranking._is_ip("x")
    assert ranking._host("http://[bad") == ""


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

def _analyse(obj, **kw):
    body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return signals.analyse(body, content_class=kw.pop("cc", "json"), **kw)


def test_mask_text():
    assert signals.mask_text("mail a@b.co id 12345678 tok abcdefghijklmnopqrstuvwxyz") == \
        "mail <email> id <n> tok <tok>"


def test_pii_types_counts_and_others():
    rows = [{"email": f"u{i}@lab.invalid", "phone": f"+39 06 555 01{i:02d}", "dob": "1990-01-01",
             "ssn": "123-45-6789", "iban": "GB82WEST12345698765432", "card": "4111111111111111",
             "cf": "RSSMRA85T10A562S"} for i in range(4)]
    s = _analyse(rows)
    assert s.pii_types == ["email", "phone", "card", "iban", "ssn", "codice_fiscale", "dob"]
    assert s.pii_record_estimate == 4 and s.pii_others
    assert "pii" in s.leak_signals and "pii_others" in s.leak_signals
    assert "u0@lab.invalid" not in json.dumps(s.__dict__)


def test_phone_and_ssn_need_their_key():
    s = _analyse([{"note": "+39 06 5550100", "x": "123-45-6789"}])
    assert "phone" not in s.pii_types and "ssn" not in s.pii_types


def test_card_needs_luhn_and_text_fallback():
    assert "card" not in _analyse({"card": "4111111111111112"}).pii_types
    text = b"call 4111 1111 1111 1111 or GB82WEST12345698765432 RSSMRA85T10A562S a@b.co x@y.io z@w.io"
    s = signals.analyse(text, content_class="text")
    assert s.pii_types == ["email", "card", "iban", "codice_fiscale"] and s.pii_others
    assert not signals._iban_ok("GB00WEST12345698765432")


def test_one_own_record_is_not_others():
    s = _analyse({"email": "me@lab.invalid"})
    assert s.pii_types == ["email"] and not s.pii_others


def test_sensitive_key_tokenizer():
    s = _analyse({"monkey": 1, "data": [{"password_hash": "x", "apiKey": "y", "roles": [],
                                          "isAdmin": True, "keyboard": 1}],
                  "user@x.io": {"token": 1}, "123456789": 1})
    assert s.sensitive_fields == ["data[].password_hash", "data[].apiKey", "data[].roles",
                                  "data[].isAdmin", "<k>.token"]
    assert "monkey" not in " ".join(s.sensitive_fields) and "keyboard" not in " ".join(s.sensitive_fields)
    assert s.structured and s.max_array_len == 1


def test_sensitive_fields_are_capped():
    s = _analyse({f"secret_{i}": i for i in range(40)})
    assert len(s.sensitive_fields) == signals.MAX_SENSITIVE_FIELDS


def test_secrets_keep_detector_names_and_the_values_only_for_display():
    body = b'{"aws": "AKIAIOSFODNN7EXAMPLQ", "contact": "x@lab.invalid"}'
    s = signals.analyse(body, content_class="json", secrets=True, source_url="http://h/x")
    assert s.secret_types == ["AWS Access Key ID"] and "secret" in s.leak_signals
    assert s.secret_values == ["AKIAIOSFODNN7EXAMPLQ"]
    assert s.secret_value_types == ["AWS Access Key ID"]
    shown = {k: v for k, v in s.__dict__.items() if k not in ("secret_values",)}
    assert "AKIA" not in json.dumps(shown)


def test_the_snippet_masks_tokens_the_agent_could_read():
    text = "token: Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd mail: a@lab.invalid id: 1234567"
    assert signals.mask_text(text) == "token: <tok> mail: <email> id: <n>"


def test_pii_off_and_binary_carry_nothing():
    assert _analyse([{"email": f"a{i}@b.co"} for i in range(5)], pii=False).pii_types == []
    assert signals.analyse(b"\x00\x01", content_class="binary").leak_signals == []
    assert signals.analyse(b"", content_class="json").leak_signals == []
    assert signals.analyse(b"{bad json", content_class="json").structured is False


def test_a_detector_fault_is_no_signal(monkeypatch):
    monkeypatch.setattr(signals, "_walk", mock.Mock(side_effect=RuntimeError))
    assert signals.analyse(b'{"a":1}', content_class="json") == signals.Signals()


@pytest.mark.parametrize("ctype,body,expected", [
    ("application/json; charset=utf-8", b"", "json"), ("text/html", b"", "html"),
    ("application/xml", b"", "xml"), ("text/plain", b"", "text"), ("image/png", b"", "binary"),
    ("application/pdf", b"", "binary"), ("", b"", "other"), ("", b' [1]', "json"),
    ("", b"<!DOCTYPE html>", "html"), ("", b"<?xml ?>", "xml"), ("", b"hello", "text"),
    ("", b"\x00\x01\x02\x03", "binary"), ("application/x-foo", b"plain words", "text"),
])
def test_content_class(ctype, body, expected):
    assert signals.content_class(ctype, body) == expected


@pytest.mark.parametrize("size,bucket", [(0, "<1k"), (1024, "1-10k"), (10 * 1024, "10-100k"),
                                         (10 ** 6, ">100k")])
def test_size_bucket(size, bucket):
    assert signals.size_bucket(size) == bucket


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

def _match(path, body, status=200, method="GET", headers=None, cc="text", gen="found", secrets=()):
    return signatures.match(path=path, method=method, status=status, headers=headers or {},
                            body=body, content_class=cc, generated_by=gen, secret_types=list(secrets))


@pytest.mark.parametrize("path,body,sig", [
    ("/.git/HEAD", b"ref: refs/heads/main\n", "git_head"),
    ("/app/.git/HEAD", b"a" * 40 + b"\n", "git_head"),
    ("/.git/config", b"[core]\nbare = false", "git_config"),
    ("/.svn/wc.db", b"SQLite format 3\x00", "svn_wcdb"),
    ("/.svn/entries", b"12\n", "svn_entries"),
    ("/.hg/requires", b"revlogv1\nstore\nfncache\n", "hg_requires"),
    ("/.env.production", b"DB_HOST=x\nDB_PASSWORD=y\n", "env_lines"),
    ("/web.config", b"<configuration/>", "web_config"),
    ("/console", b"<script>EVALEX = true</script>", "werkzeug_debugger"),
    ("/_ignition/health-check", b'{"can_execute_commands":true}', "ignition_exec"),
    ("/_profiler/latest", b"<title>Symfony Profiler</title>", "symfony_profiler"),
    ("/debug/pprof/", b"Types of profiles available:", "go_pprof"),
    ("/server-status", b"<h1>Apache Server Status for lab</h1>", "apache_server_status"),
    ("/oops", b"Action Controller: Exception caught", "rails_exception"),
    ("/oops", b"Server Error in '/' Application. Stack Trace:", "aspnet_error"),
    ("/oops", b"Whitelabel Error Page at org.springframework.web.Foo(Foo.java:1)", "spring_whitelabel"),
    ("/actuator/mappings", b'{"contexts":{"app":{"mappings":{}}}}', "actuator_mappings"),
    ("/rails/info/routes", b"<h2>Routes</h2>", "rails_routes"),
    ("/v3/api-docs", b'{"openapi":"3.0.0","paths":{"/internal/sync":{}}}', "openapi_internal"),
    ("/swagger.json", b'{"swagger":"2.0","paths":{"/x":{}},"tags":[{"name":"admin-ops"}]}', "openapi_internal"),
    ("/api/cfg", b'{"a":1}', "secret_matcher"),
])
def test_each_signature(path, body, sig):
    hit = _match(path, body, secrets=["AWS Access Key ID"] if sig == "secret_matcher" else ())
    assert hit and hit["signature"] == sig


def test_negative_signatures():
    assert _match("/.git/HEAD", b"<html>") is None
    assert _match("/.svn/entries", b"<html>") is None
    assert _match("/.hg/requires", b"<html>\nbody") is None
    assert _match("/.env", b"<html>A_B=1\nC_D=2", cc="html") is None
    assert _match("/.env", b"ONE=1") is None
    assert _match("/_ignition/health-check", b'{"can_execute_commands":false}') is None
    assert _match("/_ignition/health-check", b"not json") is None
    assert _match("/actuator/mappings", b"nope") is None
    assert _match("/v3/api-docs", b'{"openapi":"3","paths":{"/pets":{}}}') is None
    assert _match("/v3/api-docs", b"{broken") is None
    assert signatures.is_api_spec("[1]") is None


def test_status_gating():
    """Debug pages show at any status (a real one answers 500); the rest need a 2xx."""
    assert _match("/x", b"You're seeing this error because you have <code>DEBUG = True</code>",
                  status=500)["kind"] == "debug_page"
    assert _match("/x", b"__debugger__", status=500)["kind"] == "debug_console"
    assert _match("/.env", b"A_B=1\nC_D=2", status=500) is None
    assert _match("/.git/HEAD", b"ref: refs/heads/main", status=None) is None


def test_actuator_env_and_heapdump_severity():
    hit = _match("/actuator/env", b'{"propertySources":[{"name":"a"}]}')
    assert hit["severity"] == "high" and "1 property source" in hit["evidence"]
    assert _match("/env", b"propertySources: broken")["signature"] == "actuator_env"
    hd = _match("/actuator/heapdump", b"", method="HEAD", headers={"content-type": "application/octet-stream"})
    assert hd["signature"] == "actuator_heapdump" and hd["severity"] == "high"
    assert _match("/actuator/heapdump", b"", method="HEAD", headers={"content-type": "text/html"}) is None


@pytest.mark.parametrize("body,sig", [
    (b"PK\x03\x04", "zip_magic"), (b"\x1f\x8b\x08", "gzip_magic"), (b"7z\xbc\xaf\x27\x1c", "7z_magic"),
    (b"Rar!\x1a\x07\x00", "rar_magic"), (b"\x00" * 257 + b"ustar\x00", "tar_magic"),
    (b"-- MySQL dump 10.13", "sql_dump"), (b"x\nCREATE TABLE t", "sql_dump"),
])
def test_backup_magic(body, sig):
    assert _match("/b.zip", body, gen="backup")["signature"] == sig
    assert _match("/b.zip", body, gen="found") is None or sig not in ("zip_magic",)


def test_php_source_only_when_served_as_text():
    assert _match("/c.php.bak", b"<?php x", gen="backup", headers={"content-type": "text/plain"})
    assert _match("/c.php.bak", b"<?php x", gen="backup", headers={"content-type": "text/html"}) is None


def test_phpinfo_is_medium():
    hit = _match("/phpinfo.php", b"<title>phpinfo()</title> PHP Version </td>")
    assert hit["kind"] == "debug_page" and hit["severity"] == "medium"


# ---------------------------------------------------------------------------
# Verdict and normalizers
# ---------------------------------------------------------------------------

def _obs(path, status=200, cc="json", gen="found", variant_of="", body=b"x" * 100, hints=(),
         **kw):
    route = Route(BASE, path, generated_by=gen, variant_of=variant_of, hints=list(hints))
    obs = verdict.Observation(route=route, content_class=cc, size=len(body))
    obs.anon = prober.Answer(url=route.url, method="GET", status_code=status, content=body)
    for k, v in kw.items():
        setattr(obs, k, v)
    return obs


@pytest.mark.parametrize("path,gen,router,category,cls", [
    ("/api/v1/x", "version", False, "api", "old_version"),
    ("/admin/dashboard", "found", True, "other", "client_gated"),
    ("/actuator/env", "found", False, "other", "debug_management"),
    ("/api/admin/users", "found", False, "api", "admin_function"),
    ("/api/reports/export", "found", False, "api", "data_export"),
    ("/uploads/invoice.pdf", "found", False, "upload", "uploaded_content"),
    ("/internal/sync", "found", False, "other", "internal_api"),
    ("/api/items", "found", False, "api", "internal_api"),
    ("/about", "found", False, "other", "unknown"),
])
def test_route_class(path, gen, router, category, cls):
    assert verdict.route_class(Route(BASE, path, generated_by=gen, router=router, category=category)) == cls


def test_neighbour_hints_siblings_and_versions():
    obs = [_obs(f"/api/admin/{n}", status=401) for n in ("a", "b", "c")]
    obs += [_obs("/api/admin/open"), _obs("/api/admin/page", cc="html"),
            _obs("/api/v2/o", status=403), _obs("/api/v1/o", gen="version", variant_of="/api/v2/o")]
    hints = verdict._neighbour_hints(obs)
    assert hints[(BASE, "/api/admin/open", "GET")] == ["siblings_locked"]
    assert (BASE, "/api/admin/page", "GET") not in hints
    assert hints[(BASE, "/api/v1/o", "GET")] == ["version_locked"]


@pytest.mark.parametrize("expected,cc,leaks,match,conf", [
    (["openapi"], "html", [], None, 0.9),
    (["vary_auth"], "html", [], None, 0.9),
    ([], "html", ["pii"], True, 0.9),
    (["path_word"], "json", [], None, 0.6),
    (["seen_denied"], "xml", [], None, 0.6),
    (["path_word"], "html", [], None, 0.4),
    ([], "json", ["pii"], False, 0.4),
])
def test_anonymous_confidence(expected, cc, leaks, match, conf):
    obs = _obs("/x", cc=cc, bodies_match=match)
    obs.anon_signals = signals.Signals(pii_types=["email"] if leaks else [])
    assert verdict._anon_confidence(expected, obs) == conf


def test_assess_rules_and_new_endpoints():
    users = signals.Signals(pii_types=["email"], pii_record_estimate=5, pii_others=True,
                            sensitive_fields=["[].password"])
    seed = _obs("/internal/stats", gen="seed", hints=["path_word"])
    found = _obs("/api/v2/items", hints=[])                        # no hint, no leak: no node
    leak = _obs("/api/v2/people", anon_signals=users)
    artifact = _obs("/.git/HEAD", gen="vcs", signature={"kind": "vcs_exposure", "signature": "git_head",
                                                         "evidence": "ref", "severity": "high"})
    spec = _obs("/internal/openapi.json", gen="seed", hints=["path_word"], api_spec=True)
    dropped = _obs("/internal/w", hints=["path_word"], drop="wall")
    authed = _obs("/api/me", status=401, authed_usable=True,
                  authed_signals=signals.Signals(sensitive_fields=["reset_token"], key_paths=["reset_token"]))
    authed.authed = prober.Answer(url=BASE + "/api/me", method="GET", status_code=200)
    out = verdict.assess([seed, found, leak, artifact, spec, dropped, authed], {})
    kinds = {(f["path"], f["exposure_kind"]) for f in out["findings"]}
    assert kinds == {("/internal/stats", "anonymous_access"), ("/api/v2/people", "anonymous_access"),
                     ("/api/v2/people", "sensitive_data"), ("/.git/HEAD", "vcs_exposure"),
                     ("/api/me", "sensitive_data")}
    me = [f for f in out["findings"] if f["path"] == "/api/me"][0]
    assert me["authed_status"] == 200 and me["evidence_snippet"] == "keys: reset_token"
    assert [e["path"] for e in out["new_endpoints"]] == ["/internal/stats"]
    assert {e["path"] for e in out["endpoint_status"]} == {"/api/v2/items", "/api/v2/people", "/api/me",
                                                           "/internal/w"}
    assert out["dropped"]["wall"] == 1 and out["logged_in_compared"] == 1


def test_backup_equal_to_its_original_is_not_a_backup():
    sig = {"kind": "backup_file", "signature": "php_source", "evidence": "x", "severity": "medium"}
    original = _obs("/c.php", body=b"<?php same")
    copy = _obs("/c.php.bak", gen="backup", variant_of="/c.php", body=b"<?php same", signature=sig)
    other = _obs("/d.php.bak", gen="backup", variant_of="/d.php", body=b"<?php other", signature=sig)
    out = verdict.assess([original, copy, other], {})
    assert [f["path"] for f in out["findings"]] == ["/d.php.bak"]


def test_finding_shape_drops_unmeasured_keys_and_dedups():
    obs = _obs("/internal/x", hints=["path_word"])
    obs.anon = None
    f = normalizers.build_finding(obs, kind="anonymous_access", route_class="internal_api",
                                  auth_expected_by=["path_word"], confidence=0.4)
    assert "anon_status" not in f and "authed_status" not in f and "bodies_match" not in f
    assert f["vulnerability_type"] == "unauthenticated_endpoint" and f["catch_all_check"] == "n/a"
    assert normalizers.dedup_key(f) == (BASE, "/internal/x", "GET", "anonymous_access")
    assert normalizers.is_artifact({"exposure_kind": "env_file"})
    assert not normalizers.is_artifact(f)


def test_no_route_exposure_type_is_a_security_check_type():
    """T33: the triage model classifies by type before source."""
    assert "cors_misconfiguration" not in normalizers.VULNERABILITY_TYPES.values()


def test_build_result_filters_artifacts_and_counts():
    result = normalizers.build_result(
        [{"exposure_kind": "env_file", "route_class": "unknown", "needs_agent_confirmation": False},
         {"exposure_kind": "anonymous_access", "route_class": "internal_api", "needs_agent_confirmation": True}],
        new_endpoints=[{"path": "/.git/x"}, {"path": "/api/x"}], summary={"hosts": 2}, error="X")
    assert result["new_endpoints"] == [{"path": "/api/x"}]
    s = result["summary"]
    assert (s["candidates"], s["findings"], s["hosts"], s["error"]) == (1, 1, 2, "X")
    assert s["by_kind"] == {"env_file": 1, "anonymous_access": 1}
    json.dumps(result)


def test_parent_prefix_and_artifact_path():
    assert verdict.parent_prefix("/api/admin/x") == "/api/admin/"
    assert verdict.parent_prefix("/x") == "/"
    assert verdict.is_artifact_path("/app/.git/HEAD") and not verdict.is_artifact_path("/api/git")


def test_page_entry_is_masked_and_titled():
    answer = prober.Answer(url="u", method="GET", status_code=200,
                           headers={"content-type": "text/html", "server": "nginx"},
                           content=b"<title> Hi  there </title> a@b.co")
    entry = verdict.page_entry(answer, "http://h/x")
    assert entry["title"] == "Hi there" and "<email>" in entry["body"] and entry["host"] == "h"
    assert verdict._title(b"no title") == ""


# ---------------------------------------------------------------------------
# Pacer and prober
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self):
        self.now = 100.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_pacer_serializes_workers():
    clock = _Clock()
    pacer = prober._Pacer(4, clock=clock, sleep=clock.sleep)
    threads = [threading.Thread(target=pacer.wait) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert pacer._next == pytest.approx(100.0 + 8 * 0.25)
    pacer.back_off(10)
    assert pacer._next >= clock.now + 10
    prober._Pacer(0).wait()   # no rate, no wait


def test_pacer_is_process_wide_until_reset():
    a = prober._pacer_for(5)
    assert prober._pacer_for(50) is a
    prober._reset_pacer()
    assert prober._pacer_for(5) is not a


class _Response:
    def __init__(self, status=200, headers=None, chunks=(b"body",)):
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        self.closed = True


def _prober(transport, guard=lambda u: True, **kw):
    clock = _Clock()
    return prober.Prober(kw.pop("settings", {}), guard=guard, timeout=3, rps=0,
                         pacer=prober._Pacer(0, clock=clock, sleep=clock.sleep),
                         transport=transport, **kw)


def test_prober_builds_the_request():
    calls = []

    def transport(method, url, **kw):
        calls.append((method, url, kw))
        return _Response(chunks=(b"a" * 1500,))
    p = _prober(transport)
    answer = p.send("GET", "http://h/x", auth={"Authorization": "Bearer t"}, range_bytes=1024, max_bytes=1024)
    method, url, kw = calls[0]
    assert (method, url) == ("GET", "http://h/x")
    assert kw["headers"]["Range"] == "bytes=0-1023" and kw["headers"]["Authorization"] == "Bearer t"
    assert kw["headers"]["User-Agent"].startswith("Mozilla/5.0") and kw["allow_redirects"] is False
    assert kw["timeout"] == 3 and kw["proxies"] == {}
    assert answer.truncated and len(answer.content) == 1024 and answer.range_read and answer.with_auth
    assert p.sent == 1 and p.sent_with_auth == 1


def test_head_reads_no_body():
    response = _Response(chunks=(b"should not be read",))
    answer = _prober(lambda *a, **k: response).send("HEAD", "http://h/x")
    assert answer.content == b"" and response.closed


def test_guard_refusal_and_fault_send_nothing():
    calls = []
    p = _prober(lambda *a, **k: calls.append(1), guard=lambda u: False)
    assert p.send("GET", "http://h/x") is None and p.refused == 1

    def boom(_u):
        raise RuntimeError
    assert _prober(lambda *a, **k: calls.append(1), guard=boom).send("GET", "http://h/x") is None
    assert calls == []


def test_stop_sends_nothing(monkeypatch):
    from recon.helpers import shutdown
    monkeypatch.setattr(shutdown, "stop_requested", lambda: True)
    assert _prober(lambda *a, **k: pytest.fail("sent")).send("GET", "http://h/x") is None


def test_429_backs_off_then_retries_once():
    answers = [_Response(429, {"Retry-After": "7"}), _Response(200)]
    p = _prober(lambda *a, **k: answers.pop(0))
    answer = p.send("GET", "http://h/x")
    assert answer.status_code == 200 and p.sent == 2
    assert prober._retry_after({"retry-after": "x"}) == 1.0
    assert prober._retry_after({"retry-after": "999"}) == 30.0


def test_connection_failure_marks_the_host_but_an_http_error_body_does_not():
    import requests
    scope = cb.scope((), label="t")

    def refuse(*_a, **_k):
        raise requests.ConnectionError("refused")
    p = _prober(refuse, breaker_scope=scope)
    for _ in range(10):
        answer = p.send("GET", "http://10.9.9.9:81/x")
    assert answer is None or answer.error == "ConnectionError"
    assert scope.hosts()   # the host went down and is reported

    class Broken(_Response):
        def iter_content(self, chunk_size=1):
            raise ValueError("mid-read")
    a = _prober(lambda *_a, **_k: Broken()).send("GET", "http://h/x")
    assert a.status_code == 200 and a.error == "ValueError"


def test_capture_routing_eligibility(monkeypatch):
    import sys
    import types
    fake = types.SimpleNamespace(get_capture_routing=lambda tool: ("http://127.0.0.1:8888", "tok"))
    monkeypatch.setitem(sys.modules, "helpers.proxy_routing", fake)
    monkeypatch.setitem(sys.modules, "helpers", types.SimpleNamespace(proxy_routing=fake))
    seen = []

    def transport(method, url, **kw):
        seen.append(kw)
        return _Response()
    for profile, routed_authed in [({"authType": "bearer", "authValue": "t"}, True),
                                   ({"authType": "basic", "authValue": "u:p"}, True),
                                   ({"authType": "cookie", "authValue": "s=1"}, True),
                                   ({"authType": "header", "authValue": "k"}, False),
                                   ({"authType": "apikey", "authValue": "k"}, False),
                                   ({"authType": "bearer", "authValue": "t", "extraHeaders": {"X-T": "1"}}, False)]:
        p = _prober(transport, settings={"AUTH_PROFILE": profile, "IP_MODE": True, "TARGET_IPS": ["10.0.0.5"]})
        seen.clear()
        p.send("GET", BASE + "/x")
        p.send("GET", BASE + "/x", auth={"Authorization": "x"})
        anon, authed = seen
        assert anon["proxies"] and anon["headers"]["X-Redamon-Ctx"] == "tok"
        assert bool(authed["proxies"]) is routed_authed
        assert ("X-Redamon-Ctx" in authed["headers"]) is routed_authed


def test_capture_routing_is_fail_open(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "helpers.proxy_routing", None)
    assert _prober(lambda *a, **k: _Response())._routing(False) == ({}, "")


def test_auth_headers_follow_the_profile_scope():
    s = {"AUTH_PROFILE": {"authType": "bearer", "authValue": "t"}, "IP_MODE": True, "TARGET_IPS": ["10.0.0.5"]}
    p = _prober(lambda *a, **k: _Response(), settings=s)
    assert p.auth_headers(BASE + "/x") == {"Authorization": "Bearer t"}
    assert p.auth_headers(BASE + "/y") == {"Authorization": "Bearer t"}   # cached per host
    assert p.auth_headers("http://10.0.0.9/x") == {}
    roe = dict(s, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["10.0.0.5"])
    assert _prober(lambda *a, **k: _Response(), settings=roe).auth_headers(BASE + "/x") == {}
    assert _prober(lambda *a, **k: _Response()).auth_headers(BASE + "/x") == {}


def test_tls_warnings_are_silenced_at_import():
    """T34: an unverified request must never print a warning naming the host."""
    import urllib3
    src = Path(prober.__file__).read_text()
    assert "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)" in src
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.warn("x", urllib3.exceptions.InsecureRequestWarning)
    assert not caught


# ---------------------------------------------------------------------------
# Guard and config
# ---------------------------------------------------------------------------

def test_guard_private_operator_target_allowed_js_only_private_refused():
    """T39: the control of a private operator target is sent; a private IP named
    only in a bundle is never requested."""
    combined = {"metadata": {"expanded_ips": ["10.1.2.3"]}, "subdomains": [],
                "http_probe": {"by_url": {"http://10.1.2.3": {"url": "http://10.1.2.3"}}}}
    guard = scanner.build_guard(combined, {"IP_MODE": True, "TARGET_IPS": ["10.1.2.3"]})
    assert guard("http://10.1.2.3/rdm-control") is True
    assert guard("http://10.9.9.9/x") is False
    assert guard("http://169.254.169.254/latest") is False
    assert guard("ftp://10.1.2.3/") is False and guard("http://[bad/") is False


def test_guard_full_discovery_subdomain_seen_only_in_js(monkeypatch):
    import socket
    from recon.main_recon_modules import ip_filter
    combined = {"metadata": {"filtered_mode": False}, "domain": "example.com",
                "subdomains": ["www.example.com"], "http_probe": {"by_url": {}}}

    def resolve(host, *_a, **_k):
        ip = {"www.example.com": "10.0.0.8", "new.example.com": "10.0.0.9",
              "pub.example.com": "93.184.216.34"}[host]
        return [(socket.AF_INET, 1, 6, "", (ip, 0))]
    monkeypatch.setattr(ip_filter.socket, "getaddrinfo", resolve)
    guard = scanner.build_guard(combined, {"TARGET_DOMAIN": "example.com"})
    assert guard("http://www.example.com/x") is True      # the run's own host: private allowed
    assert guard("http://new.example.com/x") is False     # JS-only host on a private address
    assert guard("http://pub.example.com/x") is True      # JS-only host, public
    assert guard("http://other.org/x") is False           # out of scope


def test_guard_honours_the_roe_exclusion():
    combined = {"metadata": {"expanded_ips": ["10.1.2.3"]}, "http_probe": {"by_url": {}}}
    guard = scanner.build_guard(combined, {"IP_MODE": True, "TARGET_IPS": ["10.1.2.3"],
                                           "ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["10.1.2.3"]})
    assert guard("http://10.1.2.3/x") is False


def test_config_clamps_and_respects_a_slower_ceiling():
    cfg = scanner.config({"ROUTE_EXPOSURE_MAX_RPS": 500, "ROUTE_EXPOSURE_WORKERS": 0,
                          "ROUTE_EXPOSURE_TIMEOUT": "x", "ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST": 1,
                          "ROUTE_EXPOSURE_MAX_ROUTES_TOTAL": float("nan")})
    assert (cfg["rps"], cfg["workers"], cfg["timeout"], cfg["per_host"], cfg["total"]) == (50, 1, 10, 10, 3000)
    assert scanner.config({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0.5})["rps"] == 0.5
    assert scanner.config({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 0.5})["rps"] == 5
    assert all(scanner.config({})[k] for k in scanner.SWITCHES if k != "cross_host")
    assert scanner.config({})["cross_host"] is False


# ---------------------------------------------------------------------------
# v2: catalogs, git walk, riders
# ---------------------------------------------------------------------------

def _answer(status=200, headers=None, content=b"", method="GET", url=BASE):
    return prober.Answer(url=url, method=method, status_code=status,
                         headers={k.lower(): v for k, v in (headers or {}).items()}, content=content)


class _FakeProbe:
    """A prober stand-in: answers from a {url: Answer} map and records what was sent."""
    def __init__(self, answers, auth=None):
        self._answers = answers
        self._auth = auth or {}
        self.sent = []

    def send(self, method, url, *, auth=None, headers=None, range_bytes=None, max_bytes=None):
        self.sent.append((method, url, (headers or {}).get("Origin")))
        return self._answers.get(url)

    def auth_headers(self, url):
        return dict(self._auth)


def test_catalog_parses_actuator_mappings():
    doc = {"contexts": {"app": {"mappings": {"dispatcherServlets": {"d": [
        {"details": {"requestMappingConditions": {"patterns": ["/api/internal/billing/reconcile",
                                                               "/api/orders/{id}"]}}}]}}}}}
    out = catalogs.parse(json.dumps(doc).encode(), "application/json")
    assert "/api/internal/billing/reconcile" in out and "/api/orders/{id}" not in out


def test_catalog_parses_openapi_and_skips_templated():
    doc = {"openapi": "3.0.0", "paths": {"/api/status": {}, "/api/v2/orders/{id}": {}}}
    out = catalogs.parse(json.dumps(doc).encode(), "application/json")
    assert out == ["/api/status"]


def test_catalog_parses_rails_routes_static_head():
    body = b"users GET /users/:id(.:format) users#show\nhealth GET /health(.:format) health#show"
    out = catalogs.parse(body, "text/html; charset=rails")
    assert "/users" in out and "/health" in out


def test_catalog_junk_never_raises():
    assert catalogs.parse(b"\xff\x00 not json", "application/json") == []


def test_git_inflate_is_bounded():
    bomb = zlib_compress(b"A" * (2 * 1024 * 1024))
    assert len(gitwalk._inflate(bomb)) <= gitwalk.MAX_OBJECT_BYTES


def test_git_walk_proves_a_commit_from_head_ref_object():
    root = BASE + "/.git"
    commit_hash = "a" * 40
    tree_hash = "b" * 40
    obj = zlib_compress(b"commit 40\x00tree " + tree_hash.encode() + b"\nauthor x\n")
    probe = _FakeProbe({
        root + "/refs/heads/main": _answer(content=commit_hash.encode()),
        root + f"/objects/{commit_hash[:2]}/{commit_hash[2:]}": _answer(content=obj),
    })
    proof = gitwalk.walk(probe, root, b"ref: refs/heads/main\n")
    assert proof["git_walk_proof"] == "head>ref>commit" and proof["git_tree_prefix"] == "bbbbbbbb"


def test_git_walk_without_a_commit_object_is_no_proof():
    root = BASE + "/.git"
    probe = _FakeProbe({root + "/objects/" + "aa/" + "a" * 38: _answer(content=zlib_compress(b"blob 3\x00abc"))})
    assert gitwalk.walk(probe, root, (b"a" * 40)) == {}


def test_cors_rider_flags_a_credentialed_reflected_origin():
    url = BASE + "/api/profile"
    answers = {}
    probe = _FakeProbe(answers, auth={"Authorization": "Bearer t"})

    def send(method, u, *, auth=None, headers=None, range_bytes=None, max_bytes=None):
        origin = (headers or {}).get("Origin")
        probe.sent.append((method, u, origin))
        return _answer(headers={"Access-Control-Allow-Origin": origin,
                                "Access-Control-Allow-Credentials": "true"})
    probe.send = send
    out = riders.cors_rider(probe, Route(BASE, "/api/profile"))
    assert "reflected" in out["cors_variants"] and "null" in out["cors_variants"]


def test_cors_rider_ignores_wildcard_without_credentials():
    probe = _FakeProbe({}, auth={"Authorization": "Bearer t"})
    probe.send = lambda *a, **k: _answer(headers={"Access-Control-Allow-Origin": "*"})
    assert riders.cors_rider(probe, Route(BASE, "/api/profile")) == {}


def test_cache_rider_flags_a_cacheable_hit_and_skips_vary_cookie():
    hit = _answer(headers={"Cache-Control": "public, max-age=600", "X-Cache": "HIT", "Age": "5"})
    out = riders.cache_rider(hit)
    assert "cache-control:public" in out["cache_signals"] and "cache:hit" in out["cache_signals"]
    varied = _answer(headers={"Cache-Control": "public", "Vary": "Cookie", "X-Cache": "HIT"})
    assert riders.cache_rider(varied) == {}
    no_layer = _answer(headers={"Cache-Control": "public, max-age=600"})
    assert riders.cache_rider(no_layer) == {}


def test_catalog_shapes_it_does_not_understand_yield_nothing():
    assert catalogs._concrete("") is None and catalogs._concrete("relative/x") is None
    assert catalogs._concrete("/" + "a" * 300) is None
    assert catalogs._from_actuator_mappings({"contexts": []}) == []
    assert catalogs._from_actuator_mappings({"contexts": {"a": {"mappings": {"dispatcherServlets": []}}}}) == []
    assert catalogs._from_openapi({"paths": []}) == []


def test_catalog_openapi_server_and_base_path_prefix_the_routes():
    v3 = {"servers": [{"url": "https://api.lab.invalid/v2"}], "paths": {"/orders": {}}}
    assert catalogs.parse(json.dumps(v3).encode(), "application/json") == ["/v2/orders"]
    v2 = {"basePath": "/api/", "paths": {"/users": {}}}
    assert catalogs.parse(json.dumps(v2).encode(), "application/json") == ["/api/users"]


def test_catalog_rails_skips_lines_without_a_path():
    body = b"Prefix Verb URI Pattern\nhealth GET /health(.:format)\n/rails/info"
    assert "/health" in catalogs.parse(body, "text/html")


class _Down:
    def send(self, *a, **k):
        return None

    def auth_headers(self, url):
        return {}


def test_git_walk_degrades_to_no_proof_on_every_failure():
    root = BASE + "/.git"
    assert gitwalk.walk(_Down(), root, b"ref: refs/heads/main\n") == {}      # the ref never answers
    assert gitwalk.walk(_Down(), root, b"no ref here") == {}                 # nothing to follow
    assert gitwalk.walk(_Down(), root, b"a" * 40) == {}                      # the object never answers
    assert gitwalk._inflate(b"not zlib at all") == b""

    class _Boom(_Down):
        def send(self, *a, **k):
            raise RuntimeError("socket")
    assert gitwalk.walk(_Boom(), root, b"a" * 40) == {}


def test_git_walk_commit_without_a_tree_line_keeps_only_the_proof():
    commit = "e" * 40
    probe = _FakeProbe({BASE + f"/.git/objects/{commit[:2]}/{commit[2:]}": _answer(content=zlib_compress(b"commit 5\x00hello"))})
    assert gitwalk.walk(probe, BASE + "/.git", commit.encode()) == {"git_walk_proof": "head>ref>commit"}


def test_riders_guard_their_inputs():
    assert riders._registrable("10.0.0.5") == "10.0.0.5" and riders._registrable("app.lab.invalid") == "lab.invalid"
    route = Route(BASE, "/api/profile")
    assert riders.cors_rider(_FakeProbe({}, auth={"Authorization": "x"}), route, enabled=False) == {}
    assert riders.cors_rider(_FakeProbe({}), route) == {}                           # no profile, no rider
    assert riders.cors_rider(_FakeProbe({}, auth={"Authorization": "x"}), route) == {}  # nothing answered
    assert riders.cache_rider(None) == {} and riders.cache_rider(_answer(), enabled=False) == {}
    shared = _answer(headers={"Cache-Control": "s-maxage=300", "X-Cache": "MISS"})
    assert "s-maxage" in riders.cache_rider(shared)["cache_signals"]
