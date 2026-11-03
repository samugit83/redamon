"""Website mirrors and the project's Rules of Engagement (R-URL-7, CF-5, SEC-10)."""
from __future__ import annotations

import ast
import asyncio
import shutil
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import httpx

from workspace_import import mirror as mirror_mod
from workspace_import import mirror_rules
from workspace_import.errors import ImportFailure
from workspace_import.mirror import MirrorOptions, mirror

try:  # sibling-test helper; robust to namespace-package shadowing
    from tests.test_workspace_mirror import MirrorBase, html, typed
except ModuleNotFoundError:
    from test_workspace_mirror import MirrorBase, html, typed

NOW = datetime(2026, 1, 12, 10, 0, tzinfo=timezone.utc)  # a Monday


def settings(**kw):
    base = {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [], "IP_MODE": False, "TARGET_DOMAIN": "",
            "SUBDOMAIN_LIST": [], "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [], "TARGET_IPS": [],
            "STEALTH_MODE": False, "ROE_GLOBAL_MAX_RPS": 0}
    base.update(kw)
    return base


class RoeMirror(MirrorBase):
    async def run_with(self, cfg, seed="https://example.test/docs/", opts=None, **kw):
        rules = mirror_rules.rules_for(seed, cfg, now_utc=NOW)
        return await self.run_mirror(seed=seed, opts=opts, roe_excluded=rules.roe_excluded,
                                     concurrency=rules.concurrency, gap_for=rules.gap_for, **kw)

    async def test_roe_disabled_has_no_effect(self):
        cfg = settings(ROE_ENABLED=False, ROE_EXCLUDED_HOSTS=["example.test", "cdn.example.test"])
        self.assertIsNone(mirror_rules.rules_for("https://example.test/", cfg, now_utc=NOW).roe_excluded)
        await self.run_with(cfg, opts=MirrorOptions(external_assets=True))
        self.assertIn("https://cdn.example.test/lib.js", self.requested())

    async def test_excluded_seed_fails_roe_excluded(self):
        cfg = settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["example.test"])
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_with(cfg)
        self.assertEqual(ctx.exception.code, "roe_excluded")
        self.assertEqual(self.seen, [])

    async def test_excluded_asset_host_skipped(self):
        cfg = settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["cdn.example.test"])
        await self.run_with(cfg, opts=MirrorOptions(external_assets=True))
        self.assertNotIn("https://cdn.example.test/lib.js", self.requested())
        line = next(m for m in self.manifest() if m["url"] == "https://cdn.example.test/lib.js")
        self.assertEqual(line["skipped"], "roe")

    def test_domain_entry_excludes_subdomains(self):
        def excluded(entries, host):
            rules = mirror_rules.rules_for("https://site.example.test/", settings(
                ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=entries), now_utc=NOW)
            return rules.roe_excluded(host)
        self.assertTrue(excluded(["example.test"], "docs.example.test"))
        self.assertTrue(excluded(["example.test"], "example.test"))
        self.assertTrue(excluded(["*.example.test"], "docs.example.test"))
        self.assertFalse(excluded(["*.example.test"], "example.test"))
        self.assertFalse(excluded(["example.test"], "notexample.test"))

    async def test_two_projects_mirror_concurrently_each_with_own_roe(self):
        answers = {"p1": settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["cdn.example.test"]),
                   "p2": settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["example.test"])}

        def fetch(project_id, _url, **_kw):
            return answers[project_id]
        with mock.patch.object(mirror_rules, "fetch_agent_settings", fetch):
            s1, s2 = await asyncio.gather(mirror_rules.load_settings("p1"), mirror_rules.load_settings("p2"))
        r1 = mirror_rules.rules_for("https://example.test/docs/", s1, now_utc=NOW)
        r2 = mirror_rules.rules_for("https://example.test/docs/", s2, now_utc=NOW)
        out2 = self.tmp / "out2"
        one = self.run_mirror(opts=MirrorOptions(external_assets=True), roe_excluded=r1.roe_excluded)
        two = mirror("https://example.test/docs/", out2, MirrorOptions(external_assets=True),
                     fetcher_factory=self.factory, roe_excluded=r2.roe_excluded, sleep=self.clock.sleep,
                     now=self.clock.now)
        results = await asyncio.gather(one, two, return_exceptions=True)
        self.assertEqual(results[0].pages, 5)
        self.assertIsInstance(results[1], ImportFailure)
        self.assertEqual(results[1].code, "roe_excluded")
        self.assertNotIn("https://cdn.example.test/lib.js", self.requested())

    async def test_settings_failure_fails_closed(self):
        def down(*_a, **_kw):
            raise ConnectionError("webapp down")
        with mock.patch.object(mirror_rules, "fetch_agent_settings", down):
            with self.assertRaises(ImportFailure) as ctx:
                await mirror_rules.load_settings("p1")
        self.assertEqual(ctx.exception.code, "settings_unavailable")


class GlobalSettingsNeverUsed(unittest.TestCase):
    FORBIDDEN = {"get_setting", "get_settings", "target_scope_domains", "load_project_settings"}

    def test_import_package_never_uses_global_settings(self):
        package = Path(mirror_mod.__file__).resolve().parent
        for f in sorted(package.glob("*.py")):
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Name):
                    names = [node.id]
                elif isinstance(node, ast.Attribute):
                    names = [node.attr]
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name.split(".")[-1] for a in node.names]
                for name in names:
                    self.assertNotIn(name, self.FORBIDDEN, f"{f.name}:{node.lineno} reads {name}")


WINDOW = {"ROE_TIME_WINDOW_ENABLED": True, "ROE_TIME_WINDOW_TIMEZONE": "UTC",
          "ROE_TIME_WINDOW_DAYS": ["monday"], "ROE_TIME_WINDOW_START_TIME": "09:00",
          "ROE_TIME_WINDOW_END_TIME": "18:00"}


class InScopeTargets(MirrorBase):
    def test_in_scope_mirror_refused_outside_window(self):
        cfg = settings(ROE_ENABLED=True, TARGET_DOMAIN="example.test", **WINDOW)
        mirror_rules.rules_for("https://docs.example.test/", cfg, now_utc=NOW)  # inside: no refusal
        with self.assertRaises(ImportFailure) as ctx:
            mirror_rules.rules_for("https://docs.example.test/", cfg, now_utc=NOW.replace(hour=20))
        self.assertEqual(ctx.exception.code, "roe_outside_window")

    def test_in_scope_mirror_refused_after_end_date(self):
        cfg = settings(ROE_ENABLED=True, TARGET_DOMAIN="example.test", ROE_ENGAGEMENT_END_DATE="2026-01-01")
        with self.assertRaises(ImportFailure) as ctx:
            mirror_rules.rules_for("https://example.test/", cfg, now_utc=NOW)
        self.assertEqual(ctx.exception.code, "roe_outside_window")
        # RoE off: the dates do not apply.
        mirror_rules.rules_for("https://example.test/", dict(cfg, ROE_ENABLED=False), now_utc=NOW)

    async def test_in_scope_mirror_rate_capped(self):
        cfg = settings(ROE_ENABLED=True, TARGET_DOMAIN="example.test", ROE_GLOBAL_MAX_RPS=2)
        rules = mirror_rules.rules_for("https://example.test/docs/", cfg, now_utc=NOW)
        self.assertEqual((rules.gap_for("example.test"), rules.gap_for("elsewhere.test")),
                         (0.5, mirror_mod.SAME_HOST_GAP_SEC))
        times = []
        base = self.handler

        def timed(request):
            if request.url.host == "example.test":
                times.append(self.clock.t)
            return base(request)
        self.handler = timed
        await self.run_mirror(gap_for=rules.gap_for, concurrency=1)
        self.assertTrue(all(b - a >= 0.5 - 1e-9 for a, b in zip(times, times[1:])), times)

    def test_stealth_forces_serial_slow_crawl(self):
        cfg = settings(TARGET_DOMAIN="example.test", STEALTH_MODE=True)
        rules = mirror_rules.rules_for("https://example.test/docs/", cfg, now_utc=NOW)
        self.assertEqual((rules.concurrency, rules.gap_for("docs.example.test")), (1, 1.0))

    def test_out_of_scope_host_unaffected(self):
        cfg = settings(ROE_ENABLED=True, TARGET_DOMAIN="target.example.test", STEALTH_MODE=True,
                       ROE_GLOBAL_MAX_RPS=1, ROE_ENGAGEMENT_END_DATE="2026-01-01", **WINDOW)
        rules = mirror_rules.rules_for("https://docs.example.test/", cfg, now_utc=NOW.replace(hour=23))
        self.assertFalse(rules.seed_in_scope)
        self.assertEqual((rules.concurrency, rules.gap_for("docs.example.test")),
                         (mirror_mod.CONCURRENCY, mirror_mod.SAME_HOST_GAP_SEC))

    def test_batch_and_ip_mode_scope_detection(self):
        batch = settings(DOMAIN_BATCH_MODE=True, DOMAIN_BATCH_GROUPS=[
            {"rootDomain": "one.example.test"}, {"rootDomain": "Two.Example.Test"}, {"rootDomain": "bad domain"},
            {"rootDomain": "x..example.test"}, "not-a-dict"])
        self.assertEqual(mirror_rules.scope_domains(batch), ["one.example.test", "two.example.test"])
        check = mirror_rules.scope_check(batch)
        self.assertTrue(check("www.two.example.test"))
        self.assertFalse(check("three.example.test"))

        groups = settings(SCOPE_GROUPS_SOURCE="webapp", SCOPE_GROUPS=[{"scan_root": "app.example.test"}],
                          TARGET_DOMAIN="ignored.example.test")
        self.assertEqual(mirror_rules.scope_domains(groups), ["app.example.test"])

        ip = settings(IP_MODE=True, TARGET_IPS=["203.0.113.7", "198.51.100.0/24", "junk"],
                      TARGET_DOMAIN="example.test")
        check = mirror_rules.scope_check(ip)
        self.assertTrue(check("203.0.113.7"))
        self.assertTrue(check("198.51.100.42"))
        self.assertFalse(check("example.test"))
        self.assertEqual(mirror_rules.scope_domains(ip), [])
        stealth_ip = dict(ip, STEALTH_MODE=True)
        self.assertEqual(mirror_rules.rules_for("http://198.51.100.42/", stealth_ip, now_utc=NOW).concurrency, 1)
        self.assertEqual(mirror_rules.rules_for("http://192.0.2.1/", stealth_ip, now_utc=NOW).concurrency,
                         mirror_mod.CONCURRENCY)


if __name__ == "__main__":
    unittest.main()
