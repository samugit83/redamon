"""tooling/scripts/takeover_finding_rekey.py (recon audit S-23, S-24, S-27).

A takeover finding's id hashes its provider. A certificate's issuer alone no
longer names the provider (an Amazon-issued certificate made it `aws-s3`, and
in the S-23 builds `aws`; a Google Trust Services one `google`): the finding
keeps the tool's placeholder. The generic DNS detections `dangling-cname` /
`dns-saas` now take the provider the CNAME or a certificate SAN on the
provider's edge domain names. The script moves each old node to the id today's
writer derives from what the node stores, with the mute, the Priority Board
layers (a person's DECISION included), the agent's CONFIRMS proof edges, the
un-mute exemptions, the fix items and the captured transactions. Fake Neo4j and
Postgres sessions.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts import takeover_finding_rekey as rk  # noqa: E402

UID, PID = "u-takeover", "p-takeover"
HOST = "portal.example.test"
ACM_ISSUER = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
GTS_ISSUER = "CN=WE1,O=Google Trust Services,C=US"
CLOUDFLARE_ISSUER = "CN=Cloudflare Inc ECC CA-3,O=Cloudflare\\, Inc.,C=US"

OLD = rk.th.finding_id(HOST, "aws-s3", "cname")
NEW = rk.th.finding_id(HOST, "unknown", "cname")
# Where the S-23 builds wrote an ACM-only finding, and the S-23/S-24 run of
# this script renamed one (the id only).
AWS_ID = rk.th.finding_id(HOST, "aws", "cname")
OLD_DANGLING = rk.th.finding_id(HOST, "dangling-cname", "dns")
NEW_DANGLING = rk.th.finding_id(HOST, "heroku", "dns")


def _tool_raw(service=""):
    return json.dumps({"subjack": {"subdomain": HOST, "vulnerable": True, "service": service}})


def _acm_row(**over):
    """The node an ELB host with an ACM certificate was written as: Subjack named
    no service, the CNAME no provider, and the issuer said `aws-s3`."""
    row = {"id": OLD, "hostname": HOST, "provider": "aws-s3", "method": "cname",
           "cname_target": "app-123.us-east-1.elb.amazonaws.com",
           "cert_provider": "aws-s3", "cert_issuer": ACM_ISSUER,
           "cert_subject_cn": "www.example.test", "tool_raw": _tool_raw()}
    row.update(over)
    return row


def _dangling_row(**over):
    row = {"id": OLD_DANGLING, "hostname": HOST, "provider": "dangling-cname", "method": "dns",
           "cname_target": "orphan-app.herokuapp.com.", "cert_provider": None,
           "cert_issuer": None, "cert_subject_cn": None,
           "tool_raw": json.dumps({"nuclei_takeover": {"template_id": "detect-dangling-cname"}})}
    row.update(over)
    return row


class FakeSession:
    def __init__(self, old=(), nodes=None):
        self.old = list(old)
        self.nodes = nodes or {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if query is rk.OLD_FINDINGS:
            return [r for r in self.old if r["provider"] in params["providers"]]
        if query is rk.READ_PAIR:
            return [{"id": i, **self.nodes[i]} for i in (params["old"], params["new"])
                    if i in self.nodes]
        return []

    def writes(self):
        return [(q, p) for q, p in self.calls if q not in (rk.OLD_FINDINGS, rk.READ_PAIR)]


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = [("id",), ("user_id",)]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.log.append(("sql", " ".join(sql.split()), params))

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows=((PID, UID),)):
        self.rows = list(rows)
        self.log = []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.log.append(("commit",))


PROJECT = {"id": PID, "user_id": UID}

DECIDED = {"id": OLD, "source": "takeover_scan", "user_id": UID, "project_id": PID,
           "hostname": HOST, "takeover_provider": "aws-s3",
           "triage_status": "likely_noise", "triage_source": "human",
           "muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1",
           "updated_at": "2026-10-01T00:00:00Z"}


def _plan(*rows):
    return rk.plan_project(FakeSession(rows), PROJECT)


class TestDerivation(unittest.TestCase):
    def test_an_amazon_issuer_alone_moves_to_the_tools_placeholder(self):
        self.assertIsNone(rk.san_provider(_acm_row()))
        self.assertEqual(rk.new_provider(_acm_row()), ("unknown", None))

    def test_any_issuer_alone_moves_to_the_tools_placeholder(self):
        for provider, issuer in (("aws", ACM_ISSUER), ("google", GTS_ISSUER),
                                 ("cloudflare", CLOUDFLARE_ISSUER)):
            row = _acm_row(provider=provider, cert_provider=provider, cert_issuer=issuer,
                           cname_target="portal.example.test.cdn.cloudflare.net")
            with self.subTest(provider=provider):
                self.assertEqual(rk.new_provider(row), ("unknown", None))

    def test_a_provider_the_issuer_could_not_name_was_a_tools(self):
        # Heroku's own edge certificate is Amazon-issued: the issuer names AWS,
        # so `heroku` came from a tool; tool_raw need not even be readable.
        row = _acm_row(provider="heroku", cert_provider="aws", cname_target=None,
                       tool_raw="{")
        self.assertEqual(rk.new_provider(row), ("heroku", None))

    def test_a_cname_provider_beside_an_issuer_only_certificate_stays(self):
        row = _acm_row(provider="heroku", cert_provider="google", cert_issuer=GTS_ISSUER,
                       cname_target="example-app.herokudns.com", tool_raw="{")
        self.assertEqual(rk.new_provider(row), ("heroku", None))

    def test_tools_with_different_placeholders_leave_the_node_alone(self):
        raw = json.dumps({
            "subjack": {"subdomain": HOST, "vulnerable": True, "service": "none"},
            "baddns": {"target": HOST, "module": "", "signature": "", "indicator": ""}})
        provider, reason = rk.new_provider(_acm_row(tool_raw=raw))
        self.assertIsNone(provider)
        self.assertIn("different placeholders", reason)

    def test_the_script_reads_every_provider_an_issuer_has_named(self):
        self.assertEqual(set(rk.ISSUER_PROVIDERS),
                         set(rk.th._ISSUER_PROVIDER_MARKERS.values()) | {"aws-s3"})

    def test_an_s3_cname_keeps_s3(self):
        row = _acm_row(cname_target="assets.example.test.s3.amazonaws.com")
        self.assertEqual(rk.new_provider(row), ("aws-s3", None))

    def test_a_certificate_whose_subject_is_s3_keeps_s3(self):
        row = _acm_row(cert_subject_cn="*.s3.amazonaws.com")
        self.assertEqual(rk.san_provider(row), "aws-s3")
        self.assertEqual(rk.new_provider(row), ("aws-s3", None))

    def test_a_tool_that_named_s3_keeps_s3(self):
        row = _acm_row(tool_raw=json.dumps({
            "subjack": {"subdomain": HOST, "vulnerable": True, "service": ""},
            "nuclei_takeover": {"template_id": "aws-bucket-takeover", "tags": ["takeover"],
                                "matched_at": f"https://{HOST}/"}}))
        self.assertEqual(rk.tool_providers(row["tool_raw"]), ["unknown", "aws-s3"])
        self.assertEqual(rk.new_provider(row), ("aws-s3", None))

    def test_a_tool_raw_cut_at_its_limit_leaves_the_node_alone(self):
        provider, reason = rk.new_provider(_acm_row(tool_raw=_tool_raw()[:-5]))
        self.assertIsNone(provider)
        self.assertIn("tool_raw cannot be read", reason)

    def test_a_tool_that_named_another_provider_leaves_the_node_alone(self):
        provider, reason = rk.new_provider(_acm_row(tool_raw=_tool_raw("heroku")))
        self.assertIsNone(provider)
        self.assertIn("another provider", reason)

    def test_another_issuers_certificate_is_not_amazons(self):
        # Only a SAN, which the node does not store, can have named S3 here.
        row = _acm_row(cert_issuer="Example Edge CA")
        self.assertEqual(rk.san_provider(row), "aws-s3")
        self.assertEqual(rk.new_provider(row), ("aws-s3", None))

    def test_a_dangling_cname_takes_the_cname_provider(self):
        self.assertEqual(rk.new_provider(_dangling_row()), ("heroku", None))

    def test_a_dangling_cname_takes_a_san_provider_when_the_cname_names_none(self):
        row = _dangling_row(cname_target="orphan.deadcdn.example", cert_provider="heroku",
                            cert_issuer=ACM_ISSUER, cert_subject_cn="*.herokuapp.com")
        self.assertEqual(rk.new_provider(row), ("heroku", None))

    def test_a_dangling_cname_keeps_its_placeholder_beside_an_issuer_only_certificate(self):
        for cert_provider in ("aws-s3", "aws"):
            row = _dangling_row(cname_target="orphan.deadcdn.example",
                                cert_provider=cert_provider, cert_issuer=ACM_ISSUER,
                                cert_subject_cn="www.example.test")
            with self.subTest(cert_provider=cert_provider):
                self.assertEqual(rk.new_provider(row), ("dangling-cname", None))

    def test_a_dangling_cname_with_nothing_observed_stays(self):
        row = _dangling_row(cname_target="orphan.deadcdn.example")
        self.assertEqual(rk.new_provider(row), ("dangling-cname", None))


class TestPlan(unittest.TestCase):
    def test_an_acm_only_s3_finding_moves_to_the_placeholder(self):
        plan = _plan(_acm_row())
        self.assertEqual(plan["rekeys"], [{
            "old_id": OLD, "new_id": NEW, "hostname": HOST, "method": "cname",
            "old_provider": "aws-s3", "new_provider": "unknown"}])
        self.assertEqual(plan["unmapped"], [])

    def test_an_issuer_only_google_finding_moves_to_the_placeholder(self):
        row = _acm_row(id=rk.th.finding_id(HOST, "google", "cname"), provider="google",
                       cert_provider="google", cert_issuer=GTS_ISSUER,
                       cname_target="portal.example.test.cdn.cloudflare.net")
        (r,) = _plan(row)["rekeys"]
        self.assertEqual((r["new_id"], r["new_provider"]), (NEW, "unknown"))

    def test_a_node_the_s23_builds_wrote_as_aws_moves_on(self):
        (r,) = _plan(_acm_row(id=AWS_ID, provider="aws", cert_provider="aws"))["rekeys"]
        self.assertEqual((r["old_id"], r["new_id"]), (AWS_ID, NEW))

    def test_a_node_the_s23_run_renamed_to_aws_moves_on(self):
        # That run renamed the id only: the node still stores aws-s3.
        (r,) = _plan(_acm_row(id=AWS_ID))["rekeys"]
        self.assertEqual((r["old_id"], r["new_id"], r["old_provider"]),
                         (AWS_ID, NEW, "aws-s3"))

    def test_a_dangling_cname_the_s24_run_renamed_to_aws_moves_back(self):
        renamed = rk.th.finding_id(HOST, "aws", "dns")
        row = _dangling_row(id=renamed, cname_target="orphan.deadcdn.example",
                            cert_provider="aws-s3", cert_issuer=ACM_ISSUER,
                            cert_subject_cn="www.example.test")
        (r,) = _plan(row)["rekeys"]
        self.assertEqual((r["old_id"], r["new_id"], r["new_provider"]),
                         (renamed, OLD_DANGLING, "dangling-cname"))

    def test_findings_a_tool_cname_or_san_named_are_not_listed(self):
        rows = (_acm_row(id=rk.th.finding_id(HOST, "heroku", "cname"), provider="heroku",
                         cert_provider="aws", cname_target=None, tool_raw=_tool_raw("heroku")),
                _acm_row(id=rk.th.finding_id(HOST, "github-pages", "cname"),
                         provider="github-pages", cert_provider="google",
                         cert_issuer=GTS_ISSUER, tool_raw=_tool_raw("github")),
                _acm_row(id=rk.th.finding_id(HOST, "heroku", "dns"), provider="heroku",
                         method="dns", cert_provider="heroku", cert_subject_cn="*.herokuapp.com",
                         cname_target=None))
        self.assertEqual(_plan(*rows), {"rekeys": [], "unmapped": []})

    def test_a_dangling_cname_finding_moves_to_its_cname_provider(self):
        (r,) = _plan(_dangling_row())["rekeys"]
        self.assertEqual((r["old_id"], r["new_id"], r["new_provider"]),
                         (OLD_DANGLING, NEW_DANGLING, "heroku"))

    def test_findings_whose_provider_did_not_move_are_not_listed(self):
        rows = (_acm_row(cname_target="assets.example.test.s3.amazonaws.com"),
                _dangling_row(cname_target="orphan.deadcdn.example"))
        self.assertEqual(_plan(*rows), {"rekeys": [], "unmapped": []})

    def test_a_node_already_on_the_new_key_is_not_listed(self):
        self.assertEqual(_plan(_acm_row(id=NEW), _dangling_row(id=NEW_DANGLING)),
                         {"rekeys": [], "unmapped": []})

    def test_an_id_its_fields_do_not_explain_is_left_alone(self):
        other = rk.th.finding_id("other.example.test", "aws-s3", "cname")
        plan = _plan(_acm_row(id=other))
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual([u["old_id"] for u in plan["unmapped"]], [other])

    def test_a_node_with_no_hostname_is_left_alone(self):
        plan = _plan(_acm_row(hostname=None))
        self.assertEqual(plan["rekeys"], [])
        self.assertEqual(len(plan["unmapped"]), 1)

    def test_only_this_source_and_the_moved_providers_are_read(self):
        session = FakeSession([])
        rk.plan_project(session, PROJECT)
        (_, params), = session.calls
        self.assertEqual((params["uid"], params["pid"]), (UID, PID))
        self.assertEqual(sorted(params["providers"]), [
            "aws", "aws-s3", "cloudflare", "dangling-cname", "dns-saas", "fastly",
            "github-pages", "google", "heroku", "netlify", "shopify", "zendesk"])
        self.assertIn("v.source = 'takeover_scan'", rk.OLD_FINDINGS)

    def test_every_query_is_scoped_to_one_project_and_leaves_updated_at_alone(self):
        for name in ("OLD_FINDINGS", "READ_PAIR", "RENAME", "MERGE_ONTO_NEW", "COPY_PROOF",
                     "DELETE_OLD"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertIn("$uid", query)
                self.assertNotIn("updated_at", query)
                self.assertNotIn("triage_score", query)


class TestRekeyGraph(unittest.TestCase):
    REKEY = {"old_id": OLD, "new_id": NEW, "hostname": HOST, "method": "cname",
             "old_provider": "aws-s3", "new_provider": "unknown"}

    def test_no_new_node_yet_renames_in_place(self):
        s = FakeSession(nodes={OLD: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "renamed")
        (query, params), = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["pid"], params["uid"]),
                         (OLD, NEW, PID, UID))

    def test_after_a_scan_the_mute_the_decision_and_the_proof_move_onto_the_new_node(self):
        s = FakeSession(nodes={
            OLD: {"muted": True, "props": dict(DECIDED)},
            NEW: {"muted": False, "props": {"triage_ai_verdict": "real",
                                            "triage_base_tier": "T3"}},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "merged")
        writes = s.writes()
        merge_query, merge = writes[0]
        self.assertTrue(merge_query.startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(merge["carried"]["triage_status"], "likely_noise")
        self.assertEqual(merge["carried"]["muted_by"], "user-1")
        self.assertNotIn("updated_at", merge["carried"])
        self.assertTrue(merge["mute"])
        self.assertIn("keep.triage_ai_verdict", merge_query.split("REMOVE", 1)[1].split("\n", 1)[0])
        self.assertEqual([q for q, _ in writes][1:], [rk.COPY_PROOF, rk.DELETE_OLD])
        self.assertEqual(writes[1][1]["old"], OLD)
        self.assertEqual(writes[1][1]["new"], NEW)

    def test_an_old_node_already_gone_is_nothing(self):
        s = FakeSession(nodes={})
        self.assertEqual(rk.rekey_graph(s, UID, PID, self.REKEY), "gone")
        self.assertEqual(s.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_every_row_naming_the_old_id_follows_it(self):
        conn = FakeConn()
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, {"old_id": OLD, "new_id": NEW})
        sql = [(q, p) for kind, q, p in conn.log if kind == "sql"]
        tables = [q.split()[1] if q.startswith("UPDATE") else q.split()[2] for q, _ in sql]
        self.assertEqual(tables, ["node_filter_exemptions", "node_filter_exemptions",
                                  "remediations", "captured_http_transactions"])
        for query, params in sql:
            self.assertIn("project_id = %(pid)s", query)
            self.assertEqual((params["pid"], params["old"], params["new"]), (PID, OLD, NEW))


class TestRun(unittest.TestCase):
    def test_a_dry_run_changes_nothing_and_says_what_it_would_do(self):
        s = FakeSession([_acm_row(), _dangling_row(), _acm_row(id="takeover_0", tool_raw="{")],
                        nodes={OLD: {"muted": True, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), None, apply=False, out=lines.append)
        self.assertEqual(s.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertEqual(len([e for e in conn.log if e[0] == "sql"]), 1, "only the project list")
        text = "\n".join(lines)
        self.assertIn(f"aws-s3 -> unknown  {OLD} -> {NEW} (dry run)", text)
        self.assertIn(f"dangling-cname -> heroku  {OLD_DANGLING} -> {NEW_DANGLING} (dry run)", text)
        self.assertIn("takeover_0: its tool_raw cannot be read", text)
        self.assertIn(f"{PID}: 2 to re-key, 1 left alone", text)
        self.assertIn("would re-key 2 finding(s) in 1 project(s)", lines[-1])
        self.assertEqual(summary[PID]["outcomes"], [])

    def test_apply_writes_postgres_first_then_the_graph(self):
        s = FakeSession([_acm_row()], nodes={OLD: {"muted": False, "props": dict(DECIDED)}})
        conn, lines = FakeConn(), []
        summary = rk.run(conn, FakeDriver(s), PID, apply=True, out=lines.append)
        self.assertIn(("commit",), conn.log)
        commit_at = conn.log.index(("commit",))
        self.assertTrue(any(e[0] == "sql" and "remediations" in e[1]
                            for e in conn.log[:commit_at]))
        self.assertEqual(summary[PID]["outcomes"], ["renamed"])
        self.assertIn("done: 1 renamed", "\n".join(lines))

    def test_a_second_run_finds_nothing(self):
        # The rename moves only the id: the stored provider is the next scan's to rewrite.
        s = FakeSession([_acm_row(id=NEW), _dangling_row(id=NEW_DANGLING)])
        conn, lines = FakeConn(), []
        self.assertEqual(rk.run(conn, FakeDriver(s), None, apply=True, out=lines.append), {})
        self.assertEqual(s.writes(), [])
        self.assertIn("re-keyed 0 finding(s) in 0 project(s)", lines[-1])

    def test_a_hostname_is_never_echoed_raw(self):
        host = "evil\x1b[2J.example.test"
        s = FakeSession([_acm_row(id=rk.th.finding_id(host, "aws-s3", "cname"), hostname=host)])
        lines = []
        rk.run(FakeConn(), FakeDriver(s), None, apply=False, out=lines.append)
        self.assertNotIn("\x1b", "\n".join(lines))

    def test_a_blank_project_id_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeSession()), " ", apply=False)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["webapp"]), \
                patch.object(rk, "_connect", side_effect=AssertionError("must not connect")):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)

    def test_a_blank_project_is_refused_before_anything_runs(self):
        with patch.object(rk, "_connect", side_effect=AssertionError("must not connect")), \
                self.assertRaises(SystemExit):
            rk.main(["--project", " "])


if __name__ == "__main__":
    unittest.main()
