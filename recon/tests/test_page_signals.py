"""Item 5: the problem-page catalog (recon/helpers/page_signals.py).

Every row matches its own example and not its near miss; generic titles need
their condition; normalisation; never raises. Pure functions, no network.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from recon.helpers import page_signals as ps  # noqa: E402


def _families(**kw):
    return {m["family"]: m for m in ps.match_page(**kw)}


def _problem(**kw):
    return [m["problem"] for m in ps.match_page(**kw)]


#: (problem, keyword arguments of a page that must match it)
POSITIVE = [
    ("surge_project_not_found", dict(title="project not found", server="Surge")),
    ("ghost_domain_error", dict(title="Domain error", server="openresty", status=404)),
    ("uberflip_non_hub_domain", dict(title="Non-hub domain", status=404)),
    ("pingdom_status_page_missing", dict(title="404 - Status Page not Found", status=404)),
    ("anima_page_not_found", dict(title="Anima - Page Not Found", server="AmazonS3", status=200)),
    ("readthedocs_project_not_found", dict(title="Project not found - Read the Docs Community")),
    ("canny_page_not_found", dict(title="Page Not Found | Canny")),
    ("helpjuice_404", dict(title="Helpjuice – 404", server="Heroku", status=404)),
    ("hatenablog_not_found", dict(title="お探しのページは見つかりませんでした。 - はてなブログ", status=404)),
    ("s3_bucket_missing", dict(server="AmazonS3", status=404, path="/", mime_type="application/xml",
                               cname=["bucket.s3.eu-west-1.amazonaws.com"])),
    ("github_pages_site_not_found", dict(title="Site not found · GitHub Pages", server="GitHub.com",
                                         status=404)),
    ("heroku_no_such_app", dict(title="No such app", server="heroku-router", status=404)),
    ("wix_connect_domain_error", dict(title="ConnectYourDomain Error | Wix.com", status=404)),
    ("framer_site_not_found", dict(title="Site Not Found | Framer", server="Framer/a1b2c3", status=404)),
    ("netlify_site_not_found", dict(title="Site not found", server="Netlify", status=404)),
    ("azure_web_app_404", dict(title="Microsoft Azure Web App - Error 404", status=404)),
    ("shopify_store_unavailable", dict(title="Store unavailable", status=404)),
    ("fastly_unknown_domain", dict(title="Fastly error: unknown domain: shop.example.test", status=500)),
    ("pantheon_unknown_site", dict(title="404 - Unknown site", server="Pantheon")),
    ("zendesk_help_center_closed", dict(title="Help Center Closed",
                                        url="https://help.example.test/hc/help-center-closed")),
    ("jupyter_notebook_open", dict(title="Home Page - Select or create a notebook", status=200)),
    ("jupyterlab_open", dict(title="JupyterLab", status=200, path="/lab")),
    ("ttyd_terminal_open", dict(title="ttyd - Terminal", status=200)),
    ("ray_dashboard_open", dict(title="Ray Dashboard", status=200)),
    ("mongo_express_open", dict(title="system.users - Mongo Express", status=200)),
    ("phpmyadmin_logged_in", dict(title="db.example.test / localhost | phpMyAdmin 5.2.1", status=200)),
    ("hadoop_yarn_open", dict(title="All Applications", server="Jetty(9.4.20)", status=200)),
    ("tomcat_manager_open", dict(title="/manager", status=200, path="/manager/html")),
    ("aem_groovy_console_open", dict(title="Groovy Console", status=200, path="/etc/groovyconsole.html")),
    ("jenkins_script_console_open", dict(title="Script Console [Jenkins]", status=200)),
    ("jenkins_dashboard_open", dict(title="Dashboard [Jenkins]", status=200)),
    ("jenkins_open_signup", dict(title="Create an account! [Jenkins]", status=200)),
    ("spark_master_open", dict(title="Spark Master at spark://10.0.0.1:7077", status=200)),
    ("spark_application_open", dict(title="ETL job - Spark Jobs", status=200)),
    ("flink_dashboard_open", dict(title="Apache Flink Web Dashboard", status=200)),
    ("airflow_open", dict(title="DAGs - Airflow", status=200)),
    ("aem_crx_anonymous", dict(title="Content Explorer - UserID: anonymous", status=200)),
    ("selenium_grid_open", dict(title="WebDriver Hub", status=200)),
    ("alertmanager_open", dict(title="Alertmanager", status=200)),
    ("druid_console_open", dict(title="Apache Druid", status=200)),
    ("drill_console_open", dict(title="Apache Drill", status=200)),
    ("envoy_admin_open", dict(title="Envoy Admin", status=200)),
    ("kafka_ui_open", dict(title="Kafdrop: Broker List", status=200)),
    ("prometheus_open", dict(title="Prometheus Time Series Collection and Processing Server", status=200)),
    ("hdfs_namenode_open", dict(title="Namenode information", status=200)),
    ("cadvisor_open", dict(title="cAdvisor - /", status=200)),
    ("netdata_open", dict(title="netdata dashboard", status=200)),
    ("tiny_file_manager_open", dict(title="Tiny File Manager | Root", status=200)),
    ("shell_in_a_box_open", dict(title="Shell In A Box", status=200)),
    ("werkzeug_debugger_console", dict(title="Console // Werkzeug Debugger")),
    ("werkzeug_traceback", dict(title="KeyError: 'id' // Werkzeug Debugger")),
    ("django_debug_error", dict(title="DoesNotExist at /admin/")),
    ("django_debug_404", dict(title="Page not found at /missing")),
    ("django_default_page", dict(title="The install worked successfully! Congratulations!")),
    ("laravel_whoops", dict(title="Whoops! There was an error.")),
    ("symfony_profiler", dict(title="Symfony Profiler")),
    ("symfony_welcome", dict(title="Welcome to Symfony!")),
    ("rails_exception", dict(title="Action Controller: Exception caught")),
    ("phpinfo", dict(title="PHP 8.2.1 - phpinfo()")),
    ("apache_server_status", dict(title="Apache Status")),
    ("apache_server_info", dict(title="Server Information", server="Apache/2.4.57")),
    ("struts_problem_report", dict(title="Struts Problem Report")),
    ("tomcat_error_500", dict(title="HTTP Status 500 – Internal Server Error")),
    ("wordpress_setup_config", dict(title="WordPress › Setup Configuration File")),
    ("joomla_installer", dict(title="Joomla! Web Installer")),
    ("drupal_installer", dict(title="Choose language | Drupal")),
    ("moodle_installer", dict(title="Installation - Moodle")),
    ("gitea_installer", dict(title="Installation - Gitea: Git with a cup of tea")),
    ("forgejo_installer", dict(title="Installation - Forgejo: Beyond coding. We Forge.")),
    ("typo3_installer", dict(title="Installing TYPO3 CMS")),
    ("wikijs_setup", dict(title="Wiki.js Setup")),
    ("phpmyadmin_setup", dict(title="phpMyAdmin setup")),
    ("python_simplehttp", dict(server="SimpleHTTP/0.6 Python/3.12.1")),
    ("werkzeug_dev_server", dict(server="Werkzeug/3.0.1 Python/3.12.1")),
    ("ruby_webrick", dict(server="WEBrick/1.8.1 (Ruby/3.2.2/2023-03-30)")),
    ("python_wsgiref", dict(server="WSGIServer/0.2 CPython/3.11.4")),
    ("python_basehttp", dict(server="BaseHTTP/0.6 Python/3.8.10")),
    ("index_of", dict(title="Index of /files/")),
    ("iis_listing", dict(title="www.example.test - /files/", server="Microsoft-IIS/10.0",
                         host="www.example.test")),
    ("python_listing", dict(title="Directory listing for /")),
    ("tomcat_listing", dict(title="Directory Listing For [/docs/]")),
    ("jetty_listing", dict(title="Directory: /static/")),
    ("hacked_by", dict(title="Hacked by Someone", path="/")),
]


@pytest.mark.parametrize("problem,page", POSITIVE, ids=[p for p, _ in POSITIVE])
def test_every_row_matches_its_own_example(problem, page):
    assert problem in _problem(**page)


def test_every_page_rule_has_an_example():
    covered = {p for p, _ in POSITIVE}
    missing = {r.problem for r in ps.PAGE_RULES} - covered
    # Family members that share a test shape with a listed sibling.
    missing -= {"yii_debugger", "pyramid_debug_toolbar", "prestashop_installer", "flarum_installer"}
    assert missing == set()


@pytest.mark.parametrize("page", [
    dict(title="Sign in [Jenkins]", status=200),
    dict(title="WordPress › Installation"),
    dict(server="gunicorn/21.2.0"),
    dict(server="uvicorn"),
    dict(server="TornadoServer/6.3"),
    dict(title="Store unavailable", status=402),
    dict(title="Everything", status=200),
    dict(title="Telescope", status=200),
    dict(title="402 Please renew your subscription."),
    dict(title="404: NOT_FOUND"),
    dict(title="Runtime Error"),
    dict(title="Hacked by Someone", path="/blog/x"),
    dict(title="Monthly report - /archive", host="www.example.test"),
    dict(title="JupyterLab", status=200, path="/labels"),
    dict(title="phpMyAdmin", status=200),
    dict(title="Site not found", server="nginx", status=404),
])
def test_near_misses_match_nothing(page):
    assert ps.match_page(**page) == []


def test_family_a_needs_status_200():
    assert ps.match_page(title="Dashboard [Jenkins]", status=401) == []
    assert ps.match_page(title="Dashboard [Jenkins]") == []          # unknown status
    assert _problem(title="Dashboard [Jenkins]", status="200") == ["jenkins_dashboard_open"]


def test_normalisation():
    assert _problem(title="WordPress &rsaquo; Setup Configuration File") == ["wordpress_setup_config"]
    assert _problem(title="  Installation - Gitea:  Git with a   cup of tea ") == ["gitea_installer"]
    assert _problem(title="DAGS - AIRFLOW", status=200) == ["airflow_open"]


def test_a_takeover_row_carries_provider_outcome_and_outcome_severity():
    likely = _families(title="project not found", server="Surge")["takeover"]
    assert (likely["provider"], likely["outcome"], likely["severity"]) == ("surge", "likely_takeover", "high")
    possible = _families(title="No such app", server="Heroku", status=404)["takeover"]
    assert (possible["outcome"], possible["severity"]) == ("possible_takeover", "medium")
    dangling = _families(title="Store unavailable", status=404)["takeover"]
    assert (dangling["outcome"], dangling["severity"]) == ("dangling_dns", "low")


def test_s3_needs_an_s3_cname_when_the_cname_is_known():
    page = dict(server="AmazonS3", status=404, path="/", mime_type="application/xml")
    assert ps.match_page(**page, cname=["d111.cloudfront.net"]) == []
    assert ps.match_page(**page, cname=[]) == []
    # Unknown CNAME: left to the takeover verdict, which checks it.
    assert _problem(**page) == ["s3_bucket_missing"]
    assert ps.match_page(**{**page, "title": "Error"}, cname=["b.s3.amazonaws.com"]) == []


def test_a_listing_of_a_sensitive_folder_is_high():
    assert _families(title="Index of /backup/")["directory_listing"]["severity"] == "high"
    assert _families(title="Index of /", path="/db/")["directory_listing"]["severity"] == "high"
    assert _families(title="Index of /feedback/")["directory_listing"]["severity"] == "medium"


def test_one_match_per_family_and_families_combine():
    found = _families(title="Console // Werkzeug Debugger", server="Werkzeug/3.0.1 Python/3.12")
    assert set(found) == {"debug_page", "dev_server"}
    assert found["debug_page"]["problem"] == "werkzeug_debugger_console"
    assert found["dev_server"]["matched"] == "Werkzeug/3.0.1 Python/3.12"


class TestCertificates:
    def test_issuer_rules(self):
        staging = ps.match_certificate("CN=(STAGING) Artificial Apricot R3,O=(STAGING) Let's Encrypt,C=US")
        assert [m["problem"] for m in staging] == ["letsencrypt_staging"]
        k8s = ps.match_certificate("O=Acme Co,CN=Kubernetes Ingress Controller Fake Certificate")
        assert [m["problem"] for m in k8s] == ["kubernetes_ingress_fake_cert"]
        traefik = ps.match_certificate("", "TRAEFIK DEFAULT CERT")
        assert [m["problem"] for m in traefik] == ["traefik_default_cert"]

    def test_urlscan_issuer_is_a_cn(self):
        assert [m["problem"] for m in ps.match_certificate("Kubernetes Ingress Controller Fake Certificate")] \
            == ["kubernetes_ingress_fake_cert"]
        assert ps.match_certificate("R11") == []

    def test_expired_at_the_visit_is_low(self):
        found = ps.match_certificate("R3", age_days=120, valid_days=90)
        assert [(m["problem"], m["severity"]) for m in found] == [("expired_at_visit", "low")]
        assert ps.match_certificate("R3", age_days=10, valid_days=90) == []

    def test_a_real_issuer_matches_nothing(self):
        assert ps.match_certificate("CN=R11,O=Let's Encrypt,C=US") == []


@pytest.mark.parametrize("bad", [None, 5, b"x", {"a": 1}, ["x"]])
def test_never_raises(bad):
    assert ps.match_page(title=bad, server=bad, status=bad, mime_type=bad, cname=bad) == []
    assert isinstance(ps.match_certificate(bad, bad, bad, bad), list)
