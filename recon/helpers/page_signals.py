"""Problem pages (item 5): what a page's title, its Server header or its
certificate alone says about it.

One catalog, checked against two sources that already hold the data, so it
costs no request: urlscan's history (the URLScan section's Takeover Pages and
Problem Pages switches) and this scan's live pages and certificates (the
Security Checks' Page Content group). Pure, never raising.

The rows come from the nuclei-templates title matchers, can-i-take-over-xyz,
the products' own source and urlscan's real `page.title` / `page.server`
values (web research of 5 Nov 2026). Matching is exact unless a row says
prefix, suffix or regex, on a normalised title (entities decoded, NFKC, runs of
spaces collapsed), compared case-insensitively. A generic title is accepted
only with its condition (Server header, status, path).

Left out on purpose: Tilda's "402 Please renew your subscription." (the site is
still owned), Spring's Whitelabel page (no title), Laravel Ignition and
Symfony's exception page (the title is the error message), ASP.NET's "Runtime
Error" (hides the details), "WordPress › Installation" (an installed site shows
it too), voidtools' "Everything" and Laravel's "Telescope" (too generic), and
the takeover providers recognised only by the body or by NXDOMAIN (those stay
with the Subdomain Takeover module).
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

#: Catalog family -> (live security_check type, urlscan history type). One
#: type per family on both sides, so a "false positive" on a folder listing
#: never teaches down open consoles on the Priority Board.
FAMILY_TYPES = {
    "takeover": ("takeover_error_page", "takeover_page_seen"),
    "open_console": ("open_console", "open_console_seen"),
    "debug_page": ("debug_page", "debug_page_seen"),
    "unfinished_installer": ("unfinished_installer", "installer_seen"),
    "dev_server": ("dev_server", "dev_server_seen"),
    "directory_listing": ("directory_listing", "directory_listing_seen"),
    "defaced_page": ("defaced_page", "defaced_page_seen"),
    "test_certificate": ("test_certificate", "test_certificate_seen"),
}

#: The server and the certificate belong to the host: a Werkzeug site with 500
#: urlscan paths is one finding, not 500.
PER_HOST_FAMILIES = frozenset({"takeover", "dev_server", "test_certificate"})

#: A takeover row's outcome -> severity, when this scan confirms it.
OUTCOME_SEVERITY = {"likely_takeover": "high", "possible_takeover": "medium", "dangling_dns": "low"}

FAMILY_LABEL = {
    "takeover": "cloud provider's deleted-service page",
    "open_console": "console open without login",
    "debug_page": "debug page",
    "unfinished_installer": "unfinished installer",
    "dev_server": "development server",
    "directory_listing": "folder listing",
    "defaced_page": "defaced page",
    "test_certificate": "test or default certificate",
}


@dataclass(frozen=True)
class Rule:
    family: str
    problem: str
    label: str
    severity: str = "medium"
    #: ((how, text), ...) alternatives; how is exact | prefix | suffix | regex | none.
    titles: tuple = ()
    #: ((how, text), ...) alternatives; how is exact | prefix | product (the
    #: name before the first "/": "Werkzeug/3.0 Python/3.12" is werkzeug).
    server: tuple = ()
    status: frozenset = frozenset()
    #: (how, text); how is exact | prefix | contains | regex.
    path: tuple = ()
    url_contains: str = ""
    mime_contains: str = ""
    #: A regex the CNAME must match when the CNAME is known.
    cname: str = ""
    #: The title must be followed by " - /" after the host's own name (IIS).
    host_listing: bool = False
    #: Only on the host's root page: a blog post titled "Hacked by" is no defacement.
    root_only: bool = False
    provider: str = ""
    outcome: str = ""


def _t(*titles: str, how: str = "exact") -> tuple:
    return tuple((how, t) for t in titles)


_OK = frozenset({200})
_404 = frozenset({404})


def _console(problem, label, titles, severity, **kw) -> Rule:
    # Many of these tools have no login, or only browser Basic auth: a
    # protected one answers 401 without the app's title. A 200 with the
    # app's title means it is open.
    return Rule("open_console", problem, label, severity, titles=titles, status=_OK, **kw)


TAKEOVER_RULES = (
    Rule("takeover", "surge_project_not_found", "Surge", titles=_t("project not found"),
         server=_t("Surge"), provider="surge", outcome="likely_takeover"),
    Rule("takeover", "ghost_domain_error", "Ghost", titles=_t("Domain error"),
         server=_t("openresty"), status=_404, provider="ghost", outcome="likely_takeover"),
    Rule("takeover", "uberflip_non_hub_domain", "Uberflip", titles=_t("Non-hub domain"),
         status=_404, provider="uberflip", outcome="likely_takeover"),
    Rule("takeover", "pingdom_status_page_missing", "Pingdom",
         titles=_t("404 - Status Page not Found"), status=_404, provider="pingdom",
         outcome="likely_takeover"),
    Rule("takeover", "anima_page_not_found", "Anima", titles=_t("Anima - Page Not Found"),
         server=_t("AmazonS3"), status=_OK, provider="anima", outcome="likely_takeover"),
    Rule("takeover", "readthedocs_project_not_found", "Read the Docs",
         titles=_t("Project not found - Read the Docs Community"), provider="readthedocs",
         outcome="likely_takeover"),
    Rule("takeover", "canny_page_not_found", "Canny", titles=_t("Page Not Found | Canny"),
         provider="canny", outcome="likely_takeover"),
    Rule("takeover", "helpjuice_404", "Helpjuice", titles=_t("Helpjuice – 404"),
         server=_t("Heroku"), status=_404, provider="helpjuice", outcome="likely_takeover"),
    Rule("takeover", "hatenablog_not_found", "HatenaBlog",
         titles=_t("お探しのページは見つかりませんでした。 - はてなブログ"), status=_404,
         provider="hatenablog", outcome="likely_takeover"),
    # Without the body a missing bucket and a missing object look the same.
    Rule("takeover", "s3_bucket_missing", "AWS S3", titles=(("none", ""),), server=_t("AmazonS3"),
         status=_404, path=("exact", "/"), mime_contains="xml",
         cname=r"(?:^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com\.?$", provider="aws-s3",
         outcome="possible_takeover"),
    # The owner can block these with a DNS verification record.
    Rule("takeover", "github_pages_site_not_found", "GitHub Pages",
         titles=_t("Site not found · GitHub Pages"), server=_t("GitHub.com"), status=_404,
         provider="github-pages", outcome="possible_takeover"),
    Rule("takeover", "heroku_no_such_app", "Heroku", titles=_t("No such app"),
         server=_t("Heroku", "heroku-router"), status=_404, provider="heroku",
         outcome="possible_takeover"),
    Rule("takeover", "wix_connect_domain_error", "Wix", titles=_t("ConnectYourDomain Error | Wix.com"),
         status=_404, provider="wix", outcome="possible_takeover"),
    Rule("takeover", "framer_site_not_found", "Framer", titles=_t("Site Not Found | Framer"),
         server=_t("Framer/", how="prefix"), status=_404, provider="framer",
         outcome="possible_takeover"),
    # A verification record now blocks these: the name points nowhere useful,
    # but nobody else can claim it.
    Rule("takeover", "netlify_site_not_found", "Netlify", titles=_t("Site not found"),
         server=_t("Netlify"), status=_404, provider="netlify", outcome="dangling_dns"),
    Rule("takeover", "azure_web_app_404", "Azure App Service",
         titles=_t("Microsoft Azure Web App - Error 404"), status=_404,
         provider="azure-app-service", outcome="dangling_dns"),
    # A 402 is a closed store, still owned.
    Rule("takeover", "shopify_store_unavailable", "Shopify", titles=_t("Store unavailable"),
         status=_404, provider="shopify", outcome="dangling_dns"),
    Rule("takeover", "fastly_unknown_domain", "Fastly",
         titles=_t("Fastly error: unknown domain", how="prefix"), status=frozenset({500}),
         provider="fastly", outcome="dangling_dns"),
    Rule("takeover", "pantheon_unknown_site", "Pantheon", titles=_t("404 - Unknown site"),
         server=_t("Pantheon"), provider="pantheon", outcome="dangling_dns"),
    Rule("takeover", "zendesk_help_center_closed", "Zendesk", titles=_t("Help Center Closed"),
         url_contains="help-center-closed", provider="zendesk", outcome="dangling_dns"),
)

CONSOLE_RULES = (
    _console("jupyter_notebook_open", "Jupyter Notebook",
             _t("Home Page - Select or create a notebook"), "critical"),
    # Title unverified; the path keeps it to JupyterLab's own page.
    _console("jupyterlab_open", "JupyterLab", _t("JupyterLab"), "critical",
             path=("regex", r"^/lab(?:/|$)")),
    _console("ttyd_terminal_open", "ttyd web terminal", _t("ttyd - Terminal"), "critical"),
    _console("ray_dashboard_open", "Ray dashboard (CVE-2023-48022)", _t("Ray Dashboard"), "critical"),
    _console("mongo_express_open", "Mongo Express",
             _t("Home - Mongo Express", "system.users - Mongo Express"), "critical"),
    _console("phpmyadmin_logged_in", "phpMyAdmin, already logged in",
             _t(r"^.+ \| phpMyAdmin [0-9.]+$", how="regex"), "critical"),
    _console("hadoop_yarn_open", "Hadoop YARN", _t("All Applications", "RUNNING Applications"),
             "critical", server=_t("Jetty", how="prefix")),
    _console("tomcat_manager_open", "Tomcat Manager", _t("/manager"), "critical",
             path=("prefix", "/manager")),
    _console("aem_groovy_console_open", "AEM Groovy Console", _t("Groovy Console"), "critical",
             path=("contains", "/groovyconsole")),
    # Unverified titles: the console runs code on the controller.
    _console("jenkins_script_console_open", "Jenkins script console",
             _t("Script Console - Jenkins", "Script Console [Jenkins]"), "critical"),
    _console("jenkins_dashboard_open", "Jenkins", _t("Dashboard [Jenkins]", "Dashboard - Jenkins"),
             "high"),
    _console("jenkins_open_signup", "Jenkins open sign-up",
             _t("Register - Jenkins", "Register [Jenkins]", "Create an account! [Jenkins]"), "high"),
    _console("spark_master_open", "Spark Master", _t("Spark Master at spark://", how="prefix"), "high"),
    _console("spark_application_open", "Spark application", _t(" - Spark Jobs", how="suffix"),
             "medium"),
    _console("flink_dashboard_open", "Apache Flink", _t("Apache Flink Web Dashboard"), "high"),
    _console("airflow_open", "Airflow", _t("DAGs - Airflow", "Airflow - DAGs"), "high"),
    _console("aem_crx_anonymous", "AEM CRX, anonymous", _t("Content Explorer - UserID: anonymous"),
             "high"),
    _console("selenium_grid_open", "Selenium Grid", _t("WebDriver Hub"), "high"),
    _console("alertmanager_open", "Alertmanager", _t("Alertmanager"), "high"),
    _console("druid_console_open", "Apache Druid", _t("Apache Druid"), "high"),
    _console("drill_console_open", "Apache Drill", _t("Apache Drill"), "high"),
    _console("envoy_admin_open", "Envoy admin", _t("Envoy Admin"), "high"),
    _console("kafka_ui_open", "Kafka UI",
             _t("UI for Apache Kafka", "Kafdrop: Broker List", "Kafka Manager"), "medium"),
    _console("prometheus_open", "Prometheus",
             _t("Prometheus Time Series Collection and Processing Server"), "medium"),
    _console("hdfs_namenode_open", "HDFS NameNode", _t("Namenode information"), "medium"),
    _console("cadvisor_open", "cAdvisor", _t("cAdvisor - /"), "medium"),
    _console("netdata_open", "Netdata", _t("netdata dashboard"), "medium"),
    # Ships with the default password admin@123.
    _console("tiny_file_manager_open", "Tiny File Manager", _t("Tiny File Manager", how="prefix"),
             "high"),
    _console("shell_in_a_box_open", "Shell In A Box", _t("Shell In A Box"), "medium"),
)

DEBUG_RULES = (
    Rule("debug_page", "werkzeug_debugger_console", "Werkzeug debugger console", "high",
         titles=_t("Console // Werkzeug Debugger")),
    Rule("debug_page", "werkzeug_traceback", "Werkzeug traceback", "high",
         titles=_t(" // Werkzeug Debugger", how="suffix")),
    Rule("debug_page", "django_debug_error", "Django error page with DEBUG on", "high",
         titles=_t(r"^[A-Za-z_][\w.]* at /", how="regex")),
    Rule("debug_page", "django_debug_404", "Django 404 page with DEBUG on", "medium",
         titles=_t("Page not found at /", how="prefix")),
    Rule("debug_page", "django_default_page", "Django default page", "medium",
         titles=_t("The install worked successfully! Congratulations!")),
    Rule("debug_page", "laravel_whoops", "Laravel debug page (Whoops)", "high",
         titles=_t("Whoops! There was an error.")),
    Rule("debug_page", "symfony_profiler", "Symfony profiler", "high", titles=_t("Symfony Profiler")),
    Rule("debug_page", "symfony_welcome", "Symfony development welcome page", "medium",
         titles=_t("Welcome to Symfony!")),
    Rule("debug_page", "rails_exception", "Rails exception page", "medium",
         titles=_t("Action Controller: Exception caught")),
    Rule("debug_page", "phpinfo", "phpinfo()", "medium",
         titles=_t("phpinfo()") + _t(r"^PHP [0-9.]+ - phpinfo\(\)$", how="regex")),
    Rule("debug_page", "apache_server_status", "Apache server-status", "medium",
         titles=_t("Apache Status")),
    Rule("debug_page", "apache_server_info", "Apache server-info", "medium",
         titles=_t("Server Information"), server=_t("Apache", how="prefix")),
    Rule("debug_page", "yii_debugger", "Yii debugger", "medium", titles=_t("Yii Debugger")),
    Rule("debug_page", "struts_problem_report", "Struts problem report", "medium",
         titles=_t("Struts Problem Report")),
    Rule("debug_page", "pyramid_debug_toolbar", "Pyramid debug toolbar", "medium",
         titles=_t("Pyramid Debug Toolbar")),
    Rule("debug_page", "tomcat_error_500", "Tomcat error page", "low",
         titles=_t("HTTP Status 500 – Internal Server Error")),
)

INSTALLER_RULES = (
    Rule("unfinished_installer", "wordpress_setup_config", "WordPress", "critical",
         titles=_t("WordPress › Setup Configuration File")),
    Rule("unfinished_installer", "joomla_installer", "Joomla", "high", titles=_t("Joomla! Web Installer")),
    Rule("unfinished_installer", "drupal_installer", "Drupal", "high", titles=_t("Choose language | Drupal")),
    Rule("unfinished_installer", "moodle_installer", "Moodle", "high", titles=_t("Installation - Moodle")),
    Rule("unfinished_installer", "gitea_installer", "Gitea", "high",
         titles=_t("Installation - Gitea: Git with a cup of tea")),
    Rule("unfinished_installer", "forgejo_installer", "Forgejo", "high",
         titles=_t("Installation - Forgejo: Beyond coding. We Forge.")),
    Rule("unfinished_installer", "typo3_installer", "TYPO3", "high", titles=_t("Installing TYPO3 CMS")),
    Rule("unfinished_installer", "prestashop_installer", "PrestaShop", "high",
         titles=_t("PrestaShop Installation Assistant")),
    Rule("unfinished_installer", "flarum_installer", "Flarum", "high", titles=_t("Install Flarum")),
    Rule("unfinished_installer", "wikijs_setup", "Wiki.js", "high", titles=_t("Wiki.js Setup")),
    Rule("unfinished_installer", "phpmyadmin_setup", "phpMyAdmin setup", "medium",
         titles=_t("phpMyAdmin setup")),
)

#: Production servers (gunicorn, uvicorn, TornadoServer, waitress, Kestrel) and
#: Puma and PHP's built-in server (no Server header) are never flagged.
DEV_SERVER_RULES = (
    # `python -m http.server`: almost always a file listing.
    Rule("dev_server", "python_simplehttp", "Python http.server (SimpleHTTP)", "high",
         server=_t("SimpleHTTP", how="product")),
    Rule("dev_server", "werkzeug_dev_server", "Werkzeug development server", "medium",
         server=_t("Werkzeug", how="product")),
    Rule("dev_server", "ruby_webrick", "Ruby WEBrick", "medium", server=_t("WEBrick", how="product")),
    # Prometheus exporters and many embedded tools use these too.
    Rule("dev_server", "python_wsgiref", "Python wsgiref (WSGIServer)", "low",
         server=_t("WSGIServer", how="product")),
    Rule("dev_server", "python_basehttp", "Python BaseHTTP", "low", server=_t("BaseHTTP", how="product")),
)

LISTING_RULES = (
    Rule("directory_listing", "index_of", "folder listing (Index of)", titles=_t("Index of /", how="prefix")),
    Rule("directory_listing", "iis_listing", "IIS folder listing", host_listing=True,
         server=_t("Microsoft-IIS", how="prefix")),
    Rule("directory_listing", "python_listing", "Python http.server folder listing",
         titles=_t("Directory listing for /", how="prefix")),
    Rule("directory_listing", "tomcat_listing", "Tomcat folder listing",
         titles=_t("Directory Listing For [/", how="prefix")),
    Rule("directory_listing", "jetty_listing", "Jetty folder listing", titles=_t("Directory: /", how="prefix")),
)

DEFACEMENT_RULES = (
    Rule("defaced_page", "hacked_by", "defaced page (\"Hacked by\")", "critical",
         titles=_t(r"\bhacked by\b", how="regex"), root_only=True),
)

PAGE_RULES = TAKEOVER_RULES + CONSOLE_RULES + DEBUG_RULES + INSTALLER_RULES \
    + DEV_SERVER_RULES + LISTING_RULES + DEFACEMENT_RULES

#: A listing of one of these folders is worse than a listing of images.
_SENSITIVE_LISTING = re.compile(r"(?:^|[/_.\-])(?:backups?|git|dumps?|db|exports?)(?:$|[/_.\-])", re.I)
_CN_IN_DN = re.compile(r"(?:^|[,/]\s*)CN\s*=\s*([^,/]+)", re.I)


def normalise(text: Any) -> str:
    """Entities decoded (&rsaquo; is ›), Unicode NFKC, runs of spaces
    collapsed to one, ends trimmed."""
    if not isinstance(text, str) or not text:
        return ""
    try:
        text = unicodedata.normalize("NFKC", html.unescape(text))
    except Exception:  # noqa: BLE001
        return ""
    return re.sub(r"\s+", " ", text).strip()


def _status(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _path_of(path: str, url: str) -> str:
    if path:
        return path if path.startswith("/") else "/" + path
    try:
        return urlsplit(url or "").path or "/"
    except ValueError:
        return "/"


def _cnames(cname: Any) -> Optional[list]:
    """None when the CNAME is unknown, else the (possibly empty) list."""
    if cname is None:
        return None
    if isinstance(cname, str):
        cname = [cname]
    if not isinstance(cname, (list, tuple, set)):
        return None
    return [str(c).strip().rstrip(".").lower() for c in cname if isinstance(c, str) and c.strip()]


def _title_ok(rule: Rule, title: str, host: str) -> bool:
    if rule.host_listing:
        return bool(host) and title.casefold().startswith(f"{host.casefold()} - /")
    folded = title.casefold()
    for how, text in rule.titles:
        if how == "none" and not title:
            return True
        if not title:
            continue
        if how == "exact" and folded == text.casefold():
            return True
        if how == "prefix" and folded.startswith(text.casefold()):
            return True
        if how == "suffix" and folded.endswith(text.casefold()):
            return True
        if how == "regex" and re.search(text, title, re.I):
            return True
    return False


def _server_ok(rule: Rule, server: str) -> bool:
    if not rule.server:
        return True
    folded = server.casefold()
    product = folded.split("/", 1)[0].strip()
    for how, text in rule.server:
        want = text.casefold()
        if how == "exact" and folded == want:
            return True
        if how == "prefix" and folded.startswith(want):
            return True
        if how == "product" and product == want:
            return True
    return False


def _path_ok(rule: Rule, path: str) -> bool:
    if not rule.path:
        return True
    how, text = rule.path
    low = path.lower()
    if how == "exact":
        return low == text
    if how == "prefix":
        return low.startswith(text)
    if how == "contains":
        return text in low
    return bool(re.search(text, low))


def _cname_ok(rule: Rule, cnames: Optional[list]) -> bool:
    if not rule.cname or cnames is None:
        # Unknown: the takeover verdict checks the CNAME before anything is kept.
        return True
    return any(re.search(rule.cname, c) for c in cnames)


def _rule_matches(rule: Rule, title: str, server: str, status: Optional[int], path: str,
                  mime: str, host: str, url: str, cnames: Optional[list]) -> bool:
    if not (rule.titles or rule.host_listing) and not rule.server:
        return False
    if (rule.titles or rule.host_listing) and not _title_ok(rule, title, host):
        return False
    if rule.server and not _server_ok(rule, server):
        return False
    if rule.status and status not in rule.status:
        return False
    if rule.root_only and path != "/":
        return False
    if not _path_ok(rule, path):
        return False
    if rule.url_contains and rule.url_contains not in (url or "").lower():
        return False
    if rule.mime_contains and rule.mime_contains not in (mime or "").lower():
        return False
    return _cname_ok(rule, cnames)


def _match(rule: Rule, matched: str, severity: str = "") -> dict:
    return {"family": rule.family, "problem": rule.problem, "label": rule.label,
            "severity": severity or rule.severity, "matched": matched[:300],
            "provider": rule.provider, "outcome": rule.outcome}


def match_page(title: Any = "", server: Any = "", status: Any = None, path: str = "",
               mime_type: Any = "", host: str = "", url: str = "", cname: Any = None) -> list:
    """The problem rows a page matches, at most one per family (the first row
    of a family wins). `status` None means unknown, which no status condition
    accepts; `cname` None means unknown, which a CNAME condition leaves to the
    takeover verdict. Never raises."""
    try:
        t = normalise(title)
        s = normalise(server)
        st = _status(status)
        p = _path_of(path or "", url or "")
        h = (host or "").strip().strip(".").lower()
        if not h and url:
            h = (urlsplit(url).hostname or "").lower()
        mime = normalise(mime_type)
        cnames = _cnames(cname)
        out, families = [], set()
        for rule in PAGE_RULES:
            if rule.family in families:
                continue
            if not _rule_matches(rule, t, s, st, p, mime, h, url or "", cnames):
                continue
            families.add(rule.family)
            severity = OUTCOME_SEVERITY.get(rule.outcome, rule.severity)
            if rule.family == "directory_listing":
                listed = t.split(" ", 2)[-1] if t else ""
                if _SENSITIVE_LISTING.search(p) or _SENSITIVE_LISTING.search(listed):
                    severity = "high"
            matched = s if rule.family == "dev_server" else (t or s)
            out.append(_match(rule, matched, severity))
        return out
    except Exception:  # noqa: BLE001
        return []


CERT_RULES = (
    Rule("test_certificate", "kubernetes_ingress_fake_cert",
         "Kubernetes Ingress controller's default certificate"),
    Rule("test_certificate", "traefik_default_cert", "Traefik's default certificate"),
    Rule("test_certificate", "letsencrypt_staging", "Let's Encrypt staging certificate"),
    Rule("test_certificate", "expired_at_visit", "certificate already expired at the visit", "low"),
)
_CERT_RULE = {r.problem: r for r in CERT_RULES}


def issuer_cn(issuer: Any = "", cn: Any = "") -> str:
    """The issuer's common name: the CN field, else the CN= part of the DN,
    else the issuer itself when it is no DN (urlscan's tlsIssuer)."""
    if isinstance(cn, str) and cn.strip():
        return normalise(cn)
    text = normalise(issuer if isinstance(issuer, str) else "")
    found = _CN_IN_DN.search(text)
    if found:
        return found.group(1).strip()
    return "" if "=" in text else text


def match_certificate(issuer: Any = "", cn: Any = "", age_days: Any = None,
                      valid_days: Any = None) -> list:
    """Family X, one match at most: a default certificate of an ingress (the
    host is one the ingress does not know), a Let's Encrypt staging certificate
    (a test deployment), or, urlscan only, a certificate already expired when
    the visit was made (a neglected host; live expiry is the TLS Expired
    check). Never raises."""
    try:
        dn = normalise(issuer if isinstance(issuer, str) else "")
        name = issuer_cn(issuer, cn)
        folded = name.casefold()
        if folded == "kubernetes ingress controller fake certificate":
            return [_match(_CERT_RULE["kubernetes_ingress_fake_cert"], name)]
        if folded == "traefik default cert":
            return [_match(_CERT_RULE["traefik_default_cert"], name)]
        if "(staging)" in dn.casefold() or "(staging)" in folded:
            return [_match(_CERT_RULE["letsencrypt_staging"], dn or name)]
        age, valid = _status(age_days), _status(valid_days)
        if age is not None and valid is not None and valid > 0 and age > valid:
            return [_match(_CERT_RULE["expired_at_visit"], f"tlsAgeDays={age} > tlsValidDays={valid}")]
        return []
    except Exception:  # noqa: BLE001
        return []
