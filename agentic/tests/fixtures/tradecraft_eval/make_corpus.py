"""The synthetic corpus of the Tradecraft search measurement (T2.7, Q15): about 1,800 short
pages across four synthetic sites, and the questions asked of them.

Every host is under the reserved ``.test`` domain or the made-up ``tc-eval`` GitHub owner; every
CVE id is in the year 2098, so none names a real advisory; every page is generated text about
lab techniques. Standard library only, deterministic: ``build(root)`` writes the sites under
``root`` (served by ``tradecraft_doubles.FixtureFetcher``) and returns each page's title and
sections; ``python make_corpus.py`` rewrites ``questions.jsonl`` next to this file.

    wiki.tc-eval.test        an MkDocs wiki with sitemap.xml          (Live in the measurement)
    github.com/tc-eval/lib   a repository of Markdown payload files     (Stored)
    docs.tc-eval.test        Sphinx docs of a made-up tool, searchindex (Live)
    blog.tc-eval.test        a website of lab write-ups, crawled        (Stored)
"""

from __future__ import annotations

import json
import random
import sys
from html import escape
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIKI, DOCS, BLOG = "https://wiki.tc-eval.test/", "https://docs.tc-eval.test/", "https://blog.tc-eval.test/"
REPO = "https://github.com/tc-eval/lib"
RAW = "https://raw.githubusercontent.com/tc-eval/lib/main/"

# topic id -> (label, techniques [(slug, label, situation, words)], technologies)
TOPICS = {
    "sql_injection": ("SQL injection", [
        ("union-based", "Union-based extraction", "pull rows out through the page by matching the column count",
         "union select order by column count"),
        ("error-based", "Error-based extraction", "make the database print the value inside its error message",
         "extractvalue cast convert error message"),
        ("boolean-blind", "Boolean-based blind", "infer a value from a page that only changes between true and false",
         "substring ascii true false comparison"),
        ("time-based-blind", "Time-based blind", "confirm a condition with a delay when nothing is reflected",
         "sleep pg_sleep waitfor delay benchmark"),
        ("stacked-queries", "Stacked queries", "run a second statement after a semicolon",
         "semicolon batch second statement"),
        ("out-of-band", "Out-of-band exfiltration", "send the extracted value to a server you control over DNS",
         "dns lookup load_file utl_http exfiltration"),
    ], ["PostgreSQL", "MySQL", "MSSQL", "Oracle", "SQLite", "MariaDB"]),
    "xss": ("Cross-site scripting", [
        ("reflected", "Reflected XSS", "a parameter comes back in the page without encoding",
         "reflected parameter script alert"),
        ("stored", "Stored XSS", "a comment you save runs script for every visitor",
         "stored comment persistent payload"),
        ("dom-based", "DOM-based XSS", "client side code writes the location hash into the page",
         "innerhtml location hash sink source"),
        ("csp-bypass", "CSP bypass", "the content security policy blocks inline script",
         "content security policy nonce jsonp gadget"),
        ("filter-evasion", "Filter evasion", "angle brackets and the word script are stripped",
         "encoding event handler svg onload"),
        ("polyglots", "Polyglot payloads", "one payload that works in several contexts at once",
         "polyglot context attribute"),
    ], ["React", "Angular", "Vue.js", "WordPress", "Drupal", "Express"]),
    "ssrf": ("SSRF", [
        ("basic", "Basic SSRF", "the server fetches any URL you give it", "url fetch internal service"),
        ("cloud-metadata", "Cloud metadata via SSRF", "read the instance credentials from the metadata address",
         "metadata 169.254.169.254 instance credentials imds"),
        ("blind", "Blind SSRF", "the fetch happens but nothing comes back to you", "blind callback out of band"),
        ("dns-rebinding", "DNS rebinding", "the address check passes then the name resolves internally",
         "rebinding ttl resolver"),
        ("filter-bypass", "SSRF filter bypass", "localhost and private ranges are blocked by a deny list",
         "decimal ip redirect bypass"),
        ("protocol-smuggling", "Protocol smuggling", "reach a plain text service through the fetcher",
         "gopher dict smuggling"),
    ], ["AWS", "Azure", "Google Cloud", "Redis", "Kubernetes", "Jenkins"]),
    "path_traversal": ("Path traversal", [
        ("dot-dot-slash", "Dot-dot-slash traversal", "read a file outside the web root through a file parameter",
         "dot dot slash etc passwd"),
        ("php-wrappers", "PHP wrappers for LFI", "turn a local file inclusion into source disclosure",
         "php filter base64 wrapper include"),
        ("log-poisoning", "Log poisoning", "get code to run through an included log file",
         "access log user agent include"),
        ("zip-slip", "Zip slip", "an archive extraction writes outside its folder", "archive extraction entry name"),
        ("encoding-bypass", "Traversal encoding bypass", "the dots and slashes are filtered",
         "double encoding unicode overlong"),
    ], ["PHP", "nginx", "Apache", "IIS", "Tomcat", "Node.js"]),
    "xxe": ("XXE", [
        ("classic", "Classic XXE", "an XML upload echoes an entity you define", "external entity doctype system"),
        ("out-of-band", "Out-of-band XXE", "the parser resolves entities but shows nothing",
         "parameter entity dtd callback"),
        ("error-based", "Error-based XXE", "read a file through a parser error message", "error dtd nonexistent"),
        ("xinclude", "XInclude attack", "you control only one value inside the XML", "xinclude parse text"),
        ("svg-upload", "XXE through SVG upload", "an image upload accepts SVG", "svg image upload"),
    ], ["Java", "PHP", "ASP.NET", "Spring", "Apache", "Tomcat"]),
    "active_directory": ("Active Directory", [
        ("kerberoasting", "Kerberoasting", "crack the password of a service account offline",
         "service principal name tgs ticket hashcat"),
        ("asrep-roasting", "AS-REP roasting", "accounts that do not require preauthentication",
         "preauthentication as rep hash"),
        ("ntlm-relay", "NTLM relay", "forward a captured authentication to another host",
         "relay coercion signing responder"),
        ("adcs-esc1", "AD CS ESC1", "a certificate template lets you choose the subject",
         "certificate template subject alternative name certipy"),
        ("dcsync", "DCSync", "replicate password hashes like a domain controller", "replication drsuapi secretsdump"),
        ("delegation", "Delegation abuse", "a computer is trusted to act for other users",
         "unconstrained constrained resource based delegation"),
    ], ["Active Directory", "Kerberos", "LDAP", "AD CS", "Exchange", "BloodHound"]),
    "privilege_escalation": ("Privilege escalation", [
        ("suid", "SUID binaries", "a binary runs as root whatever user starts it", "suid gtfobins find"),
        ("sudo", "Sudo misconfiguration", "sudo lets you run one command as root", "sudo nopasswd env_keep"),
        ("kernel", "Kernel exploits", "the kernel is old and unpatched", "kernel version exploit"),
        ("token-impersonation", "Token impersonation", "a service account holds the impersonate privilege",
         "seimpersonate potato token"),
        ("uac-bypass", "UAC bypass", "an administrator token is split by user account control",
         "uac auto elevate fodhelper"),
    ], ["Docker", "Kubernetes", "Jenkins", "Redis", "MySQL", "PostgreSQL"]),
    "containers": ("Containers", [
        ("docker-socket", "Docker socket escape", "the container can reach the docker socket",
         "docker sock mount host"),
        ("privileged", "Privileged container escape", "the container runs privileged",
         "privileged cgroup release agent"),
        ("kubelet", "Kubelet API abuse", "the kubelet answers without authentication", "kubelet 10250 exec"),
        ("service-account", "Service account tokens", "a pod holds a token with broad rights",
         "service account token rbac"),
    ], ["Docker", "Kubernetes", "AWS", "Azure", "Google Cloud", "Redis"]),
    "rce": ("Remote code execution", [
        ("command-injection", "OS command injection", "a parameter ends up in a shell command",
         "semicolon pipe backtick shell"),
        ("ssti", "Server-side template injection", "the template engine evaluates what you type",
         "template expression jinja twig"),
        ("file-upload", "File upload to RCE", "the server keeps an uploaded script where it runs",
         "upload extension web shell"),
        ("reverse-shells", "Reverse shells", "you have execution and need an interactive shell",
         "reverse shell netcat bash"),
    ], ["PHP", "Node.js", "Django", "Flask", "Jenkins", "Ruby on Rails"]),
    "access_control": ("Access control", [
        ("idor", "IDOR", "change an id in the request and read someone else's record",
         "insecure direct object reference id"),
        ("jwt-none", "JWT none algorithm", "the token signature is not checked", "jwt alg none signature"),
        ("mass-assignment", "Mass assignment", "extra fields in the request change your role",
         "mass assignment role field"),
        ("403-bypass", "403 bypass", "a path answers forbidden only for some spellings",
         "header path normalization forbidden"),
    ], ["GraphQL", "Express", "Django", "Laravel", "Spring", "Ruby on Rails"]),
}
KIND_PAGES = [("bypasses", "Bypasses for {t}", "filters and WAF rules that stop {t}, and the evasions that pass them"),
              ("detection", "Detecting {t}", "logs, signatures and alerts that reveal {t}")]
TOOL_OPTIONS = [
    ("threads", "Sets the number of concurrent requests"), ("level", "Sets how many tests run per parameter"),
    ("risk", "Allows tests that may change data"), ("delay", "Waits between two requests"),
    ("timeout", "Sets how long one request may take"), ("proxy", "Sends every request through a proxy"),
    ("cookie", "Sends a cookie with every request"), ("headers", "Adds extra request headers"),
    ("dump", "Writes the rows of the chosen table"), ("tables", "Lists the tables of a database"),
    ("columns", "Lists the columns of a table"), ("batch", "Answers every question with its default"),
    ("tamper", "Runs a tamper script on each payload"), ("random-agent", "Picks a random user agent"),
    ("os-shell", "Opens an interactive operating system shell"), ("file-read", "Reads a file from the server"),
    ("technique", "Chooses the injection techniques to test"), ("time-sec", "Sets the delay a time test waits"),
    ("dbms", "Names the database engine to skip detection"), ("forms", "Tests the forms of the target page"),
]
TAMPERS = ["space2comment", "between", "charencode", "randomcase", "equaltolike", "base64encode", "apostrophemask",
           "percentage", "unionalltounion", "versionedkeywords"]


def slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-").replace("--", "-")


def page_html(title: str, description: str, sections: list[tuple[str, str]], extra_head: str = "",
              links: list[tuple[str, str]] = ()) -> str:
    body = "".join(f"<h2>{escape(h)}</h2>" + (f"<pre><code>{escape(t)}</code></pre>" if h == "Payloads"
                                              else f"<p>{escape(t)}</p>") for h, t in sections)
    nav = "".join(f'<li><a href="{escape(href)}">{escape(label)}</a></li>' for label, href in links)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{escape(title)}</title>'
            f'<meta name="description" content="{escape(description)}">{extra_head}</head><body>'
            f'<main><article><h1>{escape(title)}</h1><p>{escape(description)}</p>{body}'
            f'{"<ul>" + nav + "</ul>" if nav else ""}</article></main></body></html>')


def markdown(title: str, description: str, sections: list[tuple[str, str]]) -> str:
    out = [f"# {title}", "", description, ""]
    for h, t in sections:
        out += [f"## {h}", "", f"```\n{t}\n```" if h == "Payloads" else t, ""]
    return "\n".join(out)


def technique_sections(label: str, situation: str, words: str, tech: str) -> list[tuple[str, str]]:
    return [
        ("How it works", f"{label} on {tech}: use it when {situation}. Key ideas: {words}. "
                         f"Work only against lab targets you own."),
        ("Payloads", f"# {label} examples for {tech}\n" + "\n".join(f"{w} -- {tech.lower()} test {i}"
                                                                    for i, w in enumerate(words.split()[:5]))),
        (f"{tech} specifics", f"On {tech} the behaviour of {words.split()[0]} differs; check the version first."),
        ("Bypasses", f"When filters block {words.split()[-1]}, change case, encoding or spacing."),
    ]


def write(root: Path, url: str, text: str) -> None:
    host_path = url.split("://", 1)[1]
    path = root / host_path
    if host_path.endswith("/"):
        path = path / "index.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build(root: Path) -> dict:
    """Writes the four sites under ``root``; returns {url: {title, resource, sections, chars}}."""
    pages: dict[str, dict] = {}

    def add(url, resource, title, description, sections):
        md = markdown(title, description, sections)
        pages[url] = {"title": title, "resource": resource, "markdown": md, "chars": len(md)}

    # --- the wiki ---
    wiki_urls = []
    for topic, (topic_label, techniques, techs) in TOPICS.items():
        for tslug, label, situation, words in techniques:
            overview = f"{WIKI}{slug(topic_label)}/{tslug}/"
            sections = technique_sections(label, situation, words, topic_label)
            write(root, overview, page_html(f"{label}", f"{label}: an overview for {topic_label}.", sections))
            add(overview, "wiki", label, f"{label}: an overview for {topic_label}.", sections)
            wiki_urls.append(overview)
            for tech in techs:
                url = f"{overview}{slug(tech)}/"
                title = f"{label} on {tech}"
                desc = f"{label} against {tech}: {situation}."
                sections = technique_sections(label, situation, words, tech)
                write(root, url, page_html(title, desc, sections))
                add(url, "wiki", title, desc, sections)
                wiki_urls.append(url)
            for kind, title_t, desc_t in KIND_PAGES:
                url = f"{overview}{kind}/"
                title, desc = title_t.format(t=label), desc_t.format(t=label.lower()) + "."
                sections = [("Notes", desc_t.format(t=label.lower()) + f". Words: {words}.")]
                write(root, url, page_html(title, desc, sections))
                add(url, "wiki", title, desc, sections)
                wiki_urls.append(url)
    write(root, WIKI, page_html("TC Eval Wiki", "A synthetic wiki of lab techniques.", [],
                                extra_head='<meta name="generator" content="mkdocs-1.6.0, mkdocs-material-9.5.0">'))
    write(root, WIKI + "sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/'
          'schemas/sitemap/0.9">\n' + "".join(f"  <url><loc>{u}</loc></url>\n" for u in [WIKI] + wiki_urls)
          + "</urlset>\n")

    # --- the repository ---
    files = []
    for topic, (topic_label, techniques, techs) in TOPICS.items():
        folder = topic_label.replace(" ", "_")
        files.append((f"{folder}/README.md", f"{topic_label} payloads", f"Payload files for {topic_label}.", []))
        for tslug, label, situation, words in techniques:
            files.append((f"{folder}/{tslug}/README.md", f"{label}", f"{label} payload files: {situation}.",
                          technique_sections(label, situation, words, topic_label)[:2]))
            for tech in techs:
                files.append((f"{folder}/{tslug}/{slug(tech)}.md", f"{label} payloads for {tech}",
                              f"{label} payloads for {tech}.", technique_sections(label, situation, words, tech)))
    tree = [{"path": p, "type": "blob", "mode": "100644", "sha": f"{i:040d}"} for i, (p, *_r) in enumerate(files)]
    write(root, "https://api.github.com/repos/tc-eval/lib/", json.dumps({"default_branch": "main", "name": "lib"}))
    write(root, "https://api.github.com/repos/tc-eval/lib/git/trees/main/", json.dumps({"tree": tree, "truncated": False}))
    write(root, REPO + "/", page_html("tc-eval/lib", "A synthetic payload repository.", []))
    for path, title, desc, sections in files:
        md = markdown(title, desc, sections)
        target = root / "raw.githubusercontent.com" / "tc-eval" / "lib" / "main" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(md, encoding="utf-8")
        pages[RAW + "/".join(p.replace(" ", "%20") for p in path.split("/"))] = {
            "title": title, "resource": "repo", "markdown": md, "chars": len(md)}

    # --- the docs ---
    docs = []
    for name, what in TOOL_OPTIONS:
        docs.append((f"options/{name}", f"The --{name} option", f"{what}.", [("Usage", f"tcmap --{name} VALUE. {what}.")]))
    for i in range(1, 761):
        name, what = TOOL_OPTIONS[i % len(TOOL_OPTIONS)]
        docs.append((f"reference/r{i:03d}", f"Reference note {i}: --{name} with value {i}",
                     f"Example {i} of the --{name} option.", [("Example", f"tcmap --{name} {i}")]))
    for tamper in TAMPERS:
        docs.append((f"tampers/{tamper}", f"The {tamper} tamper script",
                     f"Rewrites each payload with {tamper} to pass a filter.",
                     [("Usage", f"tcmap --tamper={tamper}"), ("Effect", f"{tamper} changes the payload text.")]))
    for doc, title, desc, sections in docs:
        url = f"{DOCS}{doc}.html"
        write(root, url, page_html(title, desc, sections))
        add(url, "docs", title, desc, sections)
    write(root, DOCS, page_html("tcmap documentation", "Documentation of the synthetic tcmap tool.", []))
    write(root, DOCS + "searchindex.js", "Search.setIndex(" + json.dumps(
        {"docnames": [d[0] for d in docs], "titles": [d[1] for d in docs], "terms": {}}) + ")")

    # --- the blog ---
    posts, flat = [], [(topic, t) for topic, (_l, ts, techs) in TOPICS.items() for t in ts]
    for i in range(1, 181):
        topic, (tslug, label, situation, words) = flat[i % len(flat)]
        tech = TOPICS[topic][2][i % 6]
        if i % 6 == 0:
            cve = f"CVE-2098-{100000 + i}"
            title = f"{cve}: {label.lower()} in TcWidget Server 2.{i % 9}"
            desc = f"Lab write-up of {cve}, a synthetic {label.lower()} bug in the made-up TcWidget Server."
        else:
            cve = ""
            title = f"Lab write-up {i}: {label} against {tech}"
            desc = f"How a lab target fell to {label.lower()} when {situation}."
        sections = [("Setup", f"The lab ran {tech}. {desc}"), ("Exploitation", f"Steps used: {words}."),
                    ("Lessons", "Patch, encode and log.")]
        posts.append((f"posts/{i:03d}-{tslug}/", title, desc, sections, topic, cve))
    by_topic: dict[str, list] = {}
    for post in posts:
        by_topic.setdefault(post[4], []).append(post)
    for post_path, title, desc, sections, _topic, _cve in posts:
        url = BLOG + post_path
        write(root, url, page_html(title, desc, sections))
        add(url, "blog", title, desc, sections)
    for topic, items in by_topic.items():
        label = TOPICS[topic][0]
        links = [(t, "/" + p) for p, t, *_r in items]
        write(root, f"{BLOG}topics/{slug(label)}/", page_html(f"{label} write-ups", f"Write-ups about {label}.",
                                                                [("Posts", f"{len(items)} posts.")], links=links))
    write(root, BLOG, page_html("TC Eval Blog", "Synthetic lab write-ups.", [("Topics", "Pick a topic.")],
                                links=[(TOPICS[t][0], f"/topics/{slug(TOPICS[t][0])}/") for t in by_topic]))
    return pages


def questions(pages: dict) -> list[dict]:
    """About 100 questions, each with its correct page: precise, vague, CVE and browse."""
    rng = random.Random(15)
    out: list[dict] = []
    flat = [(topic, t, techs) for topic, (_l, ts, techs) in TOPICS.items() for t in ts]
    picks = rng.sample(flat, 30)
    for n, (topic, (tslug, label, situation, words), techs) in enumerate(picks):
        tech = techs[n % len(techs)]
        topic_label = TOPICS[topic][0]
        wiki_url = f"{WIKI}{slug(topic_label)}/{tslug}/{slug(tech)}/"
        repo_url = RAW + f"{topic_label.replace(' ', '_')}/{tslug}/{slug(tech)}.md"
        if n < 15:
            out.append({"kind": "precise", "query": f"{label} {tech}", "url": wiki_url, "mode": "live"})
            out.append({"kind": "precise", "query": f"{label.lower()} payloads for {tech}", "url": repo_url,
                        "mode": "stored"})
        else:
            out.append({"kind": "vague", "query": f"{situation} on {tech}", "url": wiki_url, "mode": "live"})
        if n < 10:
            out.append({"kind": "browse", "query": f"{label} payload files", "url": RAW +
                        f"{topic_label.replace(' ', '_')}/{tslug}/README.md", "mode": "stored", "resource": "repo"})
    for name, what in TOOL_OPTIONS[:15]:
        out.append({"kind": "precise", "query": f"tcmap --{name} option", "url": f"{DOCS}options/{name}.html",
                    "mode": "live"})
    for name, what in TOOL_OPTIONS[15:]:
        out.append({"kind": "vague", "query": f"how to make tcmap {what.lower()}", "url": f"{DOCS}options/{name}.html",
                    "mode": "live"})
    for tamper in TAMPERS[:5]:
        out.append({"kind": "browse", "query": f"{tamper} tamper", "url": f"{DOCS}tampers/{tamper}.html", "mode": "live",
                    "resource": "docs"})
    for i in range(6, 181, 6)[:15]:
        cve = f"CVE-2098-{100000 + i}"
        url = next(u for u, p in pages.items() if p["title"].startswith(cve + ":"))
        out.append({"kind": "cve", "query": cve, "url": url, "mode": "stored"})
    for q in out:
        assert q["url"] in pages, q
    return [dict(q, id=f"q{n:03d}") for n, q in enumerate(out, 1)]


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        corpus = build(Path(tmp))
        qs = questions(corpus)
    (HERE / "questions.jsonl").write_text("".join(json.dumps(q, sort_keys=True) + "\n" for q in qs))
    print(f"{len(corpus)} pages, {len(qs)} questions", file=sys.stderr)
