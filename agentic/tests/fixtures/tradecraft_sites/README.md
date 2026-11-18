# Synthetic tradecraft fixture sites

Every host in this folder is **synthetic**: written by `make_fixtures.py`, served only by
`FixtureFetcher` and the local test server of `tests/tradecraft_doubles.py`, never fetched
from the internet. The `.tc-fixture.test` hosts do not exist (`.test` is reserved, RFC
6761), and the GitHub hosts here hold only the made-up `tc-fixture/*` repositories. No
page names a real target. Regenerate with `make_fixtures.py`; never edit the output.

| Host | What it imitates |
|---|---|
| `contract.tc-fixture.test`, `other.*`, `down.*` | the fetcher contract suite: redirects, statuses, headers, a 20,000-byte body, an unreachable host |
| `wiki.tc-fixture.test` | an MkDocs Material wiki: 30 pages on SQL injection, XSS, SSRF and Kerberos, `sitemap.xml`, `search/search_index.json`, a `/fr/` copy of one page per topic |
| `docs.tc-fixture.test` | Sphinx docs with `searchindex.js` |
| `book.tc-fixture.test` | a GitBook with `sitemap.xml` |
| `blog.tc-fixture.test` | a website: 60 posts, `/page/2/` pagination, tag pages, `robots.txt` (a `Disallow` and a `Sitemap:` line), `sitemap.xml`; post 42 is JavaScript-only (its article is in `_rendered/`), post 13 carries prompt-injection text, post 7 names planted CVE ids |
| `github.com`, `api.github.com`, `raw.githubusercontent.com`, `codeload.github.com` | `tc-fixture/payloads` (tree with `.md`, `.yml`, `.yar`, folder READMEs, a tar.gz archive behind a redirect) and `tc-fixture/cve` (year folders; the 2023 listing is cut at 1,000 of its 1,050 entries, like the GitHub contents API; raw files exist for the small years and the first and last five of 2023) |
| `files.tc-fixture.test` | `guide.pdf`, three pages with bookmarks |
