"""What a run's read may reach, and with which GitHub token.

A forced ``section_path`` reads only a page of the resource (its start page, its live map or the
1.x map), refused before any request otherwise. A GitHub token goes only to the resource's own
repository, and only in the owner's own run: a collaborator's run, or one an administrator acts in,
reads with none, the owner's account token included. Read now keeps its token to the resource's
repository too.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import runtime  # noqa: E402
from tradecraft.contract import ReadNowRequest, V2Catalog  # noqa: E402
from tradecraft.ingest import fetch  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from test_tradecraft_reader import OWNER, WIKI, Library, header, no_browser  # noqa: E402
from test_tradecraft_read_now import _store, run as read_now  # noqa: E402

REPO = "https://github.com/tc-fixture/payloads"
TREE = {"tree": [{"title": "sqli > union", "path": "sqli/union.md"}],
        "owner": "tc-fixture", "repo": "payloads", "branch": "main"}
INSIDE = "https://raw.githubusercontent.com/tc-fixture/payloads/main/sqli/union.md"
ACCOUNT_TOKEN = "ghp_account_fake"
RESOURCE_TOKEN = "ghp_resource_fake"
COLLABORATOR = "user_collab_fake"
ADMIN = "user_admin_fake"


class Run(Library):
    """A run's library for a given person, and an administrator acting as them or not."""

    def __init__(self, person=OWNER, actor=None):
        super().__init__()
        self.person, self.actor = person, actor

    def catalog(self):
        return {**super().catalog(), "person_id": self.person, "actor_id": self.actor}

    def tokens(self):
        return [h.get("authorization") for _url, h in self.fetcher.requests]


def payloads(person=OWNER, actor=None, override=None):
    lib = Run(person, actor).add("r1", "payloads", REPO, type_="github-repo", sitemap=TREE, read_settings=no_browser())
    lib.resources[-1]["github_token"] = override
    return lib


@pytest.fixture
def account_token(monkeypatch):
    monkeypatch.setattr(runtime, "run_github_token", lambda: ACCOUNT_TOKEN)


# --------------------------------------------------------------------------------------
# Fix 1: a forced section_path stays inside the resource
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "https://api.github.com/user/repos?visibility=private",
    "https://raw.githubusercontent.com/someone-else/private-repo/main/notes.md",
    "https://github.com/tc-fixture/payloads-other",
    "https://target.tc-fixture.test/admin/",
    "../../../someone-else/private-repo/main/notes.md",
])
def test_a_forced_path_outside_the_resource_is_refused_before_any_request(path, account_token):
    lib = payloads()
    answer = lib.read(resource_id="payloads", section_path=path)
    assert answer.startswith("Error: refusing to read ") and "is not a page of resource 'payloads'" in answer
    assert lib.requested() == []


def test_a_forced_url_on_a_website_resource_is_refused_too():
    lib = Run().add("r1", "wiki", WIKI, read_settings=no_browser())
    answer = lib.read(resource_id="wiki", section_path="https://target.tc-fixture.test/")
    assert answer == reader.NOT_IN_RESOURCE.format(url="https://target.tc-fixture.test/", slug="wiki")
    assert lib.requested() == []


def test_a_forced_path_of_the_resource_still_reads(account_token):
    """A path of the 1.x map, the same page by its URL, and the start page are the resource's."""
    by_path = payloads()
    assert header(by_path.read(resource_id="payloads", section_path="sqli/union.md"), "url") == INSIDE
    assert by_path.requested() == [INSIDE]
    by_url = payloads()
    assert header(by_url.read(resource_id="payloads", section_path=INSIDE), "url") == INSIDE
    start = Run().add("r1", "wiki", WIKI, sitemap={"nav": []}, read_settings=no_browser())
    assert not start.read(resource_id="wiki", section_path=WIKI).startswith("Error: refusing")
    assert start.requested() == [WIKI]


def test_a_page_only_the_live_map_holds_is_the_resources():
    page = WIKI + "sqli/union-based/"
    lib = Run().add("r1", "wiki", WIKI, sitemap={"nav": []}, read_settings=no_browser())
    lib.entry("r1", page)
    assert not lib.read(resource_id="wiki", section_path=page).startswith("Error: refusing")
    assert lib.requested() == [page]


# --------------------------------------------------------------------------------------
# Fix 2 and decision 3: the token, only inside the repository and only in the owner's run
# --------------------------------------------------------------------------------------

def test_the_owners_run_reads_its_repository_with_the_token(account_token):
    lib = payloads()
    lib.read(resource_id="payloads", section_path="sqli/union.md")
    assert lib.tokens() == [f"token {ACCOUNT_TOKEN}"]
    own = payloads(override=RESOURCE_TOKEN)
    own.read(resource_id="payloads", section_path="sqli/union.md")
    assert own.tokens() == [f"token {RESOURCE_TOKEN}"]


@pytest.mark.parametrize("person,actor", [(COLLABORATOR, None), (OWNER, ADMIN), (None, None)],
                         ids=["collaborator", "admin acting as the owner", "no person"])
def test_another_persons_run_reads_with_no_token(person, actor, account_token):
    lib = payloads(person, actor, override=RESOURCE_TOKEN)
    lib.read(resource_id="payloads", section_path="sqli/union.md")
    assert lib.requested() == [INSIDE] and lib.tokens() == [None]


def test_a_cve_read_carries_the_token_only_in_the_owners_run(account_token):
    def cves(person):
        return Run(person).add("r1", "cves", "https://github.com/tc-fixture/cve", type_="cve-poc-db",
                               sitemap={"owner": "tc-fixture", "repo": "cve", "branch": "main"})
    own = cves(OWNER)
    assert "Synthetic entry CVE-2022-0001." in own.read(resource_id="cves", cve_id="CVE-2022-0001")
    assert set(own.tokens()) == {f"token {ACCOUNT_TOKEN}"}
    other = cves(COLLABORATOR)
    assert "Synthetic entry CVE-2022-0001." in other.read(resource_id="cves", cve_id="CVE-2022-0001")
    assert set(other.tokens()) == {None}


def test_owner_run_is_the_login_rule():
    def catalog(person, actor=None):
        return V2Catalog(v2=True, owner_id=OWNER, person_id=person, actor_id=actor)
    assert catalog(OWNER).owner_run
    assert not catalog(COLLABORATOR).owner_run
    assert not catalog(OWNER, ADMIN).owner_run
    assert not catalog(None).owner_run


def test_read_now_keeps_its_token_to_the_resources_repository():
    def with_token(url):
        return ReadNowRequest(user_id=OWNER, resource_id="r1", url=url, read_settings=no_browser(),
                              secrets={"github_token": RESOURCE_TOKEN, "credentials": None})
    _out, fetcher = read_now(_store(url=REPO, urls=(INSIDE,), resource_type="github-repo"), with_token(INSIDE))
    assert [h.get("authorization") for _u, h in fetcher.requests] == [f"token {RESOURCE_TOKEN}"]
    union = WIKI + "sqli/union-based/"
    _out, fetcher = read_now(_store(), with_token(union))
    assert [u for u, _h in fetcher.requests] == [union]
    assert [h.get("authorization") for _u, h in fetcher.requests] == [None]


# --------------------------------------------------------------------------------------
# The helpers
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("url,repo", [
    ("https://github.com/Tc-Fixture/Payloads.git", ("tc-fixture", "payloads")),
    ("https://github.com/tc-fixture/payloads/tree/main/sqli", ("tc-fixture", "payloads")),
    ("https://raw.githubusercontent.com/tc-fixture/payloads/main/a.md", ("tc-fixture", "payloads")),
    ("https://api.github.com/repos/tc-fixture/payloads/contents/2022", ("tc-fixture", "payloads")),
    ("https://api.github.com/user/repos", None),
    ("https://api.github.com/repos/tc-fixture", None),
    ("https://gist.github.com/tc-fixture/payloads", None),
    ("https://github.com.example.test/tc-fixture/payloads", None),
    ("https://raw.githubusercontent.com/tc-fixture/payloads/main/../../other/repo/x.md", None),
    ("https://raw.githubusercontent.com/tc-fixture/payloads/main/%2e%2e/%2E%2E/other/repo/x.md", None),
    ("https://raw.githubusercontent.com/tc-fixture/payloads%2F..%2Fother/main/x.md", None),
    ("https://wiki.tc-fixture.test/", None),
])
def test_github_repo(url, repo):
    assert fetch.github_repo(url) == repo


def test_repo_token():
    assert fetch.repo_token(INSIDE, "t", REPO) == "t"
    assert fetch.repo_token("https://api.github.com/repos/tc-fixture/payloads/contents/x", "t", REPO) == "t"
    assert fetch.repo_token("https://api.github.com/user/repos", "t", REPO) is None
    assert fetch.repo_token("https://raw.githubusercontent.com/other/payloads/main/a.md", "t", REPO) is None
    assert fetch.repo_token("http://raw.githubusercontent.com/tc-fixture/payloads/main/a.md", "t", REPO) is None
    assert fetch.repo_token(INSIDE, "t", WIKI) is None
    assert fetch.repo_token(INSIDE, None, REPO) is None
