import pytest

from knowledge_base.curation.safe_http import (
    MAX_REDIRECTS,
    ResponseTooLargeError,
    SafeHTTPStatusError,
    SafeResponse,
    UntrustedHostError,
    safe_get,
)


# =============================================================================
# Fake httpx shim
# =============================================================================
# safe_get holds the actual httpx calls inside `with httpx.Client(...)`,
# and no network I/O should happen in these tests. The shim below is
# the minimal surface of httpx.Client + httpx.Response that safe_get
# actually touches (build_request, send(stream=True), the response's
# is_redirect / headers / status_code / url / iter_bytes / close).


class _FakeResponse:
    """Duck-types the httpx.Response subset safe_get calls."""

    def __init__(
        self,
        status_code: int,
        headers: dict | None = None,
        body: bytes = b"",
        url: str = "",
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.url = url
        self.closed = False

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    def iter_bytes(self, chunk_size: int = 64 * 1024):
        # Emit in chunks so safe_get's streaming cap check gets to run.
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self) -> None:
        self.closed = True


class _FakeRequest:
    """Placeholder — safe_get doesn't inspect it, it just passes it
    back to send()."""

    def __init__(self, method, url, headers=None, params=None):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.params = params


class _FakeClient:
    """
    Duck-types httpx.Client enough for safe_get's redirect loop.

    ``responses`` is a list of (expected_url_substring, _FakeResponse)
    tuples consumed in order. Each call to send() pops the next one and
    asserts the request URL contains the expected substring, so tests
    can prove safe_get IS actually sending to the expected target at
    each hop and not, say, silently short-circuiting.
    """

    def __init__(self, responses):
        self._script = list(responses)
        self.sent_urls: list[str] = []

    # httpx.Client's context-manager protocol
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def build_request(self, method, url, headers=None, params=None):
        return _FakeRequest(method, url, headers, params)

    def send(self, request, stream=True):
        if not self._script:
            raise AssertionError(
                f"_FakeClient: unexpected extra send() for {request.url}"
            )
        expected_substr, resp = self._script.pop(0)
        assert expected_substr in str(request.url), (
            f"_FakeClient: expected URL containing {expected_substr!r}, "
            f"got {request.url!r}"
        )
        self.sent_urls.append(str(request.url))
        # Hand the fake response back; safe_get calls .close() in a finally.
        resp.url = str(request.url)
        return resp


@pytest.fixture
def fake_httpx(monkeypatch):
    """Return a callable `install(responses)` that swaps
    safe_http.httpx.Client with a _FakeClient preloaded with those
    responses, and returns the installed client for assertion."""

    from knowledge_base.curation import safe_http as mod

    installed = {}

    def install(responses):
        client = _FakeClient(responses)

        def factory(*args, **kwargs):
            return client

        monkeypatch.setattr(mod.httpx, "Client", factory)
        installed["client"] = client
        return client

    yield install


# =============================================================================
# Allowlist rejection — the SSRF defence
# =============================================================================


class TestHostAllowlist:

    def test_offlist_host_rejected_without_request(self, fake_httpx):
        """An off-allowlist URL must raise BEFORE any send() happens.
        We install an empty fake client and assert nothing was dispatched."""
        client = fake_httpx([])  # zero scripted responses
        with pytest.raises(UntrustedHostError, match="not on allowlist"):
            safe_get("https://evil.example.com/payload")
        # No request should have been issued
        assert client.sent_urls == []

    def test_ip_literal_rejected(self, fake_httpx):
        """A raw IP address is not on the allowlist. This is the
        metadata-service / localhost SSRF defence."""
        client = fake_httpx([])
        with pytest.raises(UntrustedHostError):
            safe_get("http://169.254.169.254/latest/meta-data/")
        assert client.sent_urls == []

    def test_localhost_rejected(self, fake_httpx):
        client = fake_httpx([])
        with pytest.raises(UntrustedHostError):
            safe_get("http://127.0.0.1:8080/admin")
        assert client.sent_urls == []

    def test_non_http_scheme_rejected(self, fake_httpx):
        client = fake_httpx([])
        for url in (
            "file:///etc/passwd",
            "ftp://github.com/foo",
            "gopher://github.com:70/evil",
            "javascript:alert(1)",
        ):
            with pytest.raises(UntrustedHostError, match="non-http"):
                safe_get(url)
        assert client.sent_urls == []

    def test_custom_allowed_hosts_respected(self, fake_httpx):
        """Callers can pass a tighter allowed_hosts — unrelated default
        allowlisted hosts must still be rejected if not in the caller's list."""
        client = fake_httpx([])
        with pytest.raises(UntrustedHostError, match="not on allowlist"):
            # github.com is on DEFAULT_ALLOWED_HOSTS but not on this caller's
            safe_get(
                "https://github.com/foo/bar",
                allowed_hosts=("services.nvd.nist.gov",),
            )
        assert client.sent_urls == []

    def test_case_insensitive_hostname_match(self, fake_httpx):
        """Host comparison is case-insensitive (RFC 3986 §3.2.2)."""
        fake_httpx([
            (
                "GitHub.com",
                _FakeResponse(
                    status_code=200,
                    headers={"content-length": "2"},
                    body=b"ok",
                ),
            )
        ])
        resp = safe_get("https://GitHub.com/foo/bar")
        assert resp.status_code == 200


# =============================================================================
# Body size caps — the memory-DoS defence
# =============================================================================

class TestSizeCap:

    def test_content_length_exceeds_cap_rejected(self, fake_httpx):
        """Honest upstream: Content-Length says 300 MB, cap is 200 MB.
        Must raise BEFORE reading any of the body."""
        fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=200,
                    headers={"content-length": str(300 * 1024 * 1024)},
                    body=b"",  # we never read it
                ),
            )
        ])
        with pytest.raises(ResponseTooLargeError, match="Content-Length"):
            safe_get(
                "https://github.com/foo/bar.tar.gz",
                max_bytes=200 * 1024 * 1024,
            )

    def test_lying_content_length_still_capped_on_stream(self, fake_httpx):
        """Malicious upstream: claims small Content-Length but actually
        streams a huge body. safe_get reads in chunks and must trip the
        cap during streaming, not trust the advertised header."""
        body = b"X" * (512 * 1024)  # 512 KB
        fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=200,
                    headers={"content-length": "100"},  # lies
                    body=body,
                ),
            )
        ])
        with pytest.raises(ResponseTooLargeError, match="streaming"):
            safe_get(
                "https://github.com/foo.tar.gz",
                max_bytes=100 * 1024,  # 100 KB cap; body is 512 KB
            )

    def test_body_under_cap_returns_full_content(self, fake_httpx):
        body = b"hello world"
        fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=200,
                    headers={"content-length": str(len(body))},
                    body=body,
                ),
            )
        ])
        resp = safe_get("https://github.com/foo", max_bytes=1024 * 1024)
        assert resp.content == body
        assert resp.status_code == 200

    def test_missing_content_length_still_streams_with_cap(self, fake_httpx):
        """Some responses omit Content-Length entirely (chunked encoding).
        The streaming cap must still apply."""
        body = b"Z" * (256 * 1024)  # 256 KB
        fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=200,
                    headers={},  # no Content-Length
                    body=body,
                ),
            )
        ])
        with pytest.raises(ResponseTooLargeError):
            safe_get("https://github.com/foo", max_bytes=64 * 1024)


# =============================================================================
# Redirect handling — validated per-hop, not just the initial URL
# =============================================================================

class TestRedirects:

    def test_allowlisted_redirect_followed(self, fake_httpx):
        """github.com → codeload.github.com is the normal case. Both
        hosts are on the allowlist so the redirect should be followed
        and the final body returned."""
        body = b"tarball contents"
        client = fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=302,
                    headers={
                        "location": "https://codeload.github.com/owner/repo/tar.gz/main",
                    },
                ),
            ),
            (
                "codeload.github.com",
                _FakeResponse(
                    status_code=200,
                    headers={"content-length": str(len(body))},
                    body=body,
                ),
            ),
        ])
        resp = safe_get(
            "https://github.com/owner/repo/archive/refs/heads/main.tar.gz"
        )
        assert resp.status_code == 200
        assert resp.content == body
        # Two hops, both allowlisted hosts
        assert len(client.sent_urls) == 2
        assert "github.com" in client.sent_urls[0]
        assert "codeload.github.com" in client.sent_urls[1]

    def test_redirect_to_offlist_host_rejected(self, fake_httpx):
        """Compromised upstream: replies with a 302 pointing at
        http://127.0.0.1:8080. safe_get must NOT issue that request —
        the redirect target is validated before being dispatched."""
        client = fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=302,
                    headers={"location": "http://127.0.0.1:8080/admin"},
                ),
            ),
        ])
        with pytest.raises(UntrustedHostError, match="not on allowlist"):
            safe_get("https://github.com/foo")
        # The only URL actually sent was the initial github.com hit.
        # The 127.0.0.1 follow-up must NOT appear.
        assert len(client.sent_urls) == 1
        assert "github.com" in client.sent_urls[0]
        assert "127.0.0.1" not in "".join(client.sent_urls)

    def test_redirect_to_file_scheme_rejected(self, fake_httpx):
        """A Location header with a non-http(s) scheme is a protocol
        downgrade attack."""
        client = fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=301,
                    headers={"location": "file:///etc/passwd"},
                ),
            ),
        ])
        with pytest.raises(UntrustedHostError):
            safe_get("https://github.com/foo")
        # Never issued the file:// "request"
        assert len(client.sent_urls) == 1

    def test_redirect_chain_exceeds_max_redirects(self, fake_httpx):
        """A bouncing chain of allowlisted-but-looping redirects gets
        stopped at MAX_REDIRECTS to prevent a slowloris-style attack."""
        hops = []
        for _ in range(MAX_REDIRECTS + 1):
            hops.append(
                (
                    "github.com",
                    _FakeResponse(
                        status_code=302,
                        headers={"location": "https://github.com/loop"},
                    ),
                )
            )
        fake_httpx(hops)
        with pytest.raises(UntrustedHostError, match="more than"):
            safe_get("https://github.com/start")

    def test_redirect_without_location_header_rejected(self, fake_httpx):
        """A 3xx response with no Location header is malformed and we
        refuse it rather than silently returning the empty body."""
        fake_httpx([
            (
                "github.com",
                _FakeResponse(
                    status_code=302,
                    headers={},  # no Location
                ),
            ),
        ])
        with pytest.raises(UntrustedHostError, match="Location"):
            safe_get("https://github.com/foo")


# =============================================================================
# SafeResponse surface
# =============================================================================

class TestSafeResponse:

    def test_raise_for_status_raises_on_4xx(self):
        r = SafeResponse(
            status_code=404,
            content=b"not found",
            headers={},
            url="https://github.com/missing",
        )
        with pytest.raises(SafeHTTPStatusError) as exc_info:
            r.raise_for_status()
        assert exc_info.value.status_code == 404
        assert exc_info.value.url == "https://github.com/missing"

    def test_raise_for_status_raises_on_5xx(self):
        r = SafeResponse(
            status_code=503,
            content=b"",
            headers={},
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        )
        with pytest.raises(SafeHTTPStatusError) as exc_info:
            r.raise_for_status()
        assert exc_info.value.status_code == 503

    def test_raise_for_status_silent_on_2xx(self):
        r = SafeResponse(
            status_code=200,
            content=b"ok",
            headers={},
            url="https://github.com/foo",
        )
        r.raise_for_status()  # no exception

    def test_text_decodes_utf8(self):
        r = SafeResponse(
            status_code=200,
            content="héllo".encode("utf-8"),
            headers={},
            url="",
        )
        assert r.text == "héllo"

    def test_text_replaces_bad_bytes(self):
        """Malformed bytes get the replacement char rather than crashing."""
        r = SafeResponse(
            status_code=200,
            content=b"\xff\xfe not utf8",
            headers={},
            url="",
        )
        # Should not raise; bad bytes become U+FFFD
        assert isinstance(r.text, str)

    def test_json_parses_body(self):
        r = SafeResponse(
            status_code=200,
            content=b'{"totalResults": 2, "vulnerabilities": []}',
            headers={},
            url="",
        )
        assert r.json() == {"totalResults": 2, "vulnerabilities": []}
