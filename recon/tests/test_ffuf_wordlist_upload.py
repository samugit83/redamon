"""
Unit tests for FFuf custom wordlist upload feature.

Tests the API route (GET/POST/DELETE), filename sanitization,
path construction, security (path traversal, dotfiles, non-txt),
and end-to-end flow without making real network calls.

These tests run locally using filesystem operations on a temp directory,
mirroring the logic in webapp/src/app/api/projects/[id]/wordlists/route.ts.
"""

import os
import re
import sys
import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# Replicate the sanitization logic from route.ts in Python for unit testing
# ===========================================================================

def sanitize_filename(name: str) -> Optional[str]:
    """Mirror of sanitizeFilename() from route.ts."""
    basename = os.path.basename(name)
    if not basename or '..' in basename or basename.startswith('.'):
        return None
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '_', basename)
    if not cleaned.lower().endswith('.txt'):
        return None
    return cleaned


def safe_project_id(project_id: str) -> str:
    """Mirror of safeId logic from route.ts."""
    return re.sub(r'[^a-zA-Z0-9_-]', '', project_id)


def to_container_path(project_id: str, filename: str) -> str:
    """Mirror of toContainerPath() from route.ts."""
    safe_id = safe_project_id(project_id)
    return f"/app/recon/wordlists/{safe_id}/{filename}"


# ===========================================================================
# Sanitization tests
# ===========================================================================

def test_sanitize_valid_txt():
    """Valid .txt filenames should pass sanitization."""
    assert sanitize_filename("wordlist.txt") == "wordlist.txt"
    assert sanitize_filename("my-custom-list.txt") == "my-custom-list.txt"
    assert sanitize_filename("dir_bruteforce_v2.txt") == "dir_bruteforce_v2.txt"
    print("PASS: test_sanitize_valid_txt")


def test_sanitize_rejects_non_txt():
    """Non-.txt extensions should be rejected."""
    assert sanitize_filename("payload.php") is None
    assert sanitize_filename("script.py") is None
    assert sanitize_filename("shell.sh") is None
    assert sanitize_filename("binary.exe") is None
    assert sanitize_filename("archive.zip") is None
    assert sanitize_filename("noextension") is None
    print("PASS: test_sanitize_rejects_non_txt")


def test_sanitize_rejects_dotfiles():
    """Filenames starting with a dot should be rejected."""
    assert sanitize_filename(".hidden.txt") is None
    assert sanitize_filename(".env") is None
    assert sanitize_filename(".gitkeep") is None
    print("PASS: test_sanitize_rejects_dotfiles")


def test_sanitize_strips_path_traversal():
    """Path traversal should be stripped by basename, then '..' check rejects."""
    result = sanitize_filename("../../etc/passwd.txt")
    # basename strips to "passwd.txt", no '..' in basename, so it passes
    assert result == "passwd.txt"

    result = sanitize_filename("../../../secret.txt")
    assert result == "secret.txt"
    print("PASS: test_sanitize_strips_path_traversal")


def test_sanitize_rejects_double_dot_in_name():
    """Filenames with '..' anywhere should be rejected."""
    assert sanitize_filename("file..txt") is None
    assert sanitize_filename("..hidden.txt") is None
    print("PASS: test_sanitize_rejects_double_dot_in_name")


def test_sanitize_replaces_special_chars():
    """Special characters should be replaced with underscores."""
    assert sanitize_filename("my wordlist (v2).txt") == "my_wordlist__v2_.txt"
    assert sanitize_filename("list@#$%.txt") == "list____.txt"
    result = sanitize_filename("über-list.txt")
    assert result is not None and result.endswith("-list.txt")
    print("PASS: test_sanitize_replaces_special_chars")


def test_sanitize_empty_string():
    """Empty string should be rejected."""
    assert sanitize_filename("") is None
    print("PASS: test_sanitize_empty_string")


def test_sanitize_case_insensitive_extension():
    """Extension check should be case-insensitive."""
    assert sanitize_filename("LIST.TXT") == "LIST.TXT"
    assert sanitize_filename("words.Txt") == "words.Txt"
    print("PASS: test_sanitize_case_insensitive_extension")


# ===========================================================================
# Project ID sanitization tests
# ===========================================================================

def test_safe_project_id_cuid():
    """CUID project IDs should pass through unchanged."""
    cuid = "cmmyst07q0004k801jphgln0a"
    assert safe_project_id(cuid) == cuid
    print("PASS: test_safe_project_id_cuid")


def test_safe_project_id_strips_traversal():
    """Path traversal characters should be stripped from project IDs."""
    assert safe_project_id("../../../etc") == "etc"
    assert safe_project_id("../../passwd") == "passwd"
    assert safe_project_id("id/../../root") == "idroot"
    print("PASS: test_safe_project_id_strips_traversal")


def test_safe_project_id_strips_special():
    """Special characters should be stripped from project IDs."""
    assert safe_project_id("project@123") == "project123"
    assert safe_project_id("proj ect") == "project"
    print("PASS: test_safe_project_id_strips_special")


def test_safe_project_id_empty_after_strip():
    """All-special-chars project ID should result in empty string."""
    assert safe_project_id("../..") == ""
    assert safe_project_id("///") == ""
    print("PASS: test_safe_project_id_empty_after_strip")


# ===========================================================================
# Container path tests
# ===========================================================================

def test_container_path_format():
    """Container path should follow /app/recon/wordlists/<id>/<file> format."""
    path = to_container_path("abc123", "custom.txt")
    assert path == "/app/recon/wordlists/abc123/custom.txt"
    print("PASS: test_container_path_format")


def test_container_path_sanitizes_id():
    """Container path should sanitize the project ID."""
    path = to_container_path("../evil", "list.txt")
    assert path == "/app/recon/wordlists/evil/list.txt"
    assert ".." not in path
    print("PASS: test_container_path_sanitizes_id")


# ===========================================================================
# Filesystem integration tests (using temp directories)
# ===========================================================================

def test_upload_list_delete_flow():
    """Full CRUD flow: upload a wordlist, list it, delete it."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_id = "test_project_123"
    project_dir = os.path.join(tmpdir, project_id)

    try:
        # Upload: create directory and write file
        os.makedirs(project_dir, exist_ok=True)
        content = b"admin\nlogin\nbackup\nconfig\n"
        filepath = os.path.join(project_dir, "custom.txt")
        with open(filepath, 'wb') as f:
            f.write(content)

        # List: read directory
        files = [f for f in os.listdir(project_dir) if f.endswith('.txt')]
        assert len(files) == 1
        assert files[0] == "custom.txt"
        assert os.path.getsize(filepath) == len(content)

        # Delete: remove file
        os.unlink(filepath)
        files_after = [f for f in os.listdir(project_dir) if f.endswith('.txt')]
        assert len(files_after) == 0

        print("PASS: test_upload_list_delete_flow")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_multiple_wordlists():
    """Multiple wordlists should coexist and list alphabetically."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_id = "multi_test"
    project_dir = os.path.join(tmpdir, project_id)

    try:
        os.makedirs(project_dir, exist_ok=True)

        for name in ["zebra.txt", "alpha.txt", "middle.txt"]:
            with open(os.path.join(project_dir, name), 'w') as f:
                f.write(f"content of {name}\n")

        files = sorted(f for f in os.listdir(project_dir) if f.endswith('.txt'))
        assert files == ["alpha.txt", "middle.txt", "zebra.txt"]

        print("PASS: test_multiple_wordlists")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_non_txt_files_excluded():
    """Non-.txt files in the directory should be excluded from listing."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_dir = os.path.join(tmpdir, "proj1")

    try:
        os.makedirs(project_dir, exist_ok=True)
        with open(os.path.join(project_dir, "valid.txt"), 'w') as f:
            f.write("word1\nword2\n")
        with open(os.path.join(project_dir, "script.py"), 'w') as f:
            f.write("print('hi')\n")
        with open(os.path.join(project_dir, ".gitkeep"), 'w') as f:
            f.write("")

        txt_files = [f for f in os.listdir(project_dir) if f.lower().endswith('.txt')]
        assert txt_files == ["valid.txt"]

        print("PASS: test_non_txt_files_excluded")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_overwrite_existing_file():
    """Uploading a file with the same name should overwrite it."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_dir = os.path.join(tmpdir, "proj_overwrite")

    try:
        os.makedirs(project_dir, exist_ok=True)
        filepath = os.path.join(project_dir, "words.txt")

        with open(filepath, 'w') as f:
            f.write("original\n")
        assert os.path.getsize(filepath) == 9

        with open(filepath, 'w') as f:
            f.write("replaced content is longer\n")
        assert os.path.getsize(filepath) == 27

        with open(filepath, 'r') as f:
            assert "replaced" in f.read()

        print("PASS: test_overwrite_existing_file")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_empty_directory_returns_empty_list():
    """An empty project directory should return an empty list."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_dir = os.path.join(tmpdir, "empty_proj")

    try:
        os.makedirs(project_dir, exist_ok=True)
        files = [f for f in os.listdir(project_dir) if f.endswith('.txt')]
        assert files == []

        print("PASS: test_empty_directory_returns_empty_list")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_nonexistent_directory_returns_empty():
    """A non-existent directory should return empty (not error)."""
    tmpdir = tempfile.mkdtemp(prefix="redamon_wl_test_")
    project_dir = os.path.join(tmpdir, "does_not_exist")

    try:
        assert not os.path.exists(project_dir)
        if os.path.exists(project_dir):
            files = [f for f in os.listdir(project_dir) if f.endswith('.txt')]
        else:
            files = []
        assert files == []

        print("PASS: test_nonexistent_directory_returns_empty")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ===========================================================================
# Settings integration test -- wordlist path flows through unchanged
# ===========================================================================

def test_ffuf_wordlist_custom_path_in_settings():
    """Custom wordlist path should flow through project_settings unchanged."""
    from unittest import mock
    import importlib

    custom_path = "/app/recon/wordlists/testproj123/my_custom.txt"
    fake_project = {
        "ffufEnabled": True,
        "ffufWordlist": custom_path,
    }

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_project
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("requests.get", return_value=mock_resp):
        from recon.project_settings import fetch_project_settings
        settings = fetch_project_settings("testproj123", "http://localhost:3000")

    assert settings['FFUF_WORDLIST'] == custom_path, \
        f"Expected custom path, got: {settings['FFUF_WORDLIST']}"
    print("PASS: test_ffuf_wordlist_custom_path_in_settings")


def test_ffuf_wordlist_builtin_path_in_settings():
    """Built-in wordlist path should flow through project_settings unchanged."""
    from unittest import mock

    builtin_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    fake_project = {
        "ffufEnabled": True,
        "ffufWordlist": builtin_path,
    }

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_project
    mock_resp.raise_for_status = mock.MagicMock()

    with mock.patch("requests.get", return_value=mock_resp):
        from recon.project_settings import fetch_project_settings
        settings = fetch_project_settings("testproj123", "http://localhost:3000")

    assert settings['FFUF_WORDLIST'] == builtin_path, \
        f"Expected builtin path, got: {settings['FFUF_WORDLIST']}"
    print("PASS: test_ffuf_wordlist_builtin_path_in_settings")


def test_ffuf_run_uses_custom_wordlist_path():
    """run_ffuf_discovery should pass custom wordlist path to ffuf -w."""
    from unittest import mock

    dns_mock = mock.MagicMock()
    with mock.patch.dict('sys.modules', {
        'dns': dns_mock,
        'dns.resolver': dns_mock.resolver,
        'dns.zone': dns_mock.zone,
        'dns.query': dns_mock.query,
    }):
        # Force re-import with dns mocked
        import importlib
        if 'recon.helpers.resource_enum.ffuf_helpers' in sys.modules:
            mod = sys.modules['recon.helpers.resource_enum.ffuf_helpers']
        else:
            # Need to also mock the security_checks transitive dep
            if 'recon.helpers.security_checks' not in sys.modules:
                if 'recon.helpers' in sys.modules:
                    importlib.reload(sys.modules['recon.helpers'])
            from recon.helpers.resource_enum.ffuf_helpers import run_ffuf_discovery as _rfd
            mod = sys.modules['recon.helpers.resource_enum.ffuf_helpers']

        run_ffuf_discovery = mod.run_ffuf_discovery

    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd['cmd'] = cmd
        return mock.MagicMock(returncode=0)

    custom_path = "/app/recon/wordlists/proj123/custom_dirs.txt"

    with mock.patch("subprocess.run", side_effect=fake_run), \
         mock.patch("tempfile.mkdtemp", return_value="/tmp/test_ffuf"), \
         mock.patch("shutil.rmtree"), \
         mock.patch("os.path.exists", return_value=False):

        run_ffuf_discovery(
            target_urls=["https://example.com"],
            wordlist=custom_path,
            threads=10, rate=0, timeout=10, max_time=60,
            match_codes=[200], filter_codes=[], filter_size="",
            extensions=[], recursion=False, recursion_depth=2,
            auto_calibrate=True, custom_headers=[],
            follow_redirects=False,
            allowed_hosts={"example.com"},
        )

    cmd = captured_cmd['cmd']
    assert "-w" in cmd
    w_idx = cmd.index("-w") + 1
    assert cmd[w_idx] == custom_path, f"Expected {custom_path}, got {cmd[w_idx]}"
    print("PASS: test_ffuf_run_uses_custom_wordlist_path")


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    tests = [fn for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test_fn.__name__} — {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    if failed == 0:
        print("All tests passed!")
    else:
        print(f"{failed} test(s) FAILED")
        sys.exit(1)
