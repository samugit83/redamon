import io
import json
import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from knowledge_base.curation.file_cache import (
    MAX_TAR_DECOMPRESSED_BYTES,
    MAX_TAR_MEMBER_BYTES,
    MAX_YAML_ANCHORS,
    MAX_YAML_ALIASES,
    MAX_YAML_BYTES,
    MAX_YAML_FLOW_DEPTH,
    TarballTooLargeError,
    YAMLTooComplexError,
    bounded_tar_iter,
    bounded_yaml_load,
    diff_files,
    file_hash,
    load_file_hashes,
    safe_relative_path,
    safe_write_text,
    save_file_hashes,
)

class TestFileHash:

    def test_deterministic(self):
        h1 = file_hash("hello world")
        h2 = file_hash("hello world")
        assert h1 == h2

    def test_different_content_different_hash(self):
        h1 = file_hash("hello")
        h2 = file_hash("world")
        assert h1 != h2

    def test_length_16(self):
        assert len(file_hash("anything")) == 16

    def test_empty_string(self):
        h = file_hash("")
        assert len(h) == 16
        assert isinstance(h, str)


class TestLoadSaveFileHashes:

    def test_save_and_load_roundtrip(self, tmp_path):
        hashes = {"file_a.md": "abc123", "dir/file_b.md": "def456"}
        save_file_hashes(tmp_path, hashes)
        loaded = load_file_hashes(tmp_path)
        assert loaded == hashes

    def test_load_missing_returns_empty(self, tmp_path):
        loaded = load_file_hashes(tmp_path)
        assert loaded == {}

    def test_load_corrupted_returns_empty(self, tmp_path):
        (tmp_path / ".file_hashes.json").write_text("not valid json{{{")
        loaded = load_file_hashes(tmp_path)
        assert loaded == {}

    def test_save_creates_parent_dir(self, tmp_path):
        sub = tmp_path / "nested" / "deep"
        save_file_hashes(sub, {"a": "b"})
        assert (sub / ".file_hashes.json").exists()

    def test_save_writes_valid_json(self, tmp_path):
        hashes = {"a.md": "h1", "b.md": "h2"}
        save_file_hashes(tmp_path, hashes)
        raw = (tmp_path / ".file_hashes.json").read_text()
        parsed = json.loads(raw)
        assert parsed == hashes


class TestSafeRelativePath:
    """Verifies the tar slip / path traversal defense."""

    @pytest.fixture
    def base(self, tmp_path):
        return tmp_path

    # ----- safe inputs -----

    def test_normal_filename(self, base):
        result = safe_relative_path("Certutil.yml", base)
        assert result is not None
        assert result.parent == base

    def test_subdirectory_path(self, base):
        result = safe_relative_path("OSBinaries/Certutil.yml", base)
        assert result is not None
        assert result == base / "OSBinaries" / "Certutil.yml"

    def test_no_extension(self, base):
        result = safe_relative_path("python", base)
        assert result is not None

    def test_leading_dot_slash(self, base):
        result = safe_relative_path("./foo.yml", base)
        assert result is not None

    def test_dot_slash_in_middle(self, base):
        result = safe_relative_path("foo/./bar.yml", base)
        assert result is not None

    def test_deep_nesting_inside_base(self, base):
        result = safe_relative_path("a/b/c/d/e/f.yml", base)
        assert result is not None
        assert result == base / "a" / "b" / "c" / "d" / "e" / "f.yml"

    # ----- unsafe inputs (must be rejected) -----

    def test_relative_escape_simple(self, base):
        assert safe_relative_path("../etc/passwd", base) is None

    def test_relative_escape_nested(self, base):
        assert safe_relative_path("OSBinaries/../../../etc/passwd", base) is None

    def test_relative_escape_deep(self, base):
        assert safe_relative_path("../../../../../../etc/shadow", base) is None

    def test_dotdot_in_middle(self, base):
        assert safe_relative_path("foo/../bar", base) is None

    def test_absolute_path_unix(self, base):
        assert safe_relative_path("/etc/passwd", base) is None

    def test_empty_string(self, base):
        assert safe_relative_path("", base) is None

    def test_nul_byte(self, base):
        assert safe_relative_path("file\x00name", base) is None

    def test_dotdot_only(self, base):
        assert safe_relative_path("..", base) is None


class TestDiffFiles:

    def test_all_new_when_no_cache(self):
        new_files = {"a.md": "content a", "b.md": "content b"}
        changed, updated = diff_files(new_files, {})
        assert len(changed) == 2
        assert "a.md" in changed
        assert "b.md" in changed
        assert len(updated) == 2

    def test_all_unchanged(self):
        new_files = {"a.md": "content a", "b.md": "content b"}
        old_hashes = {
            "a.md": file_hash("content a"),
            "b.md": file_hash("content b"),
        }
        changed, updated = diff_files(new_files, old_hashes)
        assert len(changed) == 0
        assert updated == old_hashes

    def test_one_changed(self):
        new_files = {"a.md": "content a", "b.md": "MODIFIED b"}
        old_hashes = {
            "a.md": file_hash("content a"),
            "b.md": file_hash("content b"),
        }
        changed, updated = diff_files(new_files, old_hashes)
        assert len(changed) == 1
        assert "b.md" in changed
        assert updated["b.md"] == file_hash("MODIFIED b")
        assert updated["a.md"] == old_hashes["a.md"]

    def test_new_file_added(self):
        new_files = {"a.md": "content a", "c.md": "new file c"}
        old_hashes = {"a.md": file_hash("content a")}
        changed, updated = diff_files(new_files, old_hashes)
        assert len(changed) == 1
        assert "c.md" in changed
        assert "c.md" in updated
        assert "a.md" in updated  # preserved

    def test_old_hash_preserved_when_file_missing(self):
        """Files that disappear from new_files keep their old hash entry.
        (We don't auto-delete from the manifest — that's intentional.)"""
        new_files = {"a.md": "content a"}
        old_hashes = {
            "a.md": file_hash("content a"),
            "deleted.md": "old_hash",
        }
        changed, updated = diff_files(new_files, old_hashes)
        assert len(changed) == 0
        assert "deleted.md" in updated  # preserved


# =============================================================================
# bounded_tar_iter
# =============================================================================

def _build_tar(members: list[tuple[str, bytes]]) -> bytes:
    """Build an uncompressed tar archive in memory containing ``members``.

    Uses 'w' (uncompressed) so the test doesn't have to wait on gzip
    for what's already a tiny in-memory blob."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestBoundedTarIter:

    def test_yields_only_regular_files(self):
        """Directories, symlinks, and other non-file members are silently
        skipped — KB clients never want those."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            # Regular file
            info = tarfile.TarInfo(name="real.txt")
            info.size = 3
            tar.addfile(info, io.BytesIO(b"foo"))
            # Directory member
            dir_info = tarfile.TarInfo(name="some_dir/")
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)
            # Symlink member
            link_info = tarfile.TarInfo(name="evil_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tar.addfile(link_info)

        with tarfile.open(fileobj=io.BytesIO(buf.getvalue()), mode="r") as tar:
            members = list(bounded_tar_iter(tar, label="test"))

        assert len(members) == 1
        assert members[0].name == "real.txt"

    def test_under_limits_yields_all_members(self):
        data = _build_tar([
            ("a.yaml", b"a" * 1024),
            ("b.yaml", b"b" * 2048),
            ("c.yaml", b"c" * 512),
        ])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            members = list(bounded_tar_iter(tar, label="test"))
        assert [m.name for m in members] == ["a.yaml", "b.yaml", "c.yaml"]

    def test_per_member_cap_raises(self):
        """A single file exceeding the per-member cap must raise before
        yielding anything past it. The caller's except clause (falls
        back to cached data) then catches it."""
        data = _build_tar([
            ("small.yaml", b"ok"),
            ("huge.yaml", b"X" * (MAX_TAR_MEMBER_BYTES + 1)),
        ])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            with pytest.raises(TarballTooLargeError, match="per-member cap"):
                list(bounded_tar_iter(tar, label="test"))

    def test_per_member_cap_custom(self):
        """Explicit per-member override lets tests pin the exact limit."""
        data = _build_tar([
            ("tiny.yaml", b"x" * 100),
            ("bigger.yaml", b"y" * 500),
        ])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            with pytest.raises(TarballTooLargeError, match="per-member cap 256"):
                list(bounded_tar_iter(
                    tar, label="test",
                    max_member_bytes=256,
                    max_total_bytes=10 * 1024,
                ))

    def test_cumulative_total_cap_raises(self):
        """Each member is under the per-member cap but the sum exceeds
        the total-decompressed cap — must raise mid-iteration."""
        data = _build_tar([
            ("a.yaml", b"a" * 400),
            ("b.yaml", b"b" * 400),
            ("c.yaml", b"c" * 400),  # cumulative 1200 > 1000
        ])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            with pytest.raises(TarballTooLargeError, match="cumulative"):
                list(bounded_tar_iter(
                    tar, label="test",
                    max_member_bytes=500,   # per-member OK
                    max_total_bytes=1000,   # cumulative trips
                ))

    def test_label_appears_in_error_message(self):
        """The label is what lets operators distinguish which client
        was hit by the limit in logs — pin it here."""
        data = _build_tar([("big.yaml", b"X" * 100)])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            with pytest.raises(TarballTooLargeError, match="nuclei-templates"):
                list(bounded_tar_iter(
                    tar, label="nuclei-templates",
                    max_member_bytes=50,
                ))


# =============================================================================
# bounded_yaml_load — Sec #4: YAML algorithmic-complexity defence
# =============================================================================

class TestBoundedYamlLoad:

    def test_benign_yaml_parses(self):
        """Ordinary YAML under all limits parses to the expected dict."""
        content = """
id: CVE-2024-0001
info:
  name: Test template
  severity: high
  tags:
    - sqli
    - auth
http:
  - method: GET
    path:
      - "{{BaseURL}}/api"
"""
        data = bounded_yaml_load(content, label="test")
        assert data["id"] == "CVE-2024-0001"
        assert data["info"]["severity"] == "high"
        assert "sqli" in data["info"]["tags"]

    def test_size_cap_raises(self):
        """A document over MAX_YAML_BYTES is refused before parsing."""
        # Build a huge but structurally trivial YAML scalar
        huge = "a: " + "X" * (MAX_YAML_BYTES + 1)
        with pytest.raises(YAMLTooComplexError, match="size"):
            bounded_yaml_load(huge, label="test")

    def test_flow_depth_cap_raises(self):
        """Deeply nested flow-style brackets trip the flow-depth guard."""
        depth = MAX_YAML_FLOW_DEPTH + 10
        nested = "x: " + ("[" * depth) + "1" + ("]" * depth)
        with pytest.raises(YAMLTooComplexError, match="flow-style"):
            bounded_yaml_load(nested, label="test")

    def test_anchor_count_cap_raises(self):
        """Too many & anchor declarations — catches the declaration side
        of billion-laughs."""
        content = "list:\n" + "\n".join(
            f"  - &anchor{i} value{i}"
            for i in range(MAX_YAML_ANCHORS + 5)
        )
        with pytest.raises(YAMLTooComplexError, match="anchors"):
            bounded_yaml_load(content, label="test")

    def test_alias_count_cap_raises(self):
        """Too many * alias references — the expansion side of
        billion-laughs. Build a document that declares one anchor
        and then references it far more times than MAX_YAML_ALIASES."""
        # Build raw text; don't need it to actually parse as a legal
        # YAML alias graph — the scan is pre-parse.
        lines = ["base: &b 1"]
        lines.extend(f"r{i}: *b" for i in range(MAX_YAML_ALIASES + 5))
        content = "\n".join(lines)
        with pytest.raises(YAMLTooComplexError, match="aliases"):
            bounded_yaml_load(content, label="test")

    def test_indent_cap_raises(self):
        """Pathological leading whitespace (e.g., 8 KB of spaces on a
        line) trips the indent-char cap even if nesting is shallow."""
        # 300 chars of leading space — over the 256-char default cap
        content = "a: 1\n" + (" " * 300) + "b: 2\n"
        with pytest.raises(YAMLTooComplexError, match="indentation"):
            bounded_yaml_load(content, label="test")

    def test_custom_caps_respected(self):
        """Callers can tighten the limits for specific contexts."""
        content = "a: " + "X" * 100
        with pytest.raises(YAMLTooComplexError, match="size"):
            bounded_yaml_load(content, label="test", max_bytes=50)

    def test_label_surfaced_in_error(self):
        with pytest.raises(YAMLTooComplexError, match="gtfobins:awk"):
            bounded_yaml_load(
                "a: " + "X" * 100,
                label="gtfobins:awk",
                max_bytes=50,
            )

    def test_yaml_error_passes_through(self):
        """Malformed YAML that trips the parser (not our pre-scan) should
        raise yaml.YAMLError — NOT our YAMLTooComplexError. Callers
        catch them separately."""
        import yaml as _yaml
        malformed = "key: value: double colon: not valid"
        # Our guards don't fire (size, depth, anchors all OK)
        # and yaml.safe_load itself raises
        with pytest.raises(_yaml.YAMLError):
            bounded_yaml_load(malformed, label="test")


# =============================================================================
# safe_write_text
# =============================================================================

class TestSafeWriteText:

    def test_writes_normal_file(self, tmp_path):
        dest = tmp_path / "cached.yaml"
        safe_write_text(dest, "hello world\n", encoding="utf-8")
        assert dest.exists()
        assert dest.read_text() == "hello world\n"

    def test_overwrites_existing_file(self, tmp_path):
        dest = tmp_path / "cached.yaml"
        dest.write_text("old content")
        safe_write_text(dest, "new content")
        assert dest.read_text() == "new content"

    def test_refuses_symlink_target(self, tmp_path):
        """The core TOCTOU defence: a symlink sitting at the destination
        path must NOT be followed. This is the attack scenario where a
        concurrent process swaps the legitimate cache path for a symlink
        pointing at /etc/passwd (or similar) between the time
        safe_relative_path validated the path and the time we open it."""
        decoy = tmp_path / "decoy_target.txt"
        decoy.write_text("original decoy content")

        dest = tmp_path / "cached.yaml"
        # Set up: dest is a symlink → decoy
        os.symlink(decoy, dest)
        assert dest.is_symlink()

        # safe_write_text should refuse to write through the symlink.
        # The exact errno varies by platform (ELOOP on Linux/macOS,
        # sometimes EMLINK); just assert OSError.
        with pytest.raises(OSError):
            safe_write_text(dest, "attacker-controlled content")

        # And the symlink target must be UNTOUCHED — this is the core
        # invariant we're defending.
        assert decoy.read_text() == "original decoy content"

    def test_encoding_respected(self, tmp_path):
        dest = tmp_path / "latin.txt"
        safe_write_text(dest, "café", encoding="utf-8")
        # Round-trip as bytes to prove utf-8 encoding
        assert dest.read_bytes() == "café".encode("utf-8")
