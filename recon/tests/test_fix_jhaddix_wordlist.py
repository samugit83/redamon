"""
The jhaddix all.txt wordlist must actually reach Amass when the user selects it.

The image downloaded the list to /app/recon/wordlists/, but every recon
container bind-mounts the host's recon/ over /app/recon, which hides it, and the
Amass sibling container mounts the list by HOST path anyway. So selecting
"jhaddix all.txt (~2.18M entries)" silently brute-forced with Amass's ~8K
built-in list. Now the image bakes the list outside /app/recon, run_amass copies
it into recon/wordlists/ (= the host's) on first use, downloads it from the same
pinned URL when the image predates that, and warns when neither works.

Run (inside the redamon-recon image):
    python /repo/tooling/scripts/pytest_isolated.py unit tests/test_fix_jhaddix_wordlist.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.main_recon_modules import domain_recon as dr  # noqa: E402

HOST_RECON_OUTPUT = "/srv/redamon/recon/output"
HOST_WORDLIST = "/srv/redamon/recon/wordlists/jhaddix-all.txt"
WORDLIST_CONTENT = "www\napi\nmail\n"

BRUTE_JHADDIX = {
    "AMASS_ENABLED": True,
    "AMASS_BRUTE": True,
    "AMASS_BRUTE_WORDLISTS": ["default", "jhaddix-all"],
}


@pytest.fixture
def paths(tmp_path, monkeypatch):
    """Point the installed and baked wordlist at tmp_path. `raising=False` lets
    these tests run (and fail on behaviour) against code without the constants."""
    installed = tmp_path / "recon" / "wordlists" / "jhaddix-all.txt"
    installed.parent.mkdir(parents=True)
    baked = tmp_path / "opt" / "jhaddix-all.txt"
    monkeypatch.setattr(dr, "JHADDIX_WORDLIST_PATH", str(installed), raising=False)
    monkeypatch.setattr(dr, "JHADDIX_BAKED_PATH", str(baked), raising=False)
    monkeypatch.setenv("HOST_RECON_OUTPUT_PATH", HOST_RECON_OUTPUT)
    return installed, baked


def _bake(baked):
    baked.parent.mkdir(parents=True, exist_ok=True)
    baked.write_text(WORDLIST_CONTENT)


def _run_amass(settings, requests_get=None):
    calls = []

    def fake_run(cmd, **_kw):
        calls.append(list(cmd))
        return mock.MagicMock(returncode=0, stdout="", stderr="")

    get = requests_get or mock.MagicMock(side_effect=AssertionError("unexpected download"))
    with mock.patch.object(dr, "_source_skipped", return_value=False), \
         mock.patch.object(dr, "_source_record"), \
         mock.patch.object(dr.subprocess, "run", side_effect=fake_run), \
         mock.patch.object(dr.requests, "get", get):
        dr.run_amass("example.test", settings=dict(settings))
    assert len(calls) == 1
    return calls[0], get


def _wordlist_mounted(cmd):
    mount = f"{HOST_WORDLIST}:/wordlist/jhaddix-all.txt:ro"
    if mount not in cmd:
        return False
    i = cmd.index(mount)
    image = cmd.index("caffix/amass:latest")
    assert cmd[i - 1] == "-v" and i < image, "the wordlist mount must precede the image"
    assert cmd[cmd.index("-w") + 1] == "/wordlist/jhaddix-all.txt"
    return True


def _leftovers(directory):
    return [p.name for p in directory.iterdir() if p.name != "jhaddix-all.txt"]


def _response(chunks=(b"www\n", b"api\n", b"mail\n"), fail_after=None):
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.raise_for_status.return_value = None

    def iter_content(chunk_size=None):
        for i, c in enumerate(chunks):
            if fail_after is not None and i == fail_after:
                raise dr.requests.ConnectionError("connection reset")
            yield c

    resp.iter_content.side_effect = iter_content
    return resp


class TestJhaddixSelected:
    def test_baked_copy_is_installed_on_the_host_and_mounted(self, paths, capsys):
        installed, baked = paths
        _bake(baked)

        cmd, get = _run_amass(BRUTE_JHADDIX)

        assert installed.read_text() == WORDLIST_CONTENT
        # Amass runs in a sibling container that may not be root.
        assert installed.stat().st_mode & 0o777 == 0o644
        assert _leftovers(installed.parent) == []
        assert _wordlist_mounted(cmd)
        get.assert_not_called()
        assert "Using jhaddix all.txt" in capsys.readouterr().out

    def test_an_installed_copy_is_used_as_is(self, paths):
        installed, _baked = paths
        installed.write_text(WORDLIST_CONTENT)

        with mock.patch.object(dr.shutil, "copy2") as copy2:
            cmd, get = _run_amass(BRUTE_JHADDIX)

        copy2.assert_not_called()
        get.assert_not_called()
        assert _wordlist_mounted(cmd)

    def test_downloads_the_pinned_list_when_the_image_has_no_baked_copy(self, paths):
        installed, _baked = paths
        get = mock.MagicMock(return_value=_response())

        cmd, _ = _run_amass(BRUTE_JHADDIX, requests_get=get)

        assert installed.read_text() == WORDLIST_CONTENT
        assert installed.stat().st_mode & 0o777 == 0o644
        assert _leftovers(installed.parent) == []
        assert _wordlist_mounted(cmd)
        assert get.call_args.args[0] == dr.JHADDIX_WORDLIST_URL
        assert get.call_args.kwargs.get("timeout"), "the download must be bounded"

    def test_unavailable_list_falls_back_to_built_in_with_a_clear_warning(self, paths, capsys):
        installed, _baked = paths
        get = mock.MagicMock(side_effect=dr.requests.ConnectionError("offline"))

        cmd, _ = _run_amass(BRUTE_JHADDIX, requests_get=get)

        out = capsys.readouterr().out
        assert "-brute" in cmd and "-w" not in cmd
        assert not any("jhaddix" in tok for tok in cmd)
        assert not installed.exists()
        assert re.search(r"WARNING.*jhaddix all\.txt was selected", out), out
        assert "Using Amass built-in wordlist" in out

    def test_an_interrupted_download_leaves_no_file_behind(self, paths, capsys):
        installed, _baked = paths
        get = mock.MagicMock(return_value=_response(fail_after=1))

        cmd, _ = _run_amass(BRUTE_JHADDIX, requests_get=get)

        assert not installed.exists(), "a partial wordlist was installed"
        assert _leftovers(installed.parent) == []
        assert "-w" not in cmd
        assert "WARNING" in capsys.readouterr().out

    def test_no_host_path_warns_instead_of_staying_silent(self, paths, monkeypatch, capsys):
        installed, baked = paths
        _bake(baked)
        monkeypatch.delenv("HOST_RECON_OUTPUT_PATH")

        cmd, _ = _run_amass(BRUTE_JHADDIX)

        assert "-w" not in cmd
        assert not installed.exists()
        assert "WARNING" in capsys.readouterr().out

    def test_install_is_an_atomic_replace_within_the_wordlists_dir(self, paths):
        installed, baked = paths
        _bake(baked)
        real_replace = dr.os.replace
        replaced = []

        def spy(src, dst):
            replaced.append((Path(src), Path(dst)))
            return real_replace(src, dst)

        with mock.patch.object(dr.os, "replace", side_effect=spy):
            _run_amass(BRUTE_JHADDIX)

        assert len(replaced) == 1
        src, dst = replaced[0]
        assert dst == installed
        # Same directory, so os.replace is a rename and readers never see half a file.
        assert src.parent == installed.parent and src != dst


class TestJhaddixNotSelected:
    @pytest.mark.parametrize("settings", [
        {"AMASS_ENABLED": True, "AMASS_BRUTE": True, "AMASS_BRUTE_WORDLISTS": ["default"]},
        {"AMASS_ENABLED": True, "AMASS_BRUTE": False,
         "AMASS_BRUTE_WORDLISTS": ["default", "jhaddix-all"]},
        {"AMASS_ENABLED": True},
    ])
    def test_nothing_is_copied_downloaded_or_warned(self, paths, settings, capsys):
        installed, baked = paths
        _bake(baked)

        cmd, get = _run_amass(settings)

        assert not installed.exists()
        get.assert_not_called()
        assert "-w" not in cmd
        assert "WARNING" not in capsys.readouterr().out

    def test_default_brute_command_is_unchanged(self, paths):
        cmd, _ = _run_amass({"AMASS_ENABLED": True, "AMASS_BRUTE": True,
                             "AMASS_TIMEOUT": 7, "AMASS_BRUTE_WORDLISTS": ["default"]})
        config = cmd[cmd.index("-v") + 1]
        assert config.endswith(":/root/.config/amass")
        # The name a timeout kills the container by (R-9) differs per run.
        i = cmd.index("--name")
        assert cmd[i + 1].startswith("amass-")
        del cmd[i:i + 2]
        assert cmd == ["docker", "run", "--rm", "-v", config, "caffix/amass:latest",
                       "enum", "-d", "example.test", "-timeout", "7", "-brute"]


class TestImageAndRepo:
    def test_dockerfile_bakes_the_list_outside_the_bind_mounted_app_recon(self):
        dockerfile = (_RECON / "Dockerfile").read_text()
        block = dockerfile[dockerfile.index("jhaddix"):]
        target = re.search(r"-o\s+(\S*jhaddix-all\.txt)", block).group(1)
        assert not target.startswith("/app/recon"), (
            f"{target} is hidden by the host recon/ bind mount at runtime")
        assert target == dr.JHADDIX_BAKED_PATH

    def test_runtime_download_uses_the_same_pinned_url_as_the_image(self):
        dockerfile = (_RECON / "Dockerfile").read_text()
        assert dr.JHADDIX_WORDLIST_URL in dockerfile
        # Pinned to an immutable gist revision, not the mutable /raw/ HEAD.
        assert re.search(r"/raw/[0-9a-f]{40}/all\.txt$", dr.JHADDIX_WORDLIST_URL)

    def test_installed_copy_is_gitignored(self):
        lines = (_REPO / ".gitignore").read_text().splitlines()
        assert "recon/wordlists/jhaddix-all.txt" in lines
