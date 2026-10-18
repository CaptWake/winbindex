"""Tests for the ``winbindex`` command-line interface."""

from __future__ import annotations

import gzip
import json
import uuid
from pathlib import Path

import pytest
import responses
from winbindex import DEFAULT_SYMBOL_SERVER_URL, DEFAULT_WINBINDEX_BASE_URL, __version__
from winbindex.cli import main

from tests.test_pdb import _rsds, _minimal_pe

SHA_A = "a" * 64  # x64, downloadable, pdb in index, 11-22H2
SHA_B = "b" * 64  # x86, metadata-only, 1809
SHA_C = "c" * 64  # x64, downloadable, no pdb, 11-22H2 + 11-23H2, newest

SAMPLE = {
    SHA_A: {
        "fileInfo": {
            "version": "10.0.22621.1 (WinBuild.160101.0800)",
            "description": "Windows NT BASE API Client DLL",
            "timestamp": 0xDEADBEEF,
            "virtualSize": 0x1000,
            "machineType": 0x8664,
            "size": 1234,
            "signingStatus": "Signed",
        },
        "windowsVersions": {
            "11-22H2": {"KB5023778": {"windowsVersionInfo": {"releaseDate": "2023-03-21"}}},
        },
        "pdb": {"pdbName": "kernel32.pdb", "pdbGuid": "1B72224D-37B8-1792-2820-0ED8994498B2", "pdbAge": 1},
    },
    SHA_B: {
        "fileInfo": {"version": "10.0.19041.1", "machineType": 0x14C, "size": 999, "signingStatus": "Unsigned"},
        "windowsVersions": {"1809": {"BASE": {"windowsVersionInfo": {"releaseDate": "2018-10-09"}}}},
    },
    SHA_C: {
        "fileInfo": {
            "version": "11.0.22000.42",
            "timestamp": 0xCAFEBABE,
            "virtualSize": 0x2000,
            "machineType": 0x8664,
            "size": 2222,
            "signingStatus": "Signed",
        },
        "windowsVersions": {
            "11-22H2": {"KB5025221": {"updateInfo": {"releaseDate": "2023-04-11"}}},
            "11-23H2": {"KB5031455": {"updateInfo": {"releaseDate": "2023-10-31"}}},
        },
    },
}

META_URL = f"{DEFAULT_WINBINDEX_BASE_URL}/by_filename_compressed/kernel32.dll.json.gz"
BIN_A = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
BIN_C = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/CAFEBABE2000/kernel32.dll"
PDB_A = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.pdb/1B72224D37B8179228200ED8994498B21/kernel32.pdb"


def _gz(data: dict) -> bytes:
    return gzip.compress(json.dumps(data).encode())


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch, tmp_path: Path):
    # Never touch the real user cache from the test-suite.
    monkeypatch.setenv("WINBINDEX_CACHE_DIR", str(tmp_path / "cache"))


@pytest.fixture
def rsps():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as r:
        r.add(responses.GET, META_URL, body=_gz(SAMPLE), status=200)
        yield r


@pytest.fixture
def run(capsys):
    def _run(*argv: str, cache: bool = False) -> tuple[int, str, str]:
        args = list(argv) + ([] if cache else ["--no-cache"])
        code = main(args)
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


# ------------------------------------------------------------------ general


class TestGeneral:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == f"winbindex {__version__}"

    def test_global_option_after_subcommand(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "--timeout", "5", "--retries", "0")
        assert code == 0
        assert "SHA256" in out

    def test_global_option_before_subcommand_not_clobbered(self, rsps, run, tmp_path: Path):
        cache = tmp_path / "explicit"
        code, _, _ = run("--cache-dir", str(cache), "list", "kernel32.dll", cache=True)
        assert code == 0
        assert (cache / "kernel32.dll.json.gz").is_file()

    def test_cache_dir_after_subcommand(self, rsps, run, tmp_path: Path):
        cache = tmp_path / "after"
        code, _, _ = run("list", "kernel32.dll", "--cache-dir", str(cache), cache=True)
        assert code == 0
        assert (cache / "kernel32.dll.json.gz").is_file()

    def test_default_cache_dir_from_env(self, rsps, run, tmp_path: Path):
        code, _, _ = run("list", "kernel32.dll", cache=True)
        assert code == 0
        assert (tmp_path / "cache" / "kernel32.dll.json.gz").is_file()

    def test_not_indexed_is_exit_2(self, run):
        with responses.RequestsMock() as r:
            r.add(responses.GET, META_URL, status=404)
            code, out, err = run("list", "kernel32.dll")
        assert code == 2
        assert out == ""
        assert "not indexed" in err

    def test_invalid_filename_is_exit_2_without_traceback(self, run):
        code, _, err = run("list", "a|b.dll")
        assert code == 2
        assert err.startswith("error:")
        assert "Traceback" not in err

    def test_path_argument_uses_the_file_name(self, rsps, run):
        code, out, err = run("list", "C:\\Windows\\System32\\Kernel32.dll", "-q")
        assert code == 0
        assert out.split() == [SHA_B, SHA_A, SHA_C]
        assert "note: looking up 'Kernel32.dll'" in err

    def test_repeated_filenames_are_looked_up_once(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "KERNEL32.DLL", "-q")
        assert code == 0
        assert out.split() == [SHA_B, SHA_A, SHA_C]

    def test_verbose_counts_on_both_sides_of_the_subcommand(self, rsps, run, monkeypatch):
        import winbindex.cli as cli

        levels: list[int] = []
        monkeypatch.setattr(cli, "_configure_logging", levels.append)
        run("-v", "list", "kernel32.dll", "-v")
        assert levels == [2]

    @pytest.mark.parametrize(
        ("option", "value", "message"),
        [("--retries", "-1", "must be >= 0"), ("--timeout", "0", "must be > 0"), ("--cache-ttl", "x", "a number")],
    )
    def test_numeric_options_are_validated(self, capsys, option, value, message):
        with pytest.raises(SystemExit) as exc:
            main(["list", "x.dll", option, value, "--no-cache"])
        assert exc.value.code == 2
        assert message in capsys.readouterr().err

    def test_bad_machine_is_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["list", "x.dll", "--machine", "sparc", "--no-cache"])
        assert exc.value.code == 2
        assert "Unknown machine type" in capsys.readouterr().err

    def test_keyboard_interrupt_is_130(self, rsps, run, monkeypatch):
        import winbindex.cli as cli

        def boom(*_a, **_k):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "cmd_list", boom)
        monkeypatch.setattr(cli, "build_parser", _parser_with(boom))
        code, _, err = run("list", "kernel32.dll")
        assert code == 130
        assert "interrupted" in err

    def test_one_of_several_files_missing(self, rsps, run):
        rsps.add(responses.GET, META_URL.replace("kernel32.dll", "nope.dll"), status=404)
        code, out, err = run("list", "kernel32.dll", "nope.dll")
        assert code == 1
        assert "'nope.dll' is not indexed" in err
        assert "FILE" in out and "kernel32.dll" in out  # FILE column for multi-file listings

    def test_one_of_several_files_without_matches_is_named(self, rsps, run):
        ntdll = {"d" * 64: _entry("10.0.1", 0x8664)}
        rsps.add(responses.GET, META_URL.replace("kernel32.dll", "ntdll.dll"), body=_gz(ntdll))
        code, out, err = run("list", "kernel32.dll", "ntdll.dll", "--machine", "x86")
        assert code == 0
        assert "kernel32.dll" in out
        assert "No matching entries for ntdll.dll." in err
        assert "no ntdll.dll entries for --machine x86; available: x64" in err


def _entry(version: str | None, machine: int | None, *, timestamp: int | None = 0x11111111, pdb=None) -> dict:
    """A minimal index entry; ``timestamp=None`` makes it metadata-only (not downloadable)."""
    file_info: dict = {"version": version, "machineType": machine, "size": 100, "signingStatus": "Signed"}
    if timestamp is not None:
        file_info |= {"timestamp": timestamp, "virtualSize": 0x2000}
    entry: dict = {
        "fileInfo": file_info,
        "windowsVersions": {"11-22H2": {"KB1": {"windowsVersionInfo": {"releaseDate": "2023-01-01"}}}},
    }
    if pdb is not None:
        entry["pdb"] = pdb
    return entry


def _parser_with(func):
    from winbindex.cli import build_parser as real

    def build():
        p = real()
        for action in p._subparsers._group_actions[0]._name_parser_map.values():  # type: ignore[union-attr]
            action.set_defaults(func=func)
        return p

    return build


# --------------------------------------------------------------------- list


class TestList:
    def test_table(self, rsps, run):
        code, out, err = run("list", "kernel32.dll")
        assert code == 0
        lines = out.splitlines()
        assert lines[0].split() == [
            "SHA256",
            "VERSION",
            "ARCH",
            "SIGNED",
            "SIZE",
            "RELEASED",
            "WINDOWS",
            "UPDATES",
            "DOWNLOAD",
        ]
        # Sorted numerically by version: 10.0.19041.1 < 10.0.22621.1 < 11.0.22000.42
        assert [ln.split()[1] for ln in lines[1:]] == ["10.0.19041.1", "10.0.22621.1", "11.0.22000.42"]
        row_a = next(ln for ln in lines if ln.startswith("a" * 16))
        assert "x64" in row_a and "yes" in row_a and "1.2 KB" in row_a and "2023-03-21" in row_a
        assert row_a.endswith("bin+pdb")
        row_b = next(ln for ln in lines if ln.startswith("b" * 16))
        assert "x86" in row_b and " no " in row_b and row_b.endswith("-")
        assert "3 matching entries (2 downloadable, 1 with PDB metadata)" in err

    def test_full_version_and_no_header(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "--full-version", "--no-header", "--sha256", SHA_A)
        assert code == 0
        assert out.splitlines() == [out.splitlines()[0]]
        assert "(WinBuild.160101.0800)" in out

    def test_quiet_prints_full_hashes(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q")
        assert code == 0
        assert out.split() == [SHA_B, SHA_A, SHA_C]

    def test_json(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "--json", "--sha256", "aaaa")
        assert code == 0
        data = json.loads(out)
        assert len(data) == 1
        item = data[0]
        assert item["sha256"] == SHA_A
        assert item["machine"] == "x64"
        assert item["signed"] is True
        assert item["description"] == "Windows NT BASE API Client DLL"
        assert item["releaseDate"] == "2023-03-21"
        assert item["pdb"] == {"name": "kernel32.pdb", "guid": "1B72224D37B8179228200ED8994498B2", "age": 1}
        assert item["binaryUrl"] == BIN_A
        assert item["pdbUrl"] == PDB_A
        assert item["releases"][0]["update"] == "KB5023778"

    def test_sha256_prefix(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--sha256", "CCCC")
        assert code == 0
        assert out.split() == [SHA_C]

    def test_machine_by_name(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--machine", "amd64")
        assert code == 0
        assert out.split() == [SHA_A, SHA_C]

    def test_latest_per_arch(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--latest")
        assert code == 0
        assert set(out.split()) == {SHA_B, SHA_C}

    def test_latest_with_machine(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--latest", "--machine", "x64")
        assert out.split() == [SHA_C]

    def test_limit_and_reverse(self, rsps, run):
        code, out, err = run("list", "kernel32.dll", "-q", "--reverse", "--limit", "1")
        assert out.split() == [SHA_C]
        assert "showing 1 of 3" in err

    def test_sort_by_date(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--sort", "date")
        assert out.split() == [SHA_B, SHA_A, SHA_C]

    def test_no_match_gives_hint(self, rsps, run):
        code, out, err = run("list", "kernel32.dll", "--windows-version", "11-22H3")
        assert code == 1
        assert out == ""
        assert "No matching entries" in err
        assert "did you mean '11-22H2'" in err

    def test_hint_ignores_case_like_the_filter_does(self, rsps, run):
        _, _, err = run("list", "kernel32.dll", "--windows-version", "11-22h3")
        assert "did you mean '11-22H2'" in err

    def test_no_match_unknown_arch_hint(self, rsps, run):
        code, _, err = run("list", "kernel32.dll", "--machine", "arm64")
        assert code == 1
        assert "--machine arm64; available: x64, x86" in err

    def test_hint_names_the_filter_that_removed_everything(self, rsps, run):
        _, _, err = run("list", "kernel32.dll", "--with-pdb", "--machine", "x86")
        assert "the other filters match 1 entry of kernel32.dll, but without PDB metadata" in err

    def test_singular_summary(self, rsps, run):
        _, _, err = run("list", "kernel32.dll", "--sha256", "aaaa")
        assert "1 matching entry (1 downloadable" in err

    @pytest.mark.parametrize("reverse", [False, True])
    def test_entries_without_a_version_sort_last(self, rsps, run, reverse):
        data = {"a" * 64: _entry("10.0.2", 0x8664), "b" * 64: _entry(None, 0x8664), "c" * 64: _entry("10.0.1", 0x8664)}
        rsps.replace(responses.GET, META_URL, body=_gz(data))
        _, out, _ = run("list", "kernel32.dll", "-q", *(["--reverse"] if reverse else []))
        expected = ["a" * 64, "c" * 64] if reverse else ["c" * 64, "a" * 64]
        assert out.split() == [*expected, "b" * 64]

    def test_windows_version_case_insensitive(self, rsps, run):
        code, out, _ = run("list", "kernel32.dll", "-q", "--windows-version", "11-23h2")
        assert out.split() == [SHA_C]


# ---------------------------------------------------------------------- url


class TestUrl:
    def test_binary_urls_only_for_downloadable_entries(self, rsps, run):
        code, out, err = run("url", "kernel32.dll")
        assert code == 0
        assert out.splitlines() == [BIN_A, BIN_C]
        assert "skipped" not in err

    def test_explicit_no_downloadable_reports_skips(self, rsps, run):
        code, out, err = run("url", "kernel32.dll", "--no-downloadable")
        assert code == 1
        assert out == ""
        assert "skipped 1 entry without download metadata" in err

    def test_latest_picks_like_download_does(self, rsps, run, tmp_path: Path):
        # The newest build is metadata-only: both commands must fall back to the newest downloadable one.
        data = {"a" * 64: _entry("10.0.1", 0x8664), "b" * 64: _entry("10.0.2", 0x8664, timestamp=None)}
        rsps.replace(responses.GET, META_URL, body=_gz(data))
        code, out, _ = run("url", "kernel32.dll", "--latest")
        assert code == 0
        assert out.strip() == f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/111111112000/kernel32.dll"
        _, out, _ = run("download", "kernel32.dll", "--latest", "--dry-run", "-o", str(tmp_path))
        assert " 10.0.1 x64" in out

    def test_ambiguous_sha256_prefix_warns(self, rsps, run):
        data = {"ab" + "1" * 62: _entry("10.0.1", 0x8664), "ab" + "2" * 62: _entry("10.0.2", 0x8664)}
        rsps.replace(responses.GET, META_URL, body=_gz(data))
        code, out, err = run("url", "kernel32.dll", "--sha256", "ab")
        assert len(out.splitlines()) == 2
        assert "warning: --sha256 'ab' is ambiguous: it matches 2 kernel32.dll entries" in err

    def test_pdb_urls(self, rsps, run):
        code, out, err = run("url", "kernel32.dll", "--pdb")
        assert code == 0
        assert out.splitlines() == [PDB_A]
        assert "skipped 2 entries without PDB metadata" in err
        assert "download --pdb" in err

    def test_nothing_printed_is_exit_1(self, rsps, run):
        code, out, _ = run("url", "kernel32.dll", "--pdb", "--machine", "x86")
        assert code == 1
        assert out == ""

    def test_custom_symbol_server(self, rsps, run):
        code, out, _ = run("url", "kernel32.dll", "--latest", "--machine", "x64", "--symbol-server", "http://m/s/")
        assert out.strip() == "http://m/s/kernel32.dll/CAFEBABE2000/kernel32.dll"

    def test_json(self, rsps, run):
        code, out, _ = run("url", "kernel32.dll", "--json")
        assert [i["url"] for i in json.loads(out)] == [BIN_A, BIN_C]


# ----------------------------------------------------------------- download


class TestDownload:
    def test_dry_run_writes_nothing(self, rsps, run, tmp_path: Path):
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "--dry-run", "-o", str(dest))
        assert code == 0
        assert "[1/2]" in out and "[2/2]" in out and BIN_A in out
        assert "dry run: 2 files" in err
        assert not dest.exists()

    def test_download_sha_layout(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_A, body=b"A" * 100)
        rsps.add(responses.GET, BIN_C, body=b"C" * 200)
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "-o", str(dest))
        assert code == 0
        assert (dest / SHA_A[:16] / "kernel32.dll").read_bytes() == b"A" * 100
        assert (dest / SHA_C[:16] / "kernel32.dll").read_bytes() == b"C" * 200
        assert sorted(p.name for p in dest.iterdir()) == [SHA_A[:16], SHA_C[:16]]  # no dir for metadata-only entry
        assert out.count("  ok  ->") == 2
        assert "Done: 2 downloaded, 0 skipped (exist), 0 failed" in err

    def test_rerun_skips_existing_and_overwrite_refetches(self, rsps, run, tmp_path: Path):
        # SHA_C's index key is timestamp 0xCAFEBABE / image size 0x2000; both PEs below carry it.
        v1 = _minimal_pe(None, timestamp=0xCAFEBABE)
        v2 = _minimal_pe(_rsds(uuid.uuid4(), 1, b"kernel32.pdb"), timestamp=0xCAFEBABE)
        rsps.add(responses.GET, BIN_C, body=v1)
        dest = tmp_path / "out"
        assert run("download", "kernel32.dll", "--latest", "--machine", "x64", "-o", str(dest))[0] == 0
        code, out, err = run("download", "kernel32.dll", "--latest", "--machine", "x64", "-o", str(dest))
        assert code == 0
        assert "exists (skipped)" in out
        assert "Done: 0 downloaded, 1 skipped (exist), 0 failed" in err

        rsps.replace(responses.GET, BIN_C, body=v2)
        code, _, _ = run("download", "kernel32.dll", "--latest", "--machine", "x64", "-o", str(dest), "--overwrite")
        assert code == 0
        assert (dest / SHA_C[:16] / "kernel32.dll").read_bytes() == v2

    @pytest.mark.parametrize(
        ("existing", "problem"),
        [(_minimal_pe(None, timestamp=0x12345678), "a different build"), (b"not a pe", "not a PE file")],
    )
    def test_existing_file_of_another_build_is_not_reported_as_present(self, rsps, run, tmp_path, existing, problem):
        # E.g. --layout flat re-run after a new update: the old binary must not count as "exists".
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "kernel32.dll").write_bytes(existing)
        argv = ["download", "kernel32.dll", "--latest", "--machine", "x64", "--layout", "flat", "-o", str(dest)]
        code, out, err = run(*argv)
        assert code == 1
        assert f"already exists but is {problem}; use --overwrite to replace it" in out
        assert "1 failed" in err
        assert (dest / "kernel32.dll").read_bytes() == existing

        code, out, _ = run(*argv, "--dry-run")
        assert code == 1
        assert f"would FAIL: {dest / 'kernel32.dll'} already exists but is {problem}" in out

    def test_no_downloadable_fails_per_item_instead_of_aborting(self, rsps, run, tmp_path: Path):
        code, out, err = run("download", "kernel32.dll", "--no-downloadable", "-o", str(tmp_path / "out"))
        assert code == 1
        assert "FAILED: no download metadata in the index" in out
        assert "Done: 0 downloaded, 0 skipped (exist), 1 failed" in err
        assert "Traceback" not in err

        code, out, _ = run("download", "kernel32.dll", "--no-downloadable", "--dry-run", "-o", str(tmp_path / "out"))
        assert code == 1
        assert "would FAIL: no download metadata in the index" in out

    def test_dry_run_reports_existing_files_and_pdbs(self, rsps, run, tmp_path: Path):
        dest = tmp_path / "out"
        (dest / SHA_C[:16]).mkdir(parents=True)
        (dest / SHA_C[:16] / "kernel32.dll").write_bytes(_minimal_pe(None, timestamp=0xCAFEBABE))
        code, out, err = run("download", "kernel32.dll", "--dry-run", "--pdb", "-o", str(dest))
        assert code == 0
        assert "exists (would skip)" in out
        assert f"+ kernel32.pdb  {PDB_A}" in out  # PDB triple from the index
        assert "+ pdb: not in the index; read from the binary after download" in out
        assert "dry run: 1 file to download (1.2 KB), 1 already present; nothing written" in err

    def test_pdb_name_from_the_index_cannot_escape_dest(self, rsps, run, tmp_path: Path):
        pdb = {"pdbName": "../../escaped.pdb", "pdbGuid": "1B72224D37B8179228200ED8994498B2", "pdbAge": 1}
        rsps.replace(responses.GET, META_URL, body=_gz({"a" * 64: _entry("10.0.1", 0x8664, pdb=pdb)}))
        rsps.add(responses.GET, f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/111111112000/kernel32.dll", body=b"bin")
        pdb_url = f"{DEFAULT_SYMBOL_SERVER_URL}/escaped.pdb/1B72224D37B8179228200ED8994498B21/escaped.pdb"
        rsps.add(responses.GET, pdb_url, body=b"pdb")
        dest = tmp_path / "a" / "b" / "out"
        code, _, _ = run("download", "kernel32.dll", "--pdb", "-o", str(dest))
        assert code == 0
        assert [p.relative_to(tmp_path) for p in tmp_path.rglob("escaped.pdb")] == [
            Path("a/b/out") / ("a" * 16) / "escaped.pdb"
        ]

    def test_version_layout_with_unknown_arch_is_a_safe_directory_name(self, rsps, run, tmp_path: Path):
        rsps.replace(responses.GET, META_URL, body=_gz({"a" * 64: _entry("10.0.1 / x", None)}))
        rsps.add(responses.GET, f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/111111112000/kernel32.dll", body=b"bin")
        dest = tmp_path / "out"
        code, _, _ = run("download", "kernel32.dll", "--layout", "version", "-o", str(dest))
        assert code == 0
        assert (dest / "kernel32.dll" / "10.0.1 _ x-unknown" / "kernel32.dll").read_bytes() == b"bin"

    def test_failed_download_is_reported_and_exit_1(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_A, body=b"ok")
        rsps.add(responses.GET, BIN_C, status=404)
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "-o", str(dest), "--retries", "0")
        assert code == 1
        assert "FAILED: not available on the symbol server (HTTP 404)" in out
        assert "Done: 1 downloaded, 0 skipped (exist), 1 failed" in err
        assert not (dest / SHA_C[:16] / "kernel32.dll.part").exists()

    def test_pdb_from_index(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_A, body=b"bin")
        rsps.add(responses.GET, PDB_A, body=b"pdb")
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "--sha256", "aaaa", "--pdb", "-o", str(dest))
        assert code == 0
        assert (dest / SHA_A[:16] / "kernel32.pdb").read_bytes() == b"pdb"
        assert "+ kernel32.pdb" in out
        assert "PDBs: 1 downloaded" in err

    def test_pdb_extracted_from_binary(self, rsps, run, tmp_path: Path):
        guid = uuid.UUID("0123456789ABCDEF0123456789ABCDEF")
        rsps.add(responses.GET, BIN_C, body=_minimal_pe(_rsds(guid, 2, b"c:\\x\\kernel32.pdb")))
        pdb_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.pdb/0123456789ABCDEF0123456789ABCDEF2/kernel32.pdb"
        rsps.add(responses.GET, pdb_url, body=b"extracted-pdb")
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "--sha256", "cccc", "--pdb", "-o", str(dest))
        assert code == 0
        assert (dest / SHA_C[:16] / "kernel32.pdb").read_bytes() == b"extracted-pdb"
        assert "PDBs: 1 downloaded" in err

    def test_pdb_unavailable_is_not_a_failure(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_C, body=b"not a pe")
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "--sha256", "cccc", "--pdb", "-o", str(dest))
        assert code == 1  # could not parse the binary -> counted as a PDB failure
        assert "pdb: FAILED: could not parse binary" in out

    def test_pdb_missing_record_is_unavailable(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_C, body=_minimal_pe(None))
        dest = tmp_path / "out"
        code, out, err = run("download", "kernel32.dll", "--sha256", "cccc", "--pdb", "-o", str(dest))
        assert code == 0
        assert "pdb: unavailable (no PDB record in binary)" in out
        assert "1 unavailable" in err

    def test_version_layout(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_A, body=b"a")
        rsps.add(responses.GET, BIN_C, body=b"c")
        dest = tmp_path / "out"
        code, _, _ = run("download", "kernel32.dll", "--layout", "version", "-o", str(dest))
        assert code == 0
        assert (dest / "kernel32.dll" / "10.0.22621.1-x64" / "kernel32.dll").read_bytes() == b"a"
        assert (dest / "kernel32.dll" / "11.0.22000.42-x64" / "kernel32.dll").read_bytes() == b"c"

    def test_flat_layout_requires_unique_names(self, rsps, run, tmp_path: Path):
        code, _, err = run("download", "kernel32.dll", "--layout", "flat", "-o", str(tmp_path / "out"))
        assert code == 2
        assert "--layout flat needs unique filenames" in err

    def test_flat_layout_with_latest(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_C, body=b"c")
        dest = tmp_path / "out"
        code, _, _ = run(
            "download", "kernel32.dll", "--layout", "flat", "--latest", "--machine", "x64", "-o", str(dest)
        )
        assert code == 0
        assert (dest / "kernel32.dll").read_bytes() == b"c"

    def test_json_output(self, rsps, run, tmp_path: Path):
        rsps.add(responses.GET, BIN_A, body=b"a")
        rsps.add(responses.GET, BIN_C, status=404)
        code, out, _ = run("download", "kernel32.dll", "--json", "-o", str(tmp_path / "out"), "--retries", "0")
        assert code == 1
        data = json.loads(out)
        assert [d["status"] for d in data] == ["ok", "failed"]
        assert data[0]["bytes"] == 1
        assert "HTTP 404" in data[1]["error"]

    def test_metadata_only_selection_reports_no_match(self, rsps, run, tmp_path: Path):
        code, out, err = run("download", "kernel32.dll", "--machine", "x86", "-o", str(tmp_path / "out"))
        assert code == 1
        assert "No matching entries" in err
        assert "the other filters match 1 entry of kernel32.dll, but without download metadata" in err
        assert not (tmp_path / "out").exists()

    def test_progress_line_fits_the_terminal(self, capsys, monkeypatch):
        import os

        from winbindex.cli import _Progress

        monkeypatch.setattr("shutil.get_terminal_size", lambda *_a, **_k: os.terminal_size((20, 24)))
        progress = _Progress(enabled=True)
        progress.start("[1/1] a-very-long-file-name.dll 10.0.22621.1485 x64")
        progress.update(512, 1024)
        progress.finish()
        assert all(len(segment) <= 19 for segment in capsys.readouterr().err.split("\r"))


# --------------------------------------------------------------------- info


class TestInfo:
    def test_text(self, rsps, run):
        code, out, err = run("info", "kernel32.dll")
        assert code == 0
        assert out.startswith("kernel32.dll\n")
        assert "description       Windows NT BASE API Client DLL" in out
        assert "3 (2 downloadable · 1 with PDB metadata · 2 signed)" in out
        assert "x64 2 · x86 1" in out
        assert "10.0.19041.1 … 11.0.22000.42" in out
        assert "2018-10-09 … 2023-10-31" in out
        assert "11-22H2" in out and "KB" not in out.split("windows versions")[0]

    def test_json(self, rsps, run):
        code, out, _ = run("info", "kernel32.dll", "--json")
        data = json.loads(out)
        assert data["entries"] == 3
        assert data["architectures"] == {"x64": 2, "x86": 1}
        assert data["newestVersion"] == "11.0.22000.42"
        assert {w["windowsVersion"]: w["entries"] for w in data["windowsVersions"]} == {
            "1809": 1,
            "11-22H2": 2,
            "11-23H2": 1,
        }
        assert [la["machine"] for la in data["latestPerArch"]] == ["x64", "x86"]

    def test_filters_apply(self, rsps, run):
        code, out, _ = run("info", "kernel32.dll", "--machine", "x86", "--json")
        assert json.loads(out)["entries"] == 1

    def test_repeated_filename_is_not_counted_twice(self, rsps, run):
        code, out, _ = run("info", "kernel32.dll", "Kernel32.DLL", "--json")
        assert code == 0
        assert json.loads(out)["entries"] == 3  # one filename -> one object, counted once

    def test_json_is_a_list_whenever_several_filenames_are_given(self, rsps, run):
        rsps.add(responses.GET, META_URL.replace("kernel32.dll", "nope.dll"), status=404)
        code, out, _ = run("info", "kernel32.dll", "nope.dll", "--json")
        assert code == 1
        data = json.loads(out)
        assert isinstance(data, list) and [d["filename"] for d in data] == ["kernel32.dll"]
