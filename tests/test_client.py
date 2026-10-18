"""Tests for :class:`winbindex.WinbindexClient`."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
import responses
from winbindex import (
    DEFAULT_SYMBOL_SERVER_URL,
    DEFAULT_WINBINDEX_BASE_URL,
    PdbInfo,
    DownloadError,
    WinbindexClient,
    InvalidDataError,
    FileNotIndexedError,
)

SAMPLE_KERNEL32 = {
    "0000000000000000000000000000000000000000000000000000000000000001": {
        "fileInfo": {
            "version": "10.0.22621.1",
            "timestamp": 0xDEADBEEF,
            "virtualSize": 0x1000,
            "machineType": 0x8664,
            "size": 1234,
            "signingStatus": "Signed",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000001",
        },
        "windowsVersions": {"11-22H2": {"KB5023778": {"sourcePaths": ["Windows\\System32\\kernel32.dll"]}}},
        "pdb": {
            "pdbName": "kernel32.pdb",
            "pdbGuid": "1B72224D-37B8-1792-2820-0ED8994498B2",
            "pdbAge": 1,
        },
    },
    "0000000000000000000000000000000000000000000000000000000000000002": {
        "fileInfo": {
            "version": "10.0.19041.1",
            "machineType": 0x14C,
            "size": 999,
            # No timestamp/virtualSize - not downloadable.
            "sha256": "0000000000000000000000000000000000000000000000000000000000000002",
            "signingStatus": "Unsigned",
        },
        "windowsVersions": {"1809": {"BASE": {"sourcePaths": ["Windows\\SysWOW64\\kernel32.dll"]}}},
    },
    "0000000000000000000000000000000000000000000000000000000000000003": {
        "fileInfo": {
            "version": "11.0.22000.42",
            "timestamp": 0xCAFEBABE,
            "virtualSize": 0x2000,
            "machineType": 0x8664,
            "size": 2222,
            "signingStatus": "Signed",
            "sha256": "0000000000000000000000000000000000000000000000000000000000000003",
        },
        "windowsVersions": {
            "11-22H2": {"KB5025221": {}},
            "11-23H2": {"KB5031455": {}},
        },
        # No pdb info.
    },
}


def _gzipped(data: dict) -> bytes:
    return gzip.compress(json.dumps(data).encode("utf-8"))


@pytest.fixture
def kernel32_url() -> str:
    return f"{DEFAULT_WINBINDEX_BASE_URL}/by_filename_compressed/kernel32.dll.json.gz"


@pytest.fixture
def mocked_kernel32(kernel32_url: str):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            kernel32_url,
            body=_gzipped(SAMPLE_KERNEL32),
            status=200,
            content_type="application/octet-stream",
        )
        yield rsps


# ----------------------------------------------------------------------- get_raw


class TestGetRaw:
    def test_get_raw(self, mocked_kernel32):
        with WinbindexClient() as client:
            data = client.get_raw("kernel32.dll")
        assert len(data) == 3
        assert "0000000000000000000000000000000000000000000000000000000000000001" in data

    def test_filename_normalized_to_lowercase(self, kernel32_url):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                kernel32_url,
                body=_gzipped(SAMPLE_KERNEL32),
                status=200,
            )
            with WinbindexClient() as client:
                data = client.get_raw("Kernel32.DLL")
            assert len(data) == 3

    def test_404_raises_file_not_indexed(self, kernel32_url):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, status=404)
            with WinbindexClient() as client, pytest.raises(FileNotIndexedError):
                client.get_raw("kernel32.dll")

    def test_invalid_gzip_raises(self, kernel32_url):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, body=b"not gzip", status=200)
            with WinbindexClient() as client, pytest.raises(InvalidDataError):
                client.get_raw("kernel32.dll")

    def test_invalid_json_raises(self, kernel32_url):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                kernel32_url,
                body=gzip.compress(b"not json"),
                status=200,
            )
            with WinbindexClient() as client, pytest.raises(InvalidDataError):
                client.get_raw("kernel32.dll")

    def test_500_with_retries_eventually_raises(self, kernel32_url):
        with responses.RequestsMock() as rsps:
            for _ in range(4):
                rsps.add(responses.GET, kernel32_url, status=500)
            with WinbindexClient(max_retries=3) as client, pytest.raises(DownloadError):
                client.get_raw("kernel32.dll")


class TestFilenameValidation:
    @pytest.mark.parametrize(
        "bad",
        ["", "../etc/passwd", "foo/bar.dll", "foo\\bar.dll", "foo<bar>.dll"],
    )
    def test_bad_filenames_rejected(self, bad: str):
        with WinbindexClient() as client, pytest.raises(ValueError):
            client.get_raw(bad)


# ---------------------------------------------------------------------- get_file


class TestGetFile:
    def test_returns_entries(self, mocked_kernel32):
        with WinbindexClient() as client:
            entries = client.get_file("kernel32.dll")
        assert len(entries) == 3
        sha = "0000000000000000000000000000000000000000000000000000000000000001"
        first = next(e for e in entries if e.sha256 == sha)
        assert first.version == "10.0.22621.1"
        assert first.has_binary_download
        assert first.has_pdb_download


# ------------------------------------------------------------------------- find


class TestFind:
    def test_filter_by_windows_version(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", windows_version="11-22H2"))
        assert len(results) == 2

    def test_filter_by_version_wildcard(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", version="10.0.*"))
        assert len(results) == 2

    def test_filter_by_machine_type(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", machine_type=0x14C))
        assert len(results) == 1

    def test_filter_by_signed(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", signed=False))
        assert len(results) == 1

    def test_filter_downloadable(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", downloadable=True))
        assert len(results) == 2

    def test_filter_with_pdb(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", with_pdb=True))
        assert len(results) == 1

    def test_filter_by_sha256_case_insensitive(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", sha256="0" * 63 + "1"))
        assert len(results) == 1

    def test_combined_filters(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(
                client.find(
                    "kernel32.dll",
                    machine_type=0x8664,
                    signed=True,
                    windows_version="11-23H2",
                )
            )
        assert len(results) == 1
        assert results[0].version == "11.0.22000.42"

    def test_predicate(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(
                client.find(
                    "kernel32.dll",
                    predicate=lambda e: (e.file_info.size or 0) > 1000,
                )
            )
        assert len(results) == 2


# -------------------------------------------------------------- download_binary


class TestDownloadBinary:
    def test_download_binary_to_directory(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, body=b"PE\x00\x00fake-binary", status=200)

        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            path = client.download_binary(entry, tmp_path)
        assert path == tmp_path / "kernel32.dll"
        assert path.read_bytes() == b"PE\x00\x00fake-binary"

    def test_download_binary_existing_no_overwrite(self, mocked_kernel32, tmp_path: Path):
        target = tmp_path / "kernel32.dll"
        target.write_bytes(b"existing")
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            with pytest.raises(FileExistsError):
                client.download_binary(entry, target)

    def test_download_binary_overwrite(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, body=b"new content", status=200)

        target = tmp_path / "kernel32.dll"
        target.write_bytes(b"existing")
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            client.download_binary(entry, target, overwrite=True)
        assert target.read_bytes() == b"new content"

    def test_progress_callback(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(
            responses.GET,
            bin_url,
            body=b"X" * 1024,
            status=200,
            headers={"Content-Length": "1024"},
        )

        progress_calls: list[tuple[int, int | None]] = []
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            client.download_binary(
                entry,
                tmp_path,
                progress=lambda d, t: progress_calls.append((d, t)),
            )
        assert progress_calls[-1] == (1024, 1024)


# ---------------------------------------------------------------- download_pdb


class TestDownloadPdb:
    def test_from_entry(self, mocked_kernel32, tmp_path: Path):
        pdb_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.pdb/1B72224D37B8179228200ED8994498B21/kernel32.pdb"
        mocked_kernel32.add(responses.GET, pdb_url, body=b"PDB-content", status=200)

        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            path = client.download_pdb(entry, tmp_path)
        assert path == tmp_path / "kernel32.pdb"
        assert path.read_bytes() == b"PDB-content"

    def test_from_pdbinfo(self, tmp_path: Path):
        pdb_info = PdbInfo(
            name="ntoskrnl.pdb",
            guid="0123456789ABCDEF0123456789ABCDEF",
            age=2,
        )
        pdb_url = f"{DEFAULT_SYMBOL_SERVER_URL}/ntoskrnl.pdb/0123456789ABCDEF0123456789ABCDEF2/ntoskrnl.pdb"
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, pdb_url, body=b"sym-data", status=200)
            with WinbindexClient() as client:
                path = client.download_pdb(pdb_info, tmp_path)
        assert path.read_bytes() == b"sym-data"


# --------------------------------------------------------------------- caching


class TestCaching:
    def test_cache_hit_avoids_network(self, kernel32_url: str, tmp_path: Path):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                kernel32_url,
                body=_gzipped(SAMPLE_KERNEL32),
                status=200,
            )
            with WinbindexClient(cache_dir=tmp_path) as client:
                client.get_raw("kernel32.dll")  # populates cache
                # Second call must not need a second network request.
                client.get_raw("kernel32.dll")
        # `responses` will fail in __exit__ if a registered call was used twice.

    def test_cache_ttl_expiry(self, kernel32_url: str, tmp_path: Path):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                kernel32_url,
                body=_gzipped(SAMPLE_KERNEL32),
                status=200,
            )
            rsps.add(
                responses.GET,
                kernel32_url,
                body=_gzipped(SAMPLE_KERNEL32),
                status=200,
            )
            with WinbindexClient(cache_dir=tmp_path, cache_ttl=0) as client:
                client.get_raw("kernel32.dll")
                # ttl=0 means cache is always stale.
                client.get_raw("kernel32.dll")

    def test_corrupt_cache_recovers(self, kernel32_url: str, tmp_path: Path):
        cache_file = tmp_path / "kernel32.dll.json.gz"
        cache_file.write_bytes(b"not gzip")

        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                kernel32_url,
                body=_gzipped(SAMPLE_KERNEL32),
                status=200,
            )
            with WinbindexClient(cache_dir=tmp_path) as client:
                data = client.get_raw("kernel32.dll")
        assert len(data) == 3

    @pytest.mark.parametrize(
        "content",
        [
            _gzipped(SAMPLE_KERNEL32)[:-20],  # truncated gzip stream: EOFError, not OSError
            gzip.compress(b'{"x": "\xff"}'),  # not UTF-8: UnicodeDecodeError
        ],
        ids=["truncated", "not-utf8"],
    )
    def test_damaged_cache_is_refetched(self, kernel32_url: str, tmp_path: Path, content: bytes):
        (tmp_path / "kernel32.dll.json.gz").write_bytes(content)
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, body=_gzipped(SAMPLE_KERNEL32), status=200)
            with WinbindexClient(cache_dir=tmp_path) as client:
                assert len(client.get_raw("kernel32.dll")) == 3

    def test_unwritable_cache_is_a_warning_not_an_error(self, kernel32_url: str, tmp_path: Path, caplog):
        cache = tmp_path / "cache"
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, body=_gzipped(SAMPLE_KERNEL32), status=200)
            with WinbindexClient(cache_dir=cache) as client:
                cache.rmdir()
                cache.write_bytes(b"")  # the cache "directory" is now a file: every write fails
                data = client.get_raw("kernel32.dll")
        assert len(data) == 3
        assert "Could not write cache file" in caplog.text


# ------------------------------------------------------------ filter semantics


class TestFilterSemantics:
    def test_sha256_prefix_matches(self, kernel32_url):
        data = dict(SAMPLE_KERNEL32)
        data["abcdef" + "0" * 58] = {"fileInfo": {"version": "1.0"}}
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, body=_gzipped(data), status=200)
            with WinbindexClient() as client:
                by_prefix = list(client.find("kernel32.dll", sha256="abcdef"))
                by_upper_prefix = list(client.find("kernel32.dll", sha256="ABCDEF00"))
                by_common_prefix = list(client.find("kernel32.dll", sha256="0" * 60))
        assert [e.sha256[:6] for e in by_prefix] == ["abcdef"]
        assert len(by_upper_prefix) == 1
        assert len(by_common_prefix) == 3

    def test_windows_version_case_insensitive(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", windows_version="11-22h2"))
        assert len(results) == 2

    def test_update_case_insensitive(self, mocked_kernel32):
        with WinbindexClient() as client:
            results = list(client.find("kernel32.dll", update="kb5023778"))
        assert len(results) == 1

    def test_filter_entries_standalone(self, mocked_kernel32):
        from winbindex import filter_entries

        with WinbindexClient() as client:
            entries = client.get_file("kernel32.dll")
        assert len(list(filter_entries(entries, signed=True))) == 2
        assert len(list(filter_entries(entries, signed=True, machine_type=0x14C))) == 0


class TestFilenameRules:
    def test_dollar_sign_allowed(self, kernel32_url):
        url = kernel32_url.replace("kernel32.dll", "foo%24bar.dll")
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, url, body=_gzipped({}), status=200)
            with WinbindexClient() as client:
                assert client.get_raw("foo$bar.dll") == {}

    def test_invalid_filename_is_winbindex_error_and_value_error(self):
        from winbindex import WinbindexError, InvalidFilenameError

        with WinbindexClient() as client, pytest.raises(InvalidFilenameError) as exc:
            client.get_raw("a:b.dll")
        assert isinstance(exc.value, WinbindexError)
        assert isinstance(exc.value, ValueError)

    @pytest.mark.parametrize("bad", [".", "..", "foo|bar.dll", "foo\x00.dll", "a*.dll"])
    def test_more_bad_filenames(self, bad: str):
        with WinbindexClient() as client, pytest.raises(ValueError):
            client.get_raw(bad)


# --------------------------------------------------------- malformed entries


class TestMalformedEntries:
    def test_bad_entry_is_skipped_not_fatal(self, kernel32_url, caplog):
        data = dict(SAMPLE_KERNEL32)
        data["0" * 63 + "9"] = {"fileInfo": {"timestamp": "not-an-int", "virtualSize": 1}}
        data["0" * 63 + "8"] = {
            "fileInfo": {"timestamp": 1, "virtualSize": 1},
            "pdb": {"pdbName": "x.pdb", "pdbGuid": "not-a-guid", "pdbAge": 1},
        }
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, kernel32_url, body=_gzipped(data), status=200)
            with WinbindexClient() as client:
                entries = client.get_file("kernel32.dll")
        # The bad-timestamp entry is dropped; the bad-guid entry survives without pdb.
        assert len(entries) == 4
        bad_guid = next(e for e in entries if e.sha256.endswith("8"))
        assert bad_guid.pdb is None
        assert "Skipping malformed" in caplog.text


# -------------------------------------------------------- download failures


class TestDownloadFailures:
    def test_symbol_server_404_is_download_error_not_file_not_indexed(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, status=404)
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            with pytest.raises(DownloadError) as exc:
                client.download_binary(entry, tmp_path)
        assert not isinstance(exc.value, FileNotIndexedError)
        assert exc.value.status_code == 404
        assert "symbol server" in str(exc.value)
        assert not list(tmp_path.iterdir())  # no .part left behind

    def test_mid_stream_failure_raises_download_error_and_cleans_up(self, mocked_kernel32, tmp_path: Path, monkeypatch):
        import requests

        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, body=b"whatever", headers={"Content-Length": "100000"})

        def broken_iter(self, chunk_size=1, decode_unicode=False):
            yield b"partial"
            raise requests.exceptions.ChunkedEncodingError("connection broken")

        with WinbindexClient(max_retries=0) as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            # Patch only once the metadata has been fetched.
            monkeypatch.setattr(requests.Response, "iter_content", broken_iter)
            with pytest.raises(DownloadError) as exc:
                client.download_binary(entry, tmp_path)
        assert exc.value.status_code is None
        assert "connection failed" in str(exc.value)
        assert not list(tmp_path.iterdir())

    def test_short_body_is_rejected(self, mocked_kernel32, tmp_path: Path):
        # urllib3 raises IncompleteRead when the body is shorter than Content-Length;
        # either way the caller must see a DownloadError and no leftover file.
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(
            responses.GET, bin_url, body=b"12345", headers={"Content-Length": "10"}, auto_calculate_content_length=False
        )
        with WinbindexClient(max_retries=0) as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            with pytest.raises(DownloadError):
                client.download_binary(entry, tmp_path)
        assert not list(tmp_path.iterdir())

    def test_asks_for_identity_encoding(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, body=b"bin")
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            client.download_binary(entry, tmp_path)
        assert mocked_kernel32.calls[-1].request.headers["Accept-Encoding"] == "identity"

    def test_encoded_response_is_not_mistaken_for_a_short_one(self, mocked_kernel32, tmp_path: Path):
        # Content-Length counts the gzip bytes; requests hands us the decoded ones.
        payload = b"MSF 7.00" + b"\x00" * 50_000
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        body = gzip.compress(payload)
        mocked_kernel32.add(
            responses.GET,
            bin_url,
            body=body,
            headers={"Content-Encoding": "gzip", "Content-Length": str(len(body))},
            auto_calculate_content_length=False,
        )
        calls: list[tuple[int, int | None]] = []
        with WinbindexClient(max_retries=0) as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            path = client.download_binary(entry, tmp_path, progress=lambda d, t: calls.append((d, t)))
        assert path.read_bytes() == payload
        assert calls[-1] == (len(payload), None)

    def test_download_many_skips_metadata_only_without_touching_disk(self, mocked_kernel32, tmp_path: Path):
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", downloadable=False))
            written = client.download_many([entry], tmp_path)
        assert written == []
        assert not list(tmp_path.iterdir())

    def test_download_many_reports_errors_via_callback(self, mocked_kernel32, tmp_path: Path):
        bin_url = f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.dll/DEADBEEF1000/kernel32.dll"
        mocked_kernel32.add(responses.GET, bin_url, status=404)
        errors = []
        with WinbindexClient() as client:
            entry = next(client.find("kernel32.dll", with_pdb=True))
            written = client.download_many([entry], tmp_path, on_error=lambda e, err: errors.append(err))
        assert written == []
        assert len(errors) == 1 and isinstance(errors[0], DownloadError)


class TestDefaultCacheDir:
    def test_env_override(self, monkeypatch, tmp_path: Path):
        from winbindex import default_cache_dir

        monkeypatch.setenv("WINBINDEX_CACHE_DIR", str(tmp_path / "x"))
        assert default_cache_dir() == tmp_path / "x"

    def test_user_agent_carries_version(self):
        from winbindex import DEFAULT_USER_AGENT, __version__

        assert __version__ in DEFAULT_USER_AGENT
