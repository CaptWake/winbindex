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
        "windowsVersions": {
            "11-22H2": {"KB5023778": {"sourcePaths": ["Windows\\System32\\kernel32.dll"]}}
        },
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
        pdb_url = (
            f"{DEFAULT_SYMBOL_SERVER_URL}/kernel32.pdb/"
            "1B72224D37B8179228200ED8994498B21/kernel32.pdb"
        )
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
        pdb_url = (
            f"{DEFAULT_SYMBOL_SERVER_URL}/ntoskrnl.pdb/"
            "0123456789ABCDEF0123456789ABCDEF2/ntoskrnl.pdb"
        )
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
