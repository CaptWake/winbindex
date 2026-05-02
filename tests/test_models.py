"""Tests for :mod:`winbindex.models`."""

from __future__ import annotations

import pytest
from winbindex.models import PdbInfo, FileInfo, FileEntry, WindowsRelease
from winbindex.exceptions import (
    InvalidDataError,
    MissingPdbInfoError,
    MissingDownloadInfoError,
)

# Real-world payload (trimmed) modelled after Winbindex output for ntdll.dll.
NTDLL_PAYLOAD = {
    "fileInfo": {
        "description": "NT Layer DLL",
        "machineType": 34404,
        "md5": "c9b7eb6b6320deb5a9dc6ab23be3029d",
        "sha1": "ac9d441181e3b35d4d321002ca5b4d26aa59615d",
        "sha256": "abb30adf05bd71ae8283d8a44e55268de3c408421ec059c626b92b9168adc0f9",
        "signatureType": "Overlay",
        "signingDate": ["2023-03-18T02:15:00"],
        "signingStatus": "Signed",
        "size": 2174872,
        "timestamp": 3085096458,
        "version": "10.0.22621.1485 (WinBuild.160101.0800)",
        "virtualSize": 2174976,
    },
    "windowsVersions": {
        "11-22H2": {
            "KB5023778": {
                "assemblies": {
                    "amd64_microsoft-windows-ntdll_31bf3856ad364e35_10.0.22621.1485_none_38c42af777bdcc16": {
                        "assemblyIdentity": {
                            "buildType": "release",
                            "language": "neutral",
                            "name": "Microsoft-Windows-Ntdll",
                            "processorArchitecture": "amd64",
                        }
                    }
                },
                "updateInfo": {
                    "releaseDate": "2023-03-21",
                    "releaseVersion": "10.0.22621.1485",
                },
                "windowsVersionInfo": {
                    "buildNumber": "22621.1485",
                    "releaseDate": "2023-03-21",
                },
            }
        }
    },
    "pdb": {
        "pdbName": "ntdll.pdb",
        "pdbGuid": "9B85C13D-1CB0-4317-A2D5-9C7CC9D4F2B0",
        "pdbAge": 1,
    },
}


# ----------------------------------------------------------------------- FileInfo


class TestFileInfo:
    def test_from_dict(self):
        info = FileInfo.from_dict(
            "abb30adf05bd71ae8283d8a44e55268de3c408421ec059c626b92b9168adc0f9",
            NTDLL_PAYLOAD["fileInfo"],
        )
        assert info.timestamp == 3085096458
        assert info.virtual_size == 2174976
        assert info.size == 2174872
        assert info.machine_type == 34404
        assert info.signing_status == "Signed"
        assert info.signing_date == ("2023-03-18T02:15:00",)
        assert info.has_download_info is True

    def test_missing_download_info(self):
        info = FileInfo.from_dict("a" * 64, {"version": "1.0"})
        assert info.has_download_info is False
        assert info.timestamp is None
        assert info.virtual_size is None

    def test_lowercases_sha256(self):
        info = FileInfo.from_dict("ABCDEF" + "0" * 58, {})
        assert info.sha256 == "abcdef" + "0" * 58

    def test_signing_date_must_be_list(self):
        with pytest.raises(InvalidDataError):
            FileInfo.from_dict("a" * 64, {"signingDate": "2023-03-18"})


# ------------------------------------------------------------------------ PdbInfo


class TestPdbInfo:
    def test_from_dict_pdb_prefixed_keys(self):
        pdb = PdbInfo.from_dict(NTDLL_PAYLOAD["pdb"])
        assert pdb.name == "ntdll.pdb"
        assert pdb.guid == "9B85C13D1CB04317A2D59C7CC9D4F2B0"
        assert pdb.age == 1

    def test_from_dict_unprefixed_keys(self):
        pdb = PdbInfo.from_dict({"name": "kernel32.pdb", "guid": "0" * 32, "age": 2})
        assert pdb.name == "kernel32.pdb"
        assert pdb.guid == "0" * 32
        assert pdb.age == 2

    def test_normalizes_dashed_guid(self):
        pdb = PdbInfo(
            name="x.pdb",
            guid="0F1E2D3C-4B5A-6789-ABCD-EF0123456789",
            age=3,
        )
        assert pdb.guid == "0F1E2D3C4B5A6789ABCDEF0123456789"

    @pytest.mark.parametrize(
        "data",
        [
            {"pdbName": "x.pdb", "pdbGuid": "0" * 32},  # missing age
            {"pdbGuid": "0" * 32, "pdbAge": 1},  # missing name
            {"pdbName": "x.pdb", "pdbAge": 1},  # missing guid
            {},
        ],
    )
    def test_incomplete_data_raises(self, data):
        with pytest.raises(InvalidDataError):
            PdbInfo.from_dict(data)

    def test_invalid_guid_raises(self):
        with pytest.raises(ValueError):
            PdbInfo(name="x.pdb", guid="not-a-guid", age=1)


# ---------------------------------------------------------------------- FileEntry


class TestFileEntry:
    @pytest.fixture
    def entry(self) -> FileEntry:
        return FileEntry.from_dict(
            "ntdll.dll",
            "abb30adf05bd71ae8283d8a44e55268de3c408421ec059c626b92b9168adc0f9",
            NTDLL_PAYLOAD,
        )

    def test_basic_fields(self, entry: FileEntry):
        assert entry.filename == "ntdll.dll"
        assert entry.sha256.startswith("abb30adf")
        assert entry.version == "10.0.22621.1485 (WinBuild.160101.0800)"
        assert entry.has_binary_download is True
        assert entry.has_pdb_download is True

    def test_releases_extracted(self, entry: FileEntry):
        assert len(entry.releases) == 1
        rel = entry.releases[0]
        assert isinstance(rel, WindowsRelease)
        assert rel.windows_version == "11-22H2"
        assert rel.update == "KB5023778"
        assert rel.release_date == "2023-03-21"

    def test_windows_versions_set(self, entry: FileEntry):
        assert entry.windows_versions == {"11-22H2"}
        assert entry.updates == {"KB5023778"}

    def test_binary_url(self, entry: FileEntry):
        url = entry.binary_url()
        assert "msdl.microsoft.com" in url
        assert url.endswith("/ntdll.dll")
        assert "/B7E2D60A213000/" in url  # timestamp + virtualSize

    def test_pdb_url(self, entry: FileEntry):
        url = entry.pdb_url()
        assert "/ntdll.pdb/" in url
        assert url.endswith("/ntdll.pdb")
        assert "9B85C13D1CB04317A2D59C7CC9D4F2B01" in url

    def test_binary_url_custom_base(self, entry: FileEntry):
        url = entry.binary_url(base_url="http://mirror.example/sym")
        assert url.startswith("http://mirror.example/sym/")

    def test_pdb_url_custom_base(self, entry: FileEntry):
        url = entry.pdb_url(base_url="http://mirror.example/sym")
        assert url.startswith("http://mirror.example/sym/")

    def test_missing_pdb_raises(self):
        payload = {**NTDLL_PAYLOAD}
        payload.pop("pdb")
        entry = FileEntry.from_dict("ntdll.dll", "a" * 64, payload)
        assert entry.has_pdb_download is False
        with pytest.raises(MissingPdbInfoError):
            entry.pdb_url()

    def test_missing_download_info_raises(self):
        entry = FileEntry.from_dict("x.dll", "a" * 64, {"fileInfo": {"version": "1.0"}})
        assert entry.has_binary_download is False
        with pytest.raises(MissingDownloadInfoError):
            entry.binary_url()

    def test_invalid_top_level_raises(self):
        with pytest.raises(InvalidDataError):
            FileEntry.from_dict("x.dll", "a" * 64, "not a dict")  # type: ignore[arg-type]

    def test_invalid_file_info_raises(self):
        with pytest.raises(InvalidDataError):
            FileEntry.from_dict("x.dll", "a" * 64, {"fileInfo": "garbage"})

    def test_pdb_with_dashes_in_guid(self):
        payload = {
            "fileInfo": {"timestamp": 1, "virtualSize": 1},
            "pdb": {
                "pdbName": "ntdll.pdb",
                "pdbGuid": "9B85C13D-1CB0-4317-A2D5-9C7CC9D4F2B0",
                "pdbAge": 1,
            },
        }
        entry = FileEntry.from_dict("ntdll.dll", "a" * 64, payload)
        assert entry.pdb is not None
        assert entry.pdb.guid == "9B85C13D1CB04317A2D59C7CC9D4F2B0"

    def test_malformed_pdb_block_is_dropped_not_fatal(self):
        payload = {
            "fileInfo": {"timestamp": 1, "virtualSize": 1},
            "pdb": {"only": "garbage"},
        }
        entry = FileEntry.from_dict("ntdll.dll", "a" * 64, payload)
        assert entry.pdb is None

    def test_raw_data_preserved(self, entry: FileEntry):
        # Make sure unexpected fields are still reachable.
        assert entry.raw["fileInfo"]["machineType"] == 34404

    def test_handles_empty_windows_versions(self):
        payload = {"fileInfo": {"timestamp": 1, "virtualSize": 1}}
        entry = FileEntry.from_dict("x.dll", "a" * 64, payload)
        assert entry.releases == ()
        assert entry.windows_versions == set()

    def test_handles_garbage_in_windows_versions(self):
        payload = {
            "fileInfo": {"timestamp": 1, "virtualSize": 1},
            "windowsVersions": {
                "1809": "not-a-dict",
                "21H2": {"KB12345": "not-a-dict"},
                "22H2": {"KB67890": {"sourcePaths": ["foo"]}},
            },
        }
        entry = FileEntry.from_dict("x.dll", "a" * 64, payload)
        # Only the well-formed cell makes it through.
        assert len(entry.releases) == 1
        assert entry.releases[0].windows_version == "22H2"
        assert entry.releases[0].source_paths == ("foo",)
