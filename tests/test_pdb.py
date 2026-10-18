"""Tests for :mod:`winbindex.utils.pdb`."""

from __future__ import annotations

import uuid
import struct

import pefile
import pytest
from winbindex import PdbInfo, MissingPdbInfoError, extract_pdb_info, extract_pdb_info_from_bytes
from winbindex.utils.pdb import _format_guid, _parse_codeview, _extract_pdb_name

GUID = uuid.UUID("9B85C13D-1CB0-4317-A2D5-9C7CC9D4F2B0")


def _rsds(guid: uuid.UUID, age: int, path: bytes) -> bytes:
    return b"RSDS" + guid.bytes_le + struct.pack("<I", age) + path + b"\x00"


def _nb10(signature: int, age: int, path: bytes) -> bytes:
    return b"NB10" + struct.pack("<III", 0, signature, age) + path + b"\x00"


def _minimal_pe(codeview: bytes | None, *, timestamp: int = 0x5F000000) -> bytes:
    """Build a tiny PE32+ image (SizeOfImage 0x2000) with one section holding a CodeView debug entry."""
    section_rva, section_raw, section_size = 0x1000, 0x200, 0x200
    debug_dir_size = 28
    debug_data_rva = section_rva + debug_dir_size
    debug_data_raw = section_raw + debug_dir_size

    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    file_header = struct.pack("<HHIIIHH", 0x8664, 1, timestamp, 0, 0, 240, 0x2022)
    data_dirs = [(0, 0)] * 16
    if codeview is not None:
        data_dirs[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]] = (section_rva, debug_dir_size)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # PE32+
        14,
        0,  # linker version
        section_size,
        0,
        0,  # code / init / uninit sizes
        0x1000,
        0x1000,  # entry point, base of code
        0x140000000,  # image base
        0x1000,
        0x200,  # section / file alignment
        6,
        0,
        0,
        0,
        6,
        0,  # OS / image / subsystem versions
        0,  # win32 version
        section_rva + 0x1000,  # size of image
        0x200,  # size of headers
        0,  # checksum
        3,
        0x8160,  # subsystem, dll characteristics
        0x100000,
        0x1000,
        0x100000,
        0x1000,  # stack / heap
        0,
        16,  # loader flags, number of RVAs
    )
    optional += b"".join(struct.pack("<II", rva, size) for rva, size in data_dirs)
    assert len(optional) == 240
    section = struct.pack(
        "<8sIIIIIIHHI", b".rdata", section_size, section_rva, section_size, section_raw, 0, 0, 0, 0, 0x40000040
    )
    headers = dos + b"PE\x00\x00" + file_header + optional + section
    headers = headers.ljust(section_raw, b"\x00")

    body = b""
    if codeview is not None:
        body = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(codeview), debug_data_rva, debug_data_raw) + codeview
    return headers + body.ljust(section_size, b"\x00")


class TestParseCodeview:
    def test_rsds(self):
        info = _parse_codeview(_rsds(GUID, 3, b"d:\\build\\x64\\kernel32.pdb"))
        assert info == PdbInfo(name="kernel32.pdb", guid="9B85C13D1CB04317A2D59C7CC9D4F2B0", age=3)

    def test_rsds_truncated(self):
        assert _parse_codeview(b"RSDS" + b"\x00" * 10) is None

    def test_rsds_without_nul_terminator(self):
        assert _parse_codeview(b"RSDS" + GUID.bytes_le + struct.pack("<I", 1) + b"x.pdb") is None

    def test_nb10_is_skipped_rather_than_mangled(self):
        # PDB 2.0 records cannot be expressed as a symbol-server GUID URL.
        assert _parse_codeview(_nb10(0x12345678, 1, b"old.pdb")) is None

    def test_unknown_magic(self):
        assert _parse_codeview(b"XXXX" + b"\x00" * 40) is None
        assert _parse_codeview(b"") is None

    @pytest.mark.parametrize("path", [b"c:\\build\\..", b"c:\\build\\", b"c:\\build\\a:b.pdb"])
    def test_rsds_with_unusable_name_is_skipped(self, path):
        # The name ends up as a file path on disk; never let it be "..", empty or reserved.
        assert _parse_codeview(_rsds(GUID, 1, path)) is None


class TestHelpers:
    def test_format_guid_matches_uuid_layout(self):
        assert _format_guid(GUID.bytes_le) == GUID.hex.upper()

    def test_format_guid_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            _format_guid(b"\x00" * 15)

    @pytest.mark.parametrize(
        ("blob", "expected"),
        [
            (b"c:\\a\\b\\ntdll.pdb\x00junk", "ntdll.pdb"),
            (b"/unix/style/x.pdb\x00", "x.pdb"),
            (b"bare.pdb\x00", "bare.pdb"),
            (b"\x00", None),
            (b"no-terminator", None),
            (b"caf\xe9.pdb\x00", "café.pdb"),  # latin-1 fallback
        ],
    )
    def test_extract_pdb_name(self, blob, expected):
        assert _extract_pdb_name(blob) == expected


class TestExtractFromPe:
    def test_extracts_rsds_from_pe(self):
        pe = _minimal_pe(_rsds(GUID, 2, b"c:\\sym\\null.pdb"))
        info = extract_pdb_info_from_bytes(pe)
        assert info.name == "null.pdb"
        assert info.guid == "9B85C13D1CB04317A2D59C7CC9D4F2B0"
        assert info.age == 2

    def test_pe_without_debug_directory(self):
        with pytest.raises(MissingPdbInfoError):
            extract_pdb_info_from_bytes(_minimal_pe(None))

    def test_pe_with_only_nb10(self):
        with pytest.raises(MissingPdbInfoError, match="RSDS"):
            extract_pdb_info_from_bytes(_minimal_pe(_nb10(1, 1, b"old.pdb")))

    def test_not_a_pe(self):
        with pytest.raises(pefile.PEFormatError):
            extract_pdb_info_from_bytes(b"definitely not a PE file")

    def test_extract_from_path(self, tmp_path):
        target = tmp_path / "null.sys"
        target.write_bytes(_minimal_pe(_rsds(GUID, 1, b"null.pdb")))
        assert extract_pdb_info(target).name == "null.pdb"

    def test_missing_path(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            extract_pdb_info(tmp_path / "nope.sys")
