from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from pathlib import Path

import pefile

from ..models import PdbInfo
from ..exceptions import MissingPdbInfoError

if TYPE_CHECKING:
    from os import PathLike

__all__ = ["extract_pdb_info", "extract_pdb_info_from_bytes"]

# IMAGE_DEBUG_TYPE_CODEVIEW
_IMAGE_DEBUG_TYPE_CODEVIEW = 2

# Magic markers in the CodeView record.
_RSDS_MAGIC = b"RSDS"  # PDB 7.0
_NB10_MAGIC = b"NB10"  # PDB 2.0 (legacy)


def extract_pdb_info(path: str | PathLike[str]) -> PdbInfo:
    """Extract PDB metadata from a PE file on disk.

    Args:
        path: Path to a PE file (``.exe`` / ``.dll`` / ``.sys`` / …).

    Returns:
        A populated :class:`~winbindex.models.PdbInfo`.

    Raises:
        PefileNotInstalledError: If ``pefile`` is not installed.
        FileNotFoundError: If ``path`` does not exist.
        MissingPdbInfoError: If the PE file has no usable
            ``IMAGE_DEBUG_TYPE_CODEVIEW`` debug directory entry.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    return extract_pdb_info_from_bytes(p.read_bytes())


def extract_pdb_info_from_bytes(data: bytes) -> PdbInfo:
    """Extract PDB metadata from raw PE bytes.

    Args:
        data: The raw bytes of a PE file.

    Returns:
        A populated :class:`~winbindex.models.PdbInfo`.

    Raises:
        PefileNotInstalledError: If ``pefile`` is not installed.
        MissingPdbInfoError: If the PE has no usable CodeView record.
    """
    pe = pefile.PE(data=data, fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
        )
        debug_entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []
        for entry in debug_entries:
            if entry.struct.Type != _IMAGE_DEBUG_TYPE_CODEVIEW:
                continue
            cv_data = pe.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
            pdb_info = _parse_codeview(cv_data)
            if pdb_info is not None:
                return pdb_info
    finally:
        pe.close()

    raise MissingPdbInfoError("PE file has no IMAGE_DEBUG_TYPE_CODEVIEW record with PDB info.")


def _parse_codeview(data: bytes) -> PdbInfo | None:  # noqa: PLR0911
    """Parse a CodeView debug record into a :class:`PdbInfo`.

    Returns ``None`` for unknown / malformed records so the caller
    can keep looking through other debug entries.
    """
    if len(data) < 4:
        return None

    magic = data[:4]
    if magic == _RSDS_MAGIC:
        # struct: 4s magic, 16s GUID, I age, then NUL-terminated PDB path.
        if len(data) < 24:
            return None
        guid_bytes, age = struct.unpack_from("<16sI", data, 4)
        guid = _format_guid(guid_bytes)
        name = _extract_pdb_name(data[24:])
        if name is None:
            return None
        return PdbInfo(name=name, guid=guid, age=age)

    if magic == _NB10_MAGIC:
        # struct: 4s magic, I offset, I signature, I age, then NUL-terminated path.
        # PDB 2.0 uses a 32-bit signature instead of a GUID; we expand
        # it to a 32-character hex string so the symbol-server URL
        # builder still works.
        if len(data) < 16:
            return None
        _, signature, age = struct.unpack_from("<III", data, 4)
        guid = f"{signature:08X}".ljust(32, "0")
        name = _extract_pdb_name(data[16:])
        if name is None:
            return None
        return PdbInfo(name=name, guid=guid, age=age)

    return None


def _extract_pdb_name(blob: bytes) -> str | None:
    """Return the basename of the NUL-terminated path embedded in ``blob``."""
    nul = blob.find(b"\x00")
    if nul < 0:
        return None
    raw = blob[:nul]
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        # The CodeView path is documented as ASCII but we have seen
        # mojibake in the wild; fall back to a permissive decode.
        decoded = raw.decode("latin-1")
    if not decoded:
        return None
    # The PDB record can hold a full path (e.g.
    # 'd:\\rs1\\... \\kernel32.pdb'); strip directories.
    return decoded.replace("\\", "/").rsplit("/", 1)[-1]


def _format_guid(raw: bytes) -> str:
    """Format the 16 GUID bytes as the canonical 32-character hex string.

    Matches the layout of a Windows ``GUID`` struct: the first three
    fields are little-endian, the rest are big-endian.
    """
    if len(raw) != 16:
        raise ValueError("GUID must be 16 bytes")
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    rest = raw[8:]
    return f"{d1:08X}{d2:04X}{d3:04X}{rest.hex().upper()}"
