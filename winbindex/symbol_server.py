"""Microsoft Public Symbol Server URL helpers.

The Microsoft public symbol server (``https://msdl.microsoft.com``)
hosts both Windows PE binaries (``.exe``, ``.dll``, ``.sys`` …) and
their associated ``.pdb`` symbol files. Files are indexed by a path
of the form::

    /download/symbols/<filename>/<index>/<filename>

where ``<index>`` is built from a small set of fields read out of
the binary or PDB itself. This module contains pure helper functions
that build those URLs — they perform no network I/O.

Reference: https://learn.microsoft.com/windows/win32/debug/symbol-store-format
"""

from __future__ import annotations

import re

#: Default base URL of the Microsoft public symbol server.
DEFAULT_SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols"

_GUID_RE = re.compile(r"^[0-9a-fA-F]{32}$")

def normalize_guid(guid: str) -> str:
    """Return ``guid`` as a 32-character uppercase hex string.

    Accepts either a dashed GUID (``"1B72224D-37B8-1792-2820-0ED8994498B2"``)
    or an undashed one (``"1B72224D37B8179228200ED8994498B2"``).

    Args:
        guid: The GUID string to normalize.

    Returns:
        The same GUID, dashes removed, uppercased.

    Raises:
        ValueError: If ``guid`` is not a valid GUID hex string.
    """
    stripped = guid.replace("-", "")
    if not _GUID_RE.match(stripped):
        raise ValueError(f"Invalid GUID: {guid!r}")
    return stripped.upper()


def build_binary_url(
    filename: str,
    timestamp: int,
    virtual_size: int,
    *,
    base_url: str = DEFAULT_SYMBOL_SERVER_URL,
) -> str:
    """Build a Microsoft Symbol Server URL for a Windows binary.

    The symbol server indexes PE files by their PE-header ``timestamp``
    (8 hex digits, uppercase, zero-padded) followed by the image's
    ``virtualSize`` (lowercase hex, *no* zero-padding). For example::

        https://msdl.microsoft.com/download/symbols/srv2.sys/EE8E2F4Fc7000/srv2.sys

    Args:
        filename: The PE filename (e.g. ``"kernel32.dll"``).
        timestamp: Value of the ``TimeDateStamp`` field in the PE file
            header (an unsigned 32-bit integer).
        virtual_size: Value of the ``SizeOfImage`` field in the PE
            optional header.
        base_url: Override of the symbol server base URL.

    Returns:
        The fully-qualified download URL.

    Raises:
        ValueError: If ``filename`` is empty, or any of the integer
            arguments are negative.
    """
    if not filename:
        raise ValueError("filename must not be empty")
    if timestamp < 0:
        raise ValueError("timestamp must be non-negative")
    if virtual_size < 0:
        raise ValueError("virtual_size must be non-negative")

    # The timestamp is formatted as 8 uppercase hex digits, zero-padded.
    # The virtualSize is formatted as lowercase hex with no padding.
    # This matches what Winbindex's frontend produces.
    index = f"{timestamp:08X}{virtual_size:x}"
    return f"{base_url.rstrip('/')}/{filename}/{index}/{filename}"


def build_pdb_url(
    pdb_name: str,
    guid: str,
    age: int,
    *,
    base_url: str = DEFAULT_SYMBOL_SERVER_URL,
) -> str:
    """Build a Microsoft Symbol Server URL for a PDB file.

    PDB files are indexed by ``<GUID><AGE>`` where the GUID is rendered
    as 32 uppercase hex digits without dashes and the age is rendered
    as uppercase hex with no zero padding. For example::

        https://msdl.microsoft.com/download/symbols/kernel32.pdb/1B72224D37B8179228200ED8994498B21/kernel32.pdb

    Args:
        pdb_name: The PDB filename (e.g. ``"kernel32.pdb"``).
        guid: The PDB's GUID, with or without dashes; case insensitive.
        age: The PDB age (number of times the file has been written by the linker - an unsigned integer).
        base_url: Override of the symbol server base URL.

    Returns:
        The fully-qualified PDB download URL.

    Raises:
        ValueError: If ``pdb_name`` is empty, ``guid`` is invalid or
            ``age`` is negative.
    """
    if not pdb_name:
        raise ValueError("pdb_name must not be empty")
    if age < 0:
        raise ValueError("age must be non-negative")

    normalized_guid = normalize_guid(guid)
    index = f"{normalized_guid}{age:X}"
    return f"{base_url.rstrip('/')}/{pdb_name}/{index}/{pdb_name}"
