"""Python client for the `Winbindex <https://winbindex.m417z.com/>`_ service.

Winbindex is an index of Windows binaries (``.exe``, ``.dll``, ``.sys`` ...)
that exposes the metadata required to download them — and their
associated PDB symbol files — straight from the Microsoft public symbol
server (``https://msdl.microsoft.com``).

This package wraps the index in a small, typed Python API:

.. code-block:: python

    from winbindex import WinbindexClient

    with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
        for entry in client.find("kernel32.dll", windows_version="11-22H2"):
            print(entry.version, entry.binary_url())
            client.download_binary(entry, "downloads/")

The full metadata of every indexed file is exposed through the
:class:`~winbindex.models.FileEntry` model. URL building is handled by
the helpers in :mod:`winbindex.symbol_server` and is also reachable via
:meth:`FileEntry.binary_url` and :meth:`FileEntry.pdb_url`.
"""

from __future__ import annotations

from .client import (
    DEFAULT_USER_AGENT,
    DEFAULT_WINBINDEX_BASE_URL,
    WinbindexClient,
    ProgressCallback,
    filter_entries,
    default_cache_dir,
)
from .models import (
    MACHINE_NAMES,
    PdbInfo,
    FileInfo,
    FileEntry,
    WindowsRelease,
    machine_name,
    parse_version,
    parse_machine_type,
)
from .version import __version__
from .utils.pdb import extract_pdb_info, extract_pdb_info_from_bytes
from .exceptions import (
    DownloadError,
    WinbindexError,
    InvalidDataError,
    FileNotIndexedError,
    MissingPdbInfoError,
    InvalidFilenameError,
    MissingDownloadInfoError,
)
from .symbol_server import (
    DEFAULT_SYMBOL_SERVER_URL,
    build_pdb_url,
    normalize_guid,
    build_binary_url,
)

__all__ = [
    "__version__",
    "DEFAULT_SYMBOL_SERVER_URL",
    "DEFAULT_USER_AGENT",
    "DEFAULT_WINBINDEX_BASE_URL",
    "MACHINE_NAMES",
    "DownloadError",
    "FileEntry",
    "FileInfo",
    "FileNotIndexedError",
    "InvalidDataError",
    "InvalidFilenameError",
    "MissingDownloadInfoError",
    "MissingPdbInfoError",
    "PdbInfo",
    "ProgressCallback",
    "WinbindexClient",
    "WinbindexError",
    "WindowsRelease",
    "build_binary_url",
    "build_pdb_url",
    "default_cache_dir",
    "extract_pdb_info",
    "extract_pdb_info_from_bytes",
    "filter_entries",
    "machine_name",
    "normalize_guid",
    "parse_machine_type",
    "parse_version",
]
