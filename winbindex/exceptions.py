"""Exception types raised by the :mod:`winbindex` package."""

from __future__ import annotations


class WinbindexError(Exception):
    """Base class for all errors raised by the :mod:`winbindex` package."""


class InvalidFilenameError(WinbindexError, ValueError):
    """Raised when a filename cannot be a Windows binary name.

    Subclasses :class:`ValueError` for backwards compatibility.
    """


class FileNotIndexedError(WinbindexError):
    """Raised when the requested filename is not indexed by Winbindex.

    This corresponds to an HTTP 404 returned by the Winbindex service
    when fetching the JSON metadata for a given filename.
    """

    def __init__(self, filename: str) -> None:
        super().__init__(f"File {filename!r} is not indexed by Winbindex.")
        self.filename = filename


class DownloadError(WinbindexError):
    """Raised when an HTTP request to Winbindex or the symbol server fails.

    Attributes:
        message: The failure description without the URL.
        url: The URL that was being fetched at the time of the failure.
        status_code: The HTTP status code, or ``None`` for network-level
            failures (timeouts, connection resets, ...).
    """

    def __init__(self, message: str, url: str, *, status_code: int | None = None) -> None:
        super().__init__(f"{message} (url: {url})")
        self.message = message
        self.url = url
        self.status_code = status_code


class MissingDownloadInfoError(WinbindexError):
    """Raised when an entry lacks the metadata required to build a URL.

    For example, a file that was indexed from a manifest but never
    submitted to VirusTotal will not have ``timestamp`` and
    ``virtualSize`` fields, and therefore no binary download URL
    can be constructed for it.
    """


class MissingPdbInfoError(MissingDownloadInfoError):
    """Raised when an entry has no associated PDB metadata.

    PDB information (``name`` / ``guid`` / ``age``) is not always
    present in the Winbindex JSON. When it is missing, the PDB URL
    cannot be built from the index alone — it must be extracted from
    the binary's debug directory after downloading the PE file.
    """


class InvalidDataError(WinbindexError):
    """Raised when the data fetched from Winbindex is malformed or unexpected."""
