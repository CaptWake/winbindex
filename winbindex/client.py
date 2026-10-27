"""High-level synchronous client for the Winbindex service.

The :class:`WinbindexClient` is the main entry point of the library.
It is responsible for:

* fetching the gzipped JSON metadata published at
  ``https://winbindex.m417z.com/data/by_filename_compressed/<file>.json.gz``,
* parsing it into :class:`~winbindex.models.FileEntry` instances,
* and downloading binaries / PDBs from the Microsoft public symbol
  server (``https://msdl.microsoft.com``) using the metadata.

The client is thread-safe in the sense that each method call uses a
single underlying :class:`requests.Session`; sessions themselves are
documented as thread-safe by ``urllib3``.
"""

from __future__ import annotations

import os
import re
import sys
import gzip
import json
import time
import logging
import tempfile
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import quote
from collections.abc import Mapping, Callable, Iterable, Iterator

import requests

from .models import PdbInfo, FileEntry, _check_bare_filename
from .version import __version__
from .exceptions import (
    DownloadError,
    InvalidDataError,
    FileNotIndexedError,
)
from .symbol_server import DEFAULT_SYMBOL_SERVER_URL, build_pdb_url

__all__ = [
    "DEFAULT_USER_AGENT",
    "DEFAULT_WINBINDEX_BASE_URL",
    "ProgressCallback",
    "WinbindexClient",
    "default_cache_dir",
    "filter_entries",
]

logger = logging.getLogger(__name__)

#: Default base URL of the Winbindex data hosting service.
DEFAULT_WINBINDEX_BASE_URL = "https://winbindex.m417z.com/data"

#: Default User-Agent used for outbound HTTP requests. Overridable via
#: the ``user_agent`` argument of :class:`WinbindexClient`.
DEFAULT_USER_AGENT = f"winbindex-python/{__version__} (+https://github.com/CaptWake/winbindex)"

#: Type of an optional progress callback passed to download helpers.
#: Receives ``(bytes_downloaded, total_bytes_or_None)``.
ProgressCallback = Callable[[int, "int | None"], None]


def default_cache_dir() -> Path:
    """Return the platform-appropriate cache directory for Winbindex metadata.

    ``$WINBINDEX_CACHE_DIR`` wins when set. Otherwise
    ``%LOCALAPPDATA%\\winbindex\\cache`` on Windows,
    ``~/Library/Caches/winbindex`` on macOS and
    ``$XDG_CACHE_HOME/winbindex`` (default ``~/.cache/winbindex``) elsewhere.
    """
    override = os.environ.get("WINBINDEX_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "winbindex" / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "winbindex"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "winbindex"


@dataclass
class _Retry:
    """Tiny helper to keep retry logic in one place (instead of using urllib3)."""

    total: int = 3
    backoff_factor: float = 0.5
    statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})


class WinbindexClient:
    """Synchronous client for the Winbindex service.

    Args:
        base_url: Base URL of the Winbindex data host. Override only if
            you are mirroring the data yourself.
        symbol_server_url: Base URL of the Microsoft public symbol
            server. Override to point at a private mirror (e.g. a local
            ``symstore``-formatted cache served over HTTP).
        cache_dir: If set, fetched JSON files are persisted here so
            that subsequent calls do not hit the network. Cache files
            are validated against the optional ``cache_ttl``. See
            :func:`default_cache_dir` for a sensible default.
        cache_ttl: Time-to-live in seconds for files in ``cache_dir``.
            ``None`` means cached files never expire.
        timeout: Per-request HTTP timeout in seconds. Applied to every
            request made through this client.
        session: Optional pre-configured :class:`requests.Session`.
            When ``None`` a fresh session is constructed.
        user_agent: Custom User-Agent header value.
        max_retries: Maximum number of retries on transient failures
            (``429``, ``5xx``, connection errors).

    Example:
        >>> client = WinbindexClient(cache_dir="~/.cache/winbindex")
        >>> entries = client.get_file("kernel32.dll")
        >>> for entry in entries:
        ...     print(entry.version, entry.binary_url())
    """

    def __init__(
        self,
        base_url: str = DEFAULT_WINBINDEX_BASE_URL,
        symbol_server_url: str = DEFAULT_SYMBOL_SERVER_URL,
        *,
        cache_dir: str | Path | None = None,
        cache_ttl: float | None = None,
        timeout: float = 30.0,
        session: requests.Session | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.symbol_server_url = symbol_server_url.rstrip("/")
        self.cache_dir = Path(cache_dir).expanduser() if cache_dir else None
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._owns_session = session is None
        self._session: requests.Session = session or requests.Session()
        self._session.headers.setdefault("User-Agent", user_agent)
        self._retry = _Retry(total=max_retries)

        if self.cache_dir is not None:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Context-manager / cleanup
    # ------------------------------------------------------------------
    def __enter__(self) -> WinbindexClient:
        """Return ``self`` so the client may be used as a context manager."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Close the underlying session on context-manager exit."""
        self.close()

    def close(self) -> None:
        """Close the underlying :class:`requests.Session` (if owned)."""
        if self._owns_session:
            self._session.close()

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    def get_raw(self, filename: str) -> dict[str, Any]:
        """Fetch and decompress the raw Winbindex JSON for a filename.

        Args:
            filename: A Windows binary filename (case-insensitive on
                the server, but typically lowercase). Examples:
                ``"kernel32.dll"``, ``"ntoskrnl.exe"``, ``"ci.dll"``.

        Returns:
            The decoded JSON object — a mapping ``sha256 -> entry``.

        Raises:
            InvalidFilenameError: If ``filename`` is not a plausible
                Windows filename (empty, contains a path separator, ...).
            FileNotIndexedError: If the server returns ``404``.
            DownloadError: For any other HTTP / network failure.
            InvalidDataError: If the response is not valid gzipped JSON.
        """
        normalized = _normalize_filename(filename)
        cached = self._read_cache(normalized)
        if cached is not None:
            return cached

        url = f"{self.base_url}/by_filename_compressed/{quote(normalized, safe='')}.json.gz"
        logger.info("Fetching metadata for %s from %s", normalized, url)
        try:
            response = self._request("GET", url)
        except DownloadError as err:
            if err.status_code == 404:
                raise FileNotIndexedError(filename) from None
            raise

        try:
            content = response.content
        except requests.RequestException as err:
            raise DownloadError(f"connection failed while reading response: {err}", url) from err
        finally:
            response.close()

        try:
            decompressed = gzip.decompress(content)
        except OSError as err:
            raise InvalidDataError(f"Response from {url} is not valid gzip data.") from err

        try:
            data = json.loads(decompressed)
        except json.JSONDecodeError as err:
            raise InvalidDataError(f"Response from {url} is not valid JSON.") from err

        if not isinstance(data, dict):
            raise InvalidDataError(f"Top-level JSON must be an object, got {type(data).__name__}")

        self._write_cache(normalized, data)
        return data

    def get_file(self, filename: str) -> list[FileEntry]:
        """Return all known versions of ``filename`` as :class:`FileEntry` objects.

        Malformed entries are skipped with a warning rather than
        aborting the whole listing.

        Args:
            filename: A Windows binary filename, e.g. ``"kernel32.dll"``.

        Returns:
            A list of :class:`FileEntry` instances, one per indexed
            SHA256. The order is the order in which the JSON dictionary
            keys are returned (insertion order on Python 3.7+, which
            matches the source file).

        Raises:
            FileNotIndexedError: If ``filename`` is not indexed.
        """
        raw = self.get_raw(filename)
        normalized = _normalize_filename(filename)
        entries: list[FileEntry] = []
        for sha256, entry in raw.items():
            try:
                entries.append(FileEntry.from_dict(normalized, sha256, entry))
            except InvalidDataError as err:
                logger.warning(
                    "Skipping malformed Winbindex entry sha256=%s for %s: %s",
                    sha256,
                    normalized,
                    err,
                )
        return entries

    def find(
        self,
        filename: str,
        *,
        sha256: str | None = None,
        version: str | None = None,
        windows_version: str | None = None,
        update: str | None = None,
        machine_type: int | None = None,
        signed: bool | None = None,
        downloadable: bool | None = None,
        predicate: Callable[[FileEntry], bool] | None = None,
    ) -> Iterator[FileEntry]:
        """Iterate over entries matching a set of filter criteria.

        All filters are combined with logical AND. Pass ``None`` (the
        default) to skip any given filter. See :func:`filter_entries`
        for the semantics of each filter.

        Yields:
            Each :class:`FileEntry` that satisfies every supplied
            filter.

        Raises:
            FileNotIndexedError: If ``filename`` is not indexed.
        """
        yield from filter_entries(
            self.get_file(filename),
            sha256=sha256,
            version=version,
            windows_version=windows_version,
            update=update,
            machine_type=machine_type,
            signed=signed,
            downloadable=downloadable,
            predicate=predicate,
        )

    # ------------------------------------------------------------------
    # Downloads
    # ------------------------------------------------------------------
    def download_binary(
        self,
        entry: FileEntry,
        dest: str | Path,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
        chunk_size: int = 64 * 1024,
    ) -> Path:
        """Download the binary referenced by ``entry`` to ``dest``.

        ``dest`` may be either an existing directory (or a path ending
        in a separator), in which case the file is written under
        ``dest/<filename>``, or a full file path.

        Args:
            entry: The :class:`FileEntry` to download.
            dest: Destination directory or path.
            overwrite: If ``False`` (the default) raise on existing
                files. If ``True``, the file is replaced.
            progress: Optional callback invoked after each chunk with
                ``(bytes_so_far, content_length_or_None)``.
            chunk_size: Streaming chunk size.

        Returns:
            The :class:`Path` to the file that was written.

        Raises:
            MissingDownloadInfoError: If the entry has no download URL.
            DownloadError: On HTTP / network failure, including a
                ``404`` when the symbol server does not host this build
                (``status_code == 404``).
            FileExistsError: If ``overwrite`` is ``False`` and the file
                already exists.
        """
        url = entry.binary_url(base_url=self.symbol_server_url)
        target = _resolve_dest(dest, entry.filename)
        return self._download_to_file(url, target, overwrite=overwrite, progress=progress, chunk_size=chunk_size)

    def download_pdb(
        self,
        entry_or_pdb: FileEntry | PdbInfo,
        dest: str | Path,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
        chunk_size: int = 64 * 1024,
    ) -> Path:
        """Download the PDB referenced by ``entry_or_pdb`` to ``dest``.

        Accepts either a :class:`FileEntry` (in which case the entry's
        own :attr:`~FileEntry.pdb` triple is used) or an explicit
        :class:`PdbInfo`. The latter is useful when the PDB triple was
        extracted from a downloaded binary using
        :func:`winbindex.extract_pdb_info`.

        Args:
            entry_or_pdb: Source of the PDB triple.
            dest: Destination directory or full file path.
            overwrite: If ``False``, raise if the target already exists.
            progress: Optional progress callback.
            chunk_size: Streaming chunk size.

        Returns:
            The :class:`Path` to the file that was written.

        Raises:
            MissingPdbInfoError: If ``entry_or_pdb`` is a FileEntry
                without PDB metadata.
            DownloadError: On HTTP / network failure.
            FileExistsError: If ``overwrite`` is ``False`` and the
                target already exists.
        """
        if isinstance(entry_or_pdb, FileEntry):
            url = entry_or_pdb.pdb_url(base_url=self.symbol_server_url)
            assert entry_or_pdb.pdb is not None
            pdb_name = entry_or_pdb.pdb.name
        else:
            url = build_pdb_url(
                entry_or_pdb.name,
                entry_or_pdb.guid,
                entry_or_pdb.age,
                base_url=self.symbol_server_url,
            )
            pdb_name = entry_or_pdb.name

        target = _resolve_dest(dest, pdb_name)
        return self._download_to_file(url, target, overwrite=overwrite, progress=progress, chunk_size=chunk_size)

    def download_many(
        self,
        entries: Iterable[FileEntry],
        dest_dir: str | Path,
        *,
        include_pdb: bool = False,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
        on_error: Callable[[FileEntry, Exception], None] | None = None,
    ) -> list[Path]:
        """Bulk-download a sequence of entries.

        Each binary lands under ``dest_dir/<sha256[:16]>/<filename>`` so
        that multiple versions of the same filename do not collide.
        PDBs (if requested) are written next to the binary. Entries with
        nothing to download are skipped without touching the disk.

        Args:
            entries: An iterable of :class:`FileEntry` objects to fetch.
            dest_dir: Root directory under which files are written.
            include_pdb: If ``True``, also fetch each entry's PDB when
                metadata is available.
            overwrite: Overwrite existing files when ``True``.
            progress: Optional progress callback. Forwarded to each
                individual download.
            on_error: Optional callback invoked when a single download
                fails. When ``None`` (the default), errors propagate.

        Returns:
            The list of :class:`Path` instances that were written. The
            order matches that of ``entries``, with PDB paths
            appearing immediately after their binary when present.
        """
        root = Path(dest_dir).expanduser()

        written: list[Path] = []
        for entry in entries:
            want_binary = entry.has_binary_download
            want_pdb = include_pdb and entry.has_pdb_download
            if not (want_binary or want_pdb):
                continue

            entry_dir = root / entry.sha256[:16]
            try:
                entry_dir.mkdir(parents=True, exist_ok=True)
                if want_binary:
                    written.append(self.download_binary(entry, entry_dir, overwrite=overwrite, progress=progress))
                if want_pdb:
                    written.append(self.download_pdb(entry, entry_dir, overwrite=overwrite, progress=progress))
            except Exception as err:
                if on_error is None:
                    raise
                on_error(entry, err)
        return written

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Perform an HTTP request with simple retry handling.

        Raises:
            DownloadError: For network failures and non-2xx responses.
                ``status_code`` is set for HTTP errors (e.g. ``404``).
        """
        last_exc: Exception | None = None
        for attempt in range(self._retry.total + 1):
            try:
                response = self._session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as err:
                last_exc = err
                if attempt >= self._retry.total:
                    raise DownloadError(str(err), url) from err
                logger.debug("Request to %s failed (%s); retrying", url, err)
                self._sleep_for_retry(attempt)
                continue

            if response.status_code in self._retry.statuses:
                response.close()
                if attempt >= self._retry.total:
                    raise DownloadError(f"HTTP {response.status_code}", url, status_code=response.status_code)
                logger.debug("HTTP %s from %s; retrying", response.status_code, url)
                self._sleep_for_retry(attempt)
                continue
            if not response.ok:
                status = response.status_code
                response.close()
                raise DownloadError(f"HTTP {status}", url, status_code=status)
            return response

        # Should not be reachable, but keep mypy happy.
        raise DownloadError(str(last_exc) if last_exc else "request failed", url)

    def _sleep_for_retry(self, attempt: int) -> None:
        delay = self._retry.backoff_factor * (2**attempt)
        time.sleep(delay)

    def _download_to_file(
        self,
        url: str,
        target: Path,
        *,
        overwrite: bool,
        progress: ProgressCallback | None,
        chunk_size: int,
    ) -> Path:
        if target.exists() and not overwrite:
            raise FileExistsError(target)

        try:
            # Ask for the bytes as stored: with a compressed transfer the
            # Content-Length would not match what ends up on disk.
            response = self._request("GET", url, stream=True, headers={"Accept-Encoding": "identity"})
        except DownloadError as err:
            if err.status_code == 404:
                raise DownloadError("not available on the symbol server (HTTP 404)", url, status_code=404) from None
            raise

        logger.info("Downloading %s -> %s", url, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".part")

        try:
            total = _decoded_length(response)
            downloaded = 0
            with tmp.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if progress is not None:
                        progress(downloaded, total)
            if total is not None and downloaded != total:
                raise DownloadError(f"incomplete download: got {downloaded} of {total} bytes", url)
        except requests.RequestException as err:
            tmp.unlink(missing_ok=True)
            raise DownloadError(f"connection failed while downloading: {err}", url) from err
        except BaseException:
            # Covers DownloadError above, OSError, KeyboardInterrupt, ...
            tmp.unlink(missing_ok=True)
            raise
        finally:
            response.close()

        # tmp sits next to target, so this rename is atomic (and replaces
        # an existing file when overwrite is set).
        tmp.replace(target)
        return target

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def _cache_path(self, filename: str) -> Path | None:
        if self.cache_dir is None:
            return None
        # filename has been sanitized by _normalize_filename; but we
        # still strip any directory components defensively.
        safe = filename.replace("/", "_").replace("\\", "_")
        return self.cache_dir / f"{safe}.json.gz"

    def _read_cache(self, filename: str) -> dict[str, Any] | None:
        path = self._cache_path(filename)
        if path is None or not path.is_file():
            return None
        if self.cache_ttl is not None:
            age = time.time() - path.stat().st_mtime
            if age > self.cache_ttl:
                logger.debug("Cache file %s is stale (%.0fs old); refetching", path, age)
                return None
        try:
            with gzip.open(path, "rb") as fh:
                data = json.load(fh)
        except (OSError, EOFError, ValueError):
            # Not gzip (OSError), truncated (EOFError), not JSON / UTF-8 (ValueError).
            logger.warning("Cache file %s is corrupted; ignoring.", path)
            return None
        if not isinstance(data, dict):
            return None
        logger.debug("Using cached metadata from %s", path)
        return data

    def _write_cache(self, filename: str, data: Mapping[str, Any]) -> None:
        """Persist ``data``; failures are logged, never raised (the data was fetched fine)."""
        path = self._cache_path(filename)
        if path is None:
            return
        tmp: Path | None = None
        try:
            # A unique temp name keeps concurrent writers from clobbering each other.
            fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".part")
            tmp = Path(tmp_name)
            with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt", encoding="utf-8") as fh:
                json.dump(data, fh)
            tmp.replace(path)
        except OSError as err:
            logger.warning("Could not write cache file %s: %s", path, err)
            if tmp is not None:
                tmp.unlink(missing_ok=True)


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------
def filter_entries(
    entries: Iterable[FileEntry],
    *,
    sha256: str | None = None,
    version: str | None = None,
    windows_version: str | None = None,
    update: str | None = None,
    machine_type: int | None = None,
    signed: bool | None = None,
    downloadable: bool | None = None,
    predicate: Callable[[FileEntry], bool] | None = None,
) -> Iterator[FileEntry]:
    """Yield the entries that satisfy every supplied filter (logical AND).

    Args:
        entries: The entries to filter, e.g. from
            :meth:`WinbindexClient.get_file`.
        sha256: A full SHA256 hash or a prefix of one
            (case-insensitive). Every entry starting with it matches.
        version: A wildcard pattern matched against
            :attr:`FileEntry.version`. Supports ``*`` and ``?``.
            Example: ``"10.0.22621.*"``.
        windows_version: Match entries that appear in this Windows
            version (e.g. ``"11-22H2"``; case-insensitive).
        update: Match entries that appear in this KB / update
            identifier (e.g. ``"KB5023778"`` or ``"BASE"``;
            case-insensitive).
        machine_type: Filter on the PE machine type (e.g.
            ``0x8664`` for x64, ``0x14C`` for x86, ``0xAA64`` for
            ARM64). See :func:`~winbindex.models.parse_machine_type`.
        signed: If ``True``, only return signed binaries.
        downloadable: If ``True``, only return entries that have
            enough metadata to build a binary URL.
        predicate: Optional user-supplied predicate evaluated last,
            for anything the filters above do not cover. For example,
            ``lambda e: e.has_pdb_download`` keeps the entries whose PDB
            triple is in the index.
    """
    version_re = _wildcard_to_regex(version) if version else None
    sha_lower = sha256.lower() if sha256 else None
    winver_lower = windows_version.lower() if windows_version else None
    update_lower = update.lower() if update else None

    for entry in entries:
        if sha_lower is not None and not entry.sha256.startswith(sha_lower):
            continue
        if version_re is not None and (entry.version is None or not version_re.match(entry.version)):
            continue
        if winver_lower is not None and winver_lower not in {v.lower() for v in entry.windows_versions}:
            continue
        if update_lower is not None and update_lower not in {u.lower() for u in entry.updates}:
            continue
        if machine_type is not None and entry.file_info.machine_type != machine_type:
            continue
        if signed is not None and entry.is_signed != signed:
            continue
        if downloadable is not None and entry.has_binary_download != downloadable:
            continue
        if predicate is not None and not predicate(entry):
            continue
        yield entry


def _normalize_filename(filename: str) -> str:
    """Reject bogus filenames and normalize them.

    Anything that is not a valid bare Windows filename - empty,
    containing a path separator or another reserved character
    (``<>:"/\\|?*``), or ``.`` / ``..`` - is rejected.
    """
    # Winbindex stores filenames in lower-case.
    return _check_bare_filename(filename).lower()


def _decoded_length(response: requests.Response) -> int | None:
    """Return the size of the body as written to disk, if the server announced it.

    ``Content-Length`` counts bytes on the wire. If the server applied a
    ``Content-Encoding`` anyway (``requests`` decodes it transparently) that
    is not the size of the file, so it is treated as unknown.
    """
    encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        return None
    try:
        return int(response.headers["Content-Length"])
    except (KeyError, ValueError):
        return None


def _resolve_dest(dest: str | Path, filename: str) -> Path:
    """If ``dest`` is a directory, append ``filename``; otherwise return as-is."""
    path = Path(dest).expanduser()
    if path.is_dir() or str(dest).endswith(("/", "\\")):
        return path / filename
    return path


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a simple ``*``/``?`` wildcard pattern into a regex."""
    # Escape everything, then re-allow the two wildcard tokens.
    parts: list[str] = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE)
