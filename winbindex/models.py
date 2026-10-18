"""Typed models for the Winbindex JSON payload."""

from __future__ import annotations

import re
from typing import Any
from collections.abc import Iterator

from pydantic import Field, BaseModel, ConfigDict, ValidationError, field_validator

from .exceptions import (
    InvalidDataError,
    MissingPdbInfoError,
    InvalidFilenameError,
    MissingDownloadInfoError,
)
from .symbol_server import build_pdb_url, normalize_guid, build_binary_url

# ----------------------------------------------------------------------
# Filenames
# ----------------------------------------------------------------------
# Characters that can never appear in a Windows filename, plus control chars.
_INVALID_FILENAME_CHARS = frozenset('<>:"/\\|?*') | {chr(c) for c in range(32)}


def _check_bare_filename(name: str) -> str:
    """Return ``name`` unchanged if it is a valid bare Windows filename.

    Anything else - empty, containing a path separator or another reserved
    character (``<>:"/\\|?*``), or ``.`` / ``..`` - is rejected, so an
    accepted name is always safe to join onto a destination directory.

    Raises:
        InvalidFilenameError: If ``name`` is not a bare filename.
    """
    if not name:
        raise InvalidFilenameError("filename must not be empty")
    if "/" in name or "\\" in name:
        raise InvalidFilenameError(f"filename must be a bare filename, not a path: {name!r}")
    bad = sorted(set(name) & _INVALID_FILENAME_CHARS)
    if bad:
        raise InvalidFilenameError(f"Invalid characters in filename {name!r}: {''.join(bad)!r}")
    if name in {".", ".."}:
        raise InvalidFilenameError(f"Invalid filename: {name!r}")
    return name


# ----------------------------------------------------------------------
# PE machine types
# ----------------------------------------------------------------------
#: Human-readable names for the common PE ``Machine`` values. Every name
#: is accepted back by :func:`parse_machine_type`. ``0x1C0`` (plain ARM,
#: not used by Windows) has no name so that ``arm`` stays unambiguous.
MACHINE_NAMES: dict[int, str] = {
    0x14C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x1C4: "arm",  # ARMNT (Thumb-2), the 32-bit ARM Windows target
    0x200: "ia64",
    0xEBC: "efi",  # EFI byte code
}

_MACHINE_ALIASES: dict[str, int] = {
    "x86": 0x14C,
    "i386": 0x14C,
    "i686": 0x14C,
    "ia32": 0x14C,
    "x64": 0x8664,
    "amd64": 0x8664,
    "x86_64": 0x8664,
    "x86-64": 0x8664,
    "arm64": 0xAA64,
    "aarch64": 0xAA64,
    "arm": 0x1C4,
    "armnt": 0x1C4,
    "ia64": 0x200,
    "efi": 0xEBC,
    "ebc": 0xEBC,
}


def machine_name(machine_type: int | None) -> str:
    """Return a short architecture name (``x64``, ``x86``, ``arm64`` …) for a PE machine type.

    Unknown values are rendered as hex; ``None`` becomes ``"?"``.
    """
    if machine_type is None:
        return "?"
    return MACHINE_NAMES.get(machine_type) or f"0x{machine_type:x}"


def parse_machine_type(value: str | int) -> int:
    """Parse a PE machine type from a name (``x64``, ``amd64``, ``arm64`` …) or a number.

    Numbers may be decimal or ``0x``-prefixed hex.

    Raises:
        ValueError: If ``value`` is neither a known name nor a number.
    """
    if isinstance(value, int):
        return value
    key = value.strip().lower()
    if key in _MACHINE_ALIASES:
        return _MACHINE_ALIASES[key]
    try:
        return int(key, 0)
    except ValueError:
        known = ", ".join(sorted(set(_MACHINE_ALIASES)))
        raise ValueError(f"Unknown machine type {value!r}. Use one of: {known}, or a number.") from None


_VERSION_PREFIX_RE = re.compile(r"^\s*(\d+(?:\.\d+)*)")


def parse_version(version: str | None) -> tuple[int, ...]:
    """Return the leading dotted-integer part of ``version`` as a tuple.

    ``"10.0.22621.1485 (WinBuild.160101.0800)"`` becomes
    ``(10, 0, 22621, 1485)``. Strings with no numeric prefix (and
    ``None``) become ``()``, which sorts before every real version.
    """
    if not version:
        return ()
    match = _VERSION_PREFIX_RE.match(version)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


# ----------------------------------------------------------------------
# fileInfo
# ----------------------------------------------------------------------
class FileInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    sha256: str
    timestamp: int | None = None
    virtual_size: int | None = None
    size: int | None = None
    version: str | None = None
    description: str | None = None
    machine_type: int | None = None
    md5: str | None = None
    sha1: str | None = None
    signing_status: str | None = None
    signature_type: str | None = None
    signing_date: tuple[str, ...] | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, sha256: str, data: dict[str, Any]) -> FileInfo:
        signing_date = data.get("signingDate")
        if signing_date is not None and not isinstance(signing_date, list):
            raise InvalidDataError(f"signingDate must be a list, got {type(signing_date).__name__}")

        try:
            return cls(
                sha256=sha256.lower(),
                timestamp=data.get("timestamp"),
                virtual_size=data.get("virtualSize"),
                size=data.get("size"),
                version=data.get("version"),
                description=data.get("description"),
                machine_type=data.get("machineType"),
                md5=data.get("md5"),
                sha1=data.get("sha1"),
                signing_status=data.get("signingStatus"),
                signature_type=data.get("signatureType"),
                signing_date=tuple(signing_date) if signing_date else None,
                raw=dict(data),
            )
        except ValidationError as err:
            raise InvalidDataError(f"Malformed fileInfo for sha256={sha256!r}: {err}") from err

    @property
    def has_download_info(self) -> bool:
        return self.timestamp is not None and self.virtual_size is not None

    @property
    def version_tuple(self) -> tuple[int, ...]:
        """The numeric part of :attr:`version`, suitable for sorting."""
        return parse_version(self.version)

    @property
    def short_version(self) -> str | None:
        """:attr:`version` without the trailing build tag, e.g. ``"10.0.22621.1485"``."""
        if self.version is None:
            return None
        return self.version.split(" (", 1)[0].strip() or self.version

    @property
    def machine_name(self) -> str:
        """Short architecture name for :attr:`machine_type` (``x64``, ``x86`` …)."""
        return machine_name(self.machine_type)

    @property
    def is_signed(self) -> bool:
        return self.signing_status == "Signed"


# ----------------------------------------------------------------------
# pdb
# ----------------------------------------------------------------------
class PdbInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    guid: str
    age: int

    @field_validator("name")
    @classmethod
    def check_name(cls, v: str) -> str:
        # The name becomes a path component of both the URL and the file
        # written to disk, so it must not be able to escape a directory.
        return _check_bare_filename(v)

    @field_validator("guid", mode="before")
    @classmethod
    def normalize_guid_field(cls, v: str) -> str:
        return normalize_guid(v)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PdbInfo:
        name = data.get("pdbName") or data.get("name")
        guid = data.get("pdbGuid") or data.get("guid")
        age = data.get("pdbAge") if data.get("pdbAge") is not None else data.get("age")

        if not name or not guid or age is None:
            raise InvalidDataError(f"PDB info is incomplete: name={name!r} guid={guid!r} age={age!r}")

        # The symbol server indexes PDBs by basename; drop any build path.
        basename = str(name).replace("\\", "/").rsplit("/", 1)[-1]
        try:
            return cls(name=basename, guid=str(guid), age=int(age))
        except (ValueError, TypeError) as err:  # ValidationError is a ValueError
            raise InvalidDataError(f"PDB info is malformed: name={name!r} guid={guid!r} age={age!r}") from err


# ----------------------------------------------------------------------
# windowsVersions / updateInfo
# ----------------------------------------------------------------------
class WindowsRelease(BaseModel):
    model_config = ConfigDict(frozen=True)

    windows_version: str
    update: str
    source_paths: tuple[str, ...] = ()
    release_date: str | None = None
    update_info: dict[str, Any] = Field(default_factory=dict, repr=False)
    windows_version_info: dict[str, Any] = Field(default_factory=dict, repr=False)
    assemblies: dict[str, Any] = Field(default_factory=dict, repr=False)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


# ----------------------------------------------------------------------
# Top-level entry
# ----------------------------------------------------------------------
class FileEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    file_info: FileInfo
    pdb: PdbInfo | None = None
    releases: tuple[WindowsRelease, ...] = ()
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Convenient accessors
    # ------------------------------------------------------------------
    @property
    def sha256(self) -> str:
        return self.file_info.sha256

    @property
    def version(self) -> str | None:
        return self.file_info.version

    @property
    def version_tuple(self) -> tuple[int, ...]:
        """Numeric file version for sorting, e.g. ``(10, 0, 22621, 1485)``."""
        return self.file_info.version_tuple

    @property
    def short_version(self) -> str | None:
        """File version without the build tag, e.g. ``"10.0.22621.1485"``."""
        return self.file_info.short_version

    @property
    def machine_name(self) -> str:
        """Short architecture name (``x64``, ``x86``, ``arm64`` …)."""
        return self.file_info.machine_name

    @property
    def is_signed(self) -> bool:
        return self.file_info.is_signed

    @property
    def windows_versions(self) -> set[str]:
        return {r.windows_version for r in self.releases}

    @property
    def updates(self) -> set[str]:
        return {r.update for r in self.releases}

    @property
    def release_date(self) -> str | None:
        """Earliest known release date (``YYYY-MM-DD``) across all releases, if any."""
        dates = [r.release_date for r in self.releases if r.release_date]
        return min(dates) if dates else None

    @property
    def has_binary_download(self) -> bool:
        return self.file_info.has_download_info

    @property
    def has_pdb_download(self) -> bool:
        return self.pdb is not None

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------
    def binary_url(self, *, base_url: str | None = None) -> str:
        timestamp = self.file_info.timestamp
        virtual_size = self.file_info.virtual_size
        if timestamp is None or virtual_size is None:
            raise MissingDownloadInfoError(
                f"Cannot build binary URL for {self.filename!r} "
                f"(sha256={self.sha256[:12]}…): missing timestamp or virtualSize."
            )

        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url

        return build_binary_url(self.filename, timestamp, virtual_size, **kwargs)

    def pdb_url(self, *, base_url: str | None = None) -> str:
        if self.pdb is None:
            raise MissingPdbInfoError(f"No PDB metadata for {self.filename!r} (sha256={self.sha256[:12]}…).")

        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url

        return build_pdb_url(self.pdb.name, self.pdb.guid, self.pdb.age, **kwargs)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, filename: str, sha256: str, data: dict[str, Any]) -> FileEntry:
        """Build an entry from one ``sha256 -> {...}`` item of the Winbindex JSON.

        Raises:
            InvalidDataError: If the entry is structurally unusable. A
                malformed ``pdb`` block is dropped rather than fatal.
        """
        if not isinstance(data, dict):
            raise InvalidDataError(f"Entry for sha256={sha256!r} must be a dict, got {type(data).__name__}")

        file_info_raw = data.get("fileInfo", {})
        if not isinstance(file_info_raw, dict):
            raise InvalidDataError(f"fileInfo must be a dict, got {type(file_info_raw).__name__}")

        file_info = FileInfo.from_dict(sha256, file_info_raw)

        pdb_raw = data.get("pdb")
        pdb: PdbInfo | None = None
        if isinstance(pdb_raw, dict):
            try:
                pdb = PdbInfo.from_dict(pdb_raw)
            except InvalidDataError:
                pdb = None

        releases = tuple(_iter_releases(data.get("windowsVersions", {})))

        try:
            return cls(
                filename=filename,
                file_info=file_info,
                pdb=pdb,
                releases=releases,
                raw=dict(data),
            )
        except ValidationError as err:
            raise InvalidDataError(f"Malformed entry for sha256={sha256!r}: {err}") from err


def _iter_releases(windows_versions: dict[str, Any]) -> Iterator[WindowsRelease]:
    if not isinstance(windows_versions, dict):
        return

    for win_ver, updates in windows_versions.items():
        if not isinstance(updates, dict):
            continue

        for update_id, info in updates.items():
            if not isinstance(info, dict):
                continue

            wvi = info.get("windowsVersionInfo") or {}
            update_info = info.get("updateInfo") or {}
            assemblies = info.get("assemblies") or {}

            source_paths_raw = info.get("sourcePaths") or []
            source_paths = tuple(source_paths_raw) if isinstance(source_paths_raw, list) else ()

            release_date = None
            if isinstance(wvi, dict):
                release_date = wvi.get("releaseDate")
            if release_date is None and isinstance(update_info, dict):
                release_date = update_info.get("releaseDate")

            yield WindowsRelease(
                windows_version=str(win_ver),
                update=str(update_id),
                source_paths=source_paths,
                release_date=str(release_date) if release_date is not None else None,
                update_info=dict(update_info) if isinstance(update_info, dict) else {},
                windows_version_info=dict(wvi) if isinstance(wvi, dict) else {},
                assemblies=dict(assemblies) if isinstance(assemblies, dict) else {},
                raw=dict(info),
            )
