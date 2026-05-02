from __future__ import annotations

from typing import Any
from collections.abc import Iterator

from pydantic import Field, BaseModel, ConfigDict, field_validator

from .exceptions import (
    InvalidDataError,
    MissingPdbInfoError,
    MissingDownloadInfoError,
)
from .symbol_server import build_pdb_url, normalize_guid, build_binary_url


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
            raise InvalidDataError(
                f"signingDate must be a list, got {type(signing_date).__name__}"
            )

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

    @property
    def has_download_info(self) -> bool:
        return self.timestamp is not None and self.virtual_size is not None


# ----------------------------------------------------------------------
# pdb
# ----------------------------------------------------------------------
class PdbInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    guid: str
    age: int

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
            raise InvalidDataError(
                f"PDB info is incomplete: name={name!r} guid={guid!r} age={age!r}"
            )

        return cls(name=str(name), guid=str(guid), age=int(age))


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
    def windows_versions(self) -> set[str]:
        return {r.windows_version for r in self.releases}

    @property
    def updates(self) -> set[str]:
        return {r.update for r in self.releases}

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
        if not self.file_info.has_download_info:
            raise MissingDownloadInfoError(
                f"Cannot build binary URL for {self.filename!r} "
                f"(sha256={self.sha256[:12]}…): missing timestamp or virtualSize."
            )

        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url

        return build_binary_url(
            self.filename,
            self.file_info.timestamp,
            self.file_info.virtual_size,
            **kwargs,
        )

    def pdb_url(self, *, base_url: str | None = None) -> str:
        if self.pdb is None:
            raise MissingPdbInfoError(
                f"No PDB metadata for {self.filename!r} (sha256={self.sha256[:12]}…)."
            )

        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url

        return build_pdb_url(self.pdb.name, self.pdb.guid, self.pdb.age, **kwargs)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, filename: str, sha256: str, data: dict[str, Any]) -> FileEntry:
        if not isinstance(data, dict):
            raise InvalidDataError(
                f"Entry for sha256={sha256!r} must be a dict, got {type(data).__name__}"
            )

        file_info_raw = data.get("fileInfo", {})
        if not isinstance(file_info_raw, dict):
            raise InvalidDataError(
                f"fileInfo must be a dict, got {type(file_info_raw).__name__}"
            )

        file_info = FileInfo.from_dict(sha256, file_info_raw)

        pdb_raw = data.get("pdb")
        pdb: PdbInfo | None = None
        if isinstance(pdb_raw, dict):
            try:
                pdb = PdbInfo.from_dict(pdb_raw)
            except InvalidDataError:
                pdb = None

        releases = tuple(_iter_releases(data.get("windowsVersions", {})))

        return cls(
            filename=filename,
            file_info=file_info,
            pdb=pdb,
            releases=releases,
            raw=dict(data),
        )


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

            release_date = wvi.get("releaseDate") if isinstance(wvi, dict) else None

            yield WindowsRelease(
                windows_version=str(win_ver),
                update=str(update_id),
                source_paths=source_paths,
                release_date=release_date,
                update_info=dict(update_info) if isinstance(update_info, dict) else {},
                windows_version_info=dict(wvi) if isinstance(wvi, dict) else {},
                assemblies=dict(assemblies) if isinstance(assemblies, dict) else {},
                raw=dict(info),
            )