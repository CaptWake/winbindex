"""Command-line front-end for :mod:`winbindex`.

Subcommands:

* ``info``      - summarise what the index knows about a file
* ``list``      - print matching versions of a file as a table
* ``url``       - print the binary URL for matching entries
* ``download``  - download binaries (and optionally their PDBs, found by parsing
  each downloaded binary) matching a query

Global options (cache, timeouts, ``--json``, ``-v`` ...) are accepted both
before and after the subcommand. Exit status: ``0`` on success, ``1``
when nothing matched or some items failed, ``2`` on usage or fatal
errors, ``130`` when interrupted.
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import difflib
import logging
import argparse
from typing import Any
from pathlib import Path, PureWindowsPath
from collections import Counter
from dataclasses import field, dataclass
from collections.abc import Callable, Iterable, Sequence

import pefile

from .client import WinbindexClient, filter_entries, default_cache_dir
from .models import _INVALID_FILENAME_CHARS, FileEntry, machine_name, parse_machine_type
from .version import __version__
from .utils.pdb import extract_pdb_info
from .exceptions import (
    DownloadError,
    WinbindexError,
    FileNotIndexedError,
    MissingPdbInfoError,
)
from .symbol_server import DEFAULT_SYMBOL_SERVER_URL

logger = logging.getLogger("winbindex.cli")

#: Metadata cached on disk is refetched after this many seconds.
DEFAULT_CACHE_TTL = 24 * 3600

EXIT_OK = 0
EXIT_NO_MATCH = 1  # also: partial failure
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

_SORT_CHOICES = ("version", "date", "size", "sha", "none")
_LAYOUT_CHOICES = ("sha", "version", "flat")


# ======================================================================
# Small output helpers
# ======================================================================
def _human_size(n: int | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            break
        value /= 1024
    return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"


def _truncate(text: str, width: int) -> str:
    if width <= 0 or len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _render_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    show_header: bool = True,
    right_align: Iterable[int] = (),
) -> str:
    """Render rows as a whitespace-aligned table (two spaces between columns)."""
    rows = [list(r) for r in rows]
    widths = [len(h) for h in headers] if show_header else [0] * len(headers)
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]
    right = set(right_align)

    def fmt(row: Sequence[str]) -> str:
        cells = [cell.rjust(widths[i]) if i in right else cell.ljust(widths[i]) for i, cell in enumerate(row)]
        return "  ".join(cells).rstrip()

    lines = [fmt(headers)] if show_header else []
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def _signed_label(entry: FileEntry) -> str:
    status = entry.file_info.signing_status
    if status is None:
        return "?"
    if status == "Signed":
        return "yes"
    if status == "Unsigned":
        return "no"
    return status.lower()


def _download_label(entry: FileEntry) -> str:
    return "bin" if entry.has_binary_download else "-"


def _entry_to_dict(entry: FileEntry, client: WinbindexClient) -> dict[str, Any]:
    """Serialise an entry for ``--json`` output (stable camelCase keys)."""
    fi = entry.file_info
    return {
        "filename": entry.filename,
        "sha256": entry.sha256,
        "sha1": fi.sha1,
        "md5": fi.md5,
        "version": fi.version,
        "shortVersion": fi.short_version,
        "description": fi.description,
        "machineType": fi.machine_type,
        "machine": fi.machine_name,
        "size": fi.size,
        "timestamp": fi.timestamp,
        "virtualSize": fi.virtual_size,
        "signed": fi.is_signed,
        "signingStatus": fi.signing_status,
        "signatureType": fi.signature_type,
        "signingDate": list(fi.signing_date) if fi.signing_date else None,
        "releaseDate": entry.release_date,
        "windowsVersions": sorted(entry.windows_versions),
        "updates": sorted(entry.updates),
        "releases": [
            {
                "windowsVersion": r.windows_version,
                "update": r.update,
                "releaseDate": r.release_date,
                "sourcePaths": list(r.source_paths),
            }
            for r in entry.releases
        ],
        "binaryUrl": entry.binary_url(base_url=client.symbol_server_url) if entry.has_binary_download else None,
    }


def _print_json(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _note(msg: str) -> None:
    """Print a diagnostic line on stderr, keeping it ordered after any stdout output."""
    sys.stdout.flush()
    print(msg, file=sys.stderr)


def _warn(msg: str) -> None:
    _note(f"warning: {msg}")


# ======================================================================
# Entry selection (shared by every subcommand)
# ======================================================================
@dataclass
class Selection:
    filenames: list[str] = field(default_factory=list)  # as requested, without repeats
    entries: list[FileEntry] = field(default_factory=list)
    matched: int = 0  # before --limit / --latest
    missing: list[str] = field(default_factory=list)  # filenames not indexed
    empty: list[str] = field(default_factory=list)  # indexed filenames nothing was selected for
    hints: list[str] = field(default_factory=list)


def _filter_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """The :func:`filter_entries` keyword arguments given on the command line."""
    return {
        "sha256": args.sha256,
        "version": args.file_version,
        "windows_version": args.windows_version,
        "update": args.update,
        "machine_type": args.machine,
        "signed": args.signed,
        "downloadable": args.downloadable,
    }


def _sort_value(name: str, entry: FileEntry) -> Any:
    """The value ``--sort name`` orders by, or ``None`` when the entry lacks it."""
    if name == "version":
        return entry.version_tuple or None
    if name == "date":
        return entry.release_date
    if name == "size":
        return entry.file_info.size
    if name == "sha":
        return entry.sha256
    raise ValueError(name)


def _sort_entries(entries: list[FileEntry], name: str, *, reverse: bool) -> list[FileEntry]:
    """Sort on ``name`` (ties: version, date, hash). Entries lacking the value go last either way."""
    known = [e for e in entries if _sort_value(name, e) is not None]
    unknown = [e for e in entries if _sort_value(name, e) is None]
    known.sort(key=lambda e: (_sort_value(name, e), e.version_tuple, e.release_date or "", e.sha256), reverse=reverse)
    return known + unknown


def _requested_filenames(names: Sequence[str]) -> list[str]:
    """Reduce paths to their file name (with a note) and drop repeats, ignoring case."""
    unique: dict[str, str] = {}
    for name in names:
        if "/" in name or "\\" in name:
            base = PureWindowsPath(name).name  # splits on both separators
            if base:
                _note(f"note: looking up {base!r}; Winbindex is keyed by file name, not path")
                name = base
        unique.setdefault(name.lower(), name)
    return list(unique.values())


def _latest_per_arch(entries: list[FileEntry]) -> list[FileEntry]:
    """Keep the newest entry per architecture (entries without a machine type are ignored)."""
    best: dict[int, FileEntry] = {}
    for e in entries:
        if e.file_info.machine_type is None:
            continue
        current = best.get(e.file_info.machine_type)
        if current is None or (e.version_tuple, e.release_date or "") > (
            current.version_tuple,
            current.release_date or "",
        ):
            best[e.file_info.machine_type] = e
    keep = {id(e) for e in best.values()}
    return [e for e in entries if id(e) in keep]


def _hints_for_empty_match(filename: str, entries: list[FileEntry], args: argparse.Namespace) -> list[str]:
    """Explain why a filter matched nothing, suggesting close values."""
    hints: list[str] = []

    def suggest(kind: str, wanted: str, known: set[str]) -> None:
        by_lower = {k.lower(): k for k in known}
        if not known or wanted.lower() in by_lower:
            return
        # The filters ignore case, so the suggestions must too.
        close = difflib.get_close_matches(wanted.lower(), sorted(by_lower), n=3, cutoff=0.5)
        msg = f"{kind} {wanted!r} is unknown for {filename}"
        if close:
            msg += f"; did you mean {', '.join(repr(by_lower[c]) for c in close)}?"
        else:
            shown = sorted(known)[:12]
            more = f", ... ({len(known) - len(shown)} more)" if len(known) > len(shown) else ""
            msg += f"; known values: {', '.join(shown)}{more}"
        hints.append(msg)

    def matches_without(name: str) -> int:
        """How many entries would match if only the ``name`` filter were dropped."""
        return sum(1 for _ in filter_entries(entries, **{**_filter_kwargs(args), name: None}))

    if args.windows_version:
        suggest("--windows-version", args.windows_version, {v for e in entries for v in e.windows_versions})
    if args.update:
        suggest("--update", args.update, {u for e in entries for u in e.updates})
    if args.machine is not None and all(e.file_info.machine_type != args.machine for e in entries):
        available = ", ".join(sorted({e.machine_name for e in entries}))
        hints.append(f"no {filename} entries for --machine {machine_name(args.machine)}; available: {available}")
    if args.downloadable and (n := matches_without("downloadable")):
        hints.append(
            f"the other filters match {_plural(n, 'entry', 'entries')} of {filename}, but without download "
            "metadata (the index lacks the PE timestamp and image size)"
        )
    return hints


def _select(client: WinbindexClient, args: argparse.Namespace) -> Selection:
    """Load, filter, sort and limit entries for every filename on the command line."""
    sel = Selection(filenames=_requested_filenames(args.filenames))
    sort = getattr(args, "sort", "version")
    reverse = getattr(args, "reverse", False)
    latest = getattr(args, "latest", False)
    limit = getattr(args, "limit", None)
    criteria = _filter_kwargs(args)

    for filename in sel.filenames:
        try:
            all_entries = client.get_file(filename)
        except FileNotIndexedError:
            sel.missing.append(filename)
            continue

        matched = list(filter_entries(all_entries, **criteria))
        if not matched and all_entries:
            sel.hints.extend(_hints_for_empty_match(filename, all_entries, args))
        elif args.sha256 and len(matched) > 1 and getattr(args, "cmd", None) in ("url", "download"):
            _warn(f"--sha256 {args.sha256!r} is ambiguous: it matches {len(matched)} {filename} entries")

        if sort != "none":
            matched = _sort_entries(matched, sort, reverse=reverse)
        elif reverse:
            matched.reverse()
        sel.matched += len(matched)
        if latest:
            kept = _latest_per_arch(matched)
            if matched and not kept:
                sel.hints.append(f"--latest keeps one entry per architecture, but no matching {filename} has one")
            matched = kept
        if limit is not None:
            matched = matched[:limit]
        if not matched:
            sel.empty.append(filename)
        sel.entries.extend(matched)

    return sel


def _report_selection_problems(sel: Selection) -> int | None:
    """Print missing-file / no-match diagnostics. Returns an exit code if the command should stop."""
    for filename in sel.missing:
        _note(f"error: {filename!r} is not indexed by Winbindex.")
    if sel.missing and len(sel.missing) == len(sel.filenames):
        return EXIT_ERROR
    if sel.empty:  # also reported when other files did match
        _note(f"No matching entries for {', '.join(sel.empty)}.")
        for hint in sel.hints:
            _note(f"hint: {hint}")
        if not sel.hints:
            _note(f"hint: run `winbindex info {sel.empty[0]}` to see what is available.")
    if not sel.entries:
        return EXIT_NO_MATCH
    return None


# ======================================================================
# info
# ======================================================================
def _info_for(filename: str, entries: list[FileEntry]) -> dict[str, Any]:
    arch_counts = Counter(e.machine_name for e in entries)
    versions = sorted({e.version_tuple for e in entries if e.version_tuple})
    dates = sorted({r.release_date for e in entries for r in e.releases if r.release_date})
    descriptions = Counter(e.file_info.description for e in entries if e.file_info.description)

    per_winver: dict[str, dict[str, Any]] = {}
    for e in entries:
        for r in e.releases:
            bucket = per_winver.setdefault(r.windows_version, {"entries": set(), "updates": set(), "dates": []})
            bucket["entries"].add(e.sha256)
            bucket["updates"].add(r.update)
            if r.release_date:
                bucket["dates"].append(r.release_date)

    windows_versions = [
        {
            "windowsVersion": wv,
            "entries": len(b["entries"]),
            "updates": len(b["updates"]),
            "firstRelease": min(b["dates"]) if b["dates"] else None,
            "lastRelease": max(b["dates"]) if b["dates"] else None,
        }
        for wv, b in per_winver.items()
    ]
    windows_versions.sort(key=lambda d: (d["firstRelease"] or "", d["windowsVersion"]))

    latest = _latest_per_arch(entries)
    latest.sort(key=lambda e: e.machine_name)

    return {
        "filename": filename,
        "entries": len(entries),
        "downloadable": sum(e.has_binary_download for e in entries),
        "signed": sum(e.is_signed for e in entries),
        "architectures": dict(arch_counts.most_common()),
        "description": descriptions.most_common(1)[0][0] if descriptions else None,
        "oldestVersion": ".".join(map(str, versions[0])) if versions else None,
        "newestVersion": ".".join(map(str, versions[-1])) if versions else None,
        "firstRelease": dates[0] if dates else None,
        "lastRelease": dates[-1] if dates else None,
        "latestPerArch": [
            {
                "machine": e.machine_name,
                "version": e.short_version,
                "releaseDate": e.release_date,
                "sha256": e.sha256,
                "windowsVersions": sorted(e.windows_versions),
            }
            for e in latest
        ],
        "windowsVersions": windows_versions,
    }


def _print_info(info: dict[str, Any]) -> None:
    def row(label: str, value: str) -> None:
        print(f"  {label:<18}{value}")

    print(info["filename"])
    if info["description"]:
        row("description", info["description"])
    row(
        "entries",
        f"{info['entries']} ({info['downloadable']} downloadable · {info['signed']} signed)",
    )
    row("architectures", " · ".join(f"{k} {v}" for k, v in info["architectures"].items()) or "-")
    if info["oldestVersion"]:
        row("file versions", f"{info['oldestVersion']} ... {info['newestVersion']}")
    if info["firstRelease"]:
        row("release dates", f"{info['firstRelease']} ... {info['lastRelease']}")
    if info["latestPerArch"]:
        lines = [
            f"{la['machine']:<6} {la['version'] or '?':<18} {la['releaseDate'] or '?':<11} sha256 {la['sha256'][:16]}"
            for la in info["latestPerArch"]
        ]
        row("latest per arch", lines[0])
        for line in lines[1:]:
            row("", line)
    if info["windowsVersions"]:
        print("  windows versions")
        table = _render_table(
            ["VERSION", "ENTRIES", "UPDATES", "FIRST", "LAST"],
            [
                [
                    w["windowsVersion"],
                    str(w["entries"]),
                    str(w["updates"]),
                    w["firstRelease"] or "-",
                    w["lastRelease"] or "-",
                ]
                for w in info["windowsVersions"]
            ],
            right_align=(1, 2),
        )
        for line in table.splitlines():
            print(f"    {line}")


def cmd_info(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``info`` subcommand."""
    sel = _select(client, args)
    stop = _report_selection_problems(sel)
    if stop is not None:
        return stop

    by_file: dict[str, list[FileEntry]] = {}
    for e in sel.entries:
        by_file.setdefault(e.filename, []).append(e)
    infos = [_info_for(fn, entries) for fn, entries in by_file.items()]

    if args.json:
        # The shape follows the command line, not what was found, so scripts can rely on it.
        _print_json(infos if len(sel.filenames) > 1 else infos[0])
    else:
        for i, info in enumerate(infos):
            if i:
                print()
            _print_info(info)
    return EXIT_NO_MATCH if sel.missing else EXIT_OK


# ======================================================================
# list
# ======================================================================
def cmd_list(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``list`` subcommand."""
    sel = _select(client, args)
    stop = _report_selection_problems(sel)
    if stop is not None:
        return stop

    if args.json:
        _print_json([_entry_to_dict(e, client) for e in sel.entries])
    elif args.quiet:
        for e in sel.entries:
            print(e.sha256)
    else:
        multi = len(sel.filenames) > 1
        list_width = 0 if args.wide else 28
        headers = (["FILE"] if multi else []) + [
            "SHA256",
            "VERSION",
            "ARCH",
            "SIGNED",
            "SIZE",
            "RELEASED",
            "WINDOWS",
            "UPDATES",
            "DOWNLOAD",
        ]
        rows = []
        for e in sel.entries:
            version = (e.version if args.full_version else e.short_version) or "<no version>"
            row = ([e.filename] if multi else []) + [
                e.sha256[:16],
                version,
                e.machine_name,
                _signed_label(e),
                _human_size(e.file_info.size),
                e.release_date or "-",
                _truncate(", ".join(sorted(e.windows_versions)) or "-", list_width),
                _truncate(", ".join(sorted(e.updates)) or "-", list_width),
                _download_label(e),
            ]
            rows.append(row)
        size_col = headers.index("SIZE")
        print(_render_table(headers, rows, show_header=not args.no_header, right_align=(size_col,)))

    shown = len(sel.entries)
    matching = _plural(sel.matched, "matching entry", "matching entries")
    summary = matching if shown == sel.matched else f"showing {shown} of {matching}"
    downloadable = sum(e.has_binary_download for e in sel.entries)
    _note(f"{summary} ({downloadable} downloadable)")
    return EXIT_NO_MATCH if sel.missing else EXIT_OK


# ======================================================================
# url
# ======================================================================
def cmd_url(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``url`` subcommand."""
    if args.downloadable is None:
        # As in `download`: --latest / --limit must choose among entries that have a URL.
        args.downloadable = True
    sel = _select(client, args)
    stop = _report_selection_problems(sel)
    if stop is not None:
        return stop

    printed: list[dict[str, Any]] = []
    skipped = 0
    for e in sel.entries:
        if not e.has_binary_download:  # only with --no-downloadable
            skipped += 1
            continue
        url = e.binary_url(base_url=client.symbol_server_url)
        printed.append(
            {
                "filename": e.filename,
                "sha256": e.sha256,
                "version": e.version,
                "machine": e.machine_name,
                "url": url,
            }
        )

    if args.json:
        _print_json(printed)
    else:
        for item in printed:
            print(item["url"])

    if skipped:
        _note(f"skipped {_plural(skipped, 'entry', 'entries')} without download metadata")
    if not printed:
        return EXIT_NO_MATCH
    return EXIT_NO_MATCH if sel.missing else EXIT_OK


# ======================================================================
# download
# ======================================================================
class _Progress:
    """Single-line, in-place progress on a TTY; silent otherwise."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._prefix = ""
        self._width = 0
        self._started = 0.0

    def start(self, prefix: str) -> None:
        self._prefix = prefix
        self._started = time.monotonic()
        if self.enabled:
            self._write(prefix)

    def update(self, done: int, total: int | None) -> None:
        if not self.enabled:
            return
        if total:
            pct = 100.0 * done / total
            self._write(f"{self._prefix}  {_human_size(done)} / {_human_size(total)}  {pct:5.1f}%")
        else:
            self._write(f"{self._prefix}  {_human_size(done)}")

    def finish(self) -> float:
        """Clear the progress line; returns elapsed seconds."""
        if self.enabled and self._width:
            sys.stderr.write("\r" + " " * self._width + "\r")
            sys.stderr.flush()
            self._width = 0
        return time.monotonic() - self._started

    def _write(self, text: str) -> None:
        # A line wider than the terminal wraps, and "\r" can then no longer erase it.
        text = _truncate(text, shutil.get_terminal_size().columns - 1)
        padded = text.ljust(self._width)
        self._width = max(self._width, len(text))
        sys.stderr.write("\r" + padded)
        sys.stderr.flush()


@dataclass
class _DownloadResult:
    entry: FileEntry
    status: str  # ok | exists | failed | dry-run
    path: Path | None = None
    bytes: int = 0
    seconds: float = 0.0
    error: str | None = None
    pdb_status: str | None = None  # ok | exists | unavailable | failed | None
    pdb_path: Path | None = None
    pdb_bytes: int = 0
    pdb_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "filename": self.entry.filename,
            "sha256": self.entry.sha256,
            "version": self.entry.version,
            "machine": self.entry.machine_name,
            "status": self.status,
            "path": str(self.path) if self.path else None,
            "bytes": self.bytes,
            "error": self.error,
        }
        if self.pdb_status is not None:
            d["pdb"] = {
                "status": self.pdb_status,
                "path": str(self.pdb_path) if self.pdb_path else None,
                "bytes": self.pdb_bytes,
                "error": self.pdb_error,
            }
        return d


def _plan_targets(entries: list[FileEntry], dest: Path, layout: str) -> dict[str, Path]:
    """Map sha256 -> directory the entry's files go into."""
    if layout == "sha":
        return {e.sha256: dest / e.sha256[:16] for e in entries}
    if layout == "flat":
        names = Counter(e.filename for e in entries)
        dupes = sorted(n for n, c in names.items() if c > 1)
        if dupes:
            raise WinbindexError(
                f"--layout flat needs unique filenames but {len(entries)} entries were selected "
                f"({', '.join(dupes)} more than once); narrow the query, e.g. with --limit 1 "
                "or --latest --machine x64."
            )
        return {e.sha256: dest for e in entries}
    # version layout: <dest>/<filename>/<version>-<arch>[/<sha8> on collision]
    base = {e.sha256: dest / e.filename / _version_dir(e) for e in entries}
    counts = Counter(base.values())
    return {sha: (p / f"{sha[:8]}" if counts[p] > 1 else p) for sha, p in base.items()}


def _version_dir(entry: FileEntry) -> str:
    """``<version>-<arch>``, made safe to use as a directory name on any OS."""
    arch = entry.machine_name if entry.file_info.machine_type is not None else "unknown"
    name = f"{entry.short_version or 'unknown'}-{arch}"
    # Version strings come from the binary's resources and may contain anything.
    return "".join("_" if ch in _INVALID_FILENAME_CHARS else ch for ch in name).rstrip(" .") or "unknown"


def _short_error(err: Exception) -> str:
    if isinstance(err, DownloadError):
        return err.message
    return str(err) or type(err).__name__


def _differs_from(path: Path, entry: FileEntry) -> str | None:
    """Say why the file at ``path`` is not ``entry``'s build, or return ``None`` if it is.

    The symbol server identifies a binary by its PE timestamp and image size,
    and its copy's SHA256 often differs from the one in the index, so the
    header, not the hash, tells whether an existing file is the right build.
    """
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except OSError as err:
        return f"unreadable ({err.strerror or err})"
    except Exception:  # pefile.PEFormatError, or anything else a non-PE file triggers
        return "not a PE file"
    try:
        # pefile declares these headers optional and fills their fields in at runtime.
        found = (
            getattr(pe.FILE_HEADER, "TimeDateStamp", None),
            getattr(pe.OPTIONAL_HEADER, "SizeOfImage", None),
        )
    finally:
        pe.close()
    if found != (entry.file_info.timestamp, entry.file_info.virtual_size):
        return "a different build"
    return None


def _precheck(entry: FileEntry, target: Path, *, overwrite: bool) -> _DownloadResult | None:
    """Settle ``entry`` without the network when possible (failed / exists); ``None`` means download it."""

    def failed(error: str) -> _DownloadResult:
        return _DownloadResult(entry=entry, status="failed", path=target, error=error)

    if not entry.has_binary_download:
        return failed("no download metadata in the index (PE timestamp and image size unknown)")
    if target.is_dir():
        return failed(f"destination {target} is a directory (mixed --layout in the same directory?)")
    if target.exists() and not overwrite:
        problem = _differs_from(target, entry)
        if problem is not None:
            return failed(f"{target} already exists but is {problem}; use --overwrite to replace it")
        return _DownloadResult(entry=entry, status="exists", path=target, bytes=target.stat().st_size)
    return None


def _download_one(
    client: WinbindexClient,
    entry: FileEntry,
    target_dir: Path,
    args: argparse.Namespace,
    progress: _Progress,
) -> _DownloadResult:
    target = target_dir / entry.filename
    result = _precheck(entry, target, overwrite=args.overwrite)
    if result is None:
        result = _DownloadResult(entry=entry, status="ok", path=target)
        try:
            client.download_binary(entry, target, overwrite=args.overwrite, progress=progress.update)
            result.bytes = target.stat().st_size
        except (DownloadError, OSError) as err:
            result.status = "failed"
            result.error = _short_error(err)
            logger.debug("download of %s failed: %s", entry.sha256, err)
    result.seconds = progress.finish()

    if not args.pdb:
        return result

    # ---- PDB: always read from the binary's debug directory; the index rarely has it.
    if result.status == "failed":
        result.pdb_status = "unavailable"
        result.pdb_error = "binary not downloaded"
        return result
    try:
        pdb_info = extract_pdb_info(target)
    except MissingPdbInfoError:
        result.pdb_status = "unavailable"
        result.pdb_error = "no PDB record in binary"
        return result
    except Exception as err:  # pefile.PEFormatError, OSError, ...
        result.pdb_status = "failed"
        result.pdb_error = f"could not parse binary: {_short_error(err)}"
        return result

    pdb_target = target_dir / pdb_info.name
    result.pdb_path = pdb_target
    if pdb_target.exists() and not args.overwrite:
        result.pdb_status = "exists"
        result.pdb_bytes = pdb_target.stat().st_size
        return result

    progress.start(f"      + {pdb_info.name}")
    try:
        client.download_pdb(pdb_info, pdb_target, overwrite=args.overwrite, progress=progress.update)
        result.pdb_status = "ok"
        result.pdb_bytes = pdb_target.stat().st_size
    except DownloadError as err:
        if err.status_code == 404:
            result.pdb_status = "unavailable"
            result.pdb_error = "not on the symbol server"
        else:
            result.pdb_status = "failed"
            result.pdb_error = _short_error(err)
    except OSError as err:
        result.pdb_status = "failed"
        result.pdb_error = _short_error(err)
    finally:
        progress.finish()
    return result


def cmd_download(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``download`` subcommand."""
    if args.downloadable is None:
        args.downloadable = True  # metadata-only entries can never be downloaded
    sel = _select(client, args)
    stop = _report_selection_problems(sel)
    if stop is not None:
        return stop

    dest = Path(args.dest).expanduser()
    targets = _plan_targets(sel.entries, dest, args.layout)
    total = len(sel.entries)
    width = len(str(total))
    pad = " " * (width * 2 + 3)
    # With -v, log lines would land in the middle of the in-place progress line.
    interactive = sys.stderr.isatty() and not args.json and not args.verbose
    progress = _Progress(enabled=interactive)
    results: list[_DownloadResult] = []
    started = time.monotonic()

    def label(i: int, e: FileEntry) -> str:
        return f"[{i:>{width}}/{total}] {e.filename} {e.short_version or '?'} {e.machine_name}"

    if args.dry_run:
        return _dry_run(client, sel, targets, args, label, pad)

    for i, e in enumerate(sel.entries, 1):
        prefix = label(i, e)
        progress.start(prefix)
        r = _download_one(client, e, targets[e.sha256], args, progress)
        results.append(r)
        if args.json:
            continue
        if r.status == "ok":
            print(f"{prefix}  {_human_size(r.bytes):>9}  ok  -> {r.path}")
        elif r.status == "exists":
            print(f"{prefix}  {_human_size(r.bytes):>9}  exists (skipped)  {r.path}")
        else:
            print(f"{prefix}  FAILED: {r.error}")
        if r.pdb_status is not None:
            name = r.pdb_path.name if r.pdb_path else "pdb"
            if r.pdb_status == "ok":
                print(f"{pad} + {name}  {_human_size(r.pdb_bytes):>9}  ok  -> {r.pdb_path}")
            elif r.pdb_status == "exists":
                print(f"{pad} + {name}  {_human_size(r.pdb_bytes):>9}  exists (skipped)")
            elif r.pdb_status == "unavailable":
                print(f"{pad} + pdb: unavailable ({r.pdb_error})")
            else:
                print(f"{pad} + pdb: FAILED: {r.pdb_error}")

    elapsed = time.monotonic() - started
    counts = Counter(r.status for r in results)
    downloaded_bytes = sum(r.bytes for r in results if r.status == "ok") + sum(
        r.pdb_bytes for r in results if r.pdb_status == "ok"
    )
    if args.json:
        _print_json([r.to_dict() for r in results])
    else:
        summary = (
            f"Done: {counts['ok']} downloaded, {counts['exists']} skipped (exist), "
            f"{counts['failed']} failed · {_human_size(downloaded_bytes)} in {elapsed:.1f}s · {dest}"
        )
        _note(summary)
        if args.pdb:
            pc = Counter(r.pdb_status for r in results if r.pdb_status)
            _note(
                f"PDBs: {pc['ok']} downloaded, {pc['exists']} skipped (exist), "
                f"{pc['unavailable']} unavailable, {pc['failed']} failed"
            )

    failed = counts["failed"] + sum(r.pdb_status == "failed" for r in results)
    return EXIT_NO_MATCH if (failed or sel.missing) else EXIT_OK


def _dry_run(
    client: WinbindexClient,
    sel: Selection,
    targets: dict[str, Path],
    args: argparse.Namespace,
    label: Callable[[int, FileEntry], str],
    pad: str,
) -> int:
    """Report what ``download`` would do, using the same checks as a real run, without writing."""
    results: list[_DownloadResult] = []
    for i, e in enumerate(sel.entries, 1):
        path = targets[e.sha256] / e.filename
        r = _precheck(e, path, overwrite=args.overwrite) or _DownloadResult(
            entry=e, status="dry-run", path=path, bytes=e.file_info.size or 0
        )
        results.append(r)
        if args.json:
            continue
        if r.status == "dry-run":
            replaces = "  (replaces the existing file)" if path.exists() else ""
            print(f"{label(i, e)}  {_human_size(r.bytes):>9}  -> {path}{replaces}")
            print(f"{pad} {e.binary_url(base_url=client.symbol_server_url)}")
        elif r.status == "exists":
            print(f"{label(i, e)}  {_human_size(r.bytes):>9}  exists (would skip)  {path}")
        else:
            print(f"{label(i, e)}  would FAIL: {r.error}")
        if args.pdb and r.status != "failed":
            print(f"{pad} + pdb: read from the binary after download")

    todo = [r for r in results if r.status == "dry-run"]
    present = sum(r.status == "exists" for r in results)
    failing = sum(r.status == "failed" for r in results)
    if args.json:
        _print_json([r.to_dict() for r in results])
    else:
        parts = [f"{_plural(len(todo), 'file')} to download ({_human_size(sum(r.bytes for r in todo))})"]
        if present:
            parts.append(f"{present} already present")
        if failing:
            parts.append(f"{failing} would fail")
        _note(f"dry run: {', '.join(parts)}; nothing written")
    return EXIT_NO_MATCH if (failing or sel.missing) else EXIT_OK


# ======================================================================
# Argument parsing
# ======================================================================
def _machine_arg(value: str) -> int:
    try:
        return parse_machine_type(value)
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err)) from None


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _non_negative_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _non_negative_float(value: str) -> float:
    try:
        x = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from None
    if not x >= 0:  # also rejects NaN
        raise argparse.ArgumentTypeError("must be >= 0")
    return x


def _positive_float(value: str) -> float:
    x = _non_negative_float(value)
    if x == 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return x


def _add_global_args(parser: argparse.ArgumentParser, *, on_subcommand: bool) -> None:
    """Register the global options.

    They are added to the top-level parser with real defaults and to
    every subparser with ``SUPPRESS`` defaults, so that they can be
    written on either side of the subcommand without the subparser's
    defaults clobbering values parsed at the top level.
    """

    def d(default: Any) -> Any:
        return argparse.SUPPRESS if on_subcommand else default

    g = parser.add_argument_group("global options (accepted before or after the subcommand)")
    g.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=d(None),
        help=f"Where to cache fetched metadata (default: {default_cache_dir()}; env WINBINDEX_CACHE_DIR).",
    )
    g.add_argument("--no-cache", action="store_true", default=d(False), help="Do not read or write the cache.")
    g.add_argument(
        "--refresh",
        action="store_true",
        default=d(False),
        help="Ignore cached metadata and fetch it again.",
    )
    g.add_argument(
        "--cache-ttl",
        type=_non_negative_float,
        metavar="SECONDS",
        default=d(DEFAULT_CACHE_TTL),
        help=f"Refetch cached metadata older than this (default: {DEFAULT_CACHE_TTL}; 0 = always).",
    )
    g.add_argument("--base-url", metavar="URL", default=d(None), help="Winbindex data mirror to query.")
    g.add_argument(
        "--symbol-server",
        metavar="URL",
        default=d(DEFAULT_SYMBOL_SERVER_URL),
        help=f"Symbol server to download from (default: {DEFAULT_SYMBOL_SERVER_URL}).",
    )
    g.add_argument(
        "--timeout",
        type=_positive_float,
        metavar="SECONDS",
        default=d(30.0),
        help="HTTP timeout per request (default: 30).",
    )
    g.add_argument(
        "--retries",
        type=_non_negative_int,
        metavar="N",
        default=d(3),
        help="Retries on transient HTTP errors (default: 3).",
    )
    g.add_argument("--json", action="store_true", default=d(False), help="Machine-readable JSON output on stdout.")
    g.add_argument(
        "-v",
        "--verbose",
        action="count",
        # argparse parses the part after the subcommand into a fresh namespace, so
        # a shared dest would restart the count there; main() adds the two up.
        dest="verbose_after_command" if on_subcommand else "verbose",
        default=d(0),
        help="Show what is happening (-v) or full HTTP debug output (-vv).",
    )


def _add_filter_args(parser: argparse.ArgumentParser, *, selection: bool = True) -> None:
    parser.add_argument(
        "filenames",
        nargs="+",
        metavar="FILENAME",
        help="Windows binary filename(s), e.g. kernel32.dll ntoskrnl.exe",
    )
    f = parser.add_argument_group("filters (all optional, combined with AND)")
    f.add_argument(
        "--sha256",
        metavar="HASH",
        help="SHA256 hash, or a prefix of one (every entry starting with it matches).",
    )
    f.add_argument(
        "--file-version",
        dest="file_version",
        metavar="PATTERN",
        help="File version wildcard, e.g. '10.0.22621.*' (matches the full version string).",
    )
    f.add_argument(
        "--windows-version",
        dest="windows_version",
        metavar="VERSION",
        help="Windows release, e.g. 11-22H2, 1809, insider-canary (see `info`).",
    )
    f.add_argument("--update", metavar="KB", help="Update identifier, e.g. KB5023778 or BASE.")
    f.add_argument(
        "--machine",
        metavar="ARCH",
        type=_machine_arg,
        help="Architecture: x64, x86, arm64, arm (or a numeric PE machine type such as 0x8664).",
    )
    f.add_argument(
        "--signed",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Only signed (or, with --no-signed, only unsigned) binaries.",
    )
    f.add_argument(
        "--downloadable",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Only entries with enough metadata to build a binary URL.",
    )
    if not selection:
        return
    s = parser.add_argument_group("selection")
    s.add_argument(
        "--sort",
        choices=_SORT_CHOICES,
        default="version",
        help="Sort order (default: version; 'none' keeps index order).",
    )
    s.add_argument("--reverse", action="store_true", help="Reverse the sort order.")
    s.add_argument(
        "--latest",
        action="store_true",
        help="Keep only the newest file version per architecture (combine with --machine for one).",
    )
    s.add_argument("--limit", type=_positive_int, metavar="N", help="Keep at most N entries per filename.")


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level :class:`argparse.ArgumentParser`."""
    parser = argparse.ArgumentParser(
        prog="winbindex",
        description="Query the Winbindex service and download Windows binaries / PDBs.",
        epilog=(
            "examples:\n"
            "  winbindex info ntoskrnl.exe\n"
            "  winbindex list kernel32.dll --windows-version 11-22H2 --machine x64\n"
            "  winbindex url ntdll.dll --file-version '10.0.22621.*' --latest\n"
            "  winbindex download kernel32.dll --latest --machine x64 --pdb -o ./out"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_global_args(parser, on_subcommand=False)

    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    p_info = sub.add_parser(
        "info",
        help="Summarise what the index knows about a file.",
        description="Summarise what the index knows about a file: counts, architectures, "
        "version and date ranges, and the Windows releases it ships in. With --json, "
        "prints one object for a single filename and a list for several.",
    )
    _add_filter_args(p_info, selection=False)
    _add_global_args(p_info, on_subcommand=True)
    p_info.set_defaults(func=cmd_info)

    p_list = sub.add_parser(
        "list",
        help="List matching versions of a file.",
        description="List matching versions of a file as a table (or JSON with --json).",
    )
    _add_filter_args(p_list)
    o = p_list.add_argument_group("output")
    o.add_argument("--full-version", action="store_true", help="Show the full version string incl. build tag.")
    o.add_argument("--wide", action="store_true", help="Do not truncate the WINDOWS / UPDATES columns.")
    o.add_argument("--no-header", action="store_true", help="Omit the header row.")
    o.add_argument("-q", "--quiet", action="store_true", help="Print only full SHA256 hashes, one per line.")
    _add_global_args(p_list, on_subcommand=True)
    p_list.set_defaults(func=cmd_list)

    p_url = sub.add_parser(
        "url",
        help="Print symbol-server URLs for matching entries.",
        description="Print the symbol-server URL of each matching binary, one per line. "
        "PDB locations are only known after downloading a binary: use `download --pdb`.",
    )
    _add_filter_args(p_url)
    _add_global_args(p_url, on_subcommand=True)
    p_url.set_defaults(func=cmd_url)

    p_dl = sub.add_parser(
        "download",
        help="Download matching binaries (and optionally PDBs).",
        description="Download matching binaries. Entries without download metadata are skipped "
        "automatically. Files that already exist are left alone unless --overwrite is given.",
    )
    _add_filter_args(p_dl)
    o = p_dl.add_argument_group("output")
    o.add_argument("-o", "--dest", default="winbindex-downloads", metavar="DIR", help="Destination directory.")
    o.add_argument(
        "--layout",
        choices=_LAYOUT_CHOICES,
        default="sha",
        help="Directory layout under DIR: sha = <sha256[:16]>/ (default), "
        "version = <filename>/<version>-<arch>/, flat = files directly in DIR.",
    )
    o.add_argument(
        "--pdb",
        action="store_true",
        help="Also fetch each binary's PDB, located by parsing the downloaded binary's debug directory.",
    )
    o.add_argument("--overwrite", action="store_true", help="Replace files that already exist.")
    o.add_argument("--dry-run", action="store_true", help="Show what would be downloaded and where.")
    _add_global_args(p_dl, on_subcommand=True)
    p_dl.set_defaults(func=cmd_download)

    return parser


def _configure_logging(verbosity: int) -> None:
    if verbosity >= 2:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif verbosity == 1:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
        logging.getLogger("winbindex").setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def _make_client(args: argparse.Namespace) -> WinbindexClient:
    cache_dir: Path | None = None
    cache_ttl: float | None = None
    if not args.no_cache:
        cache_dir = Path(args.cache_dir).expanduser() if args.cache_dir else default_cache_dir()
        cache_ttl = 0.0 if args.refresh else args.cache_ttl
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as err:
            _warn(f"cannot use cache directory {cache_dir} ({err.strerror}); continuing without cache")
            cache_dir = None
    logger.info("cache: %s", cache_dir or "disabled")

    kwargs: dict[str, Any] = {
        "symbol_server_url": args.symbol_server,
        "cache_dir": cache_dir,
        "cache_ttl": cache_ttl,
        "timeout": args.timeout,
        "max_retries": args.retries,
    }
    if args.base_url:
        kwargs["base_url"] = args.base_url
    return WinbindexClient(**kwargs)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.verbose += getattr(args, "verbose_after_command", 0)
    _configure_logging(args.verbose)

    try:
        with _make_client(args) as client:
            return int(args.func(client, args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # Reader went away (e.g. `| head`); avoid a noisy traceback at exit.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_OK
    except (WinbindexError, ValueError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        logger.debug("fatal error", exc_info=True)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
