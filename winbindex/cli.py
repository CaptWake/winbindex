"""Small command-line front-end for :mod:`winbindex`.

Subcommands:

* ``list``      - print all known versions of a file
* ``url``       - print the binary / PDB URL for a specific entry
* ``download``  - download binaries (and optionally PDBs) matching a query

The CLI is intentionally minimal - it is a thin shell around
:class:`~winbindex.client.WinbindexClient` for quick interactive use
and shell scripting. For anything beyond that, use the Python API.
"""

from __future__ import annotations

import sys
import json
import logging
import argparse
from pathlib import Path

from .client import WinbindexClient
from .models import FileEntry
from .exceptions import WinbindexError

logger = logging.getLogger("winbindex.cli")


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    """Register the standard ``--version`` / ``--windows-version`` … flags."""
    parser.add_argument("filename", help="Windows binary filename, e.g. kernel32.dll")
    parser.add_argument("--sha256", help="Match a specific SHA256 hash.")
    parser.add_argument(
        "--version",
        help="Wildcard pattern matched against the file version (e.g. '10.0.22621.*').",
    )
    parser.add_argument(
        "--windows-version",
        dest="windows_version",
        help="Match a Windows version (e.g. '11-22H2', '1809').",
    )
    parser.add_argument("--update", help="Match a KB / update identifier (e.g. KB5023778, BASE).")
    parser.add_argument(
        "--machine",
        type=lambda s: int(s, 0),
        help="Match the PE machine type (decimal or 0x... hex).",
    )
    parser.add_argument(
        "--signed",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Filter on Authenticode signing status.",
    )
    parser.add_argument(
        "--downloadable",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Only show entries with enough metadata to build a binary URL.",
    )
    parser.add_argument(
        "--with-pdb",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Only show entries that include PDB metadata.",
    )


def _matching_entries(client: WinbindexClient, args: argparse.Namespace) -> list[FileEntry]:
    return list(
        client.find(
            args.filename,
            sha256=args.sha256,
            version=args.version,
            windows_version=args.windows_version,
            update=args.update,
            machine_type=args.machine,
            signed=args.signed,
            downloadable=args.downloadable,
            with_pdb=args.with_pdb,
        )
    )


def cmd_list(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``list`` subcommand."""
    entries = _matching_entries(client, args)
    if not entries:
        print("No matching entries.", file=sys.stderr)
        return 1

    if args.json:
        out = [
            {
                "sha256": e.sha256,
                "version": e.version,
                "machineType": e.file_info.machine_type,
                "size": e.file_info.size,
                "timestamp": e.file_info.timestamp,
                "virtualSize": e.file_info.virtual_size,
                "windowsVersions": sorted(e.windows_versions),
                "updates": sorted(e.updates),
                "binaryUrl": e.binary_url() if e.has_binary_download else None,
                "pdbUrl": e.pdb_url() if e.has_pdb_download else None,
            }
            for e in entries
        ]
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    for entry in entries:
        flags = []
        if entry.has_binary_download:
            flags.append("bin")
        if entry.has_pdb_download:
            flags.append("pdb")
        flags_str = "/".join(flags) or "metadata-only"
        print(
            f"{entry.sha256[:16]}  "
            f"{(entry.version or '<no version>')[:40]:<40}  "
            f"{flags_str:<14}  "
            f"{','.join(sorted(entry.windows_versions))}"
        )
    return 0


def cmd_url(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``url`` subcommand."""
    entries = _matching_entries(client, args)
    if not entries:
        print("No matching entries.", file=sys.stderr)
        return 1

    for entry in entries:
        if args.pdb:
            if not entry.has_pdb_download:
                continue
            print(entry.pdb_url())
        else:
            if not entry.has_binary_download:
                continue
            print(entry.binary_url())
    return 0


def cmd_download(client: WinbindexClient, args: argparse.Namespace) -> int:
    """Implement the ``download`` subcommand."""
    entries = _matching_entries(client, args)
    if not entries:
        print("No matching entries.", file=sys.stderr)
        return 1

    dest = Path(args.dest).expanduser()

    def progress(done: int, total: int | None) -> None:
        if total is None:
            sys.stderr.write(f"\r  {done:,} bytes")
        else:
            pct = 100.0 * done / total if total else 0.0
            sys.stderr.write(f"\r  {done:,}/{total:,} bytes ({pct:5.1f}%)")
        sys.stderr.flush()

    written = client.download_many(
        entries,
        dest,
        include_pdb=args.with_pdb_download,
        overwrite=args.overwrite,
        progress=progress if sys.stderr.isatty() else None,
        on_error=lambda e, err: print(f"\n[!] {e.sha256[:12]}: {err}", file=sys.stderr),
    )
    if sys.stderr.isatty():
        sys.stderr.write("\n")
    print(f"Wrote {len(written)} files under {dest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level :class:`argparse.ArgumentParser`."""
    parser = argparse.ArgumentParser(
        prog="winbindex",
        description="Query the Winbindex service and download Windows binaries / PDBs.",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Directory in which to cache fetched JSON files.",
    )
    parser.add_argument(
        "--cache-ttl",
        type=float,
        default=None,
        help="Cache TTL in seconds (default: never expire).",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds.")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List indexed versions of a file.")
    _add_filter_args(p_list)
    p_list.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    p_list.set_defaults(func=cmd_list)

    p_url = sub.add_parser("url", help="Print the symbol-server URL for matching entries.")
    _add_filter_args(p_url)
    p_url.add_argument(
        "--pdb", action="store_true", help="Print the PDB URL instead of the binary URL."
    )
    p_url.set_defaults(func=cmd_url)

    p_dl = sub.add_parser("download", help="Download matching binaries (and PDBs).")
    _add_filter_args(p_dl)
    p_dl.add_argument(
        "-o",
        "--dest",
        default="winbindex-downloads",
        help="Destination directory.",
    )
    p_dl.add_argument(
        "--with-pdb-download",
        action="store_true",
        help="Also fetch PDBs when metadata is available.",
    )
    p_dl.add_argument("--overwrite", action="store_true", help="Overwrite existing files.")
    p_dl.set_defaults(func=cmd_download)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    with WinbindexClient(
        cache_dir=args.cache_dir,
        cache_ttl=args.cache_ttl,
        timeout=args.timeout,
    ) as client:
        try:
            return int(args.func(client, args))
        except WinbindexError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
