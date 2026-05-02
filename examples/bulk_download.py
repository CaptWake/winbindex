"""Bulk-download all binaries shipped with a specific Windows update.

This script collects every ``.dll`` / ``.exe`` / ``.sys`` from Winbindex
that is part of a given KB update and downloads each one in parallel.
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from winbindex import FileEntry, WinbindexClient, FileNotIndexedError

# Hand-curated short-list of common system files. In a real-world tool
# you'd discover the file list from a manifest or from a directory of
# extracted update payloads.
DEFAULT_FILES = [
    "kernel32.dll",
    "ntdll.dll",
    "ntoskrnl.exe",
    "user32.dll",
    "kernelbase.dll",
    "advapi32.dll",
    "ci.dll",
    "win32k.sys",
]


def _select(client: WinbindexClient, filename: str, kb: str) -> list[FileEntry]:
    try:
        return list(client.find(filename, update=kb, downloadable=True))
    except FileNotIndexedError:
        print(f"[skip] {filename}: not indexed", file=sys.stderr)
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb", required=True, help="KB / update identifier (e.g. KB5023778).")
    parser.add_argument("-o", "--dest", default="bulk-downloads", help="Output directory.")
    parser.add_argument(
        "--files",
        nargs="+",
        default=DEFAULT_FILES,
        help="List of filenames to download.",
    )
    parser.add_argument("--with-pdb", action="store_true", help="Also download PDBs.")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    dest = Path(args.dest).expanduser()
    dest.mkdir(parents=True, exist_ok=True)

    with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
        all_entries: list[FileEntry] = []
        for fname in args.files:
            all_entries.extend(_select(client, fname, args.kb))

        print(f"Downloading {len(all_entries)} files ...")

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(
                    client.download_many,
                    [entry],
                    dest,
                    include_pdb=args.with_pdb,
                    overwrite=False,
                ): entry
                for entry in all_entries
            }
            for f in as_completed(futures):
                entry = futures[f]
                try:
                    written = f.result()
                except FileExistsError:
                    print(f"  [skip] {entry.filename} {entry.version} (exists)")
                except Exception as err:
                    print(f"  [fail] {entry.filename} {entry.version}: {err}")
                else:
                    for p in written:
                        print(f"  [ok ] {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
