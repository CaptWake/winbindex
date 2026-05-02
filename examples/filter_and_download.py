"""Filter Winbindex entries and download the matching binaries.

Download every signed amd64 build of ``kernel32.dll`` that ships in
Windows 11 22H2.
"""

from __future__ import annotations

import sys
from pathlib import Path

from winbindex import WinbindexClient


def progress(done: int, total: int | None) -> None:
    if total is None:
        sys.stderr.write(f"\r    {done:,} bytes")
    else:
        pct = 100.0 * done / total if total else 0.0
        sys.stderr.write(f"\r    {done:,}/{total:,} bytes ({pct:5.1f}%)")
    sys.stderr.flush()


def main() -> None:
    dest = Path("./downloads/kernel32-amd64-22H2")
    dest.mkdir(parents=True, exist_ok=True)

    with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
        entries = list(
            client.find(
                "kernel32.dll",
                windows_version="11-22H2",
                machine_type=0x8664,  # AMD64
                signed=True,
                downloadable=True,
            )
        )

        print(f"Selected {len(entries)} matching kernel32.dll versions.\n")

        for entry in entries:
            print(f"[{entry.sha256[:12]}] {entry.version}")
            try:
                path = client.download_binary(
                    entry,
                    dest,
                    overwrite=False,
                    progress=progress,
                )
            except FileExistsError as err:
                print(f"  -> already on disk: {err}")
                continue
            print(f"\n  -> wrote {path}")


if __name__ == "__main__":
    main()
