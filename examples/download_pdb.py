"""Download a binary together with its PDB file.

Two strategies are demonstrated:

1. PDB metadata is present in the Winbindex JSON — use
   :meth:`WinbindexClient.download_pdb` directly with the entry.
2. PDB metadata is missing from the index — download the binary first,
   then read the PDB triple from the PE's debug directory using
   :func:`winbindex.extract_pdb_info` (requires the ``pdb`` extra).
"""

from __future__ import annotations

from pathlib import Path

from winbindex import WinbindexClient


def main() -> None:
    dest = Path("./downloads/symbols")
    dest.mkdir(parents=True, exist_ok=True)

    with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
        # Pick the most recent signed amd64 ntoskrnl.exe.
        entries = list(
            client.find(
                "ntoskrnl.exe",
                machine_type=0x8664,
                signed=True,
                downloadable=True,
            )
        )
        if not entries:
            print("No matching entries.")
            return
        entries.sort(key=lambda e: e.version or "", reverse=True)
        entry = entries[0]
        print(f"Selected {entry.version} (sha256={entry.sha256[:12]}...)")

        # 1. Download the binary.
        binary_path = client.download_binary(entry, dest, overwrite=True)
        print(f"  binary -> {binary_path}")

        # 2a. Easy path: PDB metadata is in the index.
        if entry.has_pdb_download:
            pdb_path = client.download_pdb(entry, dest, overwrite=True)
            print(f"  pdb    -> {pdb_path}")
            return

        # 2b. Fallback: parse the PE's debug directory.
        try:
            from winbindex import extract_pdb_info
        except ImportError:
            print("Install with `pip install winbindex[pdb]` to extract PDB info.")
            return

        pdb_info = extract_pdb_info(binary_path)
        print(
            f"  pdb info from binary: name={pdb_info.name} guid={pdb_info.guid} age={pdb_info.age}"
        )
        pdb_path = client.download_pdb(pdb_info, dest, overwrite=True)
        print(f"  pdb    -> {pdb_path}")


if __name__ == "__main__":
    main()
