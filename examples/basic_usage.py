"""Basic usage of the winbindex client.

List every indexed version of ``ntoskrnl.exe`` along with its download URL.
"""

from __future__ import annotations

from winbindex import WinbindexClient


def main() -> None:
    with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
        entries = client.get_file("ntoskrnl.exe")

        print(f"Found {len(entries)} indexed versions of ntoskrnl.exe\n")

        for entry in entries[:10]:  # show only the first 10
            print(f"  Version:  {entry.version}")
            print(f"  SHA256:   {entry.sha256}")
            print(f"  Size:     {entry.file_info.size} bytes")
            print(f"  Windows:  {', '.join(sorted(entry.windows_versions))}")
            if entry.has_binary_download:
                print(f"  Binary:   {entry.binary_url()}")
            else:
                print("  Binary:   (no download info available)")
            if entry.has_pdb_download:
                print(f"  PDB:      {entry.pdb_url()}")
            print()


if __name__ == "__main__":
    main()
