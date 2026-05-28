# winbindex
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/packmad/StatisticsForScientists/publish.yml) [![License: MIT](https://img.shields.io/badge/License-GPLv3-green.svg)](https://opensource.org/licenses/GPLv3)


A modular python client for the
[Winbindex](https://winbindex.m417z.com/) service - the open index of
Windows binaries (`.exe`, `.dll`, `.sys`, etc.) that exposes the metadata
required to download those binaries (and their PDB symbols) directly
from the Microsoft public symbol server (`msdl.microsoft.com`).

## Features

- **Flexible queries** - filter on file version, Windows version, KB
  number, PE machine type, signing status, downloadability, and
  arbitrary user predicates.
- **Streamed downloads** of binaries and PDBs from
  `msdl.microsoft.com`, with progress callbacks and retry on transient HTTP errors.
- **Persistent on-disk cache** with optional TTL.
- **CLI** for quick interactive use and shell scripting.

## Installation

```bash
pip install winbindex
```

## Quick start

```python
from winbindex import WinbindexClient

with WinbindexClient(cache_dir="~/.cache/winbindex") as client:
    # Iterate over every signed amd64 build of kernel32.dll
    # that ships in Windows 11 22H2.
    for entry in client.find(
        "kernel32.dll",
        windows_version="11-22H2",
        machine_type=0x8664,
        signed=True,
        downloadable=True,
    ):
        print(entry.version, entry.binary_url())
        client.download_binary(entry, "downloads/")
        if entry.has_pdb_download:
            client.download_pdb(entry, "downloads/")
```

### Filter API

`WinbindexClient.find(filename, **filters)` returns an iterator of
`FileEntry` objects matching every filter that is set. All filters are
optional and are combined with logical AND:

| Filter | Type | Description |
|---|---|---|
| `sha256` | `str` | Exact SHA256 (case-insensitive). |
| `version` | `str` | Wildcard pattern matched against `entry.version` (`*` and `?`). |
| `windows_version` | `str` | E.g. `"11-22H2"`, `"1809"`, `"insider-canary"`. |
| `update` | `str` | KB identifier or `"BASE"`. |
| `machine_type` | `int` | PE `Machine` field — `0x8664` (x64), `0x14C` (x86), `0xAA64` (ARM64). |
| `signed` | `bool` | Authenticode signing status. |
| `downloadable` | `bool` | Has both `timestamp` and `virtualSize`. |
| `with_pdb` | `bool` | Has PDB metadata in the index. |
| `predicate` | `Callable[[FileEntry], bool]` | Arbitrary user predicate. |

### Downloading PDBs when the index doesn't have them

About 80% of the indexed files don't carry a PDB triple. The recovery
path is to download the binary, then read the PDB info out of the PE's
`IMAGE_DEBUG_TYPE_CODEVIEW` debug record:

```python
from winbindex import WinbindexClient, extract_pdb_info

with WinbindexClient() as client:
    entry = next(client.find("kernel32.dll", version="10.0.22621.*"))
    binary = client.download_binary(entry, "downloads/")

    if not entry.has_pdb_download:
        pdb_info = extract_pdb_info(binary)
        client.download_pdb(pdb_info, "downloads/")
```

## CLI

```bash
$ winbindex list ntoskrnl.exe --windows-version 11-22H2 --signed
abb30adf05bd71ae   10.0.22621.1485 (WinBuild.160101.0800)   bin/pdb        11-22H2
...

$ winbindex url kernel32.dll --version "10.0.22621.*"        # binary URL
$ winbindex url kernel32.dll --version "10.0.22621.*" --pdb  # PDB URL

$ winbindex download kernel32.dll \
        --windows-version 11-22H2 --signed --machine 0x8664 \
        --with-pdb-download -o ./out
```

Run `winbindex --help` for the full reference.

## Caching

Pass `cache_dir=` to persist the gzipped JSON between runs. Use
`cache_ttl=` (seconds) to require periodic refresh. Cached files are
re-validated transparently on each call.

```python
client = WinbindexClient(
    cache_dir="~/.cache/winbindex",
    cache_ttl=24 * 3600,   # one day
)
```

## Configuration knobs

```python
WinbindexClient(
    base_url="https://winbindex.m417z.com/data",   # mirror? override here
    symbol_server_url="https://msdl.microsoft.com/download/symbols",
    cache_dir=None,
    cache_ttl=None,
    timeout=30.0,
    max_retries=3,
    user_agent="my-tool/1.0",
    session=my_requests_session,                    # bring your own
)
```

## Development
See [doc/development.md](doc/development.md) for setup, linting, testing, and release instructions.

## How it works

Winbindex publishes a [gzipped JSON
file](https://winbindex.m417z.com/data/by_filename_compressed/kernel32.dll.json.gz)
per filename. The top-level keys are SHA256 hashes; each value contains
a `fileInfo` block (PE timestamp, image size, version, hashes) and a
`windowsVersions` block describing every Windows release / KB the file
appears in. Some entries also carry a `pdb` triple
(`name` / `guid` / `age`).

The Microsoft symbol server indexes each file at a path of the form
`/<filename>/<index>/<filename>`, where:

- For binaries, `<index>` = `TimeDateStamp` (8 uppercase hex digits) +
  `SizeOfImage` (lowercase hex, no padding).
- For PDBs, `<index>` = 32-char uppercase GUID + uppercase hex age.

The library glue those two together and download the result.

## Related projects

- [Winbindex](https://github.com/m417z/winbindex) - the web service providing the binaries indexed.
- [pdbfetch](https://github.com/ajkhoury/pdbfetch) - Go tool that fetches PDBs from a local PE file

## License

GPL-3.0-or-later, matching upstream Winbindex.

This package is not affiliated with or endorsed by Microsoft or the
authors of Winbindex; it is a third-party client built on top of the
service's public data.
