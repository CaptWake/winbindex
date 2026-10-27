# winbindex
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/CaptWake/winbindex/python-audit.yml) [![License: GPLv3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)


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
- **CLI** for quick interactive use and shell scripting, with a summary
  view, tabular / JSON output, and PDB extraction from downloaded binaries.

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
| `sha256` | `str` | Full SHA256 or a prefix of one (case-insensitive); every entry starting with it matches. |
| `version` | `str` | Wildcard pattern matched against `entry.version` (`*` and `?`). |
| `windows_version` | `str` | E.g. `"11-22H2"`, `"1809"`, `"insider-canary"` (case-insensitive). |
| `update` | `str` | KB identifier or `"BASE"` (case-insensitive). |
| `machine_type` | `int` | PE `Machine` field — `0x8664` (x64), `0x14C` (x86), `0xAA64` (ARM64); see `parse_machine_type("x64")`. |
| `signed` | `bool` | Authenticode signing status. |
| `downloadable` | `bool` | Has both `timestamp` and `virtualSize`. |
| `predicate` | `Callable[[FileEntry], bool]` | Any other condition; see below. |

The same filters are available as `winbindex.filter_entries(entries, ...)`
for entries you already hold. `FileEntry` also exposes `version_tuple`
(numeric, for sorting), `short_version`, `machine_name`, `is_signed` and
`release_date`.

### Custom conditions with `predicate`

`predicate` takes any function that receives a `FileEntry` and returns
`True` to keep it. It runs after the other filters, so it only sees
entries they already accepted.

`windows_version` matches one release exactly; a predicate can match a
whole family. Every x64 `ntdll.dll` that shipped in any Windows 11
release:

```python
from winbindex import WinbindexClient

with WinbindexClient() as client:
    for entry in client.find(
        "ntdll.dll",
        machine_type=0x8664,
        predicate=lambda e: any(v.startswith("11-") for v in e.windows_versions),
    ):
        print(entry.short_version, sorted(entry.windows_versions))
```

A predicate is also how you keep only the entries whose PDB details
(name, GUID and age) are in the index, so that `download_pdb()` can
fetch the PDB without downloading the binary first:

```python
with WinbindexClient() as client:
    for entry in client.find("ntdll.dll", predicate=lambda e: e.has_pdb_download):
        client.download_pdb(entry, "symbols/")
```

The current Winbindex data rarely has these details (none of the common
system binaries we checked do), so this usually finds nothing. Read the
PDB details from the binary instead, as shown next.

Predicates combine like any Python condition, for example
`lambda e: e.is_signed and (e.release_date or "") >= "2024-01-01"`.

### Downloading PDBs when the index doesn't have them

The index usually has no PDB details for a file. The reliable path is
to download the binary, then read the PDB info out of the PE's
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
$ winbindex info ntoskrnl.exe            # what does the index know about this file?
ntoskrnl.exe
  description       NT Kernel & System
  entries           1143 (1141 downloadable · 1018 signed)
  architectures     x64 1142 · ? 1
  file versions     10.0.10240.16384 ... 10.0.28000.2952
  release dates     2015-07-29 ... 2026-09-14
  latest per arch   x64    10.0.28000.2952    2026-09-08  sha256 6ea54ed50bbac50f
  windows versions
    VERSION  ENTRIES  UPDATES  FIRST       LAST
    1507         121      130  2015-07-29  2025-10-14
    ...

$ winbindex list ntoskrnl.exe --windows-version 11-22H2 --machine x64 --signed --limit 2
SHA256            VERSION         ARCH  SIGNED     SIZE  RELEASED    WINDOWS  UPDATES    DOWNLOAD
945b23dbe1c67bb8  10.0.22621.382  x64   yes     11.4 MB  2022-09-20  11-22H2  BASE       bin
f70a89c1f806ed10  10.0.22621.525  x64   yes     11.4 MB  2022-09-27  11-22H2  KB5019311  bin
showing 2 of 74 matching entries (2 downloadable)

$ winbindex url kernel32.dll --file-version "10.0.22621.*" --latest   # newest build per arch
$ winbindex url kernel32.dll --sha256 70f1e69a                        # one entry, prefix match

$ winbindex download kernel32.dll --windows-version 11-22H2 --machine x64 --latest --pdb -o ./out
[1/1] kernel32.dll 10.0.22621.5415 x64   796.4 KB  ok  -> out/70f1e69a1d0602ec/kernel32.dll
      + kernel32.pdb     1.2 MB  ok  -> out/70f1e69a1d0602ec/kernel32.pdb
Done: 1 downloaded, 0 skipped (exist), 0 failed · 2.0 MB in 3.4s · out
PDBs: 1 downloaded, 0 skipped (exist), 0 unavailable, 0 failed
```

Highlights:

- `--machine` accepts names (`x64`, `x86`, `arm64`, `arm`) as well as
  numeric PE machine types, and every name shown in the `ARCH` column
  works there. `--sha256` accepts a prefix; `url` and `download` warn
  when it matches more than one entry.
- Filenames are matched case-insensitively; a path such as
  `C:\Windows\System32\kernel32.dll` is reduced to its file name.
- `--latest` keeps the newest build per architecture, `--limit N`,
  `--sort version|date|size|sha` and `--reverse` shape the selection.
  Entries lacking the sort value (e.g. no version) are listed last.
- `url` and `download` only consider entries that can be downloaded, so
  `--latest` picks the same build in both.
- `url` prints binary URLs only. A PDB's location is read from the
  binary's debug directory, so `download --pdb` downloads each binary,
  parses it and then fetches its PDB.
  `--layout sha|version|flat` controls the directory structure and
  `--dry-run` shows what would happen, including files that would be
  skipped. An existing file is skipped only if it is the same build
  (same PE timestamp and image size); a different file in its place is
  reported as a failure. `--overwrite` replaces existing files.
- `--json` gives machine-readable output for every command; `list -q`
  prints full SHA256 hashes for piping back into `--sha256`. `info --json`
  prints one object for a single filename and a list for several.
- Metadata is cached in the platform cache directory (`~/.cache/winbindex`
  on Linux, override with `--cache-dir` / `$WINBINDEX_CACHE_DIR`) and
  refreshed after 24 h; `--refresh` forces a fetch, `--no-cache` disables it.
- Global options can go before or after the subcommand. `-v` shows what
  is going on, `-vv` adds HTTP debug output.
- Exit status: `0` success, `1` nothing matched or some items failed,
  `2` usage / fatal error.

Run `winbindex --help` and `winbindex <command> --help` for the full reference.

## Caching

Pass `cache_dir=` to persist the gzipped JSON between runs. Use
`cache_ttl=` (seconds) to require periodic refresh. Cached files are
re-validated transparently on each call. `winbindex.default_cache_dir()`
returns the platform-appropriate location the CLI uses.

```python
from winbindex import WinbindexClient, default_cache_dir

client = WinbindexClient(
    cache_dir=default_cache_dir(),
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
Release notes are in [doc/CHANGELOG.md](doc/CHANGELOG.md).

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

The library glues those two together and downloads the result.

Because the symbol server identifies a binary by timestamp and image
size only, the file it returns is the right build but its SHA256 (and
sometimes its size) can differ from the one listed in the index. In a
sample of a dozen `kernel32.dll` / `ci.dll` builds, about half differed.

## Related projects

- [Winbindex](https://github.com/m417z/winbindex) - the web service providing the binaries indexed.
- [pdbfetch](https://github.com/ajkhoury/pdbfetch) - Go tool that fetches PDBs from a local PE file

## License

GPL-3.0-or-later, matching upstream Winbindex.

This package is not affiliated with or endorsed by Microsoft or the
authors of Winbindex; it is a third-party client built on top of the
service's public data.
