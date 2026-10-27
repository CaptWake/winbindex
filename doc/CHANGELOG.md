# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## 2.0.0 - 2026-10-18

### Breaking changes

- CLI: the file-version filter is now `--file-version`; `--version`
  prints the program version.
- CLI: `download --with-pdb-download` is now `download --pdb`, which also
  recovers PDBs the index lacks by reading them from the downloaded binary.
- CLI: metadata is cached by default in the platform cache directory
  (`~/.cache/winbindex` on Linux) and fetched again after 24 hours. Pass
  `--no-cache` for the previous behaviour.
- CLI: `download` exits with `1` when any file failed, and `url` when it
  printed nothing (both used to exit with `0`).
- CLI: `-v` shows progress messages; full HTTP debug output needs `-vv`.
- A `404` from the symbol server raises `DownloadError` with
  `status_code == 404` instead of `FileNotIndexedError`, which now only
  means the index does not know the filename.
- `find(sha256=...)` matches every entry whose hash starts with the given
  value, and `windows_version` / `update` ignore case.
- `PdbInfo.name` must be a bare file name (no directories, not `.` or
  `..`). `PdbInfo.from_dict` keeps only the basename of a path.

### Added

- CLI `info` command: entry counts, architectures, version and date
  ranges, the newest build per architecture, and the Windows releases a
  file ships in.
- Several filenames per command, matched case-insensitively. A path is
  reduced to its file name.
- A `list` table with architecture, signing, size, release date, Windows
  versions, updates and download availability, plus `--full-version`,
  `--wide`, `--no-header` and `-q` (bare SHA256 hashes).
- `--json` for every command.
- `--latest` (newest build per architecture), `--limit`,
  `--sort version|date|size|sha|none` and `--reverse`.
- `--machine` accepts names (`x64`, `x86`, `arm64`, `arm`, ...) as well as
  numbers, and `--sha256` accepts a prefix (`url` and `download` warn when
  it matches more than one entry).
- Hints when nothing matches: close values for typos, the available
  architectures, and which filter removed the remaining entries.
- `download` shows in-place progress, a status line per file and a
  summary, and gains `--layout sha|version|flat`, `--dry-run` and
  `--overwrite`. An existing file is skipped only when it is the same
  build (same PE timestamp and image size).
- Global options, accepted before or after the command: `--cache-dir`,
  `--no-cache`, `--refresh`, `--cache-ttl`, `--base-url`,
  `--symbol-server`, `--timeout`, `--retries`, `--json` and `-v`.
- `filter_entries()` applies the `find()` filters to entries you already
  hold.
- `default_cache_dir()` returns the platform cache directory, overridable
  with `$WINBINDEX_CACHE_DIR`.
- `parse_machine_type()`, `machine_name()` and `MACHINE_NAMES` convert
  between PE machine types and names; `parse_version()` turns a version
  string into a sortable tuple.
- `FileEntry.version_tuple`, `short_version`, `machine_name`, `is_signed`
  and `release_date`; the same properties except `release_date` on
  `FileInfo`.
- `DownloadError.status_code` and `DownloadError.message`.
- `InvalidFilenameError`, a `ValueError` subclass, for names that cannot
  exist on Windows.
- INFO and DEBUG log messages for metadata fetches, cache use, retries and
  downloads.

### Changed

- Any filename that is valid on Windows is accepted, so names with spaces
  such as `.net framework ngen v4.0.30319` can be looked up.
- `WindowsRelease.release_date` falls back to `updateInfo.releaseDate`.
- `DEFAULT_USER_AGENT` carries the package version and this project's URL.
- `download_many()` creates no directories for entries with nothing to
  download, and directory errors go to `on_error`.

### Fixed

- A malformed entry, such as a non-numeric timestamp or an invalid PDB
  GUID, no longer aborts `get_file()`. The entry is skipped with a
  warning, and a broken `pdb` block is dropped.
- A failed or interrupted download leaves no `.part` file or empty
  directory behind, a network error mid-download raises `DownloadError`,
  and a body shorter than `Content-Length` is rejected. The finished file
  replaces the target atomically.
- Downloads ask for uncompressed content, and a compressed response is no
  longer mistaken for a truncated one.
- A truncated or otherwise damaged cache file is fetched again instead of
  crashing, and a cache write failure is logged instead of failing the
  call.
- Binaries whose only CodeView record is NB10 (PDB 2.0) no longer yield a
  PDB triple with a wrong URL; `extract_pdb_info` raises
  `MissingPdbInfoError` for them.

### Security

- A PDB name from the index can no longer place the file outside the
  destination directory (for example `../../x.pdb`).

## 1.0.1 - 2026-05-02

- Initial release.
