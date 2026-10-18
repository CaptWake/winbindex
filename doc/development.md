# Development Guide

## Prerequisites

This project uses uv for dependency management.

Install it with:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## Setup

Clone the repository and install all dependencies (runtime + dev):

```bash
git clone https://github.com/CaptWake/winbindex.git
cd winbindex
uv sync
```

---

## Git Hooks (Linting, Formatting, Type Checking, Tests)

This project uses pre-commit to enforce code quality automatically.

Install the hooks:

```bash
uv run pre-commit install --hook-type pre-commit
uv run pre-commit install --hook-type pre-push
```

### What runs automatically

* **pre-commit**

  * Ruff (lint + format)
  * Mypy (type checking)

* **pre-push**

  * Pytest (run test suite)

---

## Running checks manually

Run all hooks manually:

```bash
uv run pre-commit run --all-files
uv run pre-commit run --all-files --hook-stage pre-push
```

## Running Tests

Run the full test suite using pytest:

```bash
uv run pytest
```

---

## Project Structure

```text
winbindex/   # library code
tests/       # unit tests
examples/    # usage examples
```

---

## Releasing a New Version

This project follows [Semantic Versioning](https://packaging.python.org/en/latest/discussions/versioning/) (`major.minor.patch`):

| Part  | When to increment                        |
| ----- | ---------------------------------------- |
| major | incompatible API changes                 |
| minor | new functionality (backwards-compatible) |
| patch | bug fixes (backwards-compatible)         |

Record user-visible changes in [CHANGELOG.md](CHANGELOG.md).

Bump the version, commit, and tag in one command:

```bash
uv run bump-my-version bump patch   # 1.0.0 -> 1.0.1
uv run bump-my-version bump minor   # 1.0.0 -> 1.1.0
uv run bump-my-version bump major   # 1.0.0 -> 2.0.0
```

This will:

* update `pyproject.toml`
* update version references (if configured)
* update the lockfile
* create a commit
* create a `v{version}` git tag

Push changes and tags:

```bash
git push origin main --tags
```
