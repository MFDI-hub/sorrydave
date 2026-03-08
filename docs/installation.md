# Installation

## Requirements

- **Python**: 3.9 or newer.
- **Dependencies** (installed automatically with sorrydave):
  - `rfc9420` — MLS (Messaging Layer Security) implementation used for group state, key packages, commits, welcomes.
  - `cryptography` — Scrypt (fingerprint), ECDSA (MLS signatures), HKDF (ratchet).
  - `pycryptodome` — AES128-GCM for media frame encryption/decryption.

No system libraries are required beyond what these packages use.

---

## Install the package

From the project root:

```bash
pip install -e .
```

To install a specific version from PyPI (when published):

```bash
pip install sorrydave
```

With [uv](https://github.com/astral-sh/uv):

```bash
uv pip install -e .
```

---

## Verify installation

```python
import sorrydave
print(sorrydave.__version__)
# 0.1.0

from sorrydave import DaveSession
session = DaveSession(local_user_id=123456789)
```

---

## Optional: documentation dependencies

To build or serve the docs with MkDocs:

```bash
pip install -e ".[docs]"
```

Then:

```bash
mkdocs serve
```

Open `http://127.0.0.1:8000` to view the documentation.

To build static HTML only:

```bash
mkdocs build
```

Output is written to the `site/` directory (typically git-ignored).

---

## Optional: development / tests

If the project has dev dependencies (e.g. pytest, mypy):

```bash
pip install -e ".[dev]"
```

Then run tests from the repo root, e.g.:

```bash
pytest
```

---

## Troubleshooting

- **ImportError for rfc9420**: Ensure `pip install -e .` was run in the repo root (or install sorrydave from PyPI). The package declares `rfc9420` as a dependency.
- **ImportError for cryptography or Crypto**: Same as above; `cryptography` and `pycryptodome` are required dependencies.
- **Python version**: Use `python --version` to confirm 3.9+. On some systems you may need `python3` and `pip3`.
