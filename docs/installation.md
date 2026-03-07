# Installation

## Requirements

- Python **3.9+**
- Dependencies: `rfc9420`, `cryptography`, `pycryptodome` (installed automatically with sorrydave)

## Install the package

From the project root:

```bash
pip install -e .
```

Or install with [uv](https://github.com/astral-sh/uv):

```bash
uv pip install -e .
```

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

To build static HTML:

```bash
mkdocs build
```

Output is written to the `site/` directory (ignored by git).
