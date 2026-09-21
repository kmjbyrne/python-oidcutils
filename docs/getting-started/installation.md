# Installation

## Basic

Install from the repository. The package is not yet on PyPI.

```bash
uv add git+https://github.com/kmjbyrne/python-oidcutils.git
```

## With FastAPI Support

```bash
uv add "oidcutils[fastapi] @ git+https://github.com/kmjbyrne/python-oidcutils.git"
```

## Pin A Version

```bash
uv add git+https://github.com/kmjbyrne/python-oidcutils.git@v0.0.3-beta
```

`uv add` records the dependency in your `pyproject.toml` and locks it, so the
next person to check the project out gets the same version. `uv pip install`
puts it in the environment and leaves no trace in the project, which is what you
want for a one-off look and not for a service that has to build again
tomorrow.

The FastAPI extra pulls in `fastapi` as a dependency. The core package depends
only on:

- [Authlib](https://authlib.org/) -- OAuth2 client flows
- [joserfc](https://jose.authlib.org/) -- JWT/JWKS validation
- [httpx](https://www.python-httpx.org/) -- async HTTP

## Requirements

- Python 3.12+
