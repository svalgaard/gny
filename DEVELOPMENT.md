# Development Guide

## Project Structure

```
gny/
├── main.py            # FastAPI application entry point
├── config.py          # Pydantic settings (reads .env)
├── database.py        # Async SQLAlchemy engine and session
├── auth.py            # Bearer token validation, user upsert
├── oidc_provider.py   # OIDC Discovery, UserInfo fetch
├── dns_utils.py       # PTR lookup and domain authorization check
├── models/
│   ├── enrollment.py  # Enrollment ORM model
│   ├── host.py        # Host ORM model
│   ├── log.py         # Log ORM model
│   ├── txt_record.py  # TxtRecord ORM model
│   └── user.py        # User ORM model
└── routes/
    ├── enroll.py      # POST /api/enroll, POST /api/enroll/confirm
    ├── txt.py         # POST/DELETE /api/txt, GET /api/txt/test
    └── oidc.py        # GET /api/enroll/start, GET /.well-known/sso
openapi.yaml           # OpenAPI specification
pyproject.toml         # Build config and dependencies
debian/                # Debian packaging files
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test,lint]"
```

## Testing

```bash
pytest -v
```

Tests use SQLite via `aiosqlite` — no MySQL instance required. Coverage is reported automatically.

## Linting

```bash
ruff check .
ruff format --check .
```

## Type Checking

```bash
mypy gny/
```

## OpenAPI Validation

```bash
openapi-spec-validator openapi.yaml
```

## Running Locally

```bash
uvicorn gny.main:app --reload
```

Interactive API docs: `http://localhost:8000/docs`

## CI Pipeline

The `ci.yml` workflow runs on every push and PR to `main`:

| Job | What it does |
|---|---|
| `lint` | `ruff check` and `ruff format --check` |
| `typecheck` | `mypy gny/` |
| `openapi` | `openapi-spec-validator openapi.yaml` |
| `test` | `pytest` across Python 3.11 – 3.14; uploads coverage as artifact |
| `docker` | Build Docker image (no push) |
| `deb` | Build Debian package (runs after lint/typecheck/openapi/test) |

## Building a Debian Package

```bash
sudo apt-get install -y debhelper dh-python pybuild-plugin-pyproject \
    python3-all python3-setuptools
dpkg-buildpackage -us -uc -b
```

## Building a Docker Image

```bash
docker build -t gny:local .
docker run --env-file .env -p 8000:8000 gny:local
```

## Release Process

1. Bump the version in `pyproject.toml`
2. Update `debian/changelog`:
   ```bash
   dch -v <version>-1 "Release notes here"
   ```
3. Commit and push to `main`
4. Tag and push:
   ```bash
   git tag v<version>
   git push origin v<version>
   ```

The `release.yml` workflow then automatically:

- Builds the sdist and wheel and publishes them to [PyPI](https://pypi.org/project/gny/) (via OIDC trusted publishing)
- Builds and pushes the Docker image to `ghcr.io/svalgaard/gny` (tagged with the version and `latest`)
- Builds the Debian package and creates a GitHub Release with changelog notes and all artifacts (`.deb`, wheel, sdist) attached

