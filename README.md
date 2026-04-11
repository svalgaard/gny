# GNY

***This is currently ALPHA software - lots of bits and pieces are missing.***

**GNY** is a FastAPI-based server that manages DNS TXT records for ACME `dns-01` certificate challenges. It is designed to be used as a hook target for [certbot](https://certbot.eff.org/) (or any ACME client) when automating TLS certificate issuance and renewal.

## Overview

GNY exposes a small REST API (documented in [openapi.yaml](openapi.yaml)) that lets enrolled servers add and remove `_acme-challenge.*` DNS TXT records. Access is controlled by:

1. **Enrollment** — a server registers its IP address and administrator email, receiving a Bearer token.
2. **Email confirmation** — an administrator with `access_level >= 1` confirms the enrollment via OIDC login (Google, Azure AD, or any standard OIDC provider), activating the token.
3. **PTR-based authorization** — an enrolled server may only manage TXT records for its own hostname (as resolved by reverse-DNS lookup of its IP address).

## Requirements

- Python 3.11+
- MariaDB or MySQL database
- An OIDC client (Google Cloud OAuth2, Azure AD/Entra ID app registration, or any standard OIDC provider) for enrollment confirmation
- The enrolling server must have a valid PTR (reverse-DNS) record

## Installation

```bash
pip install .
```

For development (editable install with test/lint extras):

```bash
pip install -e ".[test,lint]"
```

## Configuration

Copy `.env` and adjust values:

| Variable | Description |
|---|---|
| `APP_URL` | Public base URL of this server (e.g. `https://dns.example.com`) |
| `DB_HOST` | MariaDB/MySQL hostname |
| `DB_DATABASE` | Database name |
| `DB_USERNAME` | Database user |
| `DB_PASSWORD` | Database password |
| `OIDCProviderMetadataURL` | OIDC Discovery document URL (see below) |
| `OIDCClientID` | OIDC client ID |
| `OIDCClientSecret` | OIDC client secret |
| `OIDCRedirectURI` | OIDC redirect path (default `/.well-known/sso`) |
| `LOG_LEVEL` | Logging level: `debug`, `info`, `warning`, `error` |
| `DISPLAY_ERRORS` | Show error details in responses (`true` / `false`) |

The redirect URI registered with the OIDC provider must be `{APP_URL}{OIDCRedirectURI}`, e.g. `https://dns.example.com/.well-known/sso`.

### OIDC provider examples

**Google:**
```
OIDCProviderMetadataURL=https://accounts.google.com/.well-known/openid-configuration
```

**Azure AD / Entra ID** (replace `{tenant_id}` with your directory tenant ID):
```
OIDCProviderMetadataURL=https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration
```

## Running

```bash
uvicorn gny.main:app --host 0.0.0.0 --port 8000
```

For development with auto-reload:

```bash
uvicorn gny.main:app --reload
```

The database tables are created automatically on startup.

Interactive API docs are available at `http://localhost:8000/docs`.

## API

All endpoints are under `/api`. Full spec: [openapi.yaml](openapi.yaml).

### Enrollment workflow

#### 1. Enroll

```
POST /api/enroll
Content-Type: application/json

{ "mail": "admin@example.com" }
```

Returns a Bearer token, e.g., `gny-ab3df26e48b2467bf705156d4c8914f2`. The server's IP must resolve to a PTR record or the request is rejected with `409`.

#### 2. Confirm enrollment

Open the following URL in a browser as an administrator (a user with `access_level >= 1`):

```
GET /api/enroll/start?token={token}
```

This redirects to the configured OIDC provider (Google, Azure AD, etc.). After authenticating, the provider redirects back to `/.well-known/sso`, which upserts the user record and activates the enrollment token.

On first login, every user is created with `access_level = 0`. An existing administrator must grant access before a new user can confirm enrollments:

```sql
UPDATE users SET access_level = 1 WHERE mail = 'admin@example.com';
```

Alternatively, the `/api/enroll/confirm` endpoint accepts an OIDC Bearer token directly and confirms the enrollment programmatically (still requires `access_level >= 1`).


### Managing TXT records

All requests below require `Authorization: Bearer {enrollment_token}`.

#### Add a record

```
POST /api/txt?name=_acme-challenge.example.com&text=<validation_token>
```

#### Delete a record

```
DELETE /api/txt?name=_acme-challenge.example.com&text=<validation_token>
```

#### Test authorization

```
GET /api/txt/test?name=_acme-challenge.example.com
```

Returns `{"status": "ok"}` if the authenticated server is allowed to manage that name, or `403` otherwise.

### Authorization rules

A server enrolled from IP `1.2.3.4` whose PTR record resolves to `server.example.com` may manage any TXT record whose domain component (after stripping a leading `_acme-challenge.`) equals or is a subdomain of `server.example.com`.

## Project structure

```
gny/
├── main.py            # FastAPI application entry point
├── config.py          # Pydantic settings (reads .env)
├── database.py        # Async SQLAlchemy engine and session
├── models.py          # ORM models: Enrollment, TxtRecord, User
├── auth.py            # Bearer token validation, user upsert
├── oidc_provider.py   # OIDC Discovery, UserInfo fetch
├── dns_utils.py       # PTR lookup and domain authorization check
└── routes/
    ├── enroll.py      # POST /api/enroll, POST /api/enroll/confirm
    ├── txt.py         # POST/DELETE /api/txt, GET /api/txt/test
    └── oidc.py        # GET /api/enroll/start, GET /.well-known/sso
requirements.txt
openapi.yaml
```
