# GNY

***This is currently ALPHA software — lots of bits and pieces are missing.***

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

### PyPI

```bash
pip install gny
```

### Debian package

Pre-built `.deb` packages are attached to each [GitHub Release](https://github.com/svalgaard/gny/releases):

```bash
wget https://github.com/svalgaard/gny/releases/latest/download/gny_<version>_all.deb
sudo dpkg -i gny_<version>_all.deb
sudo apt-get install -f   # resolve any missing dependencies
```

### Docker

```bash
docker pull ghcr.io/svalgaard/gny:latest
```

## Configuration

Create a `.env` file and set the following variables:

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
| `MAIL_HOST` | SMTP hostname for outgoing mail (default `localhost`) |
| `MAIL_PORT` | SMTP port (default `25`) |
| `MAIL_ENCRYPTION` | SMTP encryption: `tls`, `starttls`, or `none` (default `tls`) |
| `MAIL_USER` | SMTP username |
| `MAIL_PASSWORD` | SMTP password |
| `APP_MAIL_ADDRESS` | From-address for outgoing mail |
| `ENROLL_CONFIRM_TIMEOUT_HOURS` | Hours before an unconfirmed enrollment expires (default `32`) |
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

### Direct

```bash
uvicorn gny.main:app --host 0.0.0.0 --port 8000
```

The database tables are created automatically on startup. Interactive API docs are available at `http://localhost:8000/docs`.

### Docker

```bash
docker run --env-file .env -p 8000:8000 ghcr.io/svalgaard/gny:latest
```

## Client Setup

The recommended certbot plugin is [certbot-dns-gny](https://pypi.org/project/certbot-dns-gny/), available from PyPI:

```bash
pip install certbot-dns-gny
```

Refer to its documentation for credentials file format and certbot integration.

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
