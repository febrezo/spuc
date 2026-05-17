# Deployment

Last updated: 2026-05-16

## Purpose

This guide describes how to deploy SPUC with the repository-provided Docker assets:

- `Dockerfile`
- `docker-compose.yml`
- `.env.example`

It focuses on the built-in web interface, persistent local state, optional OAuth bootstrap, and optional remote Sigma JSON-RPC connectivity.

## Pull from GHCR

Tagged releases publish a multi-arch image to GitHub Container Registry.

```bash
docker pull ghcr.io/febrezo/spuc:latest
docker run --rm -p 8090:8090 \
  -e SPUC_CONFIG_DIR=/data \
  -v spuc_data:/data \
  ghcr.io/febrezo/spuc:latest \
  web --host 0.0.0.0 --port 8090 --admin-user admin --admin-password '<strong-password>' --no-open
```

The published image:

- runs as non-root user `spuc`
- exposes `GET /healthz` through image-level health checks
- ships `spuc`, `spuc-agent`, and local Sigma backends used by SPUC

## Quick Start

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Edit `.env` with the values you want for your environment.

3. Start SPUC:

```bash
docker compose up --build
```

4. Open the published address, by default:

```text
http://127.0.0.1:8090/
```

## What Compose Starts

The root `docker-compose.yml` starts one SPUC container that runs:

```bash
spuc web --host 0.0.0.0 --port 8090 --admin-user <user> --admin-password <password> --no-open
```

This deployment:

- publishes the container web service on the host
- persists SPUC file-backed state under `/data`
- keeps catalog, user, runtime and intrusion-set files across restarts through the `spuc_data` volume
- includes local `sigma` plus several backend plugins inside the image

By default, `docker-compose.yml` uses this image reference:

```text
ghcr.io/febrezo/spuc:latest
```

## Variables

### Network publishing

- `SPUC_BIND_ADDRESS`
  Purpose: host interface used by Docker when publishing port `8090`.
  Typical value: `127.0.0.1` for local-only access, `0.0.0.0` to expose on all host interfaces.

- `SPUC_IMAGE`
  Purpose: image reference used by `docker-compose.yml`.
  Typical value: `ghcr.io/febrezo/spuc:latest`.

- `SPUC_HOST_PORT`
  Purpose: host port mapped to container port `8090`.
  Typical value: `8090`.

### Bootstrap administrator

- `SPUC_ADMIN_USER`
  Purpose: username created or synchronized at SPUC startup for local login mode.
  Typical value: `admin`.

- `SPUC_ADMIN_PASSWORD`
  Purpose: password created or synchronized for `SPUC_ADMIN_USER`.
  Required: yes in the provided compose file.
  Recommendation: use a long random value.

### Google OAuth bootstrap

- `SPUC_WEB_GOOGLE_CLIENT_ID`
  Purpose: Google OAuth client ID shown to the SPUC web login flow.

- `SPUC_WEB_GOOGLE_CLIENT_SECRET`
  Purpose: Google OAuth client secret paired with the client ID.

- `SPUC_WEB_GOOGLE_REDIRECT_URI`
  Purpose: callback URI registered in Google and used by SPUC.
  Typical local example: `http://127.0.0.1:8090/api/login/oauth/google/callback`

### GitHub OAuth bootstrap

- `SPUC_WEB_GITHUB_CLIENT_ID`
  Purpose: GitHub OAuth app client ID shown to the SPUC web login flow.

- `SPUC_WEB_GITHUB_CLIENT_SECRET`
  Purpose: GitHub OAuth app client secret paired with the client ID.

- `SPUC_WEB_GITHUB_REDIRECT_URI`
  Purpose: callback URI registered in GitHub and used by SPUC.
  Typical local example: `http://127.0.0.1:8090/api/login/oauth/github/callback`

### Remote Sigma JSON-RPC

- `SIGMA_RPC_URL`
  Purpose: optional remote Sigma JSON-RPC endpoint used by SPUC for backend discovery and delegated Sigma conversions.
  Typical value: `http://sigma-jsonrpc:8080/jsonrpc` in multi-container setups.
  Behavior when empty: SPUC falls back to local `sigma` inside the image.

- `SPUC_SIGMA_RPC_TOKEN`
  Purpose: optional bearer token sent to the remote Sigma JSON-RPC service.
  Behavior when empty: no auth token is sent.

## Persistence

The compose deployment sets:

```text
SPUC_CONFIG_DIR=/data
```

That means the container persists the same file-backed SPUC state described in configuration docs, including:

- `web_users.json`
- `web_oauth_policy.json`
- `abilities/*.json`
- `catalog/translation_activities.jsonl`
- `intrusion_sets/*.yaml`
- `stix-objects.json`
- `sigma/runtime.json`

## Notes

- The SPUC process inside the container binds to `0.0.0.0`, but host exposure is still controlled by `SPUC_BIND_ADDRESS`.
- OAuth providers can still remain disabled in the UI until an administrator authorizes them in `Settings`.
- If `SIGMA_RPC_URL` is not configured, the image still supports local Sigma discovery because the Docker image installs `sigma-cli` and several backend plugins.
