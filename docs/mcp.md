# MCP Integration

Last updated: 2026-05-16

## Purpose

This guide explains how to expose SPUC capabilities to other AI systems through Model Context Protocol (MCP).

SPUC does not currently implement native MCP transport.
The supported approach is to run SPUC as a tool backend (`spuc jsonrpc`) and expose it through a lightweight MCP adapter.

## Recommended Architecture

```text
MCP client (AI) -> MCP adapter (stdio or HTTP) -> spuc jsonrpc -> SPUC translators
```

- `spuc jsonrpc` remains the source of translation behavior.
- The MCP adapter maps MCP tool calls to SPUC JSON-RPC requests.
- Authentication to SPUC remains bearer-token based.

## Minimal MCP Tool Contract

Recommended MCP tools:

- `spuc_translate`
  - input:
    - `rule` (string, required)
    - `to` (string[], optional)
    - `description` (string, optional)
    - `sigma_targets` (string[], optional)
    - `mode` (`strict|partial`, optional)
    - `rule_confidence` (`0..100`, optional)
  - backend call:
    - `POST http://127.0.0.1:<port>/rpc`
    - `Authorization: Bearer <token>`

## Start SPUC JSON-RPC Backend

```bash
spuc jsonrpc --port 8080 --token '<long-random-token>'
```

## Example Backend Request

```bash
curl -X POST 'http://127.0.0.1:8080/rpc' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  --data-raw '{"rule":"[file:size = 25536]","to":["kql"]}'
```

## Containerized MCP Backend

If SPUC runs in containerized mode, expose the JSON-RPC port only to trusted local networks.

Example:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/febrezo/spuc:latest jsonrpc --port 8080 --token '<long-random-token>'
```

## Security Guidance

- Keep SPUC JSON-RPC bound to localhost or private networks.
- Always require and rotate bearer tokens.
- Avoid logging token values in adapter logs.
- Enforce request size limits in the MCP adapter.
- Prefer running MCP adapters with least privilege and explicit outbound allowlists.

## Operational Readiness Checklist

- SPUC health endpoint monitored (`GET /healthz` for web mode).
- MCP adapter startup validates SPUC reachability.
- Adapter returns clear error mapping for SPUC `ok=false` responses.
- Integration test in CI validates authenticated JSON-RPC request/response path.
