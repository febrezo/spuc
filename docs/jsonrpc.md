# SPUC JSON-RPC Service

Last updated: 2026-03-15

## Purpose

`spuc jsonrpc` exposes SPUC translation as a local HTTP API for analyst automation.

Important:

- Endpoint is `POST /rpc` on localhost.
- Authentication is mandatory via `Authorization: Bearer <token>`.
- This is a lightweight HTTP JSON endpoint (not JSON-RPC 2.0 method envelopes).

## Start the service

```bash
spuc jsonrpc --port 8080
```

Optional fixed token:

```bash
spuc jsonrpc --port 8080 --token my-token
```

At startup SPUC prints:

- listening URL
- bearer token
- a valid `curl` example

## Endpoint contract

- Method: `POST`
- Path: `/rpc`
- Content-Type: `application/json`
- Auth header: `Authorization: Bearer <token>`

### Request body

```json
{
  "rule": "[process:name = 'cmd.exe']",
  "to": ["sigma", "kql"],
  "description": "Optional analyst description",
  "sigma_targets": ["splunk"],
  "mode": "strict",
  "rule_confidence": 80
}
```

Field reference:

- `rule` (string, required): STIX pattern.
- `to` (string[], optional): target outputs.
  - Native values: `sigma`, `eql`, `kql`, `cytomic-orion-sql`, `snort`, `suricata`, `yara`.
  - Dynamic values: `sigma-to-<backend>` for compatible backends discovered from `sigma plugin list` at process startup.
  - If omitted/empty: SPUC evaluates all targets.
- `description` (string, optional): analyst context used by translators.
- `sigma_targets` (string[], optional): backend names for `sigma convert` (only applied when `to` includes `sigma`).
- `mode` (string, optional): `strict` (default) or `partial`.
- `rule_confidence` (number, optional): `0..100`.

## Response format

```json
{
  "ok": true,
  "results": [
    {
      "target": "sigma",
      "runtime_status": "exact",
      "conversion_confidence": 95,
      "rule_confidence": 80,
      "cause": null,
      "summary": "Semantic mapping preserved",
      "notes": [],
      "output": "..."
    }
  ],
  "error": null
}
```

Notes:

- `ok: true` means request was processed.
- Always inspect each `results[*].runtime_status`:
  - `exact`
  - `lossy`
  - `unsupported`

## Copy/paste-safe curl examples

### Minimal call

```bash
curl -X POST 'http://127.0.0.1:8080/rpc' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  --data-raw "{\"rule\":\"[ipv4-addr:value = '1.1.1.1']\",\"to\":[\"sigma\"]}"
```

### Multiple targets

```bash
curl -X POST 'http://127.0.0.1:8080/rpc' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  --data-raw "{\"rule\":\"[process:name = 'cmd.exe']\",\"to\":[\"sigma\",\"kql\",\"eql\"]}"
```

### Use a JSON payload file (recommended for complex rules)

```bash
cat > /tmp/spuc_rpc_payload.json << 'EOF'
{
  "rule": "[process:name = 'cmd.exe'] FOLLOWEDBY [process:name = 'powershell.exe']",
  "to": ["sigma", "kql"],
  "mode": "partial",
  "rule_confidence": 75
}
EOF

curl -X POST 'http://127.0.0.1:8080/rpc' \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/spuc_rpc_payload.json
```

## Common errors

### `401 unauthorized`

- Missing/incorrect bearer token.
- Verify token printed at startup and the exact header format.

### `400 invalid JSON: ...`

- Payload is malformed JSON.
- Common mistake: using `\'` inside JSON strings. JSON does not support escaping single quotes.

### `ok=false` with `error: "no valid target selected"`

- `to` only contains unknown values.
- Use native targets (`sigma`, `eql`, `kql`, `cytomic-orion-sql`, `snort`, `suricata`, `yara`) plus discovered `sigma-to-*` values from `spuc sigma list-targets`.

### `ok=true` but target status is `unsupported`

- Request is valid, but target backend semantics are not available for that STIX pattern.
- Review `cause`, `summary`, and `notes` fields.

## Analyst checklist

1. Start service and copy token.
2. Send one minimal `curl` call first.
3. Check per-target `runtime_status` (not only `ok`).
4. If rule is complex, move payload to a JSON file and call with `--data-binary @file`.
5. Track `rule_confidence` explicitly when using results in reports.
