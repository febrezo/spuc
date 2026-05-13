# API

Last updated: 2026-05-13

## Personal API Tokens

Personal tokens are user-scoped, revocable credentials for API access.

Storage model (persisted hashed only):

- id
- user_id
- name
- token_hash
- created_at
- revoked_at
- last_used_at
- expires_at (optional)

Token values are shown only once at creation/rotation and are never stored in clear text.

### List tokens

GET /api/user/tokens

Response:

```json
{
  "entries": [
    {
      "id": "tok-...",
      "user_id": "usr-...",
      "name": "CI token",
      "created_at": "2026-05-12T10:00:00Z",
      "revoked_at": null,
      "last_used_at": "2026-05-12T10:02:01Z",
      "expires_at": null
    }
  ]
}
```

### Create token

POST /api/user/tokens
Content-Type: application/json

```json
{
  "name": "Automation token",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

Response (token_value shown one time only):

```json
{
  "ok": true,
  "entry": {
    "token": {
      "id": "tok-...",
      "user_id": "usr-...",
      "name": "Automation token",
      "created_at": "2026-05-12T10:00:00Z",
      "revoked_at": null,
      "last_used_at": null,
      "expires_at": "2026-12-31T23:59:59Z"
    },
    "token_value": "spuc_pat_..."
  }
}
```

### Revoke token

DELETE /api/user/tokens/{token_id}

### Delete old token record

DELETE /api/user/tokens/{token_id}/purge

Use this endpoint to permanently remove an old token entry from the list (for example, previously revoked tokens).

### Rotate token

POST /api/user/tokens/{token_id}/rotate

Rotation revokes the current token and issues a replacement with a new clear token value shown only once.

## Authenticated STIX Translation

Endpoint:

- POST /api/translate/stix-pattern
- POST /api/translate/stix-bundle
- POST /api/translate/stix-pattern-summary
- Authorization: Bearer <token>
- Content-Type: application/json

Input example:

```json
{
  "type": "indicator",
  "pattern_type": "stix",
  "pattern": "[file:hashes.'SHA-256' = '...']",
  "targets": ["sigma"]
}
```

If `targets` is omitted or empty, SPUC automatically tries all available detection targets.

Success response:

```json
{
  "status": "success",
  "comments": [],
  "results": [
    {
      "type": "indicator",
      "pattern_type": "sigma",
      "pattern": "...",
      "confidence": 80,
      "target": "sigma",
      "stix": {
        "type": "indicator",
        "pattern_type": "sigma",
        "pattern": "...",
        "confidence": 80,
        "description": "Detection-oriented translation summary",
        "comments": ["Any translation notes returned by SPUC"]
      }
    }
  ]
}
```

Error response:

```json
{
  "status": "error",
  "comments": ["Unsupported STIX observable type"],
  "results": []
}
```

Notes:

- Missing/invalid/revoked token returns 401.
- Translation logic reuses the existing internal translation service.
- Each result includes a `stix` object with translation confidence, description, and comments.

### STIX indicator to STIX bundle

This endpoint returns a fully-formed STIX bundle containing:

- The original source `indicator` (pattern type `stix`).
- One translated `indicator` per successful target conversion.
- One `relationship` of type `derived-from` from each translated indicator to the source indicator.
- Relationship confidence mapped to the real translation confidence.

Endpoint:

- POST /api/translate/stix-bundle

Input example:

```json
{
  "indicator": {
    "type": "indicator",
    "id": "indicator--11111111-1111-4111-8111-111111111111",
    "name": "Example indicator",
    "description": "Original STIX description",
    "pattern_type": "stix",
    "pattern": "[process:name = 'cmd.exe']",
    "confidence": 80
  },
  "targets": ["sigma", "kql"]
}
```

Success response example:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "id": "bundle--...",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--11111111-1111-4111-8111-111111111111",
      "pattern_type": "stix",
      "pattern": "[process:name = 'cmd.exe']",
      "description": "Original STIX description"
    },
    {
      "type": "indicator",
      "id": "indicator--...",
      "pattern_type": "sigma",
      "pattern": "title: ...",
      "description": "Original STIX description\n\nSTIX Indicator automatically generated from the original STIX Pattern.",
      "confidence": 95
    },
    {
      "type": "relationship",
      "relationship_type": "derived-from",
      "source_ref": "indicator--...",
      "target_ref": "indicator--11111111-1111-4111-8111-111111111111",
      "confidence": 95
    }
  ]
}
```

### STIX pattern summary (string input)

This endpoint accepts only a STIX pattern string and a target, and returns concise metadata.

Endpoint:

- POST /api/translate/stix-pattern-summary

Input example:

```json
{
  "pattern": "[process:name = 'cmd.exe']",
  "target": "sigma",
  "description": "Analyst note"
}
```

Success response example:

```json
{
  "status": "success",
  "comments": [],
  "result": {
    "description": "Exact conversion with preserved semantics",
    "pattern": "title: '[SPUC Generated Sigma Rule] Analyst note'\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    process.name: cmd.exe\n  condition: selection\n",
    "confidence": 95,
    "target": "sigma"
  }
}
```

Curl example:

```bash
curl -X POST http://localhost:8080/api/translate/stix-pattern \
  -H "Authorization: Bearer $SPUC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "indicator",
    "pattern_type": "stix",
    "pattern": "[file:hashes.\"SHA-256\" = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]"
  }'
```

## User STIX Source Settings

These endpoints are session-authenticated through the web UI and apply to the current user only.

### Read STIX source settings

GET /api/user/settings/stix-source

The response never includes the OpenCTI API key value:

```json
{
  "entry": {
    "opencti_enabled": true,
    "opencti_endpoint": "https://opencti.example.com/graphql",
    "opencti_api_key_set": true,
    "stix_catalog_source": "opencti",
    "effective_source": "opencti"
  }
}
```

### Update STIX source settings

PUT /api/user/settings/stix-source
Content-Type: application/json

```json
{
  "opencti_enabled": true,
  "opencti_endpoint": "https://opencti.example.com/graphql",
  "opencti_api_key": "paste-key-to-set-or-rotate",
  "stix_catalog_source": "opencti"
}
```

Set `stix_catalog_source` to `local` or disable `opencti_enabled` to force local catalog usage.

### Test OpenCTI connectivity

POST /api/user/settings/opencti/test
Content-Type: application/json

```json
{
  "opencti_endpoint": "https://opencti.example.com/graphql",
  "opencti_api_key": "paste-key-to-test"
}
```

The test checks endpoint reachability, API key acceptance and a basic GraphQL query. Failures return a stable `code` such as `timeout`, `invalid_api_key`, `endpoint_unavailable`, `permissions_insufficient`, `rate_limited` or `unexpected_graphql_response`.

## STIX Object Catalog API

GET /api/stix-objects supports local and OpenCTI-backed catalog providers.

Query parameters:

- `q`: search text. Required for OpenCTI mode because SPUC does not bulk-load a whole OpenCTI instance.
- `types`: comma-separated STIX object types.
- `limit`: result limit, capped by the server.

When OpenCTI fails, SPUC returns `200` with `fallback_used: true`, `effective_source: "local"` and a non-intrusive error payload so the UI can keep working with local data.
