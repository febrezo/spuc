# Security

SPUC remains defensive-only. OpenCTI integration and translation APIs must not add offensive payload execution or claim runtime execution where none exists.

## API Keys And Tokens

- OpenCTI API keys are never returned to the frontend after saving.
- Personal API tokens are stored as hashes and clear values are shown only once.
- Revoke personal API tokens with `DELETE /api/user/tokens/{token_id}`.
- Rotate personal API tokens with `POST /api/user/tokens/{token_id}/rotate`.
- On Unix, per-user OpenCTI settings are persisted with owner-only file permissions.

## Authenticated Translation

The translation API requires a bearer token:

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

## OpenCTI Failure Handling

OpenCTI failures are non-fatal for analyst workflows. Timeout, invalid API key, endpoint outage, unexpected GraphQL response, insufficient permissions and rate limits are surfaced as non-intrusive UI messages with an option to go to user settings. SPUC keeps local-catalog fallback available.

## Integration Notes

OpenCTI settings are additive to current user and token models. Future authentication/API branches should preserve existing token and settings contracts or migrate them explicitly in a small, documented change.
