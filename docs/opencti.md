# OpenCTI

SPUC can use OpenCTI as a per-user STIX object source while preserving local-catalog fallback.

## Configure

In the web UI, open Settings, then configure:

- Enable OpenCTI for my account.
- OpenCTI GraphQL endpoint, for example `https://opencti.example.com/graphql`.
- OpenCTI API key.
- STIX catalog source: `OpenCTI`.

Use `Test connection` before saving or after rotating a key. The test verifies endpoint reachability, API key validity and a basic GraphQL query.

## Fallback Behavior

If OpenCTI is not configured, disabled or incomplete, SPUC uses the local catalog. If OpenCTI is configured but fails due to timeout, invalid key, outage, unexpected GraphQL response, insufficient permissions or rate limit, the UI shows a small warning and continues with local catalog results.

## Search Behavior

OpenCTI mode never attempts to load every object. The STIX catalog uses debounced, on-demand search by name, alias, type, STIX ID or external reference. Relevant types include `intrusion-set`, `malware`, `tool`, `campaign`, `attack-pattern`, `indicator`, `vulnerability` and `identity`.

## Remote Creation

When OpenCTI is active, SPUC checks for similar objects before creating. If candidates exist, creation stops and the UI shows:

Possible similar STIX objects were found. Review them before creating a new object.

The analyst must choose Use existing object, Create anyway or Cancel. SPUC does not silently create duplicates when similar candidates are returned.

TODO(opencti-integration): OpenCTI indicator creation requires a real STIX pattern payload from the translation/API branch. SPUC currently avoids inventing indicator semantics from name-only object forms.
