# Configuration

SPUC stores web and catalog configuration under the config root:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/spuc`
- macOS: `$HOME/Library/Application Support/spuc`
- Windows: `%APPDATA%\spuc`
- Override: `SPUC_CONFIG_DIR=/custom/path`

Current file-backed settings include web users, per-user preferences, per-user OpenCTI settings, token metadata and local STIX/catalog data. If OpenCTI is not configured for a user, SPUC uses the local catalog.

In the provided Docker/Compose deployment, this same config root is set to `/data` and persisted through the `spuc_data` volume.

## OpenCTI Source

Per-user OpenCTI settings are stored in `user_opencti_settings.json`. The API key is never returned by API responses after save; only `opencti_api_key_set` is exposed. On Unix, the settings file is written owner-readable/writable only.

Supported STIX catalog sources:

- `local`: read/write local `stix-objects.json`.
- `opencti`: search OpenCTI on demand and fall back to local if OpenCTI fails.

## Concurrency Notes

OpenCTI integration is additive and deliberately isolated from authentication/token work. Future token and translation API branches should keep API contracts backward-compatible and avoid replacing the user settings schema destructively.
