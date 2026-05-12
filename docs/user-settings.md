# User Settings

SPUC user settings are per account. Profile preferences and OpenCTI source settings are independent for each user.

## Profile

Users can update display name, locale and theme through:

- `GET /api/settings/profile`
- `POST /api/settings/profile`

## OpenCTI STIX Source

Users can update their STIX source through:

- `GET /api/user/settings/stix-source`
- `PUT /api/user/settings/stix-source`
- `POST /api/user/settings/opencti/test`

The OpenCTI API key is write-only from the frontend perspective. After saving, SPUC only returns whether a key is configured.

## Tokens

Personal API tokens are user-scoped and revocable:

- Create tokens from `POST /api/user/tokens`.
- Revoke tokens with `DELETE /api/user/tokens/{token_id}`.
- Rotate tokens with `POST /api/user/tokens/{token_id}/rotate`.

Clear token values are shown only once when created or rotated.
