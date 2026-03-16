from __future__ import annotations

import logging

from fastapi import Request

from app.config import Settings
from app.errors import AuthException

logger = logging.getLogger(__name__)


def enforce_jsonrpc_auth(request: Request, settings: Settings) -> None:
    if not settings.auth_required:
        return

    configured_token = (settings.sigma_rpc_token or '').strip()
    if not configured_token:
        # If no token is configured in .env/environment, allow requests without auth.
        return

    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        logger.warning('auth failed: missing bearer token')
        raise AuthException('missing_bearer_token')

    received = header[7:].strip()
    if not received or received != configured_token:
        logger.warning('auth failed: invalid bearer token')
        raise AuthException('invalid_bearer_token')
