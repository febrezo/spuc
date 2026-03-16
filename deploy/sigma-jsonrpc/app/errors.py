from __future__ import annotations

from dataclasses import dataclass
from typing import Any


PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

SERVER_AUTH_ERROR = -32001
SERVER_SIGMA_ERROR = -32010
SERVER_TIMEOUT_ERROR = -32011
SERVER_SIZE_ERROR = -32012


@dataclass
class RpcException(Exception):
    code: int
    message: str
    data: Any = None


class AuthException(Exception):
    pass


class SigmaEngineException(Exception):
    pass


class SigmaTimeoutException(SigmaEngineException):
    pass


class SigmaInputException(SigmaEngineException):
    pass
