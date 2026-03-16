import unittest

from starlette.requests import Request

from app.auth import enforce_jsonrpc_auth
from app.config import Settings
from app.errors import AuthException


def make_request(headers: dict[str, str]) -> Request:
    raw_headers = [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/jsonrpc",
        "headers": raw_headers,
    }
    return Request(scope)


class AuthTests(unittest.TestCase):
    def test_auth_disabled_allows_request(self) -> None:
        settings = Settings(SIGMA_AUTH_REQUIRED=False)
        request = make_request({})
        enforce_jsonrpc_auth(request, settings)

    def test_auth_missing_header_fails(self) -> None:
        settings = Settings(SIGMA_AUTH_REQUIRED=True, SIGMA_RPC_TOKEN="secret")
        request = make_request({})
        with self.assertRaises(AuthException):
            enforce_jsonrpc_auth(request, settings)

    def test_auth_valid_bearer_passes(self) -> None:
        settings = Settings(SIGMA_AUTH_REQUIRED=True, SIGMA_RPC_TOKEN="secret")
        request = make_request({"Authorization": "Bearer secret"})
        enforce_jsonrpc_auth(request, settings)

    def test_auth_without_configured_token_allows_request(self) -> None:
        settings = Settings(
            SIGMA_AUTH_REQUIRED=True,
            SIGMA_ALLOW_INSECURE_WITHOUT_TOKEN=False,
            SIGMA_RPC_TOKEN="",
        )
        request = make_request({})
        enforce_jsonrpc_auth(request, settings)


if __name__ == "__main__":
    unittest.main()
