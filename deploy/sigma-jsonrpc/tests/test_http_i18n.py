import unittest

from starlette.requests import Request

from app.routes.http import _resolve_lang


def _make_request(query: str = "", headers: dict[str, str] | None = None) -> Request:
    header_items = headers or {}
    raw_headers = [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in header_items.items()]
    path = "/"
    if query:
        path = f"/?{query}"
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": query.encode("utf-8"),
        "headers": raw_headers,
    }
    return Request(scope)


class HttpI18nTests(unittest.TestCase):
    def test_defaults_to_english(self) -> None:
        request = _make_request()
        self.assertEqual(_resolve_lang(request), "en")

    def test_query_param_overrides_headers(self) -> None:
        request = _make_request(query="lang=es", headers={"Accept-Language": "en-US,en;q=0.8"})
        self.assertEqual(_resolve_lang(request), "es")

    def test_accept_language_detects_spanish(self) -> None:
        request = _make_request(headers={"Accept-Language": "es-ES,es;q=0.9,en;q=0.5"})
        self.assertEqual(_resolve_lang(request), "es")

    def test_accept_language_detects_french(self) -> None:
        request = _make_request(headers={"Accept-Language": "fr-FR,fr;q=0.9,en;q=0.5"})
        self.assertEqual(_resolve_lang(request), "fr")

    def test_query_param_selects_russian(self) -> None:
        request = _make_request(query="lang=ru", headers={"Accept-Language": "en-US,en;q=0.8"})
        self.assertEqual(_resolve_lang(request), "ru")

    def test_unsupported_lang_falls_back_to_english(self) -> None:
        request = _make_request(query="lang=pl", headers={"Accept-Language": "pl-PL,pl;q=0.8"})
        self.assertEqual(_resolve_lang(request), "en")


if __name__ == "__main__":
    unittest.main()
