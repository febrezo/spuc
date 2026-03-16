import unittest

from app.config import Settings
from app.errors import INVALID_PARAMS, METHOD_NOT_FOUND, RpcException
from app.rpc import RpcDispatcher


class FakeEngine:
    def sigma_available(self) -> bool:
        return True

    def list_plugins(self):
        return []

    def list_backends(self):
        return ["splunk"]

    def list_pipelines(self):
        return []

    def validate_rule(self, rule_text: str):
        class _Result:
            def model_dump(self):
                return {"valid": bool(rule_text), "errors": [], "warnings": []}

        return _Result()

    def convert_rule(self, rule_text: str, target: str, pipeline=None, output_format=None):
        return {
            "target": target,
            "query": f"converted:{rule_text[:8]}",
            "pipeline": pipeline,
            "format": output_format,
            "metadata": {},
        }


class RpcDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        settings = Settings()
        self.dispatcher = RpcDispatcher(settings, FakeEngine())

    def test_unknown_method_returns_method_not_found(self) -> None:
        with self.assertRaises(RpcException) as ctx:
            self.dispatcher.dispatch("unknown.method", {})
        self.assertEqual(ctx.exception.code, METHOD_NOT_FOUND)

    def test_non_object_params_return_invalid_params(self) -> None:
        with self.assertRaises(RpcException) as ctx:
            self.dispatcher.dispatch("rpc.discover", ["bad"])
        self.assertEqual(ctx.exception.code, INVALID_PARAMS)

    def test_convert_missing_target_is_invalid_params(self) -> None:
        with self.assertRaises(RpcException) as ctx:
            self.dispatcher.dispatch(
                "sigma.convert",
                {"rule": "title: test\ndetection:\n  condition: true"},
            )
        self.assertEqual(ctx.exception.code, INVALID_PARAMS)

    def test_convert_success(self) -> None:
        result = self.dispatcher.dispatch(
            "sigma.convert",
            {
                "rule": "title: test\ndetection:\n  condition: true",
                "target": "splunk",
            },
        )
        self.assertEqual(result["target"], "splunk")
        self.assertIn("query", result)

    def test_discover_returns_expected_contract(self) -> None:
        result = self.dispatcher.dispatch("rpc.discover", {})
        self.assertIn("service", result)
        self.assertIn("version", result)
        self.assertIn("jsonrpc_endpoint", result)
        self.assertIn("methods", result)
        self.assertIn("sigma.convert", result["methods"])


if __name__ == "__main__":
    unittest.main()
