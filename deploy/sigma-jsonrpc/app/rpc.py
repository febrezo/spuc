from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from app.config import Settings
from app.engine import SigmaEngine
from app.errors import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    SERVER_SIGMA_ERROR,
    SERVER_SIZE_ERROR,
    SERVER_TIMEOUT_ERROR,
    RpcException,
    SigmaEngineException,
    SigmaInputException,
    SigmaTimeoutException,
)
from app.models import JsonRpcDiscoverResult

logger = logging.getLogger(__name__)


RpcMethod = Callable[[dict[str, Any]], Any]


class RpcDispatcher:
    def __init__(self, settings: Settings, engine: SigmaEngine) -> None:
        self.settings = settings
        self.engine = engine
        self._methods: dict[str, RpcMethod] = {
            'rpc.discover': self._rpc_discover,
            'sigma.plugins.list': self._sigma_plugins_list,
            'sigma.backends.list': self._sigma_backends_list,
            'sigma.pipelines.list': self._sigma_pipelines_list,
            'sigma.validate': self._sigma_validate,
            'sigma.convert': self._sigma_convert,
        }

    @property
    def supported_methods(self) -> list[str]:
        return sorted(self._methods.keys())

    def dispatch(self, method: str, params: Any) -> Any:
        handler = self._methods.get(method)
        if handler is None:
            raise RpcException(METHOD_NOT_FOUND, f"Method not found: {method}")

        safe_params = {} if params is None else params
        if not isinstance(safe_params, dict):
            raise RpcException(INVALID_PARAMS, 'params must be an object')

        logger.info('rpc method invoked: %s', method)
        try:
            return handler(safe_params)
        except RpcException:
            raise
        except SigmaTimeoutException as exc:
            raise RpcException(SERVER_TIMEOUT_ERROR, 'sigma command timeout', {'detail': str(exc)}) from exc
        except SigmaInputException as exc:
            code = SERVER_SIZE_ERROR if 'MAX_RULE_SIZE_BYTES' in str(exc) else INVALID_PARAMS
            raise RpcException(code, str(exc)) from exc
        except SigmaEngineException as exc:
            raise RpcException(SERVER_SIGMA_ERROR, 'sigma engine error', {'detail': str(exc)}) from exc
        except Exception as exc:
            logger.exception('unexpected internal error in method %s', method)
            raise RpcException(INTERNAL_ERROR, 'internal error') from exc

    def _rpc_discover(self, _params: dict[str, Any]) -> dict[str, Any]:
        result = JsonRpcDiscoverResult(
            service=self.settings.service_name,
            version=self.settings.service_version,
            description=self.settings.service_description,
            jsonrpc_endpoint=self.settings.jsonrpc_endpoint,
            requires_authentication=self.settings.auth_enabled,
            methods=self.supported_methods,
            active_capabilities={
                'allowlist_backends': sorted(self.settings.allowed_backends),
                'allowlist_pipelines': sorted(self.settings.allowed_pipelines),
                'max_rule_size_bytes': self.settings.max_rule_size_bytes,
                'command_timeout_seconds': self.settings.sigma_command_timeout,
                'sigma_available': self.engine.sigma_available(),
            },
        )
        return result.model_dump()

    def _sigma_plugins_list(self, _params: dict[str, Any]) -> dict[str, Any]:
        plugins = [item.model_dump() for item in self.engine.list_plugins()]
        return {'items': plugins, 'count': len(plugins)}

    def _sigma_backends_list(self, _params: dict[str, Any]) -> dict[str, Any]:
        backends = self.engine.list_backends()
        return {'items': backends, 'count': len(backends)}

    def _sigma_pipelines_list(self, _params: dict[str, Any]) -> dict[str, Any]:
        pipelines = self.engine.list_pipelines()
        return {'items': pipelines, 'count': len(pipelines)}

    def _sigma_validate(self, params: dict[str, Any]) -> dict[str, Any]:
        rule = _pick_rule(params)
        return self.engine.validate_rule(rule).model_dump()

    def _sigma_convert(self, params: dict[str, Any]) -> dict[str, Any]:
        rule = _pick_rule(params)
        target = _required_string(params, 'target')
        pipeline = _optional_string(params, 'pipeline')
        output_format = _optional_string(params, 'format')
        return self.engine.convert_rule(rule, target=target, pipeline=pipeline, output_format=output_format)


def _pick_rule(params: dict[str, Any]) -> str:
    value = params.get('rule')
    if value is None:
        value = params.get('rule_text')
    if value is None:
        raise RpcException(INVALID_PARAMS, "missing required field 'rule'")
    text = str(value).strip()
    if not text:
        raise RpcException(INVALID_PARAMS, "field 'rule' cannot be empty")
    return text


def _required_string(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if value is None:
        raise RpcException(INVALID_PARAMS, f"missing required field '{key}'")
    text = str(value).strip()
    if not text:
        raise RpcException(INVALID_PARAMS, f"field '{key}' cannot be empty")
    return text


def _optional_string(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None
