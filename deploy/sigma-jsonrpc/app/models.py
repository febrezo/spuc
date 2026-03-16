from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class JsonRpcRequest(BaseModel):
    jsonrpc: str
    method: str
    params: dict[str, Any] | list[Any] | None = None
    id: str | int | None = None

    @field_validator('jsonrpc')
    @classmethod
    def validate_jsonrpc(cls, value: str) -> str:
        if value != '2.0':
            raise ValueError("jsonrpc must be '2.0'")
        return value


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JsonRpcResponse(BaseModel):
    jsonrpc: str = '2.0'
    id: str | int | None = None
    result: Any | None = None
    error: JsonRpcError | None = None


class JsonRpcDiscoverResult(BaseModel):
    service: str
    version: str
    description: str
    jsonrpc_endpoint: str
    requires_authentication: bool
    methods: list[str]
    active_capabilities: dict[str, Any]


class PluginInfo(BaseModel):
    plugin_type: str
    identifier: str
    compatible: bool | None = None
    description: str = ''


class ValidateResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ConvertResult(BaseModel):
    target: str
    query: str
    pipeline: str | None = None
    format: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    sigma_available: bool


class VersionResponse(BaseModel):
    service: str
    version: str
