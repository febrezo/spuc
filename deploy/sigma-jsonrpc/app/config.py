from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', case_sensitive=False)

    service_name: str = Field(default='sigma-jsonrpc')
    service_version: str = Field(default='2.0.0')
    service_description: str = Field(default='Sigma JSON-RPC 2.0 microservice over HTTP')

    host: str = Field(default='0.0.0.0')
    port: int = Field(default=8080)
    log_level: str = Field(default='INFO')

    sigma_binary: str = Field(default='sigma')
    sigma_command_timeout: int = Field(default=20, alias='SIGMA_COMMAND_TIMEOUT')
    max_rule_size_bytes: int = Field(default=131072, alias='MAX_RULE_SIZE_BYTES')
    discovery_cache_ttl_seconds: int = Field(default=60, alias='SIGMA_DISCOVERY_CACHE_TTL_SECONDS')

    sigma_rpc_token: str | None = Field(default=None, alias='SIGMA_RPC_TOKEN')
    auth_required: bool = Field(default=True, alias='SIGMA_AUTH_REQUIRED')
    allow_insecure_without_token: bool = Field(default=True, alias='SIGMA_ALLOW_INSECURE_WITHOUT_TOKEN')

    sigma_allowed_backends: str = Field(default='', alias='SIGMA_ALLOWED_BACKENDS')
    sigma_allowed_pipelines: str = Field(default='', alias='SIGMA_ALLOWED_PIPELINES')

    def startup_validation(self) -> None:
        # Keep hook for future validation rules.
        return

    @property
    def jsonrpc_endpoint(self) -> str:
        return '/jsonrpc'

    @property
    def allowed_backends(self) -> set[str]:
        return _csv_to_set(self.sigma_allowed_backends)

    @property
    def allowed_pipelines(self) -> set[str]:
        return _csv_to_set(self.sigma_allowed_pipelines)

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_required and self.sigma_rpc_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.startup_validation()
    return settings


def _csv_to_set(value: str | Iterable[str]) -> set[str]:
    if isinstance(value, str):
        items = value.split(',')
    else:
        items = list(value)
    return {item.strip().lower() for item in items if item and item.strip()}
