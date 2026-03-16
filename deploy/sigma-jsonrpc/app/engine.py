from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass

from app.config import Settings
from app.errors import SigmaEngineException, SigmaInputException, SigmaTimeoutException
from app.models import PluginInfo, ValidateResult

logger = logging.getLogger(__name__)

_SAFE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


@dataclass
class _PluginCache:
    expires_at: float
    items: list[PluginInfo]


class SigmaEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._plugins_cache: _PluginCache | None = None

    def sigma_available(self) -> bool:
        try:
            completed = self._run_sigma(['--help'], timeout=5)
            return completed.returncode == 0
        except Exception:
            return False

    def list_plugins(self) -> list[PluginInfo]:
        now = time.time()
        if self._plugins_cache and self._plugins_cache.expires_at > now:
            return self._plugins_cache.items

        completed = self._run_sigma(['plugin', 'list'])
        if completed.returncode != 0:
            raise SigmaEngineException(_safe_err(completed.stderr, 'sigma plugin list failed'))

        plugins = _parse_plugin_table(completed.stdout)
        self._plugins_cache = _PluginCache(
            expires_at=now + max(1, self.settings.discovery_cache_ttl_seconds),
            items=plugins,
        )
        return plugins

    def list_backends(self) -> list[str]:
        entries = [p.identifier for p in self.list_plugins() if p.plugin_type == 'backend']
        allow = self.settings.allowed_backends
        if allow:
            entries = [item for item in entries if item.lower() in allow]
        return sorted(set(entries))

    def list_pipelines(self) -> list[str]:
        entries = [p.identifier for p in self.list_plugins() if p.plugin_type == 'pipeline']
        allow = self.settings.allowed_pipelines
        if allow:
            entries = [item for item in entries if item.lower() in allow]
        return sorted(set(entries))

    def validate_rule(self, rule_text: str) -> ValidateResult:
        self._validate_rule_size(rule_text)
        with _temp_rule_file(rule_text) as rule_path:
            validate_run = self._run_sigma(['validate', rule_path], allow_validate_fallback=True)
            if validate_run.returncode == 0:
                return ValidateResult(valid=True, errors=[], warnings=[])

            # Some sigma-cli versions may not expose `validate`; fallback to convert-to-sigma check.
            fallback_run = self._run_sigma(['convert', '-t', 'sigma', rule_path])
            if fallback_run.returncode == 0:
                return ValidateResult(valid=True, errors=[], warnings=[])

            error_text = _safe_err(fallback_run.stderr or validate_run.stderr, 'rule validation failed')
            return ValidateResult(valid=False, errors=[error_text], warnings=[])

    def convert_rule(
        self,
        rule_text: str,
        target: str,
        pipeline: str | None = None,
        output_format: str | None = None,
    ) -> dict:
        self._validate_rule_size(rule_text)
        target = self._validate_identifier(target, field='target')

        allow_backends = self.settings.allowed_backends
        if allow_backends and target.lower() not in allow_backends:
            raise SigmaInputException(
                f"target '{target}' is not allowed by SIGMA_ALLOWED_BACKENDS"
            )

        args = ['convert', '-t', target]
        if pipeline:
            pipeline = self._validate_identifier(pipeline, field='pipeline')
            allow_pipelines = self.settings.allowed_pipelines
            if allow_pipelines and pipeline.lower() not in allow_pipelines:
                raise SigmaInputException(
                    f"pipeline '{pipeline}' is not allowed by SIGMA_ALLOWED_PIPELINES"
                )
            args.extend(['-p', pipeline])

        if output_format:
            output_format = self._validate_identifier(output_format, field='format')
            args.extend(['-f', output_format])

        with _temp_rule_file(rule_text) as rule_path:
            args.append(rule_path)
            completed = self._run_sigma(args)

        if completed.returncode != 0:
            raise SigmaEngineException(_safe_err(completed.stderr, 'sigma convert failed'))

        query = (completed.stdout or '').strip()
        if not query:
            raise SigmaEngineException('sigma convert returned empty output')

        return {
            'target': target,
            'query': query,
            'pipeline': pipeline,
            'format': output_format,
            'metadata': {
                'engine': 'sigma-cli',
                'timeout_seconds': self.settings.sigma_command_timeout,
            },
        }

    def _run_sigma(
        self,
        args: list[str],
        *,
        timeout: int | None = None,
        allow_validate_fallback: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.settings.sigma_binary, *args]
        timeout_seconds = timeout or self.settings.sigma_command_timeout
        logger.info('sigma command invoked: %s', ' '.join(command[:3]))
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            logger.error('sigma command timeout after %ss: %s', timeout_seconds, args[:2])
            raise SigmaTimeoutException(f'sigma command timed out after {timeout_seconds}s') from exc
        except FileNotFoundError as exc:
            raise SigmaEngineException(
                f"sigma binary '{self.settings.sigma_binary}' not found"
            ) from exc
        except Exception as exc:
            if allow_validate_fallback:
                return subprocess.CompletedProcess(command, returncode=2, stdout='', stderr=str(exc))
            raise SigmaEngineException(f'sigma execution failed: {exc}') from exc

    def _validate_rule_size(self, rule_text: str) -> None:
        if len(rule_text.encode('utf-8')) > self.settings.max_rule_size_bytes:
            raise SigmaInputException(
                f'rule exceeds MAX_RULE_SIZE_BYTES={self.settings.max_rule_size_bytes}'
            )

    def _validate_identifier(self, value: str, *, field: str) -> str:
        cleaned = (value or '').strip()
        if not cleaned or not _SAFE_IDENTIFIER_RE.match(cleaned):
            raise SigmaInputException(
                f"invalid {field}: must match [a-zA-Z0-9_-]+"
            )
        return cleaned


class _temp_rule_file:
    def __init__(self, content: str) -> None:
        self.content = content
        self.path = ''

    def __enter__(self) -> str:
        fd, self.path = tempfile.mkstemp(prefix='sigma_rpc_', suffix='.yml')
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(self.content)
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.path and os.path.exists(self.path):
            os.unlink(self.path)


def _safe_err(raw: str | None, fallback: str) -> str:
    value = (raw or '').strip()
    return value[:500] if value else fallback


def _parse_plugin_table(stdout: str) -> list[PluginInfo]:
    lines = stdout.splitlines()
    rows = [_split_table_row(line) for line in lines]

    header_idx = -1
    header_map: dict[str, int] = {}
    for idx, row in enumerate(rows):
        if not row or _is_separator_row(row):
            continue
        normalized = [_normalize_header(cell) for cell in row]
        if 'type' in normalized and any(item in normalized for item in ('id', 'identifier', 'name')):
            header_idx = idx
            header_map['type'] = normalized.index('type')
            for key in ('id', 'identifier', 'name'):
                if key in normalized:
                    header_map['identifier'] = normalized.index(key)
                    break
            if 'compatible' in normalized:
                header_map['compatible'] = normalized.index('compatible')
            if 'description' in normalized:
                header_map['description'] = normalized.index('description')
            break

    if header_idx == -1 or 'identifier' not in header_map:
        return _fallback_plugins_parse(lines)

    parsed: list[PluginInfo] = []
    for row in rows[header_idx + 1 :]:
        if not row or _is_separator_row(row):
            continue
        try:
            plugin_type = (row[header_map['type']] if header_map.get('type') is not None else '').strip().lower()
            identifier = row[header_map['identifier']].strip().lower()
        except Exception:
            continue

        if not plugin_type or not identifier:
            continue

        compatible = None
        if 'compatible' in header_map and header_map['compatible'] < len(row):
            compatible = _parse_boolish(row[header_map['compatible']])

        description = ''
        if 'description' in header_map and header_map['description'] < len(row):
            description = row[header_map['description']].strip()

        canonical = _canonical_plugin_type(plugin_type)
        parsed.append(
            PluginInfo(
                plugin_type=canonical,
                identifier=identifier,
                compatible=compatible,
                description=description,
            )
        )

    dedup: dict[tuple[str, str], PluginInfo] = {}
    for item in parsed:
        dedup[(item.plugin_type, item.identifier)] = item
    return list(dedup.values())


def _fallback_plugins_parse(lines: list[str]) -> list[PluginInfo]:
    out: list[PluginInfo] = []
    for line in lines:
        parts = [part.strip() for part in re.split(r'\s{2,}|\t|\||│', line) if part.strip()]
        if len(parts) < 2:
            continue
        plugin_type = _canonical_plugin_type(parts[0])
        if plugin_type == 'unknown':
            continue
        out.append(PluginInfo(plugin_type=plugin_type, identifier=parts[1].lower()))
    dedup: dict[tuple[str, str], PluginInfo] = {}
    for item in out:
        dedup[(item.plugin_type, item.identifier)] = item
    return list(dedup.values())


def _split_table_row(line: str) -> list[str]:
    if '│' in line:
        return [cell.strip() for cell in line.split('│') if cell.strip()]
    if '|' in line:
        return [cell.strip() for cell in line.split('|') if cell.strip()]
    return []


def _is_separator_row(row: list[str]) -> bool:
    return all(re.match(r'^[\-\+=─━┼┤├┘└┐┌ ]+$', cell or '') for cell in row)


def _normalize_header(value: str) -> str:
    return value.strip().lower().replace(' ', '_')


def _parse_boolish(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {'true', 'yes', '1', 'y', '✓'}:
        return True
    if normalized in {'false', 'no', '0', 'n', '✗'}:
        return False
    return None


def _canonical_plugin_type(value: str) -> str:
    normalized = value.strip().lower()
    if 'backend' in normalized:
        return 'backend'
    if 'pipeline' in normalized:
        return 'pipeline'
    if 'validator' in normalized:
        return 'validator'
    return 'unknown'
