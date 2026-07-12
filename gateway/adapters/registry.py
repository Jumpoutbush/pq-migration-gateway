"""Adapter registry; external adapters can be registered without core edits."""
from __future__ import annotations

import importlib
import os

from gateway.model import ConfigError
from .base import ProtocolAdapter
from .http import HttpAdapter
from .stream import AmqpAdapter, KafkaAdapter, LegacyLineAdapter, MqttAdapter, MysqlAdapter, PostgresAdapter, RedisAdapter, StreamAdapter, TcpAdapter


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ProtocolAdapter] = {}

    def register(self, adapter: ProtocolAdapter, *, replace: bool = False) -> None:
        if adapter.name in self._adapters and not replace:
            raise ConfigError(f"adapter already registered: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ProtocolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ConfigError(f"unsupported protocol adapter: {name}") from exc

    def names(self) -> list[str]:
        return sorted(self._adapters)


def default_registry(plugin_specs: list[str] | None = None) -> AdapterRegistry:
    registry = AdapterRegistry()
    for cls in (HttpAdapter, StreamAdapter, MqttAdapter, TcpAdapter, LegacyLineAdapter, PostgresAdapter, MysqlAdapter, RedisAdapter, KafkaAdapter, AmqpAdapter):
        registry.register(cls())
    specs = plugin_specs
    if specs is None:
        specs = [item.strip() for item in os.environ.get("PQ_GATEWAY_ADAPTERS", "").split(",") if item.strip()]
    for spec in specs:
        module_name, separator, class_name = spec.partition(":")
        if not separator:
            raise ConfigError(f"external adapter must use module:Class syntax: {spec}")
        adapter_type = getattr(importlib.import_module(module_name), class_name)
        adapter = adapter_type()
        if not isinstance(adapter, ProtocolAdapter):
            raise ConfigError(f"external adapter does not implement ProtocolAdapter: {spec}")
        registry.register(adapter)
    return registry
