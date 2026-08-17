from __future__ import annotations

from collections.abc import Iterable

from .base import AssessmentPlugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, AssessmentPlugin] = {}

    def register(self, plugin: AssessmentPlugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"duplicate plugin: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> AssessmentPlugin:
        return self._plugins[name]

    def all(self) -> list[AssessmentPlugin]:
        return list(self._plugins.values())

    def select(
        self, include: Iterable[str] | None = None, exclude: Iterable[str] | None = None
    ) -> list[AssessmentPlugin]:
        includes = set(include or self._plugins)
        excludes = set(exclude or [])
        unknown = includes.difference(self._plugins)
        if unknown:
            raise ValueError(f"unknown plugins: {', '.join(sorted(unknown))}")
        return [p for name, p in self._plugins.items() if name in includes and name not in excludes]


def build_default_registry() -> PluginRegistry:
    from .builtins import BUILTIN_PLUGINS
    from .external import EXTERNAL_PLUGINS

    registry = PluginRegistry()
    for plugin_type in (*BUILTIN_PLUGINS, *EXTERNAL_PLUGINS):
        registry.register(plugin_type())
    return registry
