"""Plugin base classes and registry for extensible attacks and defenses."""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class PluginMetadata:
    name: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    category: str = ""


class AttackPlugin(ABC):
    """Base class for attack plugins."""

    metadata: PluginMetadata

    @abstractmethod
    def generate(self, target: str, **kwargs: Any) -> str:
        """Generate an adversarial variant of the target text."""
        ...

    def list_techniques(self) -> list[str]:
        return ["default"]


class DefensePlugin(ABC):
    """Base class for defense plugins."""

    metadata: PluginMetadata

    @abstractmethod
    def analyze(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze text and return detection results."""
        ...


@dataclass
class PluginRegistry:
    attacks: dict[str, type[AttackPlugin]] = field(default_factory=dict)
    defenses: dict[str, type[DefensePlugin]] = field(default_factory=dict)

    def register_attack(self, cls: type[AttackPlugin]) -> None:
        name = cls.metadata.name if hasattr(cls, "metadata") else cls.__name__
        self.attacks[name] = cls
        log.debug("plugin.registered", type="attack", name=name)

    def register_defense(self, cls: type[DefensePlugin]) -> None:
        name = cls.metadata.name if hasattr(cls, "metadata") else cls.__name__
        self.defenses[name] = cls
        log.debug("plugin.registered", type="defense", name=name)

    def discover(self, search_path: str | Path | None = None) -> int:
        """Discover plugins from a directory or Python package."""
        count = 0
        if search_path:
            count += self._discover_directory(Path(search_path))
        count += self._discover_builtins()
        return count

    def _discover_directory(self, path: Path) -> int:
        if not path.exists():
            return 0
        count = 0
        for module_info in pkgutil.iter_modules([str(path)]):
            try:
                spec = importlib.util.spec_from_file_location(
                    f"plugins.{module_info.name}",
                    str(path / f"{module_info.name}.py"),
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    count += 1
            except Exception:
                log.warning("plugin.load_failed", module=module_info.name)
        return count

    def _discover_builtins(self) -> int:
        count = 0
        for _, module_name, _ in pkgutil.iter_modules(["src/attacks", "src/defenses"]):
            try:
                mod = importlib.import_module(f"src.attacks.{module_name}")
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, AttackPlugin)
                        and obj is not AttackPlugin
                    ):
                        self.register_attack(obj)
                        count += 1
            except Exception:
                pass
        return count

    def list_attacks(self) -> list[dict[str, str]]:
        return [
            {"name": name, "category": getattr(cls, "metadata", PluginMetadata(name=name)).category}
            for name, cls in self.attacks.items()
        ]

    def list_defenses(self) -> list[dict[str, str]]:
        return [
            {"name": name, "category": getattr(cls, "metadata", PluginMetadata(name=name)).category}
            for name, cls in self.defenses.items()
        ]


_GLOBAL_REGISTRY = PluginRegistry()


def get_registry() -> PluginRegistry:
    return _GLOBAL_REGISTRY
