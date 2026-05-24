"""Plugin system for extensible attacks and defenses."""

from src.plugins.base import (
    AttackPlugin,
    DefensePlugin,
    PluginMetadata,
    PluginRegistry,
    get_registry,
)
from src.plugins.builtins import register_all

__all__ = [
    "AttackPlugin",
    "DefensePlugin",
    "PluginMetadata",
    "PluginRegistry",
    "get_registry",
    "register_all",
]
