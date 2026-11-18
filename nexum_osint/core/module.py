"""Base de los plugins y descubrimiento automático de módulos.

Para agregar una fuente nueva basta con soltar un archivo en `modules/`
(o en ~/.config/nexum-osint/plugins/) con una clase que herede de `Module`.
"""
from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .config import Config, config_dir
from .entities import Graph, Kind, Node
from .http import Http

if TYPE_CHECKING:
    from .engine import Engine


@dataclass
class Context:
    """Lo que recibe cada módulo al ejecutarse."""
    http: Http
    graph: Graph
    config: Config
    engine: "Engine"

    def emit(self, parent: Node, kind: Kind, value: str, relation: str, source: str,
             pivot: bool = True, **attrs) -> Node | None:
        """Registra una entidad descubierta, la enlaza al padre y la encola para pivotar."""
        try:
            node, created = self.graph.add(kind, value, source=source,
                                           depth=parent.depth + 1, **attrs)
        except ValueError:  # valor inválido (por ejemplo, una IP mal formada)
            return None
        self.graph.link(parent, node, relation, source)
        if created and pivot:
            self.engine.schedule(node)
        return node


class Module:
    """Una fuente de información. Se ejecuta sobre entidades de los tipos en `consumes`."""

    name: str = ""
    description: str = ""
    consumes: tuple[Kind, ...] = ()
    needs_key: str | None = None   # nombre de la API key si es obligatoria
    optional_key: str | None = None
    rate: float | None = None      # peticiones por segundo hacia el host de la API
    hosts: tuple[str, ...] = ()    # hosts a los que aplica `rate`
    active: bool = False           # True si toca directamente al objetivo
    darkweb: bool = False          # True si requiere Tor (solo con --darkweb y entorno verificado)

    async def run(self, ctx: Context, node: Node) -> None:
        raise NotImplementedError

    def available(self, config: Config) -> bool:
        return self.needs_key is None or bool(config.key(self.needs_key))


def _collect(mod) -> list[type[Module]]:
    found = []
    for obj in vars(mod).values():
        if (isinstance(obj, type) and issubclass(obj, Module) and obj is not Module
                and obj.__module__ == mod.__name__ and obj.name):
            found.append(obj)
    return found


def discover(extra_dirs: list[Path] | None = None) -> dict[str, Module]:
    """Carga todos los módulos internos y los plugins externos."""
    from .. import modules as pkg

    registry: dict[str, Module] = {}
    for info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
        for cls in _collect(mod):
            registry[cls.name] = cls()

    dirs = [config_dir() / "plugins"] + list(extra_dirs or [])
    for d in dirs:
        if not d.is_dir():
            continue
        for file in sorted(d.glob("*.py")):
            spec = importlib.util.spec_from_file_location(f"nexum_plugin_{file.stem}", file)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            try:
                spec.loader.exec_module(mod)
            except Exception as exc:
                print(f"[!] plugin {file.name} no se pudo cargar: {exc}", file=sys.stderr)
                continue
            for cls in _collect(mod):
                registry[cls.name] = cls()
    return dict(sorted(registry.items()))
