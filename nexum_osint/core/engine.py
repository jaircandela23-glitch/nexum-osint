"""Motor de investigación.

Parte de una o más entidades semilla, ejecuta en paralelo todos los módulos
aplicables y usa lo que se descubre como nueva entrada (pivoteo) hasta la
profundidad indicada.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from .entities import Graph, Kind, Node
from .http import Http
from .module import Context, Module
from .scope import in_scope, is_freemail, root_of


@dataclass
class RunStats:
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    executed: int = 0
    errors: list[dict] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        return (self.finished or time.time()) - self.started


class Engine:
    def __init__(self, http: Http, graph: Graph, config, modules: dict[str, Module],
                 depth: int = 1, concurrency: int = 20, allow_active: bool = False,
                 on_event: Callable[[str, dict], None] | None = None,
                 options: dict | None = None, tor_http: Http | None = None) -> None:
        self.http = http
        self.options = options or {}
        self.tor_http = tor_http
        self.graph = graph
        self.config = config
        self.depth = depth
        self.allow_active = allow_active
        self.on_event = on_event or (lambda kind, data: None)
        self.stats = RunStats()
        self.modules = {}
        for name, mod in modules.items():
            if not mod.available(config):
                self.stats.skipped.append(f"{name} (falta API key '{mod.needs_key}')")
            elif mod.darkweb and not (self.options.get("darkweb") and tor_http):
                self.stats.skipped.append(f"{name} (dark web: usa --darkweb)")
            elif mod.active and not allow_active:
                self.stats.skipped.append(f"{name} (módulo activo, usa --active)")
            else:
                self.modules[name] = mod
        self._sem = asyncio.Semaphore(concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._seen: set[tuple[str, str]] = set()
        self.scope: set[str] = set()
        self.ctx = Context(http, graph, config, self)
        for mod in self.modules.values():
            for host in mod.hosts:
                if mod.rate:
                    http.limiter.configure(host, mod.rate)

    def _add_scope(self, kind: Kind, value: str) -> None:
        """Registra los dominios que pertenecen al objetivo (semillas, no proveedores de correo)."""
        if kind is Kind.DOMAIN:
            host = value
        elif kind is Kind.EMAIL:
            host = value.split("@", 1)[1]
        elif kind is Kind.URL:
            from urllib.parse import urlsplit
            host = urlsplit(value).hostname or ""
        else:
            return
        if host and not is_freemail(host):
            self.scope.add(root_of(host))

    def _allowed(self, mod: Module, node: Node) -> bool:
        """Un dominio ajeno al objetivo solo se resuelve por DNS: nada activo ni pivoteo masivo."""
        if node.kind is not Kind.DOMAIN or node.depth == 0:
            return True
        if is_freemail(node.value):
            return False
        if in_scope(node.value, self.scope):
            return True
        return mod.name == "dns"

    def schedule(self, node: Node) -> None:
        if node.depth > self.depth:
            return
        for mod in self.modules.values():
            if node.kind not in mod.consumes or not self._allowed(mod, node):
                continue
            key = (mod.name, node.key)
            if key in self._seen:
                continue
            self._seen.add(key)
            task = asyncio.create_task(self._execute(mod, node))
            self._tasks.add(task)

    async def _execute(self, mod: Module, node: Node) -> None:
        async with self._sem:
            started = time.monotonic()
            self.on_event("start", {"module": mod.name, "target": node.value})
            try:
                await mod.run(self.ctx, node)
                self.on_event("done", {"module": mod.name, "target": node.value})
            except Exception as exc:
                self.stats.errors.append({
                    "module": mod.name, "target": node.value,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                self.on_event("error", {"module": mod.name, "target": node.value,
                                        "error": str(exc)})
            finally:
                self.stats.executed += 1
                self.stats.timings[mod.name] = (
                    self.stats.timings.get(mod.name, 0.0) + time.monotonic() - started
                )

    async def run(self, seeds: list[tuple[Kind, str]]) -> Graph:
        for kind, value in seeds:
            self._add_scope(kind, value)
        for kind, value in seeds:
            node, _ = self.graph.add(kind, value, source="seed", depth=0)
            self.schedule(node)
        while self._tasks:
            done, _ = await asyncio.wait(set(self._tasks), return_when=asyncio.FIRST_COMPLETED)
            self._tasks -= done
        self.stats.finished = time.time()
        return self.graph
