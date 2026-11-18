"""Búsqueda de menciones en índices de dark web, a través de Tor."""
from __future__ import annotations

import asyncio
from urllib.parse import quote_plus

from ..core.entities import Kind
from ..core.links import manual
from ..core.module import Module
from ..darkweb.sources import PARSERS, load_sources


class DarkwebIndex(Module):
    name = "darkweb_index"
    description = "Menciones del objetivo en índices .onion vía Tor (requiere --darkweb y entorno verificado)"
    consumes = (Kind.EMAIL, Kind.DOMAIN, Kind.USERNAME, Kind.NAME, Kind.PHONE)
    darkweb = True
    rate = 0.5

    def _term(self, node) -> str:
        if node.kind is Kind.NAME:
            return f'"{node.value}"'
        return node.value.lstrip("+") if node.kind is Kind.PHONE else node.value

    async def run(self, ctx, node):
        tor = ctx.engine.tor_http
        if tor is None:
            return
        term = self._term(node)
        sources = load_sources()

        async def query(src):
            parse = PARSERS.get(src.get("parser", "generic"), PARSERS["generic"])
            try:
                r = await tor.get(src["url"].format(q=quote_plus(term)), ttl=3600, retries=1)
            except ConnectionError as exc:
                return src, None, str(exc)
            return src, (parse(r.text) if r.ok else None), f"HTTP {r.status}"

        total = 0
        for src, hits, err in await asyncio.gather(*(query(s) for s in sources)):
            if hits is None:
                ctx.graph.note(self.name, f"{src['name']}: sin respuesta", err[:140], "info", node)
                continue
            for h in hits:
                ctx.emit(node, Kind.URL, h["url"], "darkweb_mention", self.name, pivot=False,
                         darkweb=True, title=h["title"], snippet=h["snippet"], index=src["name"])
            total += len(hits)
        node.attrs["darkweb_mentions"] = total
        if total:
            ctx.graph.note(self.name, f"{total} mención(es) de «{node.value}» en índices de dark web",
                           "Son resultados de un índice, no contenido verificado. No abras los enlaces fuera de "
                           "Tor Browser ni descargues archivos. Confirma por una fuente legítima antes de actuar.",
                           "high", node)
        manual(ctx, node, self.name, "Ahmia (navegador común, sin acceder a .onion)",
               f"https://ahmia.fi/search/?q={quote_plus(term)}", "darkweb_manual")
