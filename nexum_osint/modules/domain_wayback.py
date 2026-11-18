"""Historial del dominio en Internet Archive (Wayback Machine)."""
from ..core.entities import Kind, registrable
from ..core.module import Module


class Wayback(Module):
    name = "wayback"
    description = "Primera y última captura archivada y URLs históricas interesantes"
    consumes = (Kind.DOMAIN,)
    rate = 1
    hosts = ("web.archive.org",)

    INTERESTING = ("admin", "login", "backup", ".sql", ".zip", ".env", "config",
                   "phpinfo", ".git", "dump", "old", "test", "api")

    async def run(self, ctx, node):
        if node.value != registrable(node.value):
            return
        resp = await ctx.http.get("https://web.archive.org/cdx/search/cdx", params={
            "url": f"{node.value}/*", "output": "json", "fl": "timestamp,original,statuscode",
            "collapse": "urlkey", "limit": "3000", "filter": "statuscode:200"},
            ttl=24 * 3600, retries=1)
        if not resp.ok or not resp.text.strip():
            return
        rows = resp.json()[1:]
        if not rows:
            return
        stamps = sorted(r[0] for r in rows)
        node.attrs["wayback_first"] = stamps[0][:8]
        node.attrs["wayback_last"] = stamps[-1][:8]
        node.attrs["wayback_urls"] = len(rows)

        hits = sorted({r[1] for r in rows if any(k in r[1].lower() for k in self.INTERESTING)})
        if hits:
            ctx.graph.note(self.name, f"{len(hits)} URLs históricas de interés",
                           "\n".join(hits[:25]), "low", node)
