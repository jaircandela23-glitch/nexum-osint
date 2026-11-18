import json
import re

from ..core.entities import Kind, registrable
from ..core.module import Module

INTERESTING = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".sql", ".bak", ".zip", ".env", ".log", ".conf", ".pptx")


class Anubis(Module):
    name = "anubis"
    description = "Subdominios del dominio según la base abierta de Anubis (sin key)"
    consumes = (Kind.DOMAIN,)
    rate = 1
    hosts = ("jldc.me",)

    async def run(self, ctx, node):
        if registrable(node.value) != node.value:
            return
        r = await ctx.http.get(f"https://jldc.me/anubis/subdomains/{node.value}", ttl=12 * 3600)
        if r.ok:
            try:
                subs = r.json()
            except ValueError:
                return
            for s in sorted({x.lower() for x in subs if isinstance(x, str)})[:300]:
                if s.endswith("." + node.value):
                    ctx.emit(node, Kind.DOMAIN, s, "subdomain_of", self.name)


class RapidDns(Module):
    name = "rapiddns"
    description = "Subdominios del dominio desde RapidDNS (sin key)"
    consumes = (Kind.DOMAIN,)
    rate = 0.5
    hosts = ("rapiddns.io",)

    async def run(self, ctx, node):
        if registrable(node.value) != node.value:
            return
        r = await ctx.http.get(f"https://rapiddns.io/subdomain/{node.value}", params={"full": 1}, ttl=12 * 3600)
        if r.ok:
            pat = re.compile(r"<td>([a-z0-9._-]+\." + re.escape(node.value) + r")</td>", re.I)
            for s in sorted({m.lower() for m in pat.findall(r.text)})[:300]:
                ctx.emit(node, Kind.DOMAIN, s, "subdomain_of", self.name)


class CommonCrawl(Module):
    name = "commoncrawl"
    description = "URLs y archivos del dominio rastreados por Common Crawl (sin key)"
    consumes = (Kind.DOMAIN,)
    rate = 0.5
    hosts = ("index.commoncrawl.org",)

    async def run(self, ctx, node):
        if registrable(node.value) != node.value:
            return
        info = await ctx.http.get("https://index.commoncrawl.org/collinfo.json", ttl=24 * 3600)
        if not info.ok or not (cols := info.json()):
            return
        r = await ctx.http.get(cols[0]["cdx-api"], params={"url": f"*.{node.value}", "output": "json",
                               "fl": "url", "limit": 400}, ttl=12 * 3600, retries=1)
        if not r.ok:
            return
        urls = []
        for line in r.text.splitlines():
            try:
                urls.append(json.loads(line)["url"])
            except (ValueError, KeyError):
                continue
        hosts = {u.split("/")[2].split(":")[0].lower() for u in urls if u.count("/") >= 2}
        for h in sorted(hosts):
            if h.endswith("." + node.value) and h != node.value:
                ctx.emit(node, Kind.DOMAIN, h, "subdomain_of", self.name)
        files = sorted({u for u in urls if u.lower().split("?")[0].endswith(INTERESTING)})
        node.attrs["commoncrawl_urls"] = len(urls)
        if files:
            node.attrs["archivos_publicos"] = files[:25]
            ctx.graph.note(self.name, f"{len(files)} archivo(s) de interés indexados públicamente",
                           "\n".join(files[:10]), "low", node)
