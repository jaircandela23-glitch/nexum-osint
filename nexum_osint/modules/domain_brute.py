"""Descubrimiento activo de subdominios por diccionario y por permutación de nombre."""
import asyncio
import random
import string
from importlib import resources

from ..core.entities import Kind
from ..core.module import Module

DOH = "https://cloudflare-dns.com/dns-query"
HEADERS = {"accept": "application/dns-json"}


async def resolve(ctx, name: str, rtype: str = "A") -> list[dict]:
    resp = await ctx.http.get(DOH, params={"name": name, "type": rtype}, headers=HEADERS, ttl=900)
    if not resp.ok:
        return []
    return resp.json().get("Answer", []) or []


def wordlist() -> list[str]:
    text = (resources.files("nexum_osint.data") / "subdomains.txt").read_text(encoding="utf-8")
    return [w for w in text.split() if w]


class SubdomainBrute(Module):
    name = "subdomain_brute"
    description = "Subdominios comunes por diccionario (DNS-over-HTTPS) con detección de comodín"
    consumes = (Kind.DOMAIN,)
    rate = 20
    hosts = ("cloudflare-dns.com",)
    active = True

    async def run(self, ctx, node):
        if node.depth > 0:
            return   # el diccionario solo se aplica al dominio objetivo, no a cada subdominio hallado
        junk = "".join(random.choices(string.ascii_lowercase, k=14))
        wildcard = {a["data"] for a in await resolve(ctx, f"{junk}.{node.value}") if a.get("type") == 1}
        if wildcard:
            ctx.graph.note(self.name, "El dominio usa registro comodín",
                           f"Responde a nombres inexistentes con {', '.join(sorted(wildcard))}", "info", node)
        found = await asyncio.gather(*(self._probe(ctx, f"{w}.{node.value}", wildcard)
                                       for w in wordlist()))
        for name, ips in filter(None, found):
            sub = ctx.emit(node, Kind.DOMAIN, name, "brute_subdomain", self.name)
            for ip in ips:
                ctx.emit(sub or node, Kind.IP, ip, "resolves_to", self.name)

    async def _probe(self, ctx, name, wildcard):
        ips = [a["data"] for a in await resolve(ctx, name) if a.get("type") == 1]
        if ips and not set(ips) <= wildcard:
            return name, ips
        return None
