"""Dominios parecidos registrados (suplantación o typosquatting)."""
import asyncio

from ..core.entities import Kind
from ..core.module import Module
from .domain_brute import resolve

HOMOGLYPHS = {"a": "4", "e": "3", "i": "1", "l": "1", "o": "0", "s": "5", "m": "rn", "w": "vv"}
ALT_TLDS = ("com", "net", "org", "co", "io", "info", "biz", "xyz", "online", "shop", "pe", "mx", "es")
MAX_CANDIDATES = 120


def permutations(domain: str) -> list[str]:
    label, _, tld = domain.partition(".")
    out: set[str] = set()
    for i in range(len(label)):
        out.add(label[:i] + label[i + 1:])                                  # omisión
        out.add(label[:i] + label[i] * 2 + label[i + 1:])                   # repetición
        if i < len(label) - 1:
            out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])    # transposición
        if label[i] in HOMOGLYPHS:
            out.add(label[:i] + HOMOGLYPHS[label[i]] + label[i + 1:])       # homoglifo
    for sep in ("-", ""):
        for word in ("login", "secure", "soporte", "pagos"):
            out.add(f"{label}{sep}{word}")
    names = {f"{c}.{tld}" for c in out if len(c) > 1}
    names |= {f"{label}.{t}" for t in ALT_TLDS if t != tld}
    names.discard(domain)
    return sorted(names)[:MAX_CANDIDATES]


class Lookalikes(Module):
    name = "lookalikes"
    description = "Dominios similares ya registrados (errores de tipeo, homoglifos, otros TLD)"
    consumes = (Kind.DOMAIN,)
    rate = 20
    hosts = ("cloudflare-dns.com",)
    active = True

    async def run(self, ctx, node):
        if node.value.count(".") != 1 and not node.value.endswith(
                (".com.pe", ".com.mx", ".com.co", ".com.ar")):
            return   # solo dominios raíz: en un subdominio no tiene sentido
        results = await asyncio.gather(*(self._check(ctx, d) for d in permutations(node.value)))
        hits = [r for r in results if r]
        for name, ips in hits:
            ctx.emit(node, Kind.DOMAIN, name, "lookalike", self.name, pivot=False,
                     confidence="baja", ips=ips)
        if hits:
            ctx.graph.note(self.name, f"{len(hits)} dominios parecidos con resolución DNS",
                           ", ".join(n for n, _ in hits[:15]), "low", node)

    async def _check(self, ctx, name):
        ips = [a["data"] for a in await resolve(ctx, name) if a.get("type") == 1]
        return (name, ips) if ips else None
