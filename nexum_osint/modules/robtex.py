"""Robtex: DNS pasivo y datos de red (API gratuita, sin key)."""
import json

from ..core.entities import Kind
from ..core.module import Module

BASE = "https://freeapi.robtex.com"


class RobtexDomain(Module):
    name = "robtex_domain"
    description = "DNS pasivo del dominio: IPs y servidores asociados (Robtex)"
    consumes = (Kind.DOMAIN,)
    rate = 0.5
    hosts = ("freeapi.robtex.com",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(f"{BASE}/pdns/forward/{node.value}", ttl=12 * 3600, retries=1)
        if not resp.ok:
            return
        seen = set()
        for line in resp.text.splitlines()[:60]:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            kind = {"A": Kind.IP, "AAAA": Kind.IP, "NS": Kind.DOMAIN, "MX": Kind.DOMAIN,
                    "CNAME": Kind.DOMAIN}.get(rec.get("rrtype"))
            data = (rec.get("rrdata") or "").rstrip(".").lower()
            if kind and data and (kind, data) not in seen:
                seen.add((kind, data))
                ctx.emit(node, kind, data, f"robtex_{rec['rrtype'].lower()}", self.name)


class RobtexIp(Module):
    name = "robtex_ip"
    description = "Nombres de host vistos en la IP y su red (Robtex)"
    consumes = (Kind.IP,)
    rate = 0.5
    hosts = ("freeapi.robtex.com",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(f"{BASE}/ipquery/{node.value}", ttl=12 * 3600, retries=1)
        if not resp.ok:
            return
        data = resp.json()
        if data.get("status") != "ok":
            return
        node.attrs["robtex_network"] = data.get("routedesc") or data.get("whoisdesc")
        for entry in (data.get("pas") or [])[:25]:
            host = (entry.get("o") or "").rstrip(".").lower()
            if host:
                ctx.emit(node, Kind.DOMAIN, host, "robtex_host", self.name)
