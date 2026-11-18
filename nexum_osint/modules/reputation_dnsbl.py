"""Listas negras DNS (spam, malware y abuso) consultadas por DNS-over-HTTPS."""
import ipaddress

from ..core.entities import Kind
from ..core.module import Module

DOH = "https://cloudflare-dns.com/dns-query"
IP_LISTS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "dnsbl-1.uceprotect.net": "UCEPROTECT nivel 1",
    "dnsbl.dronebl.org": "DroneBL",
    "psbl.surriel.com": "Passive Spam Block List",
}
DOMAIN_LISTS = {
    "dbl.spamhaus.org": "Spamhaus DBL",
    "dbl.spameatingmonkey.net": "SpamEatingMonkey",
}


def listed(answers: list[dict]) -> list[str]:
    """Devuelve los códigos 127.x de una respuesta, descartando los de error del servicio."""
    codes = [a["data"] for a in answers if a.get("type") == 1 and a["data"].startswith("127.")]
    return [c for c in codes if not c.startswith("127.255.255.")]  # 127.255.255.x = consulta rechazada


async def _query(ctx, name: str) -> list[str]:
    resp = await ctx.http.get(DOH, params={"name": name, "type": "A"},
                              headers={"accept": "application/dns-json"}, ttl=1800)
    return listed(resp.json().get("Answer", []) or []) if resp.ok else []


class IpBlocklists(Module):
    name = "dnsbl_ip"
    description = "¿La IP figura en listas negras de spam o abuso? (Spamhaus, SpamCop, DroneBL...)"
    consumes = (Kind.IP,)
    rate = 10
    hosts = ("cloudflare-dns.com",)

    async def run(self, ctx, node):
        ip = ipaddress.ip_address(node.value)
        if ip.version != 4 or not ip.is_global:
            return
        rev = ".".join(reversed(node.value.split(".")))
        hits = [label for zone, label in IP_LISTS.items() if await _query(ctx, f"{rev}.{zone}")]
        node.attrs["blocklists"] = hits
        if hits:
            ctx.graph.note(self.name, "IP en listas negras", ", ".join(hits),
                           "high" if len(hits) > 1 else "medium", node)


class DomainBlocklists(Module):
    name = "dnsbl_domain"
    description = "¿El dominio figura en listas negras de spam o malware? (Spamhaus DBL...)"
    consumes = (Kind.DOMAIN,)
    rate = 10
    hosts = ("cloudflare-dns.com",)

    async def run(self, ctx, node):
        hits = [label for zone, label in DOMAIN_LISTS.items() if await _query(ctx, f"{node.value}.{zone}")]
        if hits:
            node.attrs["blocklists"] = hits
            ctx.graph.note(self.name, "Dominio en listas negras", ", ".join(hits), "high", node)
