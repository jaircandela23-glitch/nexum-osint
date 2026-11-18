from ..core.entities import Kind
from ..core.module import Module


class RipeStatAsn(Module):
    name = "ripestat_asn"
    description = "Titular y prefijos anunciados de un sistema autónomo (RIPEstat, sin key)"
    consumes = (Kind.ASN,)
    rate = 2
    hosts = ("stat.ripe.net",)

    async def run(self, ctx, node):
        over = await ctx.http.get("https://stat.ripe.net/data/as-overview/data.json",
                                  params={"resource": node.value}, ttl=24 * 3600)
        if over.ok:
            data = over.json().get("data", {})
            node.attrs["titular"] = data.get("holder")
        pref = await ctx.http.get("https://stat.ripe.net/data/announced-prefixes/data.json",
                                  params={"resource": node.value}, ttl=24 * 3600)
        if pref.ok:
            prefixes = [p["prefix"] for p in pref.json().get("data", {}).get("prefixes", [])]
            node.attrs["prefijos"] = len(prefixes)
            node.attrs["prefijos_ejemplo"] = prefixes[:6]


class IpAbuseContact(Module):
    name = "ip_abuse_contact"
    description = "Contacto de abuso oficial del bloque de la IP (RIPEstat, sin key)"
    consumes = (Kind.IP,)
    rate = 2
    hosts = ("stat.ripe.net",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://stat.ripe.net/data/abuse-contact-finder/data.json",
                               params={"resource": node.value}, ttl=24 * 3600)
        if r.ok:
            contacts = r.json().get("data", {}).get("abuse_contacts", [])
            if contacts:
                node.attrs["abuse_contact"] = ", ".join(contacts)


class ReverseIp(Module):
    name = "reverse_ip"
    description = "Otros dominios alojados en la misma IP (HackerTarget, gratis con cuota diaria)"
    consumes = (Kind.IP,)
    rate = 0.3
    hosts = ("api.hackertarget.com",)

    async def run(self, ctx, node):
        if ":" in node.value:
            return
        r = await ctx.http.get("https://api.hackertarget.com/reverseiplookup/", params={"q": node.value}, ttl=12 * 3600)
        if not r.ok or r.text.lower().startswith(("error", "api count", "no records")):
            return
        hosts = [h.strip().lower() for h in r.text.splitlines() if "." in h and " " not in h.strip()]
        for h in hosts[:40]:
            ctx.emit(node, Kind.DOMAIN, h, "same_ip", self.name, pivot=False)
        node.attrs["dominios_en_misma_ip"] = len(hosts)
        if len(hosts) >= 40:
            ctx.graph.note(self.name, f"{len(hosts)} dominios comparten esta IP",
                           "Hosting compartido: no asumas que pertenecen al mismo dueño.", "info", node)
