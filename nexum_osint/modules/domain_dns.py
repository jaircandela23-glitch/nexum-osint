"""Registros DNS vía DNS-over-HTTPS (sin dependencias extra)."""
import re

from ..core.entities import Kind
from ..core.module import Module

TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}
DOH = "https://cloudflare-dns.com/dns-query"


class DnsRecords(Module):
    name = "dns"
    description = "Registros A/AAAA/MX/NS/TXT/CNAME y análisis de SPF/DMARC"
    consumes = (Kind.DOMAIN,)
    rate = 8
    hosts = ("cloudflare-dns.com",)

    async def _query(self, ctx, name: str, rtype: str) -> list[str]:
        resp = await ctx.http.get(DOH, params={"name": name, "type": rtype},
                                  headers={"accept": "application/dns-json"}, ttl=1800)
        if not resp.ok:
            return []
        data = resp.json()
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == TYPES[rtype]]

    async def run(self, ctx, node):
        domain = node.value
        records: dict[str, list[str]] = {}
        for rtype in TYPES:
            records[rtype] = await self._query(ctx, domain, rtype)

        for ip in records["A"] + records["AAAA"]:
            ctx.emit(node, Kind.IP, ip, "resolves_to", self.name)
        for mx in records["MX"]:
            host = mx.split()[-1].rstrip(".")
            ctx.emit(node, Kind.DOMAIN, host, "mail_server", self.name)
        for ns in records["NS"]:
            ctx.emit(node, Kind.DOMAIN, ns.rstrip("."), "nameserver", self.name, pivot=False)
        for target in records["CNAME"]:
            ctx.emit(node, Kind.DOMAIN, target.rstrip("."), "cname", self.name)

        txt = [t.strip('"') for t in records["TXT"]]
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        if spf:
            node.attrs["spf"] = spf
            for inc in re.findall(r"include:([\w.\-]+)", spf):
                ctx.emit(node, Kind.DOMAIN, inc, "spf_include", self.name, pivot=False)
            if spf.rstrip().endswith("+all"):
                ctx.graph.note(self.name, "SPF permisivo (+all)",
                               "Cualquier servidor puede enviar correo como este dominio.",
                               "high", node)
        elif records["MX"]:
            ctx.graph.note(self.name, "Sin registro SPF",
                           "El dominio recibe correo pero no declara quién puede enviarlo.",
                           "medium", node)

        dmarc = await self._query(ctx, f"_dmarc.{domain}", "TXT")
        if dmarc:
            node.attrs["dmarc"] = dmarc[0].strip('"')
            if "p=none" in dmarc[0].replace(" ", ""):
                ctx.graph.note(self.name, "DMARC en modo monitoreo (p=none)",
                               "No se rechaza el correo suplantado.", "low", node)
        elif records["MX"]:
            ctx.graph.note(self.name, "Sin registro DMARC", "", "medium", node)

        verif = [t for t in txt if "verification" in t.lower() or "site-verif" in t.lower()]
        if verif:
            node.attrs["service_verifications"] = verif[:6]
        node.attrs["dns"] = {k: v for k, v in records.items() if v and k != "TXT"}
