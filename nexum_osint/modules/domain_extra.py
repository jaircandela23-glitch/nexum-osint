"""Más fuentes de dominios: URLScan, AlienVault OTX, HackerTarget, VirusTotal, SecurityTrails, Hunter."""
from __future__ import annotations

from ..core.entities import Kind
from ..core.module import Module


class UrlScan(Module):
    name = "urlscan"
    description = "Escaneos públicos del dominio: IPs, servidores y URLs vistas (urlscan.io, sin key)"
    consumes = (Kind.DOMAIN,)
    optional_key = "urlscan"
    rate = 0.5
    hosts = ("urlscan.io",)

    async def run(self, ctx, node):
        headers = {"API-Key": k} if (k := ctx.config.key("urlscan")) else None
        r = await ctx.http.get("https://urlscan.io/api/v1/search/",
                               params={"q": f"domain:{node.value}", "size": 100}, headers=headers, ttl=12 * 3600)
        if not r.ok:
            return
        rows = r.json().get("results", [])
        subs, ips, servers = set(), set(), set()
        for row in rows:
            page = row.get("page", {})
            if page.get("domain", "").endswith(node.value) and page["domain"] != node.value:
                subs.add(page["domain"])
            if page.get("ip"):
                ips.add(page["ip"])
            if page.get("server"):
                servers.add(page["server"])
        for sub in sorted(subs):
            ctx.emit(node, Kind.DOMAIN, sub, "subdomain_of", self.name)
        for ip in sorted(ips)[:10]:
            ctx.emit(node, Kind.IP, ip, "resolves_to", self.name)
        node.attrs["urlscan_results"] = len(rows)
        if servers:
            node.attrs["servers_seen"] = sorted(servers)[:8]


class OtxDomain(Module):
    name = "otx_domain"
    description = "DNS pasivo histórico y reputación del dominio (AlienVault OTX, sin key)"
    consumes = (Kind.DOMAIN,)
    optional_key = "otx"
    rate = 1
    hosts = ("otx.alienvault.com",)

    async def run(self, ctx, node):
        headers = {"X-OTX-API-KEY": k} if (k := ctx.config.key("otx")) else None
        r = await ctx.http.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{node.value}/passive_dns",
                               headers=headers, ttl=12 * 3600)
        if r.ok:
            records = r.json().get("passive_dns", [])
            hosts, ips = set(), set()
            for rec in records:
                host, addr, rtype = rec.get("hostname", ""), rec.get("address", ""), rec.get("record_type")
                if host.endswith(node.value) and host != node.value:
                    hosts.add(host)
                if rtype in ("A", "AAAA") and addr:
                    ips.add(addr)
            for h in sorted(hosts)[:150]:
                ctx.emit(node, Kind.DOMAIN, h, "subdomain_of", self.name)
            for ip in sorted(ips)[:15]:
                ctx.emit(node, Kind.IP, ip, "historical_ip", self.name)
            node.attrs["passive_dns_records"] = len(records)
        g = await ctx.http.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{node.value}/general",
                               headers=headers, ttl=12 * 3600)
        if g.ok:
            pulses = g.json().get("pulse_info", {}).get("count", 0)
            node.attrs["otx_pulses"] = pulses
            if pulses:
                ctx.graph.note(self.name, f"Dominio mencionado en {pulses} reportes de amenazas (OTX)",
                               "Revisar contexto: aparecer en un pulso no implica que sea malicioso.", "medium", node)


class HackerTarget(Module):
    name = "hackertarget"
    description = "Subdominios e IPs por búsqueda de hosts (HackerTarget, gratis con cuota diaria)"
    consumes = (Kind.DOMAIN,)
    rate = 0.3
    hosts = ("api.hackertarget.com",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.hackertarget.com/hostsearch/", params={"q": node.value}, ttl=12 * 3600)
        if not r.ok:
            return
        text = r.text.strip()
        if text.lower().startswith(("error", "api count exceeded")):
            ctx.graph.note(self.name, "HackerTarget: cuota diaria agotada o consulta rechazada",
                           text[:100], "info", node)
            return
        for line in text.splitlines():
            host, _, ip = line.partition(",")
            if host.endswith(node.value) and host != node.value:
                ctx.emit(node, Kind.DOMAIN, host.lower(), "subdomain_of", self.name)
            if ip:
                ctx.emit(node, Kind.IP, ip.strip(), "resolves_to", self.name)


class VirusTotalDomain(Module):
    name = "vt_domain"
    description = "Reputación del dominio y subdominios (VirusTotal, key gratuita)"
    consumes = (Kind.DOMAIN,)
    needs_key = "virustotal"
    rate = 0.06
    hosts = ("www.virustotal.com",)

    async def run(self, ctx, node):
        h = {"x-apikey": ctx.config.key("virustotal")}
        r = await ctx.http.get(f"https://www.virustotal.com/api/v3/domains/{node.value}", headers=h, ttl=24 * 3600)
        if not r.ok:
            return
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        node.attrs["vt_reputation"] = a.get("reputation")
        node.attrs["vt_categories"] = sorted(set((a.get("categories") or {}).values()))[:6]
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        if bad:
            ctx.graph.note(self.name, f"{bad} motores marcan el dominio como malicioso o sospechoso",
                           f"Detalle: {stats}", "high", node)
        subs = await ctx.http.get(f"https://www.virustotal.com/api/v3/domains/{node.value}/subdomains",
                                  params={"limit": 40}, headers=h, ttl=24 * 3600)
        if subs.ok:
            for item in subs.json().get("data", []):
                ctx.emit(node, Kind.DOMAIN, item["id"], "subdomain_of", self.name)


class SecurityTrails(Module):
    name = "securitytrails"
    description = "Subdominios históricos (SecurityTrails, key gratuita)"
    consumes = (Kind.DOMAIN,)
    needs_key = "securitytrails"
    rate = 0.5
    hosts = ("api.securitytrails.com",)

    async def run(self, ctx, node):
        r = await ctx.http.get(f"https://api.securitytrails.com/v1/domain/{node.value}/subdomains",
                               headers={"APIKEY": ctx.config.key("securitytrails")}, ttl=24 * 3600)
        if r.ok:
            for sub in r.json().get("subdomains", [])[:300]:
                ctx.emit(node, Kind.DOMAIN, f"{sub}.{node.value}", "subdomain_of", self.name)


class HunterDomain(Module):
    name = "hunter_domain"
    description = "Correos públicos asociados al dominio (Hunter.io, key gratuita)"
    consumes = (Kind.DOMAIN,)
    needs_key = "hunter"
    rate = 0.5
    hosts = ("api.hunter.io",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.hunter.io/v2/domain-search",
                               params={"domain": node.value, "limit": 25, "api_key": ctx.config.key("hunter")},
                               ttl=24 * 3600)
        if not r.ok:
            return
        d = r.json().get("data", {})
        if d.get("organization"):
            ctx.emit(node, Kind.ORG, d["organization"], "organization", self.name, pivot=False)
        for e in d.get("emails", []):
            ctx.emit(node, Kind.EMAIL, e["value"], "published_email", self.name,
                     position=e.get("position"), confidence=e.get("confidence"))
            full = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
            if full:
                ctx.emit(node, Kind.NAME, full, "staff_name", self.name, pivot=False)
