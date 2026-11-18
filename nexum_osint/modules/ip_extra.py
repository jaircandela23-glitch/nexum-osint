"""Más fuentes de IP: reputación, relé Tor, ASN y amenazas."""
from __future__ import annotations

from ..core.entities import Kind
from ..core.module import Module


class TorRelay(Module):
    name = "tor_relay"
    description = "Indica si la IP es un relé o salida de la red Tor (Onionoo, sin key)"
    consumes = (Kind.IP,)
    rate = 1
    hosts = ("onionoo.torproject.org",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://onionoo.torproject.org/details",
                               params={"search": node.value, "limit": 1, "fields": "nickname,flags,running"},
                               ttl=6 * 3600)
        if not r.ok:
            return
        relays = r.json().get("relays", [])
        if relays:
            flags = relays[0].get("flags", [])
            node.attrs["tor_relay"] = relays[0].get("nickname")
            kind = "salida (Exit)" if "Exit" in flags else "relé"
            ctx.graph.note(self.name, f"IP corresponde a un {kind} de Tor",
                           f"Nombre: {relays[0].get('nickname')}. El tráfico desde aquí no identifica a una persona.",
                           "low", node)


class OtxIp(Module):
    name = "otx_ip"
    description = "Reportes de amenazas y reputación de la IP (AlienVault OTX, sin key)"
    consumes = (Kind.IP,)
    optional_key = "otx"
    rate = 1
    hosts = ("otx.alienvault.com",)

    async def run(self, ctx, node):
        section = "IPv6" if ":" in node.value else "IPv4"
        headers = {"X-OTX-API-KEY": k} if (k := ctx.config.key("otx")) else None
        r = await ctx.http.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{node.value}/general",
                               headers=headers, ttl=12 * 3600)
        if r.ok:
            pulses = r.json().get("pulse_info", {}).get("count", 0)
            node.attrs["otx_pulses"] = pulses
            if pulses:
                ctx.graph.note(self.name, f"IP mencionada en {pulses} reportes de amenazas (OTX)", "", "medium", node)


class AbuseIpdb(Module):
    name = "abuseipdb"
    description = "Puntuación de abuso y reportes de la IP (AbuseIPDB, key gratuita)"
    consumes = (Kind.IP,)
    needs_key = "abuseipdb"
    rate = 1
    hosts = ("api.abuseipdb.com",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.abuseipdb.com/api/v2/check",
                               params={"ipAddress": node.value, "maxAgeInDays": 90},
                               headers={"Key": ctx.config.key("abuseipdb"), "Accept": "application/json"},
                               ttl=12 * 3600)
        if not r.ok:
            return
        d = r.json().get("data", {})
        node.attrs.update({k: v for k, v in {
            "abuse_score": d.get("abuseConfidenceScore"), "abuse_reports": d.get("totalReports"),
            "usage_type": d.get("usageType")}.items() if v is not None})
        if d.get("abuseConfidenceScore", 0) >= 25:
            ctx.graph.note(self.name, f"AbuseIPDB: confianza de abuso {d['abuseConfidenceScore']}%",
                           f"{d.get('totalReports', 0)} reportes en 90 días", "high" if d["abuseConfidenceScore"] >= 75 else "medium", node)


class IpInfo(Module):
    name = "ipinfo"
    description = "Ubicación, organización y hostname de la IP (ipinfo.io, token gratuito)"
    consumes = (Kind.IP,)
    needs_key = "ipinfo"
    rate = 2
    hosts = ("ipinfo.io",)

    async def run(self, ctx, node):
        r = await ctx.http.get(f"https://ipinfo.io/{node.value}", params={"token": ctx.config.key("ipinfo")}, ttl=24 * 3600)
        if r.ok:
            d = r.json()
            node.attrs.update({k: v for k, v in {
                "ipinfo_city": d.get("city"), "ipinfo_region": d.get("region"), "ipinfo_country": d.get("country"),
                "ipinfo_org": d.get("org"), "ipinfo_hostname": d.get("hostname"), "ipinfo_timezone": d.get("timezone")}.items() if v})
            if d.get("hostname"):
                ctx.emit(node, Kind.DOMAIN, d["hostname"], "reverse_dns", self.name)


class GreyNoise(Module):
    name = "greynoise"
    description = "¿La IP escanea Internet de forma masiva? (GreyNoise Community, key opcional)"
    consumes = (Kind.IP,)
    optional_key = "greynoise"
    rate = 0.3
    hosts = ("api.greynoise.io",)

    async def run(self, ctx, node):
        headers = {"key": k} if (k := ctx.config.key("greynoise")) else None
        r = await ctx.http.get(f"https://api.greynoise.io/v3/community/{node.value}", headers=headers, ttl=12 * 3600)
        if r.status == 404 or not r.ok:
            return
        d = r.json()
        node.attrs["greynoise"] = d.get("classification")
        if d.get("riot"):
            ctx.graph.note(self.name, "IP de servicio legítimo conocido (RIOT)", d.get("name", ""), "info", node)
        elif d.get("noise"):
            ctx.graph.note(self.name, f"IP de ruido de Internet ({d.get('classification')})",
                           "Escaneo masivo, no un ataque dirigido.", "low", node)


class VirusTotalIp(Module):
    name = "vt_ip"
    description = "Reputación de la IP (VirusTotal, key gratuita)"
    consumes = (Kind.IP,)
    needs_key = "virustotal"
    rate = 0.06
    hosts = ("www.virustotal.com",)

    async def run(self, ctx, node):
        r = await ctx.http.get(f"https://www.virustotal.com/api/v3/ip_addresses/{node.value}",
                               headers={"x-apikey": ctx.config.key("virustotal")}, ttl=24 * 3600)
        if not r.ok:
            return
        a = r.json().get("data", {}).get("attributes", {})
        stats = a.get("last_analysis_stats", {})
        node.attrs["vt_owner"] = a.get("as_owner")
        bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
        if bad:
            ctx.graph.note(self.name, f"{bad} motores marcan la IP como maliciosa o sospechosa", f"Detalle: {stats}", "high", node)
