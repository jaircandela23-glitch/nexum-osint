"""Geolocalización, ASN y proveedor de una IP (ip-api.com, gratis hasta 45 consultas/min)."""
from ..core.entities import Kind
from ..core.module import Module

FIELDS = "status,message,country,regionName,city,lat,lon,isp,org,as,asname,reverse,proxy,hosting,mobile,query"


class IpGeo(Module):
    name = "ipgeo"
    description = "País, ciudad, ISP, ASN y banderas de proxy/hosting"
    consumes = (Kind.IP,)
    rate = 0.7
    hosts = ("ip-api.com",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(f"http://ip-api.com/json/{node.value}",
                                  params={"fields": FIELDS}, ttl=24 * 3600)
        if not resp.ok:
            return
        data = resp.json()
        if data.get("status") != "success":
            return
        node.attrs.update({
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "coords": [data.get("lat"), data.get("lon")],
            "isp": data.get("isp"),
            "org": data.get("org"),
            "hosting": data.get("hosting"),
            "proxy_or_vpn": data.get("proxy"),
        })
        asn = (data.get("as") or "").split(" ")[0]
        if asn.upper().startswith("AS"):
            ctx.emit(node, Kind.ASN, asn, "announced_by", self.name, name=data.get("asname"))
        if data.get("hosting"):
            ctx.graph.note(self.name, "IP de hosting/datacenter",
                           f"{data.get('isp')} - no corresponde a un usuario residencial.",
                           "info", node)
        if data.get("proxy"):
            ctx.graph.note(self.name, "IP marcada como proxy/VPN/Tor", "", "low", node)
