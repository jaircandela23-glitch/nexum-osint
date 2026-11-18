from ..core.entities import Kind, registrable
from ..core.module import Module


class DomainsDb(Module):
    name = "domainsdb"
    description = "Dominios registrados con nombre parecido en otras extensiones (DomainsDB, sin key)"
    consumes = (Kind.DOMAIN,)
    rate = 1
    hosts = ("api.domainsdb.info",)

    async def run(self, ctx, node):
        if node.depth > 0 or registrable(node.value) != node.value:
            return
        label = node.value.split(".")[0]
        r = await ctx.http.get("https://api.domainsdb.info/v1/domains/search",
                               params={"domain": label, "limit": 50}, ttl=24 * 3600)
        if not r.ok:
            return
        names = sorted({d["domain"].lower() for d in r.json().get("domains", [])
                        if d.get("domain") and d["domain"].lower() != node.value and not d.get("isDead")})
        for name in names[:40]:
            ctx.emit(node, Kind.DOMAIN, name, "similar_name", self.name, pivot=False)
        node.attrs["dominios_mismo_nombre"] = len(names)


class PeeringDb(Module):
    name = "peeringdb"
    description = "Organización, sitio web y políticas de interconexión del sistema autónomo (PeeringDB, sin key)"
    consumes = (Kind.ASN,)
    rate = 1
    hosts = ("www.peeringdb.com",)

    async def run(self, ctx, node):
        number = node.value.upper().removeprefix("AS")
        r = await ctx.http.get("https://www.peeringdb.com/api/net", params={"asn": number}, ttl=24 * 3600)
        if not r.ok:
            return
        rows = r.json().get("data", [])
        if not rows:
            return
        net = rows[0]
        node.attrs.update({k: v for k, v in {
            "red": net.get("name"), "tipo_red": net.get("info_type"), "alcance": net.get("info_scope"),
            "politica_peering": net.get("policy_general"), "sitio_web": net.get("website")}.items() if v})
        if net.get("name"):
            ctx.emit(node, Kind.ORG, net["name"], "network_operator", self.name, pivot=False)
        if net.get("website"):
            ctx.emit(node, Kind.URL, net["website"], "operator_site", self.name, pivot=False)
