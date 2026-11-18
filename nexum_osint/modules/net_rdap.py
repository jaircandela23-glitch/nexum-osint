from ..core.entities import Kind
from ..core.module import Module


def vcard_fields(entity: dict) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item[0] in ("fn", "email", "org", "kind"):
            out[item[0]] = item[3] if not isinstance(item[3], list) else " ".join(map(str, item[3]))
    return out


class IpRdap(Module):
    name = "ip_rdap"
    description = "Titular registrado del bloque de la IP y contactos públicos (RDAP, sin key)"
    consumes = (Kind.IP,)
    rate = 2
    hosts = ("rdap.org",)

    async def run(self, ctx, node):
        r = await ctx.http.get(f"https://rdap.org/ip/{node.value}", ttl=24 * 3600)
        if not r.ok:
            return
        data = r.json()
        node.attrs.update({k: v for k, v in {
            "bloque": data.get("name"), "pais_registro": data.get("country"),
            "rango": f"{data.get('startAddress')} - {data.get('endAddress')}" if data.get("startAddress") else None,
        }.items() if v})
        for ent in data.get("entities", []):
            f = vcard_fields(ent)
            roles = ent.get("roles", [])
            if f.get("kind") == "org" and f.get("fn"):
                ctx.emit(node, Kind.ORG, f["fn"], "registered_to", self.name, pivot=False, roles=", ".join(roles))
            if f.get("email") and any(r in roles for r in ("abuse", "technical", "administrative")):
                ctx.emit(node, Kind.EMAIL, f["email"], "registry_contact", self.name, pivot=False, roles=", ".join(roles))
