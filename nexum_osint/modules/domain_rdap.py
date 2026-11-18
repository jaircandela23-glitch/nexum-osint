"""Datos de registro de un dominio mediante RDAP (el sucesor moderno de WHOIS)."""
from ..core.entities import Kind, registrable
from ..core.module import Module


class DomainRdap(Module):
    name = "rdap_domain"
    description = "Registrador, fechas de registro/expiración y servidores de nombres"
    consumes = (Kind.DOMAIN,)
    rate = 1
    hosts = ("rdap.org",)

    async def run(self, ctx, node):
        if node.value != registrable(node.value):
            return
        resp = await ctx.http.get(f"https://rdap.org/domain/{node.value}", ttl=24 * 3600)
        if not resp.ok:
            return
        data = resp.json()

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        node.attrs["registered"] = events.get("registration")
        node.attrs["expires"] = events.get("expiration")
        node.attrs["last_changed"] = events.get("last changed")
        node.attrs["rdap_status"] = data.get("status")

        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [None, []])[1]
            fn = next((v[3] for v in vcard if v[0] == "fn"), None)
            if "registrar" in roles and fn:
                node.attrs["registrar"] = fn
            elif fn and "registrant" in roles and fn.lower() not in ("redacted for privacy", ""):
                ctx.emit(node, Kind.ORG, fn, "registrant", self.name, pivot=False)

        for ns in data.get("nameservers", []):
            name = ns.get("ldhName")
            if name:
                ctx.emit(node, Kind.DOMAIN, name, "nameserver", self.name, pivot=False)

        exp = events.get("expiration", "")
        if exp and exp[:4].isdigit():
            from datetime import datetime, timezone
            try:
                left = datetime.fromisoformat(exp.replace("Z", "+00:00")) - datetime.now(timezone.utc)
                if left.days < 30:
                    ctx.graph.note(self.name, "Dominio próximo a expirar",
                                   f"Expira en {max(left.days, 0)} días.", "medium", node)
            except ValueError:
                pass
