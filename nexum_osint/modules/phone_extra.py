"""Teléfono: enlaces de investigación y verificaciones con keys gratuitas."""
from __future__ import annotations

from ..core.entities import Kind
from ..core.links import dork, enc, manual
from ..core.module import Module


def _variants(e164: str) -> list[str]:
    digits = e164.lstrip("+")
    return [e164, digits]


class PhoneLinks(Module):
    name = "phone_links"
    description = "Enlaces de consulta manual: mensajería, directorios y búsquedas dirigidas del número"
    consumes = (Kind.PHONE,)

    async def run(self, ctx, node):
        e164 = node.value
        digits = e164.lstrip("+")
        s = self.name
        manual(ctx, node, s, "WhatsApp (¿tiene cuenta?)", f"https://wa.me/{digits}", "mensajeria")
        manual(ctx, node, s, "Telegram (por número)", f"https://t.me/+{digits}", "mensajeria")
        manual(ctx, node, s, "Truecaller", f"https://www.truecaller.com/search/{'pe' if digits.startswith('51') else 'us'}/{digits}", "directorio")
        manual(ctx, node, s, "Sync.me", f"https://sync.me/search/?number={digits}", "directorio")
        manual(ctx, node, s, "Google: número exacto", dork(f'"{e164}" OR "{digits}"'), "buscador")
        manual(ctx, node, s, "Google: número en redes", dork(f'"{digits}" site:facebook.com OR site:linkedin.com OR site:instagram.com'), "buscador")
        manual(ctx, node, s, "Google: número en anuncios", dork(f'"{digits}" site:olx.com.pe OR site:mercadolibre.com OR site:facebook.com/marketplace'), "buscador")
        manual(ctx, node, s, "Bing: número exacto", f"https://www.bing.com/search?q={enc(chr(34) + digits + chr(34))}", "buscador")
        manual(ctx, node, s, "DuckDuckGo: número exacto", f"https://duckduckgo.com/?q={enc(chr(34) + e164 + chr(34))}", "buscador")
        manual(ctx, node, s, "Reportes de spam (Who Called Me)", f"https://www.whocalledme.com/PhoneNumber/{digits}", "reputacion")
        manual(ctx, node, s, "Reportes de spam (ShouldIAnswer)", f"https://www.shouldianswer.com/phone-number/{digits}", "reputacion")


class Veriphone(Module):
    name = "veriphone"
    description = "Validez, tipo de línea y operador en vivo (Veriphone, key gratuita)"
    consumes = (Kind.PHONE,)
    needs_key = "veriphone"
    rate = 1
    hosts = ("api.veriphone.io",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://api.veriphone.io/v2/verify",
                               params={"phone": node.value, "key": ctx.config.key("veriphone")}, ttl=24 * 3600)
        if not r.ok:
            return
        d = r.json()
        node.attrs.update({k: v for k, v in {
            "veriphone_valid": d.get("phone_valid"), "veriphone_type": d.get("phone_type"),
            "veriphone_carrier": d.get("carrier"), "veriphone_region": d.get("phone_region"),
            "international": d.get("international_number")}.items() if v not in (None, "")})
        if d.get("phone_valid") is False:
            ctx.graph.note(self.name, "Veriphone marca el número como inválido", "", "medium", node)


class IpqsPhone(Module):
    name = "ipqs_phone"
    description = "Riesgo, VOIP, abuso reciente y filtraciones del número (IPQualityScore, key gratuita)"
    consumes = (Kind.PHONE,)
    needs_key = "ipqs"
    rate = 1
    hosts = ("ipqualityscore.com",)

    async def run(self, ctx, node):
        key = ctx.config.key("ipqs")
        r = await ctx.http.get(f"https://ipqualityscore.com/api/json/phone/{key}/{node.value.lstrip('+')}", ttl=24 * 3600)
        if not r.ok:
            return
        d = r.json()
        if not d.get("success", True):
            return
        for k in ("valid", "active", "fraud_score", "carrier", "line_type", "VOIP", "risky",
                  "recent_abuse", "leaked", "country", "region", "city"):
            if d.get(k) not in (None, ""):
                node.attrs[f"ipqs_{k.lower()}"] = d[k]
        if d.get("leaked"):
            ctx.graph.note(self.name, "El número aparece en filtraciones (según IPQS)", "", "high", node)
        if d.get("VOIP"):
            ctx.graph.note(self.name, "Línea VOIP", "No está ligada a un operador móvil tradicional.", "low", node)
        if d.get("recent_abuse"):
            ctx.graph.note(self.name, "Abuso reciente asociado al número", "", "medium", node)
