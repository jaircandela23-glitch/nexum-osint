"""Análisis de números telefónicos.

Da la aproximación más honesta que existe sin acceso de operador o de ley:
validez, país/operador por plan de numeración, zona de área (solo en líneas
fijas, que sí están ligadas a una región), huso horario y, si se configura
una API key gratuita, una verificación en vivo de operador/tipo de línea.

Deliberadamente NO intenta geolocalizar en tiempo real: eso requiere acceso
a la red del operador (HLR/SS7) o una orden judicial, y no es un dato público
ni algo que este proyecto vaya a ofrecer.
"""
from __future__ import annotations

from ..data.numbering import lookup_country, peru_fixed_area, peru_mobile_block
from ..core.entities import Kind
from ..core.module import Module


class PhoneIntel(Module):
    name = "phone"
    description = "Validación, país/operador por plan de numeración, área y huso horario"
    consumes = (Kind.PHONE,)
    optional_key = "numverify"

    async def run(self, ctx, node):
        digits = node.value.lstrip("+")
        match = lookup_country(digits)
        if not match:
            ctx.graph.note(self.name, "Indicativo de país no reconocido",
                           "No coincide con ningún código E.164 de la tabla interna.",
                           "info", node)
            return

        code, country, timezones = match
        national = digits[len(code):]
        node.attrs.update({
            "country_code": f"+{code}",
            "country": country,
            "national_number": national,
            "timezones": list(timezones),
        })

        if code == "51":
            self._peru(ctx, node, national)
        else:
            node.attrs["location_precision"] = (
                "país (el plan de numeración internacional no permite acercarse más "
                "sin una fuente local propia de ese país)")

        await self._cross_check(ctx, node)

    def _peru(self, ctx, node, national: str) -> None:
        if len(national) == 9 and national.startswith("9"):
            operator = peru_mobile_block(national)
            node.attrs["line_type"] = "móvil"
            node.attrs["location_precision"] = (
                "país (Perú) — los móviles peruanos no están ligados a una región "
                "geográfica real, ni antes ni después de la portabilidad numérica")
            if operator:
                node.attrs["operator_block_original"] = operator
                ctx.graph.note(self.name, f"Bloque asignado originalmente a {operator}",
                               "La portabilidad numérica pudo cambiar el operador real; "
                               "esto es la asignación de bloque, no una consulta en vivo.",
                               "info", node)
        else:
            area = peru_fixed_area(national)
            node.attrs["line_type"] = "fija" if area else "desconocida"
            if area:
                node.attrs["area"] = area.place
                node.attrs["location_precision"] = f"departamento ({area.place}) — vía indicativo de red fija"
                ctx.graph.note(self.name, f"Línea fija registrada en {area.place}",
                               "El indicativo de red fija sí corresponde a una región real.",
                               "low", node)
            else:
                node.attrs["location_precision"] = "país (Perú) — formato no reconocido en el plan nacional"

    async def _cross_check(self, ctx, node) -> None:
        """Verificación en vivo opcional vía NumVerify/apilayer (requiere key gratuita)."""
        key = ctx.config.key("numverify")
        if not key:
            return
        resp = await ctx.http.get("https://apilayer.net/api/validate", params={
            "access_key": key, "number": node.value}, ttl=24 * 3600, retries=1)
        if not resp.ok:
            return
        data = resp.json()
        if not data.get("valid"):
            ctx.graph.note(self.name, "La verificación en vivo marca el número como inválido",
                           "", "medium", node)
            return
        node.attrs["carrier_live"] = data.get("carrier")
        node.attrs["line_type_live"] = data.get("line_type")
        if data.get("location"):
            node.attrs["location_live"] = data["location"]
