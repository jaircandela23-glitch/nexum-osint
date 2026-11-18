"""Plantilla de plugin. Cópiala a ~/.config/nexum-osint/plugins/ o a nexum_osint/modules/.

Cada plugin es una clase que hereda de Module. El motor la descubre solo,
la ejecuta en paralelo con el resto y enlaza lo que encuentres al grafo.
"""
from nexum_osint.core.entities import Kind
from nexum_osint.core.module import Module


class MiFuente(Module):
    name = "mi_fuente"                  # identificador único (se usa con -m / -x)
    description = "Qué consulta este módulo"
    consumes = (Kind.DOMAIN,)           # sobre qué tipo de entidad trabaja
    rate = 1                            # peticiones/segundo que tolera la API
    hosts = ("api.ejemplo.com",)
    # needs_key = "ejemplo"             # descomenta si la API exige key (NEXUM_EJEMPLO)

    async def run(self, ctx, node):
        # Para fuentes sin API gratuita: from nexum_osint.core.links import manual
        # manual(ctx, node, self.name, "Etiqueta", "https://...", "buscador")
        resp = await ctx.http.get(f"https://api.ejemplo.com/v1/{node.value}", ttl=3600)
        if not resp.ok:
            return
        data = resp.json()
        node.attrs["campo"] = data.get("campo")                     # atributo del nodo
        for ip in data.get("ips", []):                              # entidad nueva + pivoteo
            ctx.emit(node, Kind.IP, ip, "resolves_to", self.name)
        if data.get("riesgo"):
            ctx.graph.note(self.name, "Riesgo detectado", data["riesgo"], "medium", node)
