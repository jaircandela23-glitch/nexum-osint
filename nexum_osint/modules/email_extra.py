from ..core.entities import Kind
from ..core.module import Module


class KickboxDisposable(Module):
    name = "email_disposable"
    description = "¿El dominio del correo es de buzones desechables? (Kickbox abierto, sin key)"
    consumes = (Kind.EMAIL,)
    rate = 2
    hosts = ("open.kickbox.com",)

    async def run(self, ctx, node):
        domain = node.value.split("@", 1)[1]
        r = await ctx.http.get(f"https://open.kickbox.com/v1/disposable/{domain}", ttl=24 * 3600)
        if r.ok and r.json().get("disposable") is True:
            node.attrs["dominio_desechable"] = True
            ctx.graph.note(self.name, "Dominio de correo desechable (Kickbox)", domain, "low", node)
