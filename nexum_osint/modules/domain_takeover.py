"""Subdominios apuntando a servicios abandonados (riesgo de secuestro de subdominio)."""
from ..core.entities import Kind
from ..core.module import Module
from .domain_brute import resolve

# sufijo del CNAME -> texto que muestra el servicio cuando el recurso no está reclamado
FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "herokudns.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "fastly.net": "Fastly error: unknown domain",
    "ghost.io": "The thing you were looking for is no longer here",
    "helpscoutdocs.com": "No settings were found for this company",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "readme.io": "Project doesnt exist",
    "zendesk.com": "Help Center Closed",
    "tumblr.com": "There's nothing here",
    "pantheonsite.io": "The gods are wise",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "unbouncepages.com": "The requested URL was not found on this server",
}


def match_service(cname: str) -> str | None:
    cname = cname.rstrip(".").lower()
    return next((s for s in FINGERPRINTS if cname == s or cname.endswith("." + s)), None)


class SubdomainTakeover(Module):
    name = "takeover"
    description = "CNAME hacia servicios externos sin reclamar (GitHub Pages, S3, Heroku, Azure...)"
    consumes = (Kind.DOMAIN,)
    rate = 5
    hosts = ("cloudflare-dns.com",)
    active = True

    async def run(self, ctx, node):
        cnames = [a["data"] for a in await resolve(ctx, node.value, "CNAME") if a.get("type") == 5]
        for cname in cnames:
            service = match_service(cname)
            if not service:
                continue
            node.attrs["cname"] = cname.rstrip(".")
            if not [a for a in await resolve(ctx, cname.rstrip("."), "A") if a.get("type") == 1]:
                ctx.graph.note(self.name, "CNAME hacia un destino que ya no resuelve",
                               f"{node.value} -> {cname.rstrip('.')}: posible subdominio secuestrable",
                               "high", node)
                continue
            resp = await ctx.http.get(f"http://{node.value}/", ttl=600, retries=0)
            if FINGERPRINTS[service].lower() in resp.text.lower():
                ctx.graph.note(self.name, f"Recurso sin reclamar en {service}",
                               f"{node.value} -> {cname.rstrip('.')}", "high", node)
