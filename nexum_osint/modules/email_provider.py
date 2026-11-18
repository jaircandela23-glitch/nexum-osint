from ..core.entities import Kind
from ..core.module import Module

PROVIDERS = (
    ("google", "Google Workspace / Gmail"), ("outlook.com", "Microsoft 365 / Outlook"),
    ("protection.outlook", "Microsoft 365 / Outlook"), ("protonmail", "Proton Mail"), ("proton.ch", "Proton Mail"),
    ("zoho", "Zoho Mail"), ("mimecast", "Mimecast (filtro de correo)"), ("pphosted", "Proofpoint (filtro de correo)"),
    ("secureserver.net", "GoDaddy"), ("yahoodns", "Yahoo Mail"), ("icloud", "iCloud"), ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"), ("ovh", "OVH"), ("hostinger", "Hostinger"), ("registrar-servers", "Namecheap"),
)
FREE = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.es",
        "icloud.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "mail.com", "yandex.com", "zoho.com"}


class EmailProvider(Module):
    name = "email_provider"
    description = "Proveedor del buzón (Google, Microsoft, Proton...) deducido de los servidores MX"
    consumes = (Kind.EMAIL,)
    rate = 8
    hosts = ("cloudflare-dns.com",)

    async def run(self, ctx, node):
        domain = node.value.split("@", 1)[1]
        if domain in FREE:
            node.attrs["tipo_buzon"] = "servicio gratuito personal"
            return
        r = await ctx.http.get("https://cloudflare-dns.com/dns-query", params={"name": domain, "type": "MX"},
                               headers={"accept": "application/dns-json"}, ttl=3600)
        if not r.ok:
            return
        hosts = [a["data"].lower() for a in r.json().get("Answer", []) if a.get("type") == 15]
        for needle, label in PROVIDERS:
            if any(needle in h for h in hosts):
                node.attrs["tipo_buzon"] = f"dominio propio en {label}"
                node.attrs["proveedor_correo"] = label
                return
        if hosts:
            node.attrs["tipo_buzon"] = "dominio propio con servidor de correo independiente"
