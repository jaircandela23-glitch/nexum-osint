"""Subdominios a partir de los registros públicos de Certificate Transparency (crt.sh)."""
from ..core.entities import Kind
from ..core.module import Module


class CertTransparency(Module):
    name = "crtsh"
    description = "Subdominios y certificados emitidos (Certificate Transparency)"
    consumes = (Kind.DOMAIN,)
    rate = 0.5
    hosts = ("crt.sh",)

    async def _certspotter(self, ctx, domain: str) -> list[dict] | None:
        """Fuente alterna cuando crt.sh está caído; devuelve filas con el mismo formato que crt.sh."""
        resp = await ctx.http.get("https://api.certspotter.com/v1/issuances", params={
            "domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            ttl=12 * 3600, retries=1)
        if not resp.ok:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return [{"name_value": "\n".join(item.get("dns_names", [])),
                 "not_after": item.get("not_after", ""), "issuer_name": ""} for item in data]

    async def run(self, ctx, node):
        resp = await ctx.http.get("https://crt.sh/", params={
            "q": f"%.{node.value}", "output": "json"}, ttl=12 * 3600, retries=3)
        rows = None
        if resp.ok:
            try:
                rows = resp.json()
            except ValueError:
                rows = None
        if rows is None:
            rows = await self._certspotter(ctx, node.value)
        if rows is None:
            ctx.graph.note(self.name, "crt.sh no respondió",
                           f"HTTP {resp.status}; tampoco respondió la fuente alterna (Cert Spotter)", "warn", node)
            return

        names: dict[str, str] = {}
        issuers: set[str] = set()
        for row in rows:
            issuers.add(row.get("issuer_name", "").split("O=")[-1].split(",")[0])
            for name in row.get("name_value", "").splitlines():
                name = name.strip().lower().removeprefix("*.")
                if name.endswith(node.value) and name != node.value:
                    names[name] = row.get("not_after", "")

        for sub in sorted(names):
            ctx.emit(node, Kind.DOMAIN, sub, "subdomain_of", self.name,
                     last_cert_expiry=names[sub])
        node.attrs["certificates_seen"] = len(rows)
        node.attrs["subdomains_found"] = len(names)
        issuers.discard("")
        if issuers:
            node.attrs["cert_issuers"] = sorted(issuers)[:8]
