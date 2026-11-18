"""Servicios expuestos y vulnerabilidades conocidas desde Shodan InternetDB (gratis, sin key)."""
from ..core.entities import Kind
from ..core.module import Module


class InternetDB(Module):
    name = "internetdb"
    description = "Puertos abiertos, CPEs, hostnames y CVEs de una IP (datos pasivos)"
    consumes = (Kind.IP,)
    rate = 2
    hosts = ("internetdb.shodan.io",)

    async def run(self, ctx, node):
        resp = await ctx.http.get(f"https://internetdb.shodan.io/{node.value}", ttl=12 * 3600)
        if resp.status == 404:
            return
        if not resp.ok:
            return
        data = resp.json()
        ports = data.get("ports", [])
        node.attrs["open_ports"] = ports
        node.attrs["tags"] = data.get("tags")
        node.attrs["cpes"] = data.get("cpes")

        for host in data.get("hostnames", []):
            ctx.emit(node, Kind.DOMAIN, host, "reverse_dns", self.name)

        vulns = data.get("vulns", [])
        if vulns:
            node.attrs["cves"] = vulns
            ctx.graph.note(self.name, f"{len(vulns)} CVE asociados a {node.value}",
                           ", ".join(sorted(vulns)[:20]), "high", node)

        risky = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC",
                 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                 9200: "Elasticsearch", 11211: "Memcached"}
        exposed = [f"{p} ({risky[p]})" for p in ports if p in risky]
        if exposed:
            ctx.graph.note(self.name, "Servicios sensibles expuestos a Internet",
                           ", ".join(exposed), "high", node)
