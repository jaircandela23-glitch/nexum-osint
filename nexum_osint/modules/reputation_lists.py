import asyncio
import re

from ..core.entities import Kind, registrable
from ..core.module import Module

IP_FEEDS = {
    "blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "CINS Army": "https://cinsscore.com/list/ci-badguys.txt",
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "GreenSnow": "https://blocklist.greensnow.co/greensnow.txt",
    "Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}
HOST_FEEDS = {
    "OpenPhish": "https://openphish.com/feed.txt",
    "URLhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "StevenBlack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_ips(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        token = line.split("#")[0].split(";")[0].strip().split()
        if token and IPV4.match(token[0]):
            out.add(token[0])
    return out


def parse_hosts(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("http"):
            host = line.split("/")[2].split(":")[0]
        else:
            parts = line.split()
            host = parts[-1] if len(parts) >= 2 and IPV4.match(parts[0]) else ""
        if "." in host:
            out.add(host.lower())
    return out


class IpBlocklists(Module):
    name = "ip_blocklists"
    description = "¿La IP figura en listas públicas de ataques? (blocklist.de, CINS, Emerging Threats, GreenSnow, Feodo)"
    consumes = (Kind.IP,)

    async def run(self, ctx, node):
        if ":" in node.value:
            return

        async def check(label, url):
            try:
                r = await ctx.http.get(url, ttl=12 * 3600, retries=1)
            except ConnectionError:
                return label, None
            return label, (node.value in parse_ips(r.text) if r.ok else None)

        results = await asyncio.gather(*(check(k, v) for k, v in IP_FEEDS.items()))
        listed = [k for k, hit in results if hit]
        node.attrs["listas_negras"] = listed
        if listed:
            ctx.graph.note(self.name, f"IP presente en {len(listed)} lista(s) de ataques", ", ".join(listed), "high", node)


class DomainBlocklists(Module):
    name = "domain_blocklists"
    description = "¿El dominio figura en listas de phishing y malware? (OpenPhish, URLhaus, StevenBlack)"
    consumes = (Kind.DOMAIN,)

    async def run(self, ctx, node):
        async def check(label, url):
            try:
                r = await ctx.http.get(url, ttl=12 * 3600, retries=1)
            except ConnectionError:
                return label, None
            if not r.ok:
                return label, None
            hosts = parse_hosts(r.text)
            return label, node.value in hosts or registrable(node.value) in hosts

        listed = [k for k, hit in await asyncio.gather(*(check(k, u) for k, u in HOST_FEEDS.items())) if hit]
        node.attrs["listas_dominio"] = listed
        if listed:
            sev = "high" if set(listed) & {"OpenPhish", "URLhaus"} else "low"
            ctx.graph.note(self.name, f"Dominio presente en {len(listed)} lista(s)", ", ".join(listed), sev, node)
