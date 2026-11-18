"""Búsquedas avanzadas (dorks): enlaces listos para abrir y resultados en vivo desde DuckDuckGo."""
from __future__ import annotations

import asyncio
import html
import random
import re
from urllib.parse import parse_qs, unquote, urlsplit

from ..core.entities import Kind
from ..core.links import dork, enc, manual
from ..core.module import Module

DOC_TYPES = "filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx"


def domain_dorks(domain: str) -> list[tuple[str, str]]:
    return [
        ("Documentos publicados", f"site:{domain} ({DOC_TYPES})"),
        ("Directorios abiertos", f'site:{domain} intitle:"index of"'),
        ("Archivos de copia, registro o configuración", f"site:{domain} (ext:bak OR ext:log OR ext:sql OR ext:env OR ext:conf)"),
        ("Subdominios indexados", f"site:*.{domain} -www"),
        ("Páginas de acceso", f"site:{domain} (inurl:login OR inurl:admin OR inurl:portal)"),
        ("Menciones en otros sitios", f'"{domain}" -site:{domain}'),
        ("En código público", f'"{domain}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)'),
        ("En sitios de pegado", f'"{domain}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co)'),
    ]


def email_dorks(address: str) -> list[tuple[str, str]]:
    user = address.split("@")[0]
    return [
        ("Dirección exacta", f'"{address}"'),
        ("En redes y foros", f'"{address}" (site:linkedin.com OR site:facebook.com OR site:twitter.com OR site:reddit.com)'),
        ("En código público", f'"{address}" (site:github.com OR site:gitlab.com)'),
        ("En sitios de pegado", f'"{address}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co)'),
        ("En documentos", f'"{address}" ({DOC_TYPES})'),
        ("Usuario del correo como alias", f'"{user}" (site:instagram.com OR site:tiktok.com OR site:github.com)'),
    ]


def username_dorks(user: str) -> list[tuple[str, str]]:
    return [
        ("Alias exacto", f'"{user}"'),
        ("En redes sociales", f'"{user}" (site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:twitter.com OR site:x.com)'),
        ("En perfiles profesionales y de código", f'"{user}" (site:linkedin.com OR site:github.com OR site:gitlab.com)'),
        ("En foros", f'"{user}" (site:reddit.com OR site:forocoches.com OR site:stackoverflow.com)'),
        ("En la dirección web", f"inurl:{user}"),
    ]


BUILDERS = {Kind.DOMAIN: domain_dorks, Kind.EMAIL: email_dorks, Kind.USERNAME: username_dorks}


class DorkLinks(Module):
    name = "dorks"
    description = "Búsquedas avanzadas listas para abrir en Google, Bing y DuckDuckGo (documentos, directorios, menciones)"
    consumes = (Kind.DOMAIN, Kind.EMAIL, Kind.USERNAME)

    async def run(self, ctx, node):
        for label, query in BUILDERS[node.kind](node.value):
            manual(ctx, node, self.name, f"Google: {label}", dork(query), "dork")
        first = BUILDERS[node.kind](node.value)[0][1]
        manual(ctx, node, self.name, "Bing: consulta principal", f"https://www.bing.com/search?q={enc(first)}", "dork")
        manual(ctx, node, self.name, "DuckDuckGo: consulta principal", f"https://duckduckgo.com/?q={enc(first)}", "dork")


RESULT_TAG = re.compile(r'<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*>(.*?)</a>', re.I | re.S)
HREF = re.compile(r'href="([^"]+)"', re.I)


def parse_results(page: str) -> list[tuple[str, str]]:
    """(título, URL) de cada resultado de la versión HTML de DuckDuckGo."""
    found = []
    for tag in re.finditer(r'<a\b[^>]*class="[^"]*\bresult__a\b[^"]*"[^>]*>', page, re.I):
        href = HREF.search(tag.group(0))
        if not href:
            continue
        link = html.unescape(href.group(1))
        if link.startswith("//"):
            link = "https:" + link
        target = parse_qs(urlsplit(link).query).get("uddg")
        url = unquote(target[0]) if target else link
        if not url.startswith("http") or "duckduckgo.com" in (urlsplit(url).hostname or ""):
            continue
        title = RESULT_TAG.search(page, tag.start())
        text = re.sub(r"<[^>]+>", "", title.group(1)) if title else ""
        found.append((html.unescape(text).strip()[:120], url))
    return found


class DorkResults(Module):
    name = "dork_results"
    description = "Ejecuta las búsquedas avanzadas más útiles en DuckDuckGo y lista los resultados (sin key)"
    consumes = (Kind.DOMAIN, Kind.EMAIL, Kind.USERNAME)
    rate = 0.5
    hosts = ("html.duckduckgo.com",)
    queries = 4          # por objetivo: pocas y espaciadas para no ser bloqueado
    pause = (1.5, 3.5)   # segundos entre consultas

    async def run(self, ctx, node):
        chosen = BUILDERS[node.kind](node.value)[:self.queries]
        total, blocked = 0, False
        for i, (label, query) in enumerate(chosen):
            if i:
                await asyncio.sleep(random.uniform(*self.pause))
            resp = await ctx.http.get("https://html.duckduckgo.com/html/", params={"q": query}, ttl=12 * 3600,
                                      retries=0, rotate_ua=True)
            results = parse_results(resp.text) if resp.ok else []
            if not results and (not resp.ok or "anomaly" in resp.text.lower()):
                blocked = True
                break
            for title, url in results[:10]:
                ctx.emit(node, Kind.URL, url, "search_result", self.name, pivot=False, label=title, dork=label)
            total += len(results[:10])
        if blocked:
            ctx.graph.note(self.name, "DuckDuckGo no devolvió resultados",
                           "Puede ser un límite temporal; usa los enlaces del módulo dorks.", "warn", node)
        elif total:
            ctx.graph.note(self.name, f"{total} resultados de búsquedas avanzadas",
                           ", ".join(label for label, _ in chosen), "info", node)
