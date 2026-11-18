"""Índices de dark web: carga, y análisis de resultados sin descargar contenido .onion."""
from __future__ import annotations

import html
import json
import re
from importlib import resources
from urllib.parse import parse_qs, unquote, urlsplit

from ..core.config import config_dir

ONION_RE = re.compile(r"https?://[a-z2-7]{16,56}\.onion[^\s\"'<>]*", re.I)
TAG_RE = re.compile(r"<[^>]+>")


def load_sources() -> list[dict]:
    base = json.loads(resources.files("nexum_osint.data").joinpath("darkweb_sources.json")
                      .read_text(encoding="utf-8"))["sources"]
    custom = config_dir() / "darkweb_sources.json"
    if custom.exists():
        extra = json.loads(custom.read_text(encoding="utf-8")).get("sources", [])
        names = {s["name"] for s in extra}
        base = [s for s in base if s["name"] not in names] + extra
    return base


def _clean(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub(" ", fragment))).strip()


def parse_ahmia(body: str, limit: int = 15) -> list[dict]:
    """Extrae título, descripción y dirección .onion de los resultados de Ahmia."""
    results, seen = [], set()
    for block in re.split(r'<li[^>]*class="result"', body)[1:]:
        link = re.search(r'redirect_url=([^"&\s]+)', block)
        url = unquote(link.group(1)) if link else None
        if not url:
            m = ONION_RE.search(html.unescape(block))
            url = m.group(0) if m else None
        if not url or url in seen:
            continue
        seen.add(url)
        title = re.search(r"<a[^>]*>(.*?)</a>", block, re.S)
        desc = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
        results.append({"url": url, "title": _clean(title.group(1))[:120] if title else "",
                        "snippet": _clean(desc.group(1))[:240] if desc else ""})
        if len(results) >= limit:
            break
    return results


def parse_generic(body: str, limit: int = 15) -> list[dict]:
    seen, results = set(), []
    for m in ONION_RE.finditer(html.unescape(body)):
        url = m.group(0).rstrip(".,;)")
        host = urlsplit(url).hostname
        if host and host not in seen:
            seen.add(host)
            results.append({"url": url, "title": "", "snippet": ""})
        if len(results) >= limit:
            break
    return results


PARSERS = {"ahmia": parse_ahmia, "generic": parse_generic}
