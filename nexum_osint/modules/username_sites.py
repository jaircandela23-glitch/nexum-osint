"""Búsqueda de un alias en una lista propia de sitios, con verificación anti falsos positivos."""
from __future__ import annotations

import asyncio
import json
import re
import secrets
from importlib import resources
from pathlib import Path

from .. import sitesync
from ..core.config import config_dir
from ..core.entities import Kind
from ..core.module import Module


def load_sites() -> list[dict]:
    """Carga la lista interna y, si existe, la personal del usuario."""
    base = json.loads(resources.files("nexum_osint.data").joinpath("sites.json")
                      .read_text(encoding="utf-8"))["sites"]
    ext = sitesync.path()
    if ext.exists():
        base = sitesync.merge(base, json.loads(ext.read_text(encoding="utf-8")).get("sites", []))
    custom = config_dir() / "sites.json"
    if custom.exists():
        extra = json.loads(custom.read_text(encoding="utf-8")).get("sites", [])
        names = {s["name"] for s in extra}
        base = [s for s in base if s["name"] not in names] + extra
    return base


def classify(site: dict, status: int, body: str, final_url: str = "") -> bool | None:
    """True si el perfil existe, False si no, None si no es concluyente."""
    check = site.get("check", "status")
    if check == "wmn":
        e_str, m_str = site.get("e_string"), site.get("m_string")
        if status == site.get("e_code") and (not e_str or e_str in body) and not (m_str and m_str in body):
            return True
        if (m_str and m_str in body) or status == site.get("m_code"):
            return False
        return None
    if status in (403, 429) or status >= 500:
        return None
    if check == "errmsg":
        if any(m in body for m in site.get("errors", [])):
            return False
        return status < 400 or None
    if check == "errurl":
        return not final_url.rstrip("/").startswith(site["error_url"].format(u="").rstrip("/")) if status < 400 else False
    if check == "status":
        return status == 200 if status in (200, 404, 410) else None
    if status == 404:
        return False
    if check == "text_present":
        return site["pattern"] in body
    if check == "text_absent":
        return site["pattern"] not in body and body.strip() != ""
    if check == "json_nonempty":
        try:
            data = json.loads(body)
        except ValueError:
            return None
        return bool(data)
    return None


CONTENT_CHECKS = {"wmn", "errmsg", "errurl", "text_present", "text_absent", "json_nonempty"}


def confidence(site: dict, name_in_page: bool) -> str:
    """«confirmado» si el sitio valida por contenido o la página menciona el alias; si no, «probable»."""
    return "confirmado" if site.get("check", "status") in CONTENT_CHECKS or name_in_page else "probable"


class UsernameSites(Module):
    name = "username_sites"
    description = "Comprueba un alias en cientos de sitios y descarta falsos positivos"
    consumes = (Kind.USERNAME,)
    rate = 4

    async def _probe(self, ctx, site: dict, username: str, ttl: float):
        if site.get("regex") and not re.match(site["regex"], username):
            return site["url"].format(u=username), False, False
        url = site["url"].format(u=username)
        try:
            resp = await ctx.http.get(url, ttl=ttl, retries=1, rotate_ua=True)
        except ConnectionError:
            return url, None, False
        return url, classify(site, resp.status, resp.text, resp.url), username.lower() in resp.text.lower()

    async def run(self, ctx, node):
        sites = load_sites()
        gate = asyncio.Semaphore(30)

        async def check(site):
            async with gate:
                url, found, in_page = await self._probe(ctx, site, node.value, 6 * 3600)
                if found:
                    # Contraste: un alias inexistente no debería existir en este sitio.
                    control = "nx" + secrets.token_hex(7)
                    _, ghost, _ = await self._probe(ctx, site, control, 0)
                    if ghost:
                        return site, url, "unreliable"
                    return site, url, "found:" + confidence(site, in_page)
                return site, url, "missing" if found is False else "unknown"

        results = await asyncio.gather(*(check(s) for s in sites))

        hits = [(s, u, st.split(":")[1]) for s, u, st in results if st.startswith("found")]
        for site, url, level in hits:
            ctx.emit(node, Kind.PROFILE, url, "has_profile", self.name, pivot=False,
                     site=site["name"], category=site["category"], username=node.value, confianza=level)

        unreliable = [s["name"] for s, _, st in results if st == "unreliable"]
        unknown = [s["name"] for s, _, st in results if st == "unknown"]
        node.attrs["sites_checked"] = len(sites)
        node.attrs["profiles_found"] = len(hits)
        sure = sum(1 for _, _, level in hits if level == "confirmado")
        if hits:
            ctx.graph.note(self.name, f"{len(hits)} perfiles encontrados: {sure} confirmados, {len(hits) - sure} probables",
                           "Confirmado: el sitio distingue un alias real de uno inexistente, o su página nombra el alias. "
                           "Probable: solo respondió distinto a un alias inventado.", "info", node)
        if unreliable:
            ctx.graph.note(self.name, f"{len(unreliable)} sitios descartados por falsos positivos",
                           ", ".join(unreliable), "info", node)
        if unknown:
            ctx.graph.note(self.name, f"{len(unknown)} sitios sin respuesta concluyente",
                           ", ".join(unknown), "info", node)
