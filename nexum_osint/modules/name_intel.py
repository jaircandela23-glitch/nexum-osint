"""Personas: nombres completos. Solo fuentes públicas y enlaces a registros oficiales."""
from __future__ import annotations

import re
import unicodedata

from ..core.entities import Kind
from ..core.links import dork, enc, manual
from ..core.module import Module


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()


def username_variants(full_name: str) -> list[str]:
    parts = [p for p in re.split(r"[\s.'-]+", _ascii(full_name)) if p and p not in ("de", "del", "la", "los", "las", "y")]
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    second = parts[-2] if len(parts) >= 3 else ""
    out = {f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first[0]}{last}",
           f"{last}{first[0]}", f"{first}{last[0]}", f"{first}-{last}"}
    if second:
        out |= {f"{first}{second}", f"{first[0]}{second}{last}"}
    return sorted(v for v in out if len(v) >= 5)


class NameLinks(Module):
    name = "name_links"
    description = "Búsquedas dirigidas del nombre en buscadores, redes, registros y bases abiertas"
    consumes = (Kind.NAME,)

    async def run(self, ctx, node):
        n, q, s = node.value, enc(f'"{node.value}"'), self.name
        for label, url, purpose in [
            ("Google: nombre exacto", dork(f'"{n}"'), "buscador"),
            ("Google: perfiles LinkedIn", dork(f'"{n}" site:linkedin.com/in'), "profesional"),
            ("Google: Facebook", dork(f'"{n}" site:facebook.com'), "redes"),
            ("Google: Instagram", dork(f'"{n}" site:instagram.com'), "redes"),
            ("Google: X / Twitter", dork(f'"{n}" site:x.com OR site:twitter.com'), "redes"),
            ("Google: documentos PDF", dork(f'"{n}" filetype:pdf'), "documentos"),
            ("Google: Scholar", f"https://scholar.google.com/scholar?q={q}", "academico"),
            ("Bing: nombre exacto", f"https://www.bing.com/search?q={q}", "buscador"),
            ("DuckDuckGo: nombre exacto", f"https://duckduckgo.com/?q={q}", "buscador"),
            ("Yandex: nombre exacto", f"https://yandex.com/search/?text={q}", "buscador"),
            ("Facebook: personas", f"https://www.facebook.com/search/people/?q={enc(n)}", "redes"),
            ("LinkedIn: personas", f"https://www.linkedin.com/search/results/people/?keywords={enc(n)}", "profesional"),
            ("OpenCorporates: cargos en empresas", f"https://opencorporates.com/officers?q={enc(n)}", "empresas"),
            ("ICIJ Offshore Leaks", f"https://offshoreleaks.icij.org/search?q={enc(n)}", "empresas"),
            ("OpenSanctions", f"https://www.opensanctions.org/search/?q={enc(n)}", "listas"),
            ("Perú: SUNEDU (grados y títulos)", "https://enlinea.sunedu.gob.pe/", "registro_oficial"),
            ("Perú: SUNAT consulta RUC (por nombre)", "https://e-consultaruc.sunat.gob.pe/cl-ti-itmrconsruc/FrameCriterioBusquedaWeb.jsp", "registro_oficial"),
            ("Colombia: RUES (registro mercantil)", "https://www.rues.org.co/", "registro_oficial"),
            ("España: BORME (registro mercantil)", "https://www.boe.es/diario_borme/", "registro_oficial"),
        ]:
            manual(ctx, node, s, label, url, purpose)


class NameWikidata(Module):
    name = "name_wikidata"
    description = "Entidades públicas con ese nombre en Wikidata"
    consumes = (Kind.NAME,)
    rate = 2
    hosts = ("www.wikidata.org",)

    async def run(self, ctx, node):
        r = await ctx.http.get("https://www.wikidata.org/w/api.php", params={
            "action": "wbsearchentities", "search": node.value, "language": "es",
            "uselang": "es", "format": "json", "limit": 5, "type": "item"}, ttl=24 * 3600)
        if not r.ok:
            return
        hits = [h for h in r.json().get("search", []) if h.get("label", "").lower() == node.value.lower()]
        for h in hits:
            ctx.emit(node, Kind.URL, f"https://www.wikidata.org/wiki/{h['id']}", "wikidata_entity",
                     self.name, pivot=False, label=h.get("label"), description=h.get("description"))
        if hits:
            ctx.graph.note(self.name, f"{len(hits)} entidad(es) en Wikidata con ese nombre exacto",
                           "; ".join(f"{h['id']}: {h.get('description', 's/d')}" for h in hits), "info", node)


class NameOrcid(Module):
    name = "name_orcid"
    description = "Investigadores con ese nombre en ORCID (registro público)"
    consumes = (Kind.NAME,)
    rate = 2
    hosts = ("pub.orcid.org",)

    async def run(self, ctx, node):
        parts = node.value.split()
        if len(parts) < 2:
            return
        q = f'given-names:{parts[0]} AND family-name:{parts[-1]}'
        r = await ctx.http.get("https://pub.orcid.org/v3.0/search/", params={"q": q, "rows": 5},
                               headers={"accept": "application/json"}, ttl=24 * 3600)
        if not r.ok:
            return
        results = r.json().get("result") or []
        for item in results:
            oid = item.get("orcid-identifier", {}).get("path")
            if oid:
                ctx.emit(node, Kind.PROFILE, f"https://orcid.org/{oid}", "possible_match", self.name,
                         pivot=False, site="ORCID", confidence="baja")
        if results:
            ctx.graph.note(self.name, f"{len(results)} perfil(es) ORCID con nombre y apellido coincidentes",
                           "Homónimos posibles: verificar afiliación antes de atribuir.", "info", node)


class NameGithub(Module):
    name = "name_github"
    description = "Cuentas de GitHub cuyo nombre público coincide"
    consumes = (Kind.NAME,)
    optional_key = "github"
    rate = 0.3
    hosts = ("api.github.com",)

    async def run(self, ctx, node):
        h = {"accept": "application/vnd.github+json"}
        if key := ctx.config.key("github"):
            h["authorization"] = f"Bearer {key}"
        r = await ctx.http.get("https://api.github.com/search/users",
                               params={"q": f'"{node.value}" in:fullname', "per_page": 5}, headers=h, ttl=12 * 3600)
        if r.ok:
            for item in r.json().get("items", []):
                ctx.emit(node, Kind.PROFILE, item["html_url"], "possible_match", self.name,
                         pivot=False, site="GitHub", username=item["login"], confidence="baja")


class NameVariants(Module):
    name = "name_variants"
    description = "Genera alias probables a partir del nombre y los verifica (activar con --permute)"
    consumes = (Kind.NAME,)

    async def run(self, ctx, node):
        if not ctx.engine.options.get("permute"):
            return
        for v in username_variants(node.value)[:8]:
            ctx.emit(node, Kind.USERNAME, v, "name_permutation", self.name, confidence="baja")
