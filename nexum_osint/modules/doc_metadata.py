"""Metadatos de documentos públicos del dominio, leídos desde copias de Wayback Machine.

Las copias se descargan de archive.org, no del servidor del objetivo, por lo que
el módulo es pasivo. Los metadatos suelen revelar autores, usuarios internos,
software y la empresa que figura en la licencia de Office.
"""
import io
import re
import zipfile

from ..core.entities import Kind
from ..core.module import Module

EXT = r"\.(pdf|docx|xlsx|pptx)$"
MAX_DOCS = 8
MAX_BYTES = 8 * 1024 * 1024


def _xml_field(xml: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xml)
    return m.group(1).strip() if m else None


def read_office(blob: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        core = z.read("docProps/core.xml").decode("utf-8", "replace") if "docProps/core.xml" in z.namelist() else ""
        app = z.read("docProps/app.xml").decode("utf-8", "replace") if "docProps/app.xml" in z.namelist() else ""
    return {
        "author": _xml_field(core, "dc:creator"),
        "modified_by": _xml_field(core, "cp:lastModifiedBy"),
        "created": _xml_field(core, "dcterms:created"),
        "software": _xml_field(app, "Application"),
        "company": _xml_field(app, "Company"),
    }


def read_pdf(blob: bytes) -> dict:
    head = blob[-65536:].decode("latin-1")
    def field(name):
        m = re.search(rf"/{name}\s*\(([^)]{{1,120}})\)", head)
        return m.group(1).strip() if m else None
    return {"author": field("Author"), "software": field("Creator") or field("Producer"),
            "created": field("CreationDate"), "modified_by": None, "company": None}


def read_document(url: str, blob: bytes) -> dict:
    try:
        return read_pdf(blob) if url.lower().endswith(".pdf") else read_office(blob)
    except (zipfile.BadZipFile, KeyError, ValueError):
        return {}


class DocumentMetadata(Module):
    name = "doc_metadata"
    description = "Autores, usuarios y software en metadatos de documentos públicos (vía Wayback)"
    consumes = (Kind.DOMAIN,)
    rate = 1
    hosts = ("web.archive.org",)

    async def run(self, ctx, node):
        if node.depth > 0:
            return
        index = await ctx.http.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"{node.value}/*", "output": "json", "fl": "timestamp,original,statuscode",
                    "filter": f"original:.*{EXT}", "collapse": "urlkey", "limit": 60},
            ttl=24 * 3600)
        if not index.ok:
            return
        rows = index.json()[1:]
        people, software = set(), set()
        for ts, original, status in [r for r in rows if r[2] in ("200", "-")][:MAX_DOCS]:
            doc = await ctx.http.get(f"https://web.archive.org/web/{ts}id_/{original}",
                                     ttl=24 * 3600, retries=1)
            if not doc.ok or not doc.content or len(doc.content) > MAX_BYTES:
                continue
            meta = read_document(original, doc.content)
            for who in (meta.get("author"), meta.get("modified_by")):
                if who:
                    people.add(who)
            if meta.get("software"):
                software.add(meta["software"])
            if meta.get("company"):
                ctx.emit(node, Kind.ORG, meta["company"], "doc_company", self.name, pivot=False,
                         confidence="media")
        for who in sorted(people):
            kind = Kind.NAME if " " in who else Kind.USERNAME
            ctx.emit(node, kind, who, "doc_author", self.name, pivot=False, confidence="baja")
        if people or software:
            ctx.graph.note(self.name, "Metadatos en documentos públicos del dominio",
                           f"Autores: {', '.join(sorted(people)) or '-'} | "
                           f"Software: {', '.join(sorted(software)) or '-'}", "low", node)
