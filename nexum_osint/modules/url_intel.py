"""URLs: dominio, historial en Wayback y enlaces de búsqueda inversa de imagen."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..core.entities import Kind
from ..core.links import enc, manual
from ..core.module import Module

IMAGE_EXT = re.compile(r"\.(jpe?g|png|gif|webp|bmp|tiff?)(\?|$)", re.I)


class UrlIntel(Module):
    name = "url_intel"
    description = "Dominio de la URL, copia en Wayback y búsqueda inversa si es una imagen"
    consumes = (Kind.URL,)
    rate = 2
    hosts = ("archive.org",)

    async def run(self, ctx, node):
        if node.attrs.get("manual"):
            return
        parts = urlsplit(node.value)
        if parts.hostname:
            ctx.emit(node, Kind.DOMAIN, parts.hostname, "hosted_on", self.name)
        r = await ctx.http.get("https://archive.org/wayback/available", params={"url": node.value}, ttl=24 * 3600)
        if r.ok:
            snap = r.json().get("archived_snapshots", {}).get("closest")
            if snap:
                node.attrs["wayback"] = snap.get("url")
                node.attrs["wayback_timestamp"] = snap.get("timestamp")
        if IMAGE_EXT.search(parts.path or ""):
            u = enc(node.value)
            for label, link in [("Google Lens", f"https://lens.google.com/uploadbyurl?url={u}"),
                                ("Yandex Imágenes", f"https://yandex.com/images/search?rpt=imageview&url={u}"),
                                ("TinEye", f"https://tineye.com/search?url={u}"),
                                ("Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}")]:
                manual(ctx, node, self.name, f"Búsqueda inversa: {label}", link, "imagen")
