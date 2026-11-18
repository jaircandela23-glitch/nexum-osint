import io
import re
from datetime import datetime

from ..core.entities import Kind
from ..core.links import manual
from ..core.module import Module

IMG = re.compile(r"\.(jpe?g|tiff?|png|webp)(\?|$)", re.I)
TAGS = {271: "marca", 272: "modelo", 305: "software", 306: "fecha_modificacion", 315: "autor", 33432: "copyright"}


def _deg(value, ref):
    d, m, s = (float(x) for x in value)
    out = d + m / 60 + s / 3600
    return -out if ref in ("S", "W") else out


def read_exif(raw: bytes) -> dict:
    from PIL import Image
    img = Image.open(io.BytesIO(raw))
    exif = img.getexif()
    out = {"dimensiones": f"{img.width}x{img.height}"}
    for tag, label in TAGS.items():
        if exif.get(tag):
            out[label] = str(exif[tag]).strip()[:80]
    sub = exif.get_ifd(0x8769)
    if sub.get(36867):
        out["fecha_captura"] = str(sub[36867])
    gps = exif.get_ifd(0x8825)
    if gps.get(2) and gps.get(4):
        out["coords"] = [round(_deg(gps[2], gps.get(1, "N")), 6), round(_deg(gps[4], gps.get(3, "E")), 6)]
    return out


class ImageExif(Module):
    name = "image_exif"
    description = "Descarga la imagen y lee sus metadatos EXIF: cámara, fecha y coordenadas GPS"
    consumes = (Kind.URL,)
    active = True

    async def run(self, ctx, node):
        if node.attrs.get("manual") or not IMG.search(node.value.split("?")[0] + "?"):
            return
        r = await ctx.http.get(node.value, ttl=0, retries=0)
        if not r.ok or not r.content or len(r.content) > 25_000_000:
            return
        try:
            info = read_exif(r.content)
        except ImportError:
            ctx.graph.note(self.name, "Pillow no está instalado", "pip install Pillow", "info", node)
            return
        except Exception:
            return
        node.attrs.update({f"exif_{k}": v for k, v in info.items()})
        if "coords" in info:
            lat, lon = info["coords"]
            ctx.graph.note(self.name, "La imagen contiene coordenadas GPS", f"{lat}, {lon}", "high", node)
            manual(ctx, node, self.name, "Ver ubicación en OpenStreetMap",
                   f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}", "mapa")
        elif len(info) > 1:
            ctx.graph.note(self.name, "La imagen conserva metadatos EXIF", ", ".join(sorted(info)), "info", node)
