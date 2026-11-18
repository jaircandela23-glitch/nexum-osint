"""Enlaces de verificación manual.

Muchas fuentes legítimas (buscadores de personas, registros públicos, sitios
con captcha) no ofrecen una API gratuita. En esos casos el módulo no inventa
datos: genera el enlace exacto de consulta para que el analista lo abra.
"""
from __future__ import annotations

from urllib.parse import quote, quote_plus

from .entities import Kind, Node


def manual(ctx, parent: Node, source: str, label: str, url: str, purpose: str) -> None:
    ctx.emit(parent, Kind.URL, url, "manual_check", source, pivot=False,
             label=label, purpose=purpose, manual=True)


def dork(query: str) -> str:
    return "https://www.google.com/search?q=" + quote_plus(query)


def enc(text: str) -> str:
    return quote(text, safe="")
