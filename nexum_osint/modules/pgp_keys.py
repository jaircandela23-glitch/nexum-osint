"""Claves PGP públicas: correos y nombres asociados en servidores de claves."""
import re
from urllib.parse import unquote

from ..core.entities import Kind
from ..core.module import Module

UID_RE = re.compile(r"^(?P<name>.*?)\s*<(?P<mail>[^<>@\s]+@[^<>\s]+)>\s*$")


def parse_index(text: str) -> list[tuple[str | None, str]]:
    """Lee el índice en formato máquina (HKP, options=mr) y devuelve (nombre, correo)."""
    found = []
    for line in text.splitlines():
        if not line.startswith("uid:"):
            continue
        uid = unquote(line.split(":")[1])
        m = UID_RE.match(uid)
        if m:
            found.append((m["name"] or None, m["mail"].lower()))
    return found


class PgpKeys(Module):
    name = "pgp_keys"
    description = "Claves PGP publicadas para el correo o el dominio (keyserver.ubuntu.com)"
    consumes = (Kind.EMAIL, Kind.DOMAIN)
    rate = 1
    hosts = ("keyserver.ubuntu.com",)

    async def run(self, ctx, node):
        term = node.value if node.kind is Kind.EMAIL else f"@{node.value}"
        resp = await ctx.http.get("https://keyserver.ubuntu.com/pks/lookup",
                                  params={"op": "vindex", "options": "mr", "search": term},
                                  ttl=24 * 3600)
        if not resp.ok:
            return
        entries = parse_index(resp.text)
        if not entries:
            return
        node.attrs["pgp_keys"] = len(entries)
        for name, mail in entries:
            if node.kind is Kind.DOMAIN and not mail.endswith("@" + node.value):
                continue
            if node.kind is Kind.EMAIL and mail != node.value:
                ctx.emit(node, Kind.EMAIL, mail, "same_key", self.name)
            elif node.kind is Kind.DOMAIN:
                ctx.emit(node, Kind.EMAIL, mail, "pgp_uid", self.name)
            if name:
                ctx.emit(node, Kind.NAME, name, "pgp_name", self.name, pivot=False)
