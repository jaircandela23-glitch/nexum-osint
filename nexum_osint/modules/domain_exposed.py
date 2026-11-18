import re
import secrets

from ..core.entities import Kind, registrable
from ..core.module import Module

# ruta, firma que debe aparecer en el cuerpo (o bytes iniciales) y gravedad
CHECKS = (
    ("/.git/HEAD", lambda b, t: t.startswith("ref:"), "Repositorio Git expuesto (.git/HEAD)", "high"),
    ("/.git/config", lambda b, t: "[core]" in t, "Configuración de Git expuesta (.git/config)", "high"),
    ("/.env", lambda b, t: bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=", t)) and "<html" not in t[:300].lower(),
     "Archivo .env accesible", "high"),
    ("/wp-config.php.bak", lambda b, t: "DB_PASSWORD" in t, "Copia de wp-config.php con credenciales", "high"),
    ("/wp-config.php~", lambda b, t: "DB_PASSWORD" in t, "Copia de wp-config.php con credenciales", "high"),
    ("/backup.sql", lambda b, t: bool(re.search(r"(?i)CREATE TABLE|INSERT INTO", t[:5000])), "Volcado SQL accesible", "high"),
    ("/dump.sql", lambda b, t: bool(re.search(r"(?i)CREATE TABLE|INSERT INTO", t[:5000])), "Volcado SQL accesible", "high"),
    ("/backup.zip", lambda b, t: b[:2] == b"PK", "Copia de seguridad comprimida accesible", "high"),
    ("/phpinfo.php", lambda b, t: "PHP Version" in t, "phpinfo() accesible", "medium"),
    ("/server-status", lambda b, t: "Apache Server Status" in t, "Estado interno de Apache accesible", "medium"),
    ("/.DS_Store", lambda b, t: b[:8] == b"\x00\x00\x00\x01Bud1", "Archivo .DS_Store accesible", "low"),
)


class ExposedFiles(Module):
    name = "exposed_files"
    description = "Archivos sensibles accesibles por error (.git, .env, copias y volcados). Activo, solo el dominio base"
    consumes = (Kind.DOMAIN,)
    active = True
    rate = 3

    async def run(self, ctx, node):
        if node.depth > 0 or registrable(node.value) != node.value:
            return
        base = f"https://{node.value}"
        try:
            ghost = await ctx.http.get(f"{base}/{secrets.token_hex(8)}.php", ttl=0, retries=0)
        except ConnectionError:
            return
        ghost_len = len(ghost.content) if ghost.status == 200 else None
        found = []
        for path, matches, title, severity in CHECKS:
            try:
                r = await ctx.http.get(base + path, ttl=0, retries=0)
            except ConnectionError:
                continue
            if r.status != 200 or not r.content or len(r.content) == ghost_len:
                continue
            if matches(r.content[:20000], r.text[:20000]):
                found.append(path)
                ctx.graph.note(self.name, title, f"{base}{path}", severity, node)
        node.attrs["archivos_expuestos"] = found
