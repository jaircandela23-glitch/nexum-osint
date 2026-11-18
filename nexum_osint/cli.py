"""Interfaz de línea de comandos: `nexum-osint`."""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import re
import sys
import zipfile
from importlib import resources
from types import SimpleNamespace
from pathlib import Path

from . import __version__, branding, cases, doctor, extract, history, tools
from .core.cache import Cache
from .analysis import exposure, snapshots
from .core.config import Config, cache_dir, config_dir
from .core.engine import Engine
from .core.entities import Graph, Kind, guess_kind, normalize
from .core.http import Http
from .core.module import discover
from .core.ratelimit import RateLimiter
from .core.tor import TorControl
from .darkweb import guard, guide
from .reporting import exporters
from .ui import MUTED, UI

FORMATS = ("html", "json", "csv", "pdf", "md", "graphml")
TARGET_TYPES = ("domain", "ip", "email", "username", "phone", "name", "doc", "url", "org", "crypto")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexum-osint",
        description="NEXUM OSINT - framework modular de inteligencia de fuentes abiertas.",
        epilog=f"{branding.CREDIT} {branding.COMPANY}.")
    p.add_argument("--version", action="version", version=f"nexum-osint {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def common(s: argparse.ArgumentParser) -> None:
        s.add_argument("-d", "--depth", type=int, default=1, help="niveles de pivoteo sobre lo descubierto (default 1)")
        s.add_argument("-m", "--modules", help="solo estos módulos, separados por coma")
        s.add_argument("-x", "--exclude", help="excluir módulos, separados por coma")
        s.add_argument("-o", "--output", default="nexum_reports", help="carpeta de salida")
        s.add_argument("-f", "--format", default="html,json", help=f"formatos: {','.join(FORMATS)} (default html,json)")
        s.add_argument("-c", "--concurrency", type=int, default=20)
        s.add_argument("--active", action="store_true", help="permitir módulos activos que contactan al objetivo")
        s.add_argument("--no-cache", action="store_true")
        s.add_argument("--proxy", help="proxy HTTP/SOCKS, p. ej. socks5://127.0.0.1:9050")
        s.add_argument("--caso", help="guardar la investigación en este caso (se crea si no existe)")
        s.add_argument("--rotar-tor", action="store_true",
                       help="si un sitio bloquea (403/429), pedir un circuito nuevo a Tor (requiere --proxy de Tor)")
        s.add_argument("--permute", action="store_true",
                       help="para nombres: generar y verificar alias probables")
        s.add_argument("-q", "--quiet", action="store_true")
        s.add_argument("--config", type=Path, help="ruta alternativa del config.toml")
        s.add_argument("--darkweb", action="store_true", help="incluir búsqueda en dark web (exige entorno verificado)")
        s.add_argument("--acepto-riesgos", action="store_true", help="confirma la advertencia de dark web")
        s.add_argument("--sin-vpn", action="store_true", help="dark web sin VPN, bajo tu responsabilidad")
        s.add_argument("--force-env", action="store_true", help="dark web fuera de Kali (sin soporte)")

    s = sub.add_parser("scan", help="investigar uno o varios objetivos")
    s.add_argument("targets", nargs="*", help="dominio, IP, correo, teléfono, alias, nombre o URL (se detecta solo)")
    s.add_argument("-i", "--input", type=Path, help="archivo con un objetivo por línea (# para comentarios)")
    s.add_argument("-t", "--type", choices=TARGET_TYPES, help="forzar el tipo (obligatorio para documentos: -t doc)")
    common(s)

    sub.add_parser("menu", help="menú interactivo")
    m = sub.add_parser("modules", help="listar módulos disponibles")
    m.add_argument("--markdown", action="store_true", help="imprimir la tabla en Markdown (para la documentación)")
    cs = sub.add_parser("casos", help="casos de investigación guardados: listar, ver, comparar, exportar")
    cs.add_argument("nombre", nargs="?", help="caso a consultar (sin él, se listan todos)")
    cs.add_argument("--comparar", action="store_true", help="diferencias entre las dos últimas investigaciones del caso")
    cs.add_argument("--exportar", metavar="ARCHIVO", help="guardar el caso completo en un JSON")
    cs.add_argument("--borrar", action="store_true", help="eliminar el caso y todo lo que contiene")
    ex = sub.add_parser("extract", help="extraer correos, teléfonos, perfiles y metadatos de un archivo, carpeta, URL o texto")
    ex.add_argument("source", help="archivo, carpeta, URL, o - para leer la entrada estándar")
    ex.add_argument("--pages", type=int, default=1, help="páginas del mismo sitio a recorrer (máx. 25, solo con URL)")
    ex.add_argument("-o", "--output", help="guardar el resultado en un archivo .json o .csv")
    ex.add_argument("--scan", action="store_true", help="investigar a continuación los datos encontrados")
    t = sub.add_parser("tools", help="directorio de herramientas OSINT por categoría")
    tsub = t.add_subparsers(dest="tools_cmd")
    tl = tsub.add_parser("list", help="listar herramientas, opcionalmente de una categoría")
    tl.add_argument("--categoria", help="nombre de la categoría")
    ts = tsub.add_parser("search", help="buscar por nombre, uso o categoría")
    ts.add_argument("texto", nargs="+")
    ti = tsub.add_parser("import", help="importar la OSINT Tools Library desde una carpeta o zip propio")
    ti.add_argument("ruta", type=Path)
    st = sub.add_parser("sites", help="listar los sitios del módulo de alias")
    st.add_argument("--audit", action="store_true", help="detectar sitios que responden 'existe' a cualquier alias")
    st.add_argument("--update", action="store_true", help="descargar las listas WhatsMyName y Sherlock (más de 1.000 sitios)")
    w = sub.add_parser("watch", help="repetir una investigación cada cierto tiempo y mostrar los cambios")
    w.add_argument("targets", nargs="+")
    w.add_argument("-t", "--type", choices=TARGET_TYPES)
    w.add_argument("--cada", type=int, default=60, help="minutos entre investigaciones (default 60)")
    w.add_argument("--veces", type=int, default=0, help="número de repeticiones (0 = hasta pulsar Ctrl+C)")
    common(w)
    dr = sub.add_parser("doctor", help="diagnóstico del entorno e instalación de librerías")
    dr.add_argument("--fix", action="store_true", help="instalar las librerías de Python que falten")
    dr.add_argument("--yes", action="store_true", help="no pedir confirmación")
    dr.add_argument("--darkweb", action="store_true", help="incluir las herramientas de dark web")
    sub.add_parser("setup", help="asistente para configurar las API keys gratuitas")
    sub.add_parser("apis", help="listar APIs gratuitas, qué habilitan y cuáles están configuradas")
    sub.add_parser("about", help="créditos y licencia")
    c = sub.add_parser("cache", help="administrar la caché")
    c.add_argument("action", choices=["purge", "path"])

    d = sub.add_parser("darkweb", help="búsqueda en dark web (solo Kali, con Tor y VPN)")
    dsub = d.add_subparsers(dest="dw_cmd", required=True)
    dsub.add_parser("guide", help="guía de instalación y configuración del entorno")
    dc = dsub.add_parser("check", help="verificar que el entorno es seguro")
    dc.add_argument("--acepto-riesgos", action="store_true")
    dc.add_argument("--sin-vpn", action="store_true")
    dc.add_argument("--force-env", action="store_true")
    dc.add_argument("--config", type=Path)
    ds = dsub.add_parser("search", help="buscar un término en índices .onion")
    ds.add_argument("term", help="correo, dominio, alias, nombre entre comillas o teléfono")
    common(ds)
    return p


def _slug(text: str) -> str:
    return re.sub(r"[^\w.-]+", "_", text).strip("_")[:60] or "scan"


# ---------------------------------------------------------------- dark web
async def _darkweb_gate(args, config: Config, ui: UI):
    """Muestra la advertencia, verifica el entorno y devuelve un cliente Tor o None."""
    ui.say(guide.WARNING, "yellow")
    checks = guard.static_checks(config.tor_proxy, force_env=args.force_env, no_vpn=args.sin_vpn)
    tor_http = None
    if all(c.ok for c in checks[:3]):
        cfg = copy.copy(config)
        cfg.proxy, cfg.timeout = config.tor_proxy, 60.0
        tor_http = Http(cfg, Cache(None, enabled=False), RateLimiter(default_rate=1))
        checks.append(await guard.tor_check(tor_http))
    ack = guard.acknowledged(getattr(args, "acepto_riesgos", False))
    checks.append(guard.Check("Advertencia aceptada", ack, "Aceptada" if ack else "No aceptada",
                              "Repite con --acepto-riesgos o escribe ACEPTO cuando se te pida."))
    ui.say("Verificación del entorno", "bold")
    for c in checks:
        ui.say(f"  [{'ok' if c.ok else 'NO'}] {c.name}: {c.detail}", None if c.ok else "red")
    failed = [c for c in checks if not c.ok and c.blocking]
    if failed:
        ui.say("\nNo se puede continuar. Qué corregir:", "bold")
        for c in failed:
            ui.say(f"  - {c.name}: {c.fix}")
        ui.say("\nGuía completa:  nexum-osint darkweb guide", "dim")
        if tor_http:
            await tor_http.close()
        return None
    return tor_http


# -------------------------------------------------------------------- scan
def _read_targets(path: Path) -> list[str]:
    lines = (l.split(" #", 1)[0].strip() for l in path.read_text(encoding="utf-8").splitlines())
    return [l for l in lines if l and not l.startswith("#")]


def _build_seeds(args, ui: UI):
    seeds: list[tuple[Kind, str]] = []
    if getattr(args, "input", None):
        try:
            args.targets = list(args.targets) + _read_targets(args.input)
        except OSError as exc:
            ui.error(f"no se pudo leer {args.input}: {exc}")
            return None
    if not args.targets:
        ui.error("indica al menos un objetivo o un archivo con -i")
        return None
    for raw in args.targets:
        kind = Kind(args.type) if getattr(args, "type", None) else guess_kind(raw)
        try:
            seeds.append((kind, normalize(kind, raw)))
        except ValueError:
            ui.error(f"objetivo inválido para tipo {kind.value}: {raw}")
            return None
    return seeds


async def _scan(args, ui: UI) -> int:
    config = Config.load(args.config)
    if args.proxy:
        config.proxy = args.proxy

    registry = discover()
    wanted = set(filter(None, (args.modules or "").split(",")))
    unknown = wanted - set(registry)
    if unknown:
        ui.error(f"módulos desconocidos: {', '.join(sorted(unknown))}")
        return 2
    excluded = set(filter(None, (args.exclude or "").split(",")))
    selected = {k: v for k, v in registry.items() if (not wanted or k in wanted) and k not in excluded}

    seeds = _build_seeds(args, ui)
    if seeds is None:
        return 2
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    if set(formats) - set(FORMATS):
        ui.error(f"formato no soportado: {', '.join(sorted(set(formats) - set(FORMATS)))}")
        return 2

    tor_http = None
    if args.darkweb:
        tor_http = await _darkweb_gate(args, config, ui)
        if tor_http is None:
            return 3

    cache = Cache(cache_dir() / "cache.sqlite", enabled=not args.no_cache)
    http = Http(config, cache, RateLimiter())
    if getattr(args, "rotar_tor", False):
        if not config.proxy:
            ui.error("--rotar-tor necesita un proxy de Tor: usa --proxy socks5h://127.0.0.1:9050")
            return 2
        http.rotator = TorControl.from_setting(config.tor_control, config.tor_control_password)
    graph = Graph()
    engine = Engine(http, graph, config, selected, depth=args.depth, concurrency=args.concurrency,
                    allow_active=args.active, on_event=ui.event,
                    options={"permute": args.permute, "darkweb": bool(tor_http)}, tor_http=tor_http)

    ui.say(f"Objetivos: {', '.join(f'{k.value}:{v}' for k, v in seeds)}  ·  "
           f"{len(engine.modules)} módulos  ·  profundidad {args.depth}\n")
    try:
        await engine.run(seeds)
    finally:
        await http.close()
        if tor_http:
            await tor_http.close()
        cache.close()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    values = [v for _, v in seeds]
    stem = _slug("_".join(values))
    expo = exposure.score(graph)
    changes = snapshots.compare(snapshots.load(values), graph)
    graph.meta = {"exposicion": expo, "cambios": changes}
    written: list[Path] = []
    if "html" in formats:
        written.append(exporters.to_html(graph, engine.stats, values, args.depth, out / f"{stem}.html"))
    if "json" in formats:
        written.append(exporters.to_json(graph, engine.stats, values, args.depth, out / f"{stem}.json"))
    if "csv" in formats:
        written += exporters.to_csv(graph, out, stem)
    if "pdf" in formats:
        try:
            written.append(exporters.to_pdf(graph, engine.stats, values, args.depth, out / f"{stem}.pdf"))
        except ImportError:
            ui.error("PDF omitido: falta reportlab (pip install reportlab)")
    if "md" in formats:
        written.append(exporters.to_markdown(graph, engine.stats, values, args.depth, out / f"{stem}.md"))
    if "graphml" in formats:
        written.append(exporters.to_graphml(graph, out / f"{stem}.graphml"))

    history.record(values, out, written, sum(1 for n in graph.notes if n["severity"] == "high"))
    if getattr(args, "caso", None):
        book = cases.CaseBook()
        try:
            run_no = book.add_run(args.caso, values, args.depth, graph, expo.get("puntaje") if isinstance(expo, dict) else None, written)
        finally:
            book.close()
        ui.say(f"Guardado en el caso «{cases.clean_name(args.caso)}» (investigación {run_no}).", "dim")
    snapshots.save(values, graph)
    ui.summary(graph, engine.stats, expo, changes)
    keyless = [s.split(" ")[0] for s in engine.stats.skipped if "falta API key" in s]
    others = [s for s in engine.stats.skipped if "falta API key" not in s]
    if keyless:
        ui.say(f"\n{len(keyless)} módulos omitidos por falta de key gratuita ({', '.join(keyless)}).", "dim")
        ui.say("Configúralas con:  nexum-osint setup", "dim")
    if others:
        ui.say("Omitidos: " + "; ".join(others), "dim")
    ui.rule("Reportes")
    for path in written:
        ui.say(f"  {path}")
    return 0


# ------------------------------------------------------------- utilidades
def _mode(mod) -> str:
    return "dark web" if mod.darkweb else ("activo" if mod.active else "pasivo")


def _key_label(mod) -> str:
    return (f"requiere {mod.needs_key}" if mod.needs_key else
            f"opcional {mod.optional_key}" if mod.optional_key else "sin key")


def _watch(args, ui: UI) -> int:
    import time
    args.input = None
    runs = 0
    while True:
        runs += 1
        ui.rule(f"Vigilancia · ronda {runs}")
        code = asyncio.run(_scan(args, ui))
        if code:
            return code
        if args.veces and runs >= args.veces:
            return 0
        ui.say(f"\nPróxima ronda en {args.cada} minutos. Ctrl+C para detener.", MUTED)
        time.sleep(max(args.cada, 1) * 60)


def _list_modules(ui: UI, markdown: bool = False) -> int:
    registry = discover()
    if markdown:
        groups: dict[str, list] = {}
        for name, mod in registry.items():
            groups.setdefault(", ".join(k.value for k in mod.consumes), []).append((name, mod))
        print(f"# Módulos de {branding.TOOL} v{__version__}\n")
        print(f"{len(registry)} módulos. Los activos solo se ejecutan con `--active`; los de dark web, con `--darkweb`.\n")
        for entrada, items in sorted(groups.items()):
            print(f"## Entrada: {entrada}\n\n| Módulo | Modo | API key | Qué hace |\n|---|---|---|---|")
            for name, mod in sorted(items):
                print(f"| `{name}` | {_mode(mod)} | {_key_label(mod)} | {mod.description} |")
            print()
        return 0
    rows = [[n, ",".join(k.value for k in m.consumes), _mode(m), _key_label(m), m.description] for n, m in registry.items()]
    ui.table(f"{len(rows)} módulos", ["nombre", "entrada", "modo", "api key", "descripción"], rows)
    return 0


async def _audit_sites(ui: UI) -> int:
    import secrets
    from .modules.username_sites import UsernameSites, load_sites
    config = Config.load()
    http = Http(config, Cache(None, enabled=False), RateLimiter(default_rate=4))
    mod, sem, bad = UsernameSites(), asyncio.Semaphore(10), []

    async def one(site):
        async with sem:
            _, found, _ = await mod._probe(SimpleNamespace(http=http), site, "nx" + secrets.token_hex(7), 0)
            if found:
                bad.append(site["name"])

    sites = load_sites()
    try:
        await asyncio.gather(*(one(s) for s in sites))
    finally:
        await http.close()
    ui.say(f"{len(sites)} sitios revisados.")
    ui.say("Responden 'existe' a un alias inventado (se descartan solos en cada escaneo): " + (", ".join(sorted(bad)) or "ninguno"))
    return 0


async def _update_sites(ui: UI) -> int:
    from . import sitesync
    config = Config.load()
    http = Http(config, Cache(None, enabled=False), RateLimiter(default_rate=2))
    try:
        res = await sitesync.update(http)
    except Exception as exc:
        ui.error(f"no se pudo actualizar: {exc}")
        return 1
    finally:
        await http.close()
    ui.say(f"Listas actualizadas: {res['total']} sitios en total.")
    ui.say("Fuentes: WhatsMyName (CC BY-SA 4.0, WebBreacher y colaboradores) y Sherlock (MIT, Sherlock Project).", "dim")
    ui.say(f"Guardadas en {sitesync.path()}", "dim")
    return 0


def _list_sites(ui: UI, audit: bool, update: bool = False) -> int:
    from .modules.username_sites import load_sites
    if update:
        return asyncio.run(_update_sites(ui))
    if audit:
        return asyncio.run(_audit_sites(ui))
    sites = load_sites()
    ui.table(f"{len(sites)} sitios", ["sitio", "categoría", "comprobación"],
             [[s["name"], s["category"], s.get("check", "status")] for s in sites])
    return 0


def _apis() -> list[dict]:
    return json.loads(resources.files("nexum_osint.data").joinpath("apis.json").read_text(encoding="utf-8"))["apis"]


def _list_apis(ui: UI) -> int:
    cfg = Config.load()
    rows = [[a["service"], "sí" if cfg.key(a["key"]) else "no", a["free"], a["enables"], a["signup"]] for a in _apis()]
    ui.table("APIs gratuitas", ["servicio", "configurada", "plan gratuito", "habilita", "registro"], rows)
    ui.say("\nEl resto de módulos funciona sin ninguna key. Configura las tuyas con:  nexum-osint setup", "dim")
    return 0


def _write_config(path: Path, cfg: Config) -> None:
    lines = ["# Generado por `nexum-osint setup`. Puedes editarlo a mano.", "", "[keys]"]
    lines += [f'{k} = "{v}"' for k, v in sorted(cfg.keys.items())]
    lines += ["", "[network]", f"timeout = {int(cfg.timeout)}", f"cache_ttl = {int(cfg.cache_ttl)}",
              f'tor_proxy = "{cfg.tor_proxy}"']
    if cfg.proxy:
        lines.append(f'proxy = "{cfg.proxy}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _setup(ui: UI, ask=input) -> int:
    path = config_dir() / "config.toml"
    cfg = Config.load(path)
    ui.say("Asistente de configuración de API keys\n", "bold")
    ui.say("Todas las keys son gratuitas. Pulsa Enter para omitir una o escribe '-' para borrarla.")
    ui.say("Las keys se guardan solo en tu equipo, en " + str(path) + " (permisos 600).\n")
    for api in _apis():
        current = cfg.key(api["key"])
        ui.say(f"{api['service']}  [{'configurada' if current else 'sin configurar'}]", "bold")
        ui.say(f"  Plan gratuito: {api['free']}")
        ui.say(f"  Habilita: {api['enables']}")
        ui.say(f"  Registro: {api['signup']}")
        try:
            value = ask("  Key: ").strip()
        except EOFError:
            break
        if value == "-":
            cfg.keys.pop(api["key"], None)
        elif value:
            cfg.keys[api["key"]] = value
        ui.say()
    _write_config(path, cfg)
    ui.say(f"Configuración guardada en {path}")
    return 0


def _about(ui: UI) -> int:
    ui.about()
    return 0


# -------------------------------------------------------------------- casos
def _show_case(ui: UI, book: cases.CaseBook, name: str) -> int:
    runs = book.runs(name)
    if not runs:
        ui.error(f"No existe el caso «{name}».")
        return 2
    ui.table(f"Caso «{name}»", ["#", "fecha", "objetivos", "entidades", "altos", "exposición"],
             [[i, r["fecha"].replace("T", " "), ", ".join(r["objetivos"])[:46], r["entidades"], r["hallazgos_altos"],
               "" if r["exposicion"] is None else r["exposicion"]] for i, r in enumerate(runs, 1)])
    return 0


def _show_diff(ui: UI, diff: dict | None) -> int:
    if diff is None:
        ui.say("El caso necesita al menos dos investigaciones para compararse.", "yellow")
        return 1
    ui.say(f"Cambios entre {diff['desde'].replace('T', ' ')} y {diff['hasta'].replace('T', ' ')}", "bold")
    for key, label in (("entidades_nuevas", "Entidades nuevas"), ("entidades_ausentes", "Entidades que ya no aparecen"),
                       ("hallazgos_nuevos", "Hallazgos nuevos"), ("hallazgos_resueltos", "Hallazgos resueltos")):
        items = diff[key]
        ui.say(f"\n{label} ({len(items)})", "bold")
        for item in items[:30]:
            ui.say(f"  {item}")
        if len(items) > 30:
            ui.say(f"  ... y {len(items) - 30} más", "dim")
    return 0


def _cases_cli(ui: UI, args) -> int:
    book = cases.CaseBook()
    try:
        if not args.nombre:
            rows = book.cases()
            if not rows:
                ui.say("Aún no hay casos. Crea uno con:  nexum-osint scan <dato> --caso <nombre>")
                return 0
            ui.table("Casos", ["caso", "investigaciones", "última", "creado"],
                     [[r["caso"], r["investigaciones"], (r["ultima"] or "").replace("T", " "),
                       r["creado"].replace("T", " ")] for r in rows])
            return 0
        if args.borrar:
            if not book.delete(args.nombre):
                ui.error(f"No existe el caso «{args.nombre}».")
                return 2
            ui.say(f"Caso «{args.nombre}» eliminado.")
            return 0
        code = _show_case(ui, book, args.nombre)
        if code:
            return code
        if args.comparar:
            _show_diff(ui, book.compare(args.nombre))
        if args.exportar:
            ui.say(f"Exportado a {book.export(args.nombre, Path(args.exportar))}")
        return 0
    finally:
        book.close()


def _cases_menu(ui: UI, ask) -> None:
    book = cases.CaseBook()
    try:
        rows = book.cases()
        if not rows:
            ui.say("Aún no hay casos. Al investigar un dato desde el menú puedes guardarlo en un caso.")
            return
        ui.table("Casos", ["#", "caso", "investigaciones", "última"],
                 [[i, r["caso"], r["investigaciones"], (r["ultima"] or "").replace("T", " ")]
                  for i, r in enumerate(rows, 1)])
        pick = ask("Número del caso a abrir (Enter para volver): ").strip()
        if pick.isdigit() and 1 <= int(pick) <= len(rows):
            name = rows[int(pick) - 1]["caso"]
            _show_case(ui, book, name)
            if ask("¿Comparar las dos últimas investigaciones? [s/N]: ").strip().lower() in ("s", "si", "sí"):
                _show_diff(ui, book.compare(name))
    finally:
        book.close()


# -------------------------------------------------------------------- extracción
SHOW_LIMIT = 40


def _show_findings(ui: UI, found: extract.Findings) -> None:
    if not found.items and not found.metadata:
        ui.say("No se encontraron datos en el contenido analizado.", "yellow")
    for cat, label in extract.CATEGORIES.items():
        values = found.items.get(cat)
        if not values:
            continue
        rows = [[v] for v in values[:SHOW_LIMIT]]
        if len(values) > SHOW_LIMIT:
            rows.append([f"... y {len(values) - SHOW_LIMIT} más (usa -o para guardarlos todos)"])
        ui.table(f"{label} ({len(values)})", ["valor"], rows)
    for source, meta in list(found.metadata.items())[:12]:
        ui.card(f"Metadatos  ·  {Path(source).name or source}", [(k.replace("_", " "), str(v)) for k, v in meta.items()])
    if len(found.metadata) > 12:
        ui.say(f"... metadatos de {len(found.metadata) - 12} fuentes más (en el archivo exportado)", "dim")
    for note in found.notes:
        ui.say(note, "dim")
    ui.say(f"\n{found.total()} datos en {len(found.items)} categorías.", "bold")


def _scan_targets(targets: list[tuple[str, Kind, str]]) -> None:
    """Investiga los datos extraídos; los alias se envían aparte porque no se pueden autodetectar."""
    auto = [v for _, k, v in targets if guess_kind(v) is k]
    forced = [v for _, k, v in targets if guess_kind(v) is not k and k is Kind.USERNAME]
    if auto:
        main(["scan", *auto, "-d", "1", "-f", "html,json,pdf"])
    if forced:
        main(["scan", *forced, "-t", "username", "-d", "1", "-f", "html,json,pdf"])


def _finish_extraction(ui: UI, found: extract.Findings, output: str | None = None, scan: bool = False,
                       ask=None) -> int:
    _show_findings(ui, found)
    if output:
        ui.say(f"Guardado en {extract.export(found, Path(output))}")
    targets = extract.to_targets(found)
    if targets and ask is not None and not scan:
        ui.say(f"\n{len(targets)} datos se pueden investigar (correos, teléfonos, alias, dominios, IP...).")
        scan = ask("¿Investigarlos ahora? [s/N]: ").strip().lower() in ("s", "si", "sí")
    if scan and targets:
        _scan_targets(targets)
    return 0


async def _extract_url(url: str, pages: int) -> extract.Findings:
    http = Http(Config.load(), Cache(None, enabled=False), RateLimiter(default_rate=1))
    try:
        return await extract.from_url(http, url, max(1, min(pages, 25)))
    finally:
        await http.close()


def _extract_source(ui: UI, source: str, pages: int = 1) -> extract.Findings | None:
    if source == "-":
        return extract.from_text(sys.stdin.read(), "entrada estándar")
    if re.match(r"https?://", source, re.I):
        return asyncio.run(_extract_url(source, pages))
    path = Path(source).expanduser()
    if path.is_dir():
        return extract.from_folder(path)
    if path.is_file():
        return extract.from_file(path)
    ui.error(f"No existe: {source}")
    return None


def _extract(ui: UI, args) -> int:
    found = _extract_source(ui, args.source, args.pages)
    if found is None:
        return 2
    return _finish_extraction(ui, found, args.output, args.scan)


def _extract_menu(ui: UI, ask, mode: str) -> None:
    if mode == "extract_text":
        ui.say("Pega el texto y termina con dos líneas vacías (o Ctrl-D).")
        found = extract.from_text(extract.read_stdin_block(lambda: ask("")), "texto pegado")
    elif mode == "extract_url":
        url = ask("URL de la página: ").strip()
        if not url:
            return
        if not re.match(r"https?://", url, re.I):
            url = "https://" + url
        raw = ask("Páginas del mismo sitio a recorrer (1-25, Enter = 1): ").strip()
        found = asyncio.run(_extract_url(url, int(raw) if raw.isdigit() else 1))
    else:
        source = ask("Ruta del archivo o carpeta: ").strip().strip("'\"")
        if not source:
            return
        found = _extract_source(ui, source)
        if found is None:
            return
    out = ask("Guardar el resultado en (.json o .csv, Enter para omitir): ").strip()
    _finish_extraction(ui, found, out or None, ask=ask)


# -------------------------------------------------------------------- menú
SECTIONS = (
    ("Investigar", (
        ("1", "Investigación rápida", "Pega cualquier dato y se detecta el tipo", "quick"),
        ("2", "Persona", "Nombre completo", "name"),
        ("3", "Teléfono", "Con indicativo de país", "phone"),
        ("4", "Correo electrónico", "Cuentas, filtraciones y reputación", "email"),
        ("5", "Alias", "Perfiles en cientos de sitios", "username"),
        ("6", "Documento", "RUC, NIT, RFC y otros", "doc"),
        ("7", "Empresa", "Registros y entidades", "org"),
        ("8", "Dominio", "DNS, subdominios y exposición", "domain"),
        ("9", "Dirección IP", "Red, reputación y servicios", "ip"),
        ("10", "URL o imagen", "Metadatos y búsqueda inversa", "url"),
        ("11", "Criptomoneda", "Bitcoin y Ethereum", "crypto"),
        ("12", "Investigación completa", "Varios datos de una misma persona o empresa", "multi"),
    )),
    ("Extracción", (
        ("13", "Archivo o carpeta", "Office, PDF, correo, imágenes y texto", "extract_file"),
        ("14", "Página web", "Datos y enlaces, con rastreo opcional", "extract_url"),
        ("15", "Texto pegado", "Datos de cualquier texto que pegues", "extract_text"),
    )),
    ("Herramientas", (
        ("16", "Directorio de herramientas", "Catálogo OSINT por categoría", "tools"),
        ("17", "Dark web", "Requiere Kali, Tor y VPN", "darkweb"),
        ("18", "Reportes anteriores", "Historial de investigaciones", "history"),
        ("19", "Casos", "Investigaciones guardadas: ver, comparar, exportar", "cases"),
        ("20", "Vigilancia", "Repite una investigación y avisa de cambios", "watch"),
    )),
    ("Configuración", (
        ("21", "API keys gratuitas", "Asistente de configuración", "setup"),
        ("22", "Actualizar sitios", "Descarga WhatsMyName y Sherlock", "update"),
        ("23", "Diagnóstico del entorno", "Instala las librerías que falten", "doctor"),
        ("24", "Módulos y APIs", "Qué fuentes consulta la herramienta", "modules"),
    )),
    ("Información", (
        ("25", "Acerca de", "Autor, licencia y agradecimientos", "about"),
        ("0", "Salir", "", "exit"),
    )),
)
ACTIONS = {key: action for _, items in SECTIONS for key, _, _, action in items}
PROMPTS = {
    "name": "Nombre completo", "phone": "Teléfono con indicativo (ej. +51987654321)", "email": "Correo",
    "username": "Alias", "doc": "Número de documento", "domain": "Dominio (ej. ejemplo.com)",
    "ip": "Dirección IP", "url": "URL", "org": "Nombre de la empresa u organización",
    "crypto": "Dirección de la billetera",
}
KIND_LABEL = {"name": "nombre de persona", "phone": "teléfono", "email": "correo", "username": "alias",
              "doc": "documento", "domain": "dominio", "ip": "dirección IP", "url": "URL", "org": "empresa",
              "crypto": "dirección de criptomoneda"}
DEPTHS = {"1": ("Solo el dato", 0), "2": ("Estándar", 1), "3": ("Profunda", 2)}


def _menu_sections() -> list[tuple[str, list[tuple[str, str, str]]]]:
    return [(title, [(k, label, desc) for k, label, desc, _ in items]) for title, items in SECTIONS]


def _status() -> str:
    config = Config.load()
    apis = _apis()
    configured = sum(1 for a in apis if config.key(a["key"]))
    from .modules.username_sites import load_sites
    try:
        sites = len(load_sites())
    except Exception:
        sites = 0
    kali = guard.is_kali(guard.Probes().os_release())
    return (f"{len(discover())} módulos · {sites} sitios · {configured}/{len(apis)} API keys configuradas · "
            f"dark web: {'disponible' if kali else 'solo en Kali'}")


def _ask_options(ui: UI, ask, kind: str) -> list[str]:
    ui.say("Profundidad:  1) Solo el dato   2) Estándar   3) Profunda")
    choice = ask("Profundidad [2]: ").strip() or "2"
    label, depth = DEPTHS.get(choice, DEPTHS["2"])
    args = ["-d", str(depth)]
    if kind in ("domain", "url") and ask("¿Incluir módulos activos que contactan al objetivo? (s/N): ").strip().lower() == "s":
        args.append("--active")
    return args


def _run_scan(ui: UI, ask, targets: list[str], kind: str | None) -> None:
    extra = _ask_options(ui, ask, kind or "")
    case = cases.clean_name(ask("Guardar en un caso (nombre, Enter para omitir): "))
    if case:
        extra += ["--caso", case]
    argv = ["scan", *targets, "-f", "html,pdf,json,md", *extra]
    if kind:
        argv[2:2] = ["-t", kind]
    main(argv)


def _pick_type(ui: UI, ask, value: str) -> str | None:
    detected = guess_kind(value).value
    if ask(f"Detectado: {KIND_LABEL.get(detected, detected)}. ¿Continuar? (S/n): ").strip().lower() in ("", "s", "si", "sí"):
        return detected
    keys = list(KIND_LABEL)
    for i, k in enumerate(keys, 1):
        ui.say(f"  {i:>2}) {KIND_LABEL[k]}")
    pick = ask("Tipo correcto: ").strip()
    return keys[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(keys) else None


def _open_target(target: str) -> None:
    """Abre un archivo o enlace con el programa adecuado del entorno."""
    import shutil
    import subprocess
    import webbrowser
    if doctor.detect_env(doctor.read_os_release()) == "termux" and shutil.which("termux-open"):
        subprocess.run(["termux-open", target])
    else:
        webbrowser.open(target)


def _open(path: str) -> None:
    _open_target(Path(path).resolve().as_uri())


def _history_menu(ui: UI, ask) -> None:
    items = history.load()[:10]
    if not items:
        ui.say("Todavía no hay investigaciones guardadas.", MUTED)
        return
    ui.table("Reportes anteriores", ["#", "fecha", "objetivos", "archivos", "críticos"],
             [[i, it["fecha"].replace("T", " "), ", ".join(it["objetivos"])[:44], len(it["archivos"]), it["hallazgos"]]
              for i, it in enumerate(items, 1)])
    pick = ask("Número para ver las rutas (Enter para volver): ").strip()
    if pick.isdigit() and 1 <= int(pick) <= len(items):
        item = items[int(pick) - 1]
        ui.detail("Archivos generados", [(Path(f).suffix[1:].upper() or "ARCHIVO", f) for f in item["archivos"]])
        html = next((f for f in item["archivos"] if f.endswith(".html")), None)
        if html and ask("¿Abrir el reporte HTML en el navegador? (s/N): ").strip().lower() == "s":
            _open(html)


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


def _tool_rows(items: list[dict]) -> list[list]:
    return [[i, t["name"], _cut(t["cost"], 20) or "s/d", "sí" if t.get("account") else "no", _cut(t["what"], 60)]
            for i, t in enumerate(items, 1)]


def _tool_detail(ui: UI, ask, tool: dict) -> None:
    rows = [("Nombre", tool["name"]), ("Categoría", tool["category"]), ("Enlace", tool["url"]),
            ("Qué hace", tool["what"] or "s/d"), ("Costo", tool["cost"] or "s/d"),
            ("Requiere cuenta", "sí" if tool.get("account") else "no")]
    if tool.get("how"):
        rows.append(("Cómo usarla", tool["how"]))
    rows.append(("Origen", tool.get("origin", "NEXUM")))
    ui.detail(tool["name"], rows)
    if ask("¿Abrir el enlace en el navegador? (s/N): ").strip().lower() == "s":
        _open_target(tool["url"])


def _tool_list(ui: UI, ask, title: str, items: list[dict]) -> None:
    while True:
        ui.table(title, ["#", "herramienta", "costo", "cuenta", "qué hace"], _tool_rows(items), widths=[3, 26, 20, 6, 60])
        pick = ask("Número para ver el detalle (Enter para volver): ").strip()
        if not pick:
            return
        if pick.isdigit() and 1 <= int(pick) <= len(items):
            _tool_detail(ui, ask, items[int(pick) - 1])


def _tools_menu(ui: UI, ask) -> None:
    while True:
        catalog = tools.load()
        cats = tools.categories(catalog)
        ui.table(f"Directorio de herramientas ({len(catalog)})", ["#", "categoría", "herramientas"],
                 [[i, c, n] for i, (c, n) in enumerate(cats, 1)])
        imported = tools.user_path().exists()
        ui.say("Número = ver categoría · texto = buscar · i = importar biblioteca · Enter = volver", MUTED)
        if not imported:
            ui.say("Puedes ampliar el directorio con tu copia de la OSINT Tools Library (opción i).", MUTED)
        raw = ask("Opción: ").strip()
        if not raw:
            return
        if raw.isdigit() and 1 <= int(raw) <= len(cats):
            name = cats[int(raw) - 1][0]
            _tool_list(ui, ask, name, [t for t in catalog if t["category"] == name])
        elif raw.lower() == "i":
            _import_tools(ui, Path(ask("Ruta de la carpeta o zip de la biblioteca: ").strip().strip("'\"")))
        else:
            found = tools.search(catalog, raw)
            if found:
                _tool_list(ui, ask, f"Resultados para «{raw}»", found)
            else:
                ui.say("Sin resultados.", MUTED)


def _import_tools(ui: UI, path: Path) -> int:
    try:
        count = tools.import_library(path)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        ui.error(f"no se pudo importar: {exc}")
        return 1
    ui.say(f"Biblioteca importada: {count} herramientas.")
    ui.say(f"Guardada en {tools.user_path()}", MUTED)
    return 0


def _tools_cli(ui: UI, args) -> int:
    catalog = tools.load()
    if args.tools_cmd == "import":
        return _import_tools(ui, args.ruta)
    if args.tools_cmd == "search":
        found = tools.search(catalog, " ".join(args.texto))
        ui.table(f"{len(found)} resultados", ["#", "herramienta", "costo", "cuenta", "qué hace"], _tool_rows(found), widths=[3, 26, 20, 6, 60])
        return 0
    if args.tools_cmd == "list":
        wanted = (args.categoria or "").lower()
        items = [t for t in catalog if not wanted or t["category"].lower() == wanted]
        ui.table(f"{len(items)} herramientas", ["#", "herramienta", "costo", "cuenta", "qué hace"], _tool_rows(items), widths=[3, 26, 20, 6, 60])
        return 0
    _tools_menu(ui, input)
    return 0


def _darkweb_menu(ui: UI, ask) -> None:
    ui.say(guide.WARNING, "yellow")
    ui.say("1) Ver guía de entorno   2) Verificar entorno   3) Buscar un término   0) Volver")
    sel = ask("Opción: ").strip()
    if sel == "1":
        ui.say(guide.GUIDE)
    elif sel == "2":
        main(["darkweb", "check"])
    elif sel == "3":
        term = ask("Término a buscar: ").strip()
        if term:
            main(["darkweb", "search", term])


def _menu(ui: UI, ask=input) -> int:
    first = True
    while True:
        if not first:
            ask("\nPulsa Enter para volver al menú...")
        first = False
        ui.clear()
        ui.banner(_status())
        ui.menu(_menu_sections())
        try:
            choice = ask("\nOpción: ").strip()
        except EOFError:
            return 0
        action = ACTIONS.get(choice)
        if action is None and choice and Path(choice).expanduser().exists():
            found = _extract_source(ui, choice)
            if found is not None:
                _finish_extraction(ui, found, ask=ask)
            first = True
            continue
        if action is None:
            ui.say("Opción no válida.", "red")
            first = True
            continue
        if action == "exit":
            return 0
        try:
            if action == "setup":
                _setup(ui, ask)
            elif action == "update":
                _list_sites(ui, False, True)
            elif action == "watch":
                value = ask("Dato a vigilar: ").strip()
                minutes = ask("Minutos entre rondas [60]: ").strip() or "60"
                if value and minutes.isdigit():
                    main(["watch", value, "--cada", minutes, "-f", "html,json,md", "-d", "1"])
            elif action == "doctor":
                doctor.run(ui, fix=True, ask=ask)
            elif action == "modules":
                _list_modules(ui)
                _list_apis(ui)
            elif action == "about":
                _about(ui)
            elif action.startswith("extract_"):
                _extract_menu(ui, ask, action)
            elif action == "cases":
                _cases_menu(ui, ask)
            elif action == "tools":
                _tools_menu(ui, ask)
            elif action == "history":
                _history_menu(ui, ask)
            elif action == "darkweb":
                _darkweb_menu(ui, ask)
            elif action == "quick":
                value = ask("Dato a investigar: ").strip()
                kind = _pick_type(ui, ask, value) if value else None
                if kind:
                    _run_scan(ui, ask, [value], kind)
            elif action == "multi":
                ui.say("Escribe todos los datos que tengas, separados por coma (nombre, teléfono, correo, alias, dominio...).")
                raw = ask("Datos: ").strip()
                targets = [t.strip() for t in raw.split(",") if t.strip()]
                if targets:
                    _run_scan(ui, ask, targets, None)
            else:
                value = ask(f"{PROMPTS[action]}: ").strip()
                if value:
                    _run_scan(ui, ask, [value], action)
        except EOFError:
            return 0


# -------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        argv = ["menu"] if sys.stdin.isatty() else ["--help"]
    args = build_parser().parse_args(argv)
    ui = UI(quiet=getattr(args, "quiet", False))
    try:
        if args.cmd not in ("cache", "menu", "doctor") and not getattr(args, "markdown", False):
            ui.banner()
        if args.cmd in ("scan", "menu") and not doctor.preflight(ui):
            return 1
        if args.cmd == "doctor":
            ui.banner()
            return doctor.run(ui, fix=args.fix, assume_yes=args.yes, darkweb=args.darkweb)
        if args.cmd == "scan":
            return asyncio.run(_scan(args, ui))
        if args.cmd == "watch":
            return _watch(args, ui)
        if args.cmd == "extract":
            return _extract(ui, args)
        if args.cmd == "casos":
            return _cases_cli(ui, args)
        if args.cmd == "menu":
            return _menu(ui)
        if args.cmd == "modules":
            return _list_modules(ui, args.markdown)
        if args.cmd == "tools":
            return _tools_cli(ui, args)
        if args.cmd == "sites":
            return _list_sites(ui, args.audit, args.update)
        if args.cmd == "setup":
            return _setup(ui)
        if args.cmd == "apis":
            return _list_apis(ui)
        if args.cmd == "about":
            return _about(ui)
        if args.cmd == "darkweb":
            if args.dw_cmd == "guide":
                ui.say(guide.WARNING, "yellow")
                ui.say(guide.GUIDE)
                return 0
            if args.dw_cmd == "check":
                config = Config.load(getattr(args, "config", None))
                tor = asyncio.run(_darkweb_gate(args, config, ui))
                if tor is None:
                    return 3
                asyncio.run(tor.close())
                ui.say("\nEntorno verificado. Puedes usar:  nexum-osint darkweb search <término>")
                return 0
            if args.dw_cmd == "search":
                args.targets, args.type, args.darkweb = [args.term], None, True
                args.modules = args.modules or "darkweb_index"
                args.depth = 0
                return asyncio.run(_scan(args, ui))
        if args.cmd == "cache":
            path = cache_dir() / "cache.sqlite"
            if args.action == "path":
                print(path)
            else:
                print(f"{Cache(path).purge()} entradas expiradas eliminadas")
            return 0
    except KeyboardInterrupt:
        ui.error("interrumpido por el usuario")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
