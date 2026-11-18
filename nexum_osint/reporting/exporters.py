"""Exportadores: HTML (con marca), JSON, CSV y PDF."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from .. import __version__, branding
from ..core.engine import RunStats
from ..analysis import dossier as dos
from ..analysis import exposure, narrative
from ..core.entities import Graph, Kind

SEVERITY_ORDER = {"high": 0, "medium": 1, "warn": 2, "low": 3, "info": 4}


PURPOSE_LABEL = {
    "mensajeria": "Mensajería", "directorio": "Directorios de números", "buscador": "Buscadores",
    "reputacion": "Reputación y spam", "redes": "Redes sociales", "profesional": "Perfil profesional",
    "documentos": "Documentos", "academico": "Académico", "empresas": "Empresas y cargos",
    "listas": "Listas y sanciones", "registro_oficial": "Registros oficiales", "imagen": "Búsqueda inversa de imagen",
    "darkweb_manual": "Dark web (sin acceder a .onion)", "blockchain": "Exploradores de blockchain",
    "mapa": "Mapa",
}


def _split(graph: Graph):
    """Separa enlaces manuales, menciones de dark web y perfiles del resto de nodos."""
    manual, darkweb, profiles = {}, [], {}
    for n in graph.nodes.values():
        if n.kind is Kind.URL and n.attrs.get("manual"):
            manual.setdefault(PURPOSE_LABEL.get(n.attrs.get("purpose"), "Otros"), []).append(n)
        elif n.kind is Kind.URL and n.attrs.get("darkweb"):
            darkweb.append(n)
        elif n.kind is Kind.PROFILE:
            profiles.setdefault(n.attrs.get("category") or "otros", []).append(n)
    for items in manual.values():
        items.sort(key=lambda n: n.attrs.get("label", n.value))
    return manual, darkweb, profiles


def _meta(graph: Graph) -> dict:
    return getattr(graph, "meta", None) or {}


def _context(graph: Graph, stats: RunStats, targets: list[str], depth: int) -> dict:
    data = graph.to_dict()
    notes = sorted(graph.notes, key=lambda n: SEVERITY_ORDER.get(n["severity"], 9))
    manual, darkweb, profiles = _split(graph)
    visible = [n for n in data["nodes"] if not n["attrs"].get("manual")]
    ids = {n["id"] for n in visible}
    edges = [e for e in data["edges"] if e["src"] in ids and e["dst"] in ids]
    # Los atributos solo se muestran en las tablas; el grafo recibe nodos/aristas.
    graph_json = json.dumps({"nodes": [{k: v for k, v in n.items() if k != "attrs"} for n in visible],
                             "edges": edges}, ensure_ascii=False).replace("</", "<\\/")
    return {
        "brand": branding, "version": __version__, "targets": targets, "depth": depth,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "stats": stats,
        "data": data, "notes": notes, "graph_json": graph_json,
        "groups": [(k.value, [n for n in v if not n.attrs.get("manual") and not n.attrs.get("darkweb")])
                   for k, v in graph.by_kind().items()
                   if any(not n.attrs.get("manual") and not n.attrs.get("darkweb") for n in v)],
        "dossier": dos.build(graph), "timeline": dos.timeline(graph),
        "manual": sorted(manual.items()), "manual_total": sum(len(v) for v in manual.values()),
        "darkweb": darkweb, "profiles": sorted(profiles.items()),
        "profiles_total": sum(len(v) for v in profiles.values()),
        "counts": {"high": sum(1 for n in notes if n["severity"] == "high")},
        "exposure": _meta(graph).get("exposicion") or exposure.score(graph), "changes": _meta(graph).get("cambios"),
        "narrative": narrative.resumen(graph, targets, _meta(graph).get("exposicion") or exposure.score(graph)),
    }


def to_html(graph: Graph, stats: RunStats, targets: list[str], depth: int, out: Path) -> Path:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "j2"], default_for_string=True),
    )
    ctx = _context(graph, stats, targets, depth)
    for _, items in ctx["groups"]:
        items.sort(key=lambda n: (-len(n.sources), n.value))
    out.write_text(env.get_template("report.html.j2").render(**ctx), encoding="utf-8")
    return out


def to_json(graph: Graph, stats: RunStats, targets: list[str], depth: int, out: Path) -> Path:
    payload = {
        "tool": branding.TOOL, "version": __version__, "targets": targets, "depth": depth,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "stats": {"elapsed": round(stats.elapsed, 2), "queries": stats.executed,
                  "errors": stats.errors, "skipped": stats.skipped,
                  "timings": {k: round(v, 2) for k, v in stats.timings.items()}},
        "exposicion": _meta(graph).get("exposicion") or exposure.score(graph),
        "cambios": _meta(graph).get("cambios"),
        **graph.to_dict(),
    }
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def to_csv(graph: Graph, out_dir: Path, stem: str) -> list[Path]:
    nodes_file, edges_file = out_dir / f"{stem}_entities.csv", out_dir / f"{stem}_relations.csv"
    with nodes_file.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tipo", "valor", "fuentes", "profundidad", "atributos"])
        for n in sorted(graph.nodes.values(), key=lambda n: (n.kind.value, n.value)):
            w.writerow([n.kind.value, n.value, ";".join(sorted(n.sources)), n.depth,
                        json.dumps(n.attrs, ensure_ascii=False)])
    with edges_file.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["origen", "relacion", "destino", "fuente"])
        for e in sorted(graph.edges, key=lambda e: (e.src, e.relation, e.dst)):
            w.writerow([e.src, e.relation, e.dst, e.source])
    return [nodes_file, edges_file]


def to_pdf(graph: Graph, stats: RunStats, targets: list[str], depth: int, out: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)
    from xml.sax.saxutils import escape

    teal, dark, grey = colors.HexColor("#1f3a5f"), colors.HexColor("#1a1f27"), colors.HexColor("#5c6370")
    base = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=base["Title"], textColor=teal, fontSize=24, alignment=0, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], textColor=dark, fontSize=12, spaceBefore=14)
    body = ParagraphStyle("b", parent=base["BodyText"], fontSize=8.5, leading=11)
    small = ParagraphStyle("s", parent=body, textColor=grey, fontSize=8)
    sev_color = {"high": "#d6304c", "medium": "#d98a00", "warn": "#d98a00", "low": "#2a6fd1", "info": "#5c6b80"}

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(grey)
        canvas.drawString(15 * mm, 9 * mm, f"{branding.COMPANY} · {branding.AUTHOR_ROLE}: {branding.AUTHOR}")
        canvas.drawRightString(195 * mm, 9 * mm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=18 * mm,
                            title=f"{branding.TOOL} - {', '.join(targets)}", author=branding.AUTHOR)
    story = [Paragraph(branding.TOOL.upper(), h1), Paragraph(branding.TAGLINE, small), Spacer(1, 6)]
    meta = [["Objetivo", ", ".join(targets)],
            ["Generado", datetime.now().strftime("%Y-%m-%d %H:%M")],
            ["Entidades / relaciones", f"{len(graph.nodes)} / {len(graph.edges)}"],
            ["Consultas / duración", f"{stats.executed} / {stats.elapsed:.1f} s"]]
    t = Table(meta, colWidths=[45 * mm, 135 * mm])
    t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8.5), ("TEXTCOLOR", (0, 0), (0, -1), grey),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dde3ec"))]))
    story += [t]

    notes = sorted(graph.notes, key=lambda n: SEVERITY_ORDER.get(n["severity"], 9))
    if notes:
        story.append(Paragraph("Hallazgos", h2))
        for n in notes:
            c = sev_color.get(n["severity"], "#5c6b80")
            story.append(Paragraph(
                f'<font color="{c}"><b>[{n["severity"].upper()}]</b></font> <b>{escape(n["title"])}</b>', body))
            if n["detail"]:
                story.append(Paragraph(escape(n["detail"]).replace("\n", "<br/>")[:900], small))
    corr = graph.correlations()
    if corr:
        story.append(Paragraph("Correlaciones", h2))
        for c in corr:
            story.append(Paragraph(f'• {escape(c["title"])} <font color="#5c6b80">(confianza {c["confidence"]})</font>', body))

    manual, darkweb, _profiles = _split(graph)
    expo = _meta(graph).get("exposicion") or exposure.score(graph)
    story.append(Paragraph(escape(narrative.resumen(graph, targets, expo)), body))
    story.append(Paragraph(f"Nivel de exposición: <b>{expo['nivel']}</b> ({expo['puntaje']}/100)", h2))
    for f in expo["factores"]:
        story.append(Paragraph(f"• {escape(f)}", small))
    changes = _meta(graph).get("cambios")
    if changes:
        story.append(Paragraph(f"Cambios desde {changes['desde']}", h2))
        story.append(Paragraph(f"Entidades nuevas: {len(changes['entidades_nuevas'])} · ausentes: {len(changes['entidades_ausentes'])} · "
                               f"hallazgos nuevos: {len(changes['hallazgos_nuevos'])} · resueltos: {len(changes['hallazgos_resueltos'])}", small))
    card = dos.build(graph)
    if card:
        story.append(Paragraph("Expediente consolidado", h2))
        for section, rows_ in card.items():
            story.append(Paragraph(f"<b>{escape(section)}</b>", body))
            for r in rows_[:25]:
                story.append(Paragraph(f"• {escape(r['valor'])[:110]} "
                                       f'<font color="#5c6370">({r["confianza"]})</font>', small))
    events = dos.timeline(graph)
    if events:
        story.append(Paragraph("Línea de tiempo", h2))
        for e in events[:40]:
            story.append(Paragraph(f"{e['fecha']} · {escape(e['evento'])} · {escape(e['detalle'])}", small))
    if darkweb:
        story.append(Paragraph(f"Menciones en dark web ({len(darkweb)})", h2))
        story.append(Paragraph("Resultados de un índice, no contenido verificado. No abrir fuera de Tor Browser.", small))
        for n in darkweb[:40]:
            story.append(Paragraph(f"• {escape(n.attrs.get('title') or n.value)[:110]} "
                                   f'<font color="#5c6370">{escape(n.value)[:90]}</font>', body))
    if manual:
        story.append(Paragraph(f"Consultas manuales sugeridas ({sum(len(v) for v in manual.values())})", h2))
        for purpose, items in sorted(manual.items()):
            story.append(Paragraph(f"<b>{escape(purpose)}</b>", body))
            for n in items:
                story.append(Paragraph(f"• {escape(n.attrs.get('label', ''))}: {escape(n.value)[:120]}", small))

    for kind, items in graph.by_kind().items():
        items = [n for n in items if not n.attrs.get("manual") and not n.attrs.get("darkweb")]
        if not items:
            continue
        story.append(Paragraph(f"{kind.value.capitalize()} ({len(items)})", h2))
        rows = [["Valor", "Fuentes"]] + [
            [Paragraph(escape(n.value[:90]), body), Paragraph(escape(", ".join(sorted(n.sources))), small)]
            for n in items[:150]]
        tbl = Table(rows, colWidths=[120 * mm, 60 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
                                 ("FONTSIZE", (0, 0), (-1, 0), 8), ("TEXTCOLOR", (0, 0), (-1, 0), grey),
                                 ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dde3ec")),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(tbl)
        if len(items) > 150:
            story.append(Paragraph(f"… y {len(items) - 150} más (ver JSON/CSV).", small))
    story += [Spacer(1, 10), Paragraph(branding.NOTICE, small),
              Paragraph(f"{branding.CREDIT} {branding.REPO}", small)]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return out


def to_markdown(graph: Graph, stats: RunStats, targets: list[str], depth: int, out: Path) -> Path:
    manual, darkweb, _ = _split(graph)
    lines = [f"# {branding.TOOL}: {', '.join(targets)}", "",
             f"Generado: {datetime.now():%Y-%m-%d %H:%M} · profundidad {depth} · {stats.executed} consultas", ""]
    expo = _meta(graph).get("exposicion") or exposure.score(graph)
    lines += [narrative.resumen(graph, targets, expo), "", f"**Exposición: {expo['nivel']} ({expo['puntaje']}/100)**", ""]
    if expo["factores"]:
        lines += [f"- {f}" for f in expo["factores"]] + [""]
    changes = _meta(graph).get("cambios")
    if changes:
        lines += [f"## Cambios desde {changes['desde']}", "",
                  f"- Entidades nuevas: {len(changes['entidades_nuevas'])}",
                  f"- Entidades que ya no aparecen: {len(changes['entidades_ausentes'])}"]
        lines += [f"- Hallazgo nuevo ({s}): {t}" for s, t in changes["hallazgos_nuevos"]]
        lines += [f"- Hallazgo resuelto ({s}): {t}" for s, t in changes["hallazgos_resueltos"]] + [""]
    card = dos.build(graph)
    if card:
        lines += ["## Expediente consolidado", ""]
        for section, rows in card.items():
            lines += [f"### {section}", ""]
            lines += [f"- {r['valor']} ({r['confianza']}; {', '.join(r['fuentes'])})" for r in rows[:60]]
            lines.append("")
    notes = sorted(graph.notes, key=lambda n: SEVERITY_ORDER.get(n["severity"], 9))
    if notes:
        lines += ["## Hallazgos", ""]
        lines += [f"- **{n['severity'].upper()}** {n['title']}" + (f": {n['detail']}" if n["detail"] else "") for n in notes]
        lines.append("")
    events = dos.timeline(graph)
    if events:
        lines += ["## Línea de tiempo", ""] + [f"- {e['fecha']}: {e['evento']} ({e['detalle']})" for e in events] + [""]
    if darkweb:
        lines += ["## Menciones en dark web", ""] + [f"- {n.attrs.get('title') or '(sin título)'}: {n.value}" for n in darkweb] + [""]
    if manual:
        lines += ["## Consultas manuales", ""]
        for purpose, items in sorted(manual.items()):
            lines.append(f"### {purpose}")
            lines += [f"- [{n.attrs.get('label', n.value)}]({n.value})" for n in items]
            lines.append("")
    lines += ["---", f"{branding.CREDIT} {branding.REPO}"]
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def to_graphml(graph: Graph, out: Path) -> Path:
    from xml.sax.saxutils import quoteattr
    rows = ['<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '<key id="kind" for="node" attr.name="tipo" attr.type="string"/>',
            '<key id="label" for="node" attr.name="valor" attr.type="string"/>',
            '<key id="rel" for="edge" attr.name="relacion" attr.type="string"/>',
            '<graph id="nexum" edgedefault="directed">']
    for n in graph.nodes.values():
        if n.attrs.get("manual"):
            continue
        rows.append(f'<node id={quoteattr(n.key)}><data key="kind">{n.kind.value}</data>'
                    f'<data key="label">{quoteattr(n.value)[1:-1]}</data></node>')
    ids = {n.key for n in graph.nodes.values() if not n.attrs.get("manual")}
    for e in sorted(graph.edges, key=lambda e: (e.src, e.dst, e.relation)):
        if e.src in ids and e.dst in ids:
            rows.append(f'<edge source={quoteattr(e.src)} target={quoteattr(e.dst)}><data key="rel">{e.relation}</data></edge>')
    rows += ["</graph>", "</graphml>"]
    out.write_text("\n".join(rows), encoding="utf-8")
    return out
