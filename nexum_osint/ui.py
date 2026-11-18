"""Interfaz de consola. Usa rich si está disponible y cae a texto plano si no."""
from __future__ import annotations

import sys

from . import __version__, branding
from .core.entities import Kind

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False

ACCENT = "#00c8ff"
ACCENT2 = "#8a5cff"
BORDER = "#2f8cff"
MUTED = "grey62"
SEV_STYLE = {"high": "bold #ff5c7a", "medium": "#ffb347", "warn": "#ffb347", "low": ACCENT, "info": MUTED}
SEV_ORDER = ["high", "medium", "warn", "low", "info"]
SEV_LABEL = {"high": "ALTO", "medium": "MEDIO", "warn": "AVISO", "low": "BAJO", "info": "INFO"}


class UI:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.console = Console(stderr=False) if HAS_RICH else None

    # ---------------------------------------------------------- básicos
    def say(self, text: str = "", style: str | None = None) -> None:
        if self.quiet:
            return
        if self.console:
            self.console.print(text, style=style, highlight=False, markup=False)
        else:
            print(text)

    def rule(self, title: str = "") -> None:
        if self.quiet:
            return
        if self.console:
            self.console.rule(Text(title, style=f"bold {ACCENT}"), style=BORDER, characters="─")
        else:
            print(f"-- {title} " + "-" * max(4, 60 - len(title)))

    def panel(self, title: str, body, style: str = ACCENT) -> None:
        if self.quiet:
            return
        if self.console:
            self.console.print(Panel(body, title=Text(title, style=f"bold {ACCENT}"), title_align="left",
                                     box=box.ROUNDED, border_style=BORDER, padding=(0, 2)))
        else:
            print(f"\n[{title}]\n{body}")

    def clear(self) -> None:
        if self.console and self.console.is_terminal and not self.quiet:
            self.console.clear()

    def error(self, text: str) -> None:
        print(f"[!] {text}", file=sys.stderr)

    # ----------------------------------------------------- cabecera y menú
    def banner(self, status: str = "") -> None:
        if self.quiet:
            return
        if not self.console:
            print(f"{branding.TOOL}  v{__version__}\n{branding.TAGLINE}\n{branding.CREDIT}\n{branding.NOTICE}")
            return
        narrow = self.console.width < 58
        art = branding.LOGO_SMALL if narrow else branding.LOGO
        shades = branding.GRADIENT
        logo = Text()
        for n, line in enumerate(art.splitlines()):
            logo.append(line + "\n", style=f"bold {shades[min(n * len(shades) // max(len(art.splitlines()), 1), len(shades) - 1)]}")
        info = Text(justify="center")
        info.append(f"{branding.TAGLINE}\n", style="bold white")
        info.append(f"v{__version__}  ·  {branding.COMPANY}\n", style=ACCENT)
        info.append(branding.CREDIT, style=MUTED)
        self.console.print(Panel(Group(Align.center(logo), Align.center(info)), box=box.DOUBLE if not narrow else box.ROUNDED,
                                 border_style=BORDER, padding=(1, 2) if not narrow else (0, 1)))
        self.console.print(Align.center(Text(branding.NOTICE, style="dim yellow")))
        if status:
            self.console.print(Align.center(Text(status, style=MUTED)))

    def menu(self, sections: list[tuple[str, list[tuple[str, str, str]]]]) -> None:
        """sections: (titulo, [(clave, etiqueta, descripcion)])."""
        if not self.console:
            print("\nMENU PRINCIPAL")
            for title, items in sections:
                print(f"\n  {title}")
                for key, label, _ in items:
                    print(f"   {key:>2}. {label}")
            return
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2), expand=True)
        table.add_column(justify="right", style=f"bold {ACCENT}", no_wrap=True, width=3)
        table.add_column(no_wrap=True)
        table.add_column(style=MUTED)
        for i, (title, items) in enumerate(sections):
            if i:
                table.add_row("", "", "")
            table.add_row("", Text(title.upper(), style=f"bold {ACCENT2}"), "")
            for key, label, desc in items:
                table.add_row(key, label, desc)
        self.console.print(Panel(table, title=Text("MENÚ PRINCIPAL", style=f"bold {ACCENT}"), title_align="left",
                                 box=box.ROUNDED, border_style=BORDER, padding=(1, 2)))

    # ----------------------------------------------------------- tablas
    def table(self, title: str, columns: list[str], rows: list[list], widths: list[int] | None = None) -> None:
        if self.quiet:
            return
        if self.console:
            t = Table(title=title, header_style=f"bold {ACCENT2}", title_justify="left", box=box.SIMPLE_HEAD,
                      pad_edge=False, title_style=f"bold {ACCENT}")
            for i, c in enumerate(columns):
                t.add_column(c, overflow="fold", max_width=(widths[i] if widths else None))
            for r in rows:
                t.add_row(*[str(x) for x in r])
            self.console.print(t)
        else:
            print(f"\n{title}")
            for r in rows:
                print("  " + " | ".join(str(x) for x in r))

    def detail(self, title: str, rows: list[tuple[str, str]]) -> None:
        if self.quiet:
            return
        if not self.console:
            print(f"\n{title}")
            for k, v in rows:
                print(f"  {k}: {v}")
            return
        t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
        t.add_column(style=f"bold {ACCENT}", no_wrap=True)
        t.add_column(overflow="fold")
        for k, v in rows:
            t.add_row(k, v)
        self.panel(title, t)

    # ----------------------------------------------------------- escaneo
    def event(self, kind: str, data: dict) -> None:
        if self.quiet or kind == "start":
            return
        mark = {"done": "ok ", "error": "ERR"}.get(kind, " . ")
        line = f"[{mark}] {data['module']:<18} {data['target']}"
        if kind == "error":
            line += f"   {data.get('error', '')[:70]}"
        self.say(line, "red" if kind == "error" else MUTED if kind == "done" else None)

    def summary(self, graph, stats, expo=None, changes=None) -> None:
        if self.quiet:
            return
        groups = graph.by_kind()
        manual = [n for n in groups.get(Kind.URL, []) if n.attrs.get("manual")]
        self.say()
        self.rule("Resultado")
        if expo:
            style = {"Bajo": "green", "Moderado": "#ffb347", "Alto": "#ff8c42", "Crítico": "bold #ff5c7a"}[expo["nivel"]]
            bar = "█" * (expo["puntaje"] // 5) + "░" * (20 - expo["puntaje"] // 5)
            self.say(f"Exposición: {expo['nivel']}  {bar}  {expo['puntaje']}/100", style)
            for f in expo["factores"][:3]:
                self.say(f"  · {f}", MUTED)
            self.say()
        self.table("Entidades descubiertas", ["tipo", "cantidad"], [[k.value, len(v)] for k, v in groups.items()])
        labels = {"valido": "válido", "tipo_linea": "tipo de línea", "region": "región", "operador_original": "operador original",
                  "country": "país", "line_type": "tipo de línea", "operator_block_original": "bloque original"}
        for n in groups.get(Kind.PHONE, []):
            facts = [f"{labels[k]}: {n.attrs[k]}" for k in labels if n.attrs.get(k) not in (None, "")]
            if facts:
                self.say(f"\nTeléfono {n.value}", "bold")
                for f in facts:
                    self.say(f"  {f}")
        if manual:
            self.say(f"\n{len(manual)} consultas manuales preparadas en el reporte.", MUTED)
        notes = sorted(graph.notes, key=lambda n: SEV_ORDER.index(n["severity"]) if n["severity"] in SEV_ORDER else 9)
        important = [n for n in notes if n["severity"] in ("high", "medium", "warn")][:15]
        if important:
            self.say("\nHallazgos relevantes", "bold")
            for n in important:
                self.say(f"  [{SEV_LABEL.get(n['severity'], n['severity']):^5}] {n['title']}", SEV_STYLE.get(n["severity"]))
        corr = graph.correlations()
        if corr:
            self.say("\nCorrelaciones", "bold")
            for c in corr[:10]:
                self.say(f"  - {c['title']}  (confianza {c['confidence']})")
        if changes:
            self.say(f"\nCambios desde {changes['desde']}", "bold")
            self.say(f"  {len(changes['entidades_nuevas'])} entidades nuevas · {len(changes['entidades_ausentes'])} ausentes · "
                     f"{len(changes['hallazgos_nuevos'])} hallazgos nuevos · {len(changes['hallazgos_resueltos'])} resueltos")
            for sev, title in changes["hallazgos_nuevos"][:5]:
                self.say(f"  + [{SEV_LABEL.get(sev, sev)}] {title}", SEV_STYLE.get(sev))
        self.say(f"\n{stats.executed} consultas en {stats.elapsed:.1f} s · {len(stats.errors)} errores", MUTED)

    # ------------------------------------------------------------ about
    def about(self) -> None:
        if self.quiet:
            return
        author = [("Nombre", branding.AUTHOR), ("Alias", branding.HANDLE), ("Cargo", branding.AUTHOR_ROLE),
                  ("Ubicación", branding.LOCATION)]
        contact = list(branding.CONTACT.items()) + list(branding.SOCIALS.items())
        project = [("Proyecto", f"{branding.TOOL} v{__version__}"), ("Descripción", branding.TAGLINE),
                   ("Repositorio", branding.REPO), ("Licencia", branding.LICENSE)]
        self.detail("Autor", author)
        self.detail("Contacto", contact)
        self.detail("Proyecto", project)
        self.table("Agradecimientos y licencias de terceros", ["proyecto", "autoría", "licencia", "aporte"],
                   [list(a) for a in branding.ACKNOWLEDGEMENTS])
        self.say(f"\n{branding.COPYRIGHT}", MUTED)
        self.say("Licencia MIT: conserva este aviso de autoría en toda copia o derivado.", MUTED)
