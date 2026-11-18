import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from .darkweb.guard import is_kali

LIBS = (
    # módulo, paquete pip, nivel, para qué sirve
    ("httpx", "httpx[socks]", "requerida", "Cliente HTTP de todas las consultas"),
    ("rich", "rich", "requerida", "Menú y tablas de la terminal"),
    ("jinja2", "jinja2", "requerida", "Reportes HTML"),
    ("reportlab", "reportlab", "recomendada", "Reportes PDF"),
    ("PIL", "Pillow", "recomendada", "Metadatos EXIF de imágenes"),
    ("phonenumbers", "phonenumbers", "recomendada", "Validación y datos de teléfonos"),
    ("socksio", "socksio", "dark web", "Conexión por Tor (proxy SOCKS)"),
)
TOOLS = (
    ("tor", "Red Tor"), ("torsocks", "Enrutar comandos por Tor"), ("proxychains4", "Encadenar proxies"),
    ("openvpn", "VPN OpenVPN"), ("wg", "VPN WireGuard"),
)
LABELS = {"termux": "Termux (Android)", "kali": "Kali Linux", "debian": "Debian / Ubuntu", "arch": "Arch Linux",
          "fedora": "Fedora / RHEL", "macos": "macOS", "otro": "Otro sistema"}


@dataclass
class Report:
    env: str
    python_ok: bool
    libs: list          # (modulo, pip, nivel, uso, instalada)
    tools: list         # (comando, uso, instalada)

    @property
    def missing_core(self):
        return [l for l in self.libs if l[2] == "requerida" and not l[4]]

    @property
    def missing_pip(self):
        return [l for l in self.libs if not l[4] and l[2] != "dark web"]

    @property
    def missing_darkweb_libs(self):
        return [l for l in self.libs if not l[4] and l[2] == "dark web"]


def detect_env(os_release: str = "", platform: str = sys.platform, environ=None) -> str:
    environ = os.environ if environ is None else environ
    if environ.get("TERMUX_VERSION") or "com.termux" in environ.get("PREFIX", ""):
        return "termux"
    if platform == "darwin":
        return "macos"
    fields = dict(line.split("=", 1) for line in os_release.splitlines() if "=" in line)
    ident = fields.get("ID", "").strip('"').lower()
    like = fields.get("ID_LIKE", "").strip('"').lower()
    if is_kali(os_release):
        return "kali"
    if "arch" in (ident, like):
        return "arch"
    if ident in ("fedora", "rhel", "centos", "rocky", "almalinux") or "fedora" in like:
        return "fedora"
    if ident in ("debian", "ubuntu", "linuxmint", "parrot") or "debian" in like or "ubuntu" in like:
        return "debian"
    return "otro"


def read_os_release() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def inspect(find_spec=importlib.util.find_spec, which=shutil.which, env: str | None = None,
            version=sys.version_info) -> Report:
    env = env or detect_env(read_os_release())
    libs = [(m, p, lvl, uso, find_spec(m) is not None) for m, p, lvl, uso in LIBS]
    tools = [(t, uso, which(t) is not None) for t, uso in TOOLS]
    return Report(env, tuple(version[:2]) >= (3, 11), libs, tools)


def system_commands(env: str, darkweb: bool = False) -> list[str]:
    cmds = {
        "termux": ["pkg update -y", "pkg install -y python python-pillow libxml2 libxslt openssl"],
        "kali": ["sudo apt update", "sudo apt install -y python3 python3-venv python3-pip"],
        "debian": ["sudo apt update", "sudo apt install -y python3 python3-venv python3-pip"],
        "arch": ["sudo pacman -Sy --needed python python-pip"],
        "fedora": ["sudo dnf install -y python3 python3-pip"],
        "macos": ["brew install python"],
    }.get(env, [])
    cmds = list(cmds)
    if darkweb and env in ("kali", "debian"):
        cmds.append("sudo apt install -y tor torsocks proxychains4 openvpn wireguard-tools curl")
        cmds.append("sudo systemctl enable --now tor")
    return cmds


def pip_command(libs, env: str = "") -> list[str]:
    names = [l[1] for l in libs if not (env == "termux" and l[0] == "PIL")]
    return [sys.executable, "-m", "pip", "install", "--upgrade", *names]


def in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def guidance(report: Report) -> list[str]:
    """Pasos recomendados, según el sistema donde se ejecuta."""
    steps = []
    if not report.python_ok:
        steps.append("Se necesita Python 3.11 o superior: " + (
            "pkg install python" if report.env == "termux" else "actualiza el sistema o instala Python 3.11+"))
    if report.missing_pip:
        names = " ".join(f'"{l[1]}"' if "[" in l[1] else l[1] for l in report.missing_pip if not (report.env == "termux" and l[0] == "PIL"))
        if report.env == "termux":
            if any(l[0] == "PIL" for l in report.missing_pip):
                steps.append("pkg install -y python-pillow   # Pillow se instala con pkg, no con pip")
            if names:
                steps.append(f"pip install {names}")
        elif in_virtualenv():
            steps.append(f"pip install {names}")
        else:
            steps.append("Ejecuta ./install.sh: crea un entorno aislado e instala todo (Kali bloquea pip en el sistema).")
    if report.env == "termux":
        steps.append("Dark web: no disponible en Termux. Usa Kali Linux (máquina virtual o NetHunter).")
    elif report.env in ("kali", "debian") and not all(t[2] for t in report.tools[:3]):
        steps.append("Dark web (opcional): nexum-osint darkweb guide")
    return steps


def run(ui, fix: bool = False, assume_yes: bool = False, ask=input, darkweb: bool = False) -> int:
    report = inspect()
    ui.rule("Diagnóstico del entorno")
    ui.detail("Sistema", [("Entorno", LABELS[report.env]), ("Python", f"{sys.version.split()[0]}  ({'correcto' if report.python_ok else 'se necesita 3.11 o superior'})"),
                          ("Entorno virtual", "sí" if in_virtualenv() else "no")])
    ui.table("Librerías de Python", ["librería", "nivel", "estado", "para qué"],
             [[l[1].split("[")[0], l[2], "instalada" if l[4] else "FALTA", l[3]] for l in report.libs])
    if darkweb or report.env in ("kali", "debian"):
        ui.table("Herramientas del sistema (dark web)", ["comando", "estado", "para qué"],
                 [[t[0], "instalada" if t[2] else "falta", t[1]] for t in report.tools])
    pending = report.missing_pip
    if not pending and report.python_ok:
        ui.say("\nTodo lo necesario está instalado.", "green")
        return 0
    ui.say("\nPasos recomendados:", "bold")
    for step in guidance(report):
        ui.say(f"  {step}")
    if not fix:
        ui.say("\nPara instalar las librerías de Python desde aquí:  nexum-osint doctor --fix", "dim")
        return 1 if report.missing_core else 0
    if report.env == "termux" and any(l[0] == "PIL" for l in pending):
        cmds = system_commands("termux")
        ui.say("\nEn Termux, Pillow se instala con pkg. Ejecutando:")
        for c in cmds:
            ui.say(f"  $ {c}")
            subprocess.run(c, shell=True)
        report = inspect()
        pending = report.missing_pip
    if pending and (in_virtualenv() or report.env == "termux" or assume_yes):
        cmd = pip_command(pending, report.env)
        ui.say("\nInstalando: " + " ".join(l[1] for l in pending))
        ui.say(f"  $ {' '.join(cmd)}", "dim")
        if assume_yes or ask("¿Continuar? (S/n): ").strip().lower() in ("", "s", "si", "sí"):
            result = subprocess.run(cmd)
            if result.returncode != 0:
                ui.error("pip terminó con errores. Si ves 'externally-managed-environment', ejecuta ./install.sh.")
                return 1
    elif pending:
        ui.say("\nEste Python es del sistema y está protegido. Ejecuta ./install.sh para crear el entorno aislado.", "yellow")
        return 1
    final = inspect()
    ui.say("\nListo." if not final.missing_pip else f"\nSigue faltando: {', '.join(l[1] for l in final.missing_pip)}",
           "green" if not final.missing_pip else "red")
    return 0 if not final.missing_core else 1


def preflight(ui, ask=input, interactive: bool | None = None) -> bool:
    """Comprueba lo imprescindible al arrancar. Ofrece instalarlo si falta."""
    report = inspect()
    if not report.missing_core:
        return True
    interactive = sys.stdin.isatty() if interactive is None else interactive
    ui.error("Faltan librerías necesarias: " + ", ".join(l[1].split("[")[0] for l in report.missing_core))
    for step in guidance(report):
        print(f"    {step}", file=sys.stderr)
    if interactive and ask("¿Intentar instalarlas ahora? (S/n): ").strip().lower() in ("", "s", "si", "sí"):
        return run(ui, fix=True, ask=ask) == 0
    return False
