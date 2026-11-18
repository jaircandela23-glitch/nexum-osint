"""Datos del autor y del proyecto. Una sola fuente para banner, reportes, `about` y documentación."""

TOOL = "NEXUM OSINT"
TAGLINE = "Framework de inteligencia de fuentes abiertas"
COMPANY = "NEXUM Intelligence Systems"
AUTHOR = "Jair Muñoz Candela"
AUTHOR_ROLE = "Fundador de NEXUM Intelligence Systems"
HANDLE = "J@ir.d3v"
LOCATION = "Lima, Perú"
REPO = "https://github.com/jaircandela23-glitch/nexum-osint"
COPYRIGHT = "Copyright (c) 2026 Jair Muñoz Candela - NEXUM Intelligence Systems"
LICENSE = "MIT"

SOCIALS = {
    "GitHub": "https://github.com/jaircandela23-glitch",
}

CONTACT = {
    "Correo": "jair.candela23@hotmail.com",
    "Facebook": "Jair Muñoz Candela",
    "Instagram": "Jair Muñoz Candela",
    "TikTok": "Jair Muñoz Candela",
}

# nombre, autoría, licencia, aporte
ACKNOWLEDGEMENTS = (
    ("SpiderFoot", "Steve Micallef y colaboradores", "MIT", "Referencia de fuentes y técnicas de recolección pasiva"),
    ("Toutatis", "megadose", "GPL-3.0", "Referencia del perfil público de Instagram; sin código reutilizado"),
    ("WhatsMyName", "WebBreacher y colaboradores", "CC BY-SA 4.0", "Lista de sitios para verificar alias"),
    ("Sherlock", "Sherlock Project", "MIT", "Lista de sitios para verificar alias"),
    ("XposedOrNot", "XposedOrNot y HackUnderway", "MIT", "API y referencia de filtraciones de correo"),
    ("OSINT Tools Library", "OSINT Newsletter", "Sin licencia declarada", "Directorio opcional importado por el usuario"),
    ("libphonenumber", "Google (puerto en Python: David Drysdale)", "Apache-2.0", "Validación y datos de numeración telefónica"),
)

LOGO = r"""
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ███╗
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║████╗ ████║
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║██╔████╔██║
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║██║╚██╔╝██║
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝
                 ╔═╗╔═╗╦╔╗╔╔╦╗
                 ║ ║╚═╗║║║║ ║
                 ╚═╝╚═╝╩╝╚╝ ╩
""".strip("\n")

# Versión compacta para pantallas estrechas (Termux en vertical)
LOGO_SMALL = r"""
█▄ █ █▀▀ ▀▄▀ █ █ █▀▄▀█  █▀█ █▀ █ █▄ █ ▀█▀
█ ▀█ ██▄ █ █ █▄█ █ ▀ █  █▄█ ▄█ █ █ ▀█  █
""".strip("\n")

# Paleta: degradado cian a violeta
GRADIENT = ("#00e5ff", "#00c8ff", "#00a8ff", "#2f8cff", "#4a6dff", "#6a5cff", "#8a5cff", "#8a5cff", "#8a5cff")

BANNER = f"{TOOL}\n{TAGLINE}\n{COMPANY}"
CREDIT = f"Creado por {AUTHOR}, fundador de {COMPANY}."
NOTICE = "Uso autorizado y legal únicamente. Consulta solo fuentes públicas."
