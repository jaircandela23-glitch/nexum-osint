"""Extracción de datos: correos, teléfonos, perfiles, direcciones y metadatos.

Trabaja sobre texto pegado, archivos (texto, HTML, correo .eml, Office, PDF, imágenes),
carpetas completas y páginas web. Todo lo que devuelve sale del contenido analizado;
los identificadores con dígito verificador (RUC, criptomonedas) se validan antes de listarse.
"""
from __future__ import annotations

import csv
import email
import html
import ipaddress
import json
import re
import zipfile
from collections import deque
from dataclasses import dataclass, field
from email import policy
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .core.entities import Kind, crypto_kind
from .core.scope import is_freemail
from .modules.id_intel import RUC_PREFIX, ruc_valid

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 2000
TEXT_SUFFIXES = {".txt", ".md", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".log", ".yml", ".yaml", ".ini", ".cfg"}
OFFICE_SUFFIXES = {".docx", ".xlsx", ".pptx"}
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".tif", ".tiff", ".png", ".webp"}

CATEGORIES = {
    "emails": "Correos", "phones": "Teléfonos", "profiles": "Perfiles en redes", "urls": "Enlaces",
    "domains": "Dominios", "ips": "Direcciones IP", "crypto": "Criptomonedas", "ruc": "RUC válidos",
    "hashes": "Hashes", "cves": "CVE",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}")
URL_RE = re.compile(r"https?://[^\s<>\"'\\^`{}|]+", re.I)
PHONE_INTL_RE = re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s.\-]?\(?\d{1,4}\)?){2,5}(?!\d)")
PHONE_PE_RE = re.compile(r"(?<![\w+\-])(?<!\d[.,:/])9\d{2}[ .\-]?\d{3}[ .\-]?\d{3}(?![\w\-]|[.,:/]\d)")
IPV4_RE = re.compile(r"(?<![\w.\-])(?:\d{1,3}\.){3}\d{1,3}(?![\w\-]|\.\d)")
BARE_DOMAIN_RE = re.compile(r"(?<![@\w.\-/%])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?![\w\-]|@)", re.I)
BTC_RE = re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RUC_RE = re.compile(r"(?<![\d.])(?:10|15|16|17|20)\d{9}(?![\d.]*\d)")

# Dominios de nivel superior aceptados cuando aparecen "sueltos" en un texto (sin http ni @).
KNOWN_TLDS = frozenset(
    "com net org edu gov mil int info biz io co dev app ai me tv us uk de fr es it nl be ch at se no dk fi pl pt ie "
    "ru ua cn jp kr in au nz ca mx br ar cl pe ec bo uy py ve co xyz online site tech cloud shop store blog top "
    "pro name mobi company global group agency digital email network solutions services systems media news live "
    "world today life studio design academy center consulting finance bank legal health education tools ltd inc llc "
    "dev codes press law work zone one link page website space fun club vip".split()
)
IMAGE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff", "woff2", "map"}

# (nombre visible, expresión que captura el usuario). El orden evita que "x.com" gane a "twitter.com".
PROFILE_PATTERNS = (
    ("X / Twitter", re.compile(r"https?://(?:www\.|mobile\.)?(?:twitter|x)\.com/(@?[A-Za-z0-9_]{1,15})(?:[/?#]|$)", re.I)),
    ("Instagram", re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{1,30})(?:[/?#]|$)", re.I)),
    ("Facebook", re.compile(r"https?://(?:www\.|m\.|web\.)?facebook\.com/([A-Za-z0-9.\-]{3,60})(?:[/?#]|$)", re.I)),
    ("LinkedIn", re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(in/[A-Za-z0-9\-_%]{3,100}|company/[A-Za-z0-9\-_%]{2,100})", re.I)),
    ("TikTok", re.compile(r"https?://(?:www\.)?tiktok\.com/(@[A-Za-z0-9_.]{2,24})", re.I)),
    ("GitHub", re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9\-]{1,39})(?:[/?#]|$)", re.I)),
    ("Telegram", re.compile(r"https?://(?:t|telegram)\.me/([A-Za-z0-9_]{4,32})(?:[/?#]|$)", re.I)),
    ("YouTube", re.compile(r"https?://(?:www\.)?youtube\.com/(@[A-Za-z0-9_.\-]{3,40}|channel/[A-Za-z0-9_\-]{10,})", re.I)),
)
# Rutas que no son cuentas de usuario.
PROFILE_BLACKLIST = {
    "share", "sharer", "sharer.php", "intent", "home", "login", "signup", "about", "privacy", "explore", "search",
    "hashtag", "tr", "dialog", "plugins", "watch", "pages", "groups", "events", "marketplace", "policies", "help",
    "settings", "topics", "features", "pricing", "orgs", "sponsors", "notifications", "i", "p", "reel", "stories",
}
# Dominios muy grandes que no aportan como objetivo de investigación.
COMMON_DOMAINS = frozenset({
    "google.com", "gstatic.com", "googleapis.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "youtube.com", "linkedin.com", "tiktok.com", "github.com", "w3.org", "schema.org", "apple.com", "microsoft.com",
    "cloudflare.com", "wikipedia.org", "amazon.com", "whatsapp.com", "t.me", "wa.me", "bit.ly",
})


# Recursos de la página (imágenes, tipografías, esquemas) que no son información del objetivo.
NOISE_HOST_RE = re.compile(
    r"(^|\.)(avatars|camo|user-images|raw|objects)\.githubusercontent\.com$|(^|\.)githubassets\.com$"
    r"|(^|\.)shields\.io$|^fonts\.(googleapis|gstatic)\.com$|(^|\.)gstatic\.com$|(^|\.)schema\.org$|(^|\.)w3\.org$"
    r"|^(cdn|static|assets|img|images)\d*\.|(^|\.)gravatar\.com$|(^|\.)cloudfront\.net$"
)
ASSET_URL_RE = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|map|woff2?|ttf|eot)(\?|#|$)", re.I)


def _is_noise(url: str) -> bool:
    parts = urlsplit(url)
    return bool(ASSET_URL_RE.search(parts.path) or NOISE_HOST_RE.search(parts.hostname or ""))


@dataclass
class Findings:
    """Resultado de analizar una fuente. `items` agrupa los datos por categoría."""
    source: str
    items: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, dict] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(len(v) for v in self.items.values())

    def merge(self, other: "Findings") -> None:
        for cat, values in other.items.items():
            self.items[cat] = sorted(set(self.items.get(cat, [])) | set(values))
        self.metadata.update(other.metadata)
        self.notes.extend(other.notes)


# ------------------------------------------------------------------ texto
def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)]}>'\"")


def _valid_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _plausible_email(address: str) -> bool:
    """Descarta lo que parece correo pero no lo es: extensiones de archivo, TLD inexistentes, partes mal formadas."""
    local, domain = address.rsplit("@", 1)
    tld = domain.rsplit(".", 1)[-1]
    if tld in IMAGE_TLDS or local[0] in "-." or local[-1] in "-.":
        return False
    return tld in KNOWN_TLDS or len(tld) == 2


def _phones(text: str) -> list[str]:
    found: list[str] = []
    for match in PHONE_INTL_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 8 <= len(digits) <= 15:
            found.append("+" + digits)
    for match in PHONE_PE_RE.finditer(text):
        found.append("+51" + re.sub(r"\D", "", match.group()))
    return found


def _profiles(urls: list[str], own_host: str = "") -> list[str]:
    """Cuentas de redes sociales en una lista de URLs.

    En una página de la propia plataforma (own_host) solo cuenta el perfil de esa página: el resto
    son enlaces de navegación del sitio (características, precios, ayuda...).
    """
    found = []
    for url in urls:
        host = (urlsplit(url).hostname or "").removeprefix("www.")
        for site, pattern in PROFILE_PATTERNS:
            m = pattern.match(url)
            if not m:
                continue
            user = m.group(1)
            if user.lower().lstrip("@") in PROFILE_BLACKLIST or user.lstrip("@").isdigit():
                break
            if own_host and host == own_host.removeprefix("www."):
                break
            found.append(f"{site}: {user}")
            break
    return found


def _dedupe(values) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        seen.setdefault(v, None)
    return sorted(seen)


def from_text(text: str, source: str = "texto", own_host: str = "") -> Findings:
    """Extrae todas las categorías de datos de un texto.

    Con `own_host` (el sitio de origen) se omiten sus enlaces internos y sus propios dominios:
    solo interesa a dónde apunta la página.
    """
    text = html.unescape(text)
    emails = [e.lower().rstrip(".") for e in EMAIL_RE.findall(text)]
    emails = [e for e in emails if _plausible_email(e)]
    all_urls = [_clean_url(u) for u in URL_RE.findall(text)]
    root = own_host.removeprefix("www.").lower()

    def _own(host: str) -> bool:
        return bool(root) and (host == root or host.endswith("." + root))

    urls = [u for u in all_urls if not _is_noise(u) and not _own((urlsplit(u).hostname or "").lower())]
    ips = [str(ip) for raw in IPV4_RE.findall(text)
           if (ip := _valid_ip(raw)) and not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)]

    domains = {urlsplit(u).hostname for u in urls if urlsplit(u).hostname and not _valid_ip(urlsplit(u).hostname)}
    domains |= {e.split("@", 1)[1] for e in emails}
    domains = {d for d in domains if not NOISE_HOST_RE.search(d) and not _own(d)}
    scrubbed = EMAIL_RE.sub(" ", URL_RE.sub(" ", text))
    for m in BARE_DOMAIN_RE.finditer(scrubbed):
        tld = m.group(1).lower()
        if tld in KNOWN_TLDS and not _valid_ip(m.group(0)):
            domains.add(m.group(0).lower())
    domains = {d.removeprefix("www.") for d in domains if d and d.rsplit(".", 1)[-1] not in IMAGE_TLDS}

    crypto = [f"{crypto_kind(c)}: {c}" for c in BTC_RE.findall(text) + ETH_RE.findall(text) if crypto_kind(c)]
    ruc = [f"{r}  ({RUC_PREFIX[r[:2]]})" for r in RUC_RE.findall(text) if ruc_valid(r)]
    hashes = []
    # Una cadena hexadecimal dentro de una URL (p. ej. un commit) es un identificador, no un hash suelto.
    for h in HASH_RE.findall(URL_RE.sub(" ", ETH_RE.sub(" ", text))):
        # Un hash real mezcla letras y dígitos; una secuencia solo numérica suele ser otra cosa.
        if not h.isdigit() and not h.isalpha():
            hashes.append(f"{HASH_NAMES[len(h)]}: {h.lower()}")

    if own_host:   # en una página web los hashes son identificadores de recursos, no indicadores
        hashes = []
    items = {
        "emails": _dedupe(emails), "phones": _dedupe(_phones(text)), "profiles": _dedupe(_profiles(all_urls, own_host)),
        "urls": _dedupe(urls), "domains": _dedupe(domains), "ips": _dedupe(ips), "crypto": _dedupe(crypto),
        "ruc": _dedupe(ruc), "hashes": _dedupe(hashes), "cves": _dedupe(c.upper() for c in CVE_RE.findall(text)),
    }
    return Findings(source, {k: v for k, v in items.items() if v})


# ------------------------------------------------------------------ formatos
def _plain_ooxml_text(xml: str) -> str:
    runs = re.findall(r"<(?:w:t|a:t|t)(?:\s[^>]*)?>([^<]*)</(?:w:t|a:t|t)>", xml)
    return " ".join(html.unescape(r) for r in runs)


def _read_office(path: Path) -> tuple[str, dict]:
    """Texto, enlaces y metadatos de un .docx, .xlsx o .pptx (todos son zips de XML)."""
    meta: dict = {}
    chunks: list[str] = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()

        def read(name: str) -> str:
            data = z.read(name)
            if b"<!DOCTYPE" in data or b"<!ENTITY" in data:   # XML hostil: se ignora
                return ""
            return data.decode("utf-8", "replace")

        labels = {"creator": "autor", "lastModifiedBy": "modificado_por", "created": "creado",
                  "modified": "modificado", "title": "titulo", "subject": "asunto", "keywords": "palabras_clave",
                  "revision": "revision", "Application": "aplicacion", "Company": "empresa", "Manager": "responsable",
                  "AppVersion": "version_aplicacion", "TotalTime": "minutos_edicion"}
        for part in ("docProps/core.xml", "docProps/app.xml"):
            if part in names:
                for tag, label in labels.items():
                    m = re.search(rf"<(?:\w+:)?{tag}[^>]*>([^<]+)</", read(part))
                    if m and m.group(1).strip():
                        meta[label] = html.unescape(m.group(1).strip())
        for name in names:
            if re.fullmatch(r"word/(document|header\d*|footer\d*|footnotes|comments)\.xml|xl/sharedStrings\.xml"
                            r"|ppt/(slides|notesSlides)/[^/]+\.xml", name):
                chunks.append(_plain_ooxml_text(read(name)))
            elif name.endswith(".rels"):
                chunks += re.findall(r'Target="(https?://[^"]+)"[^>]*TargetMode="External"', read(name))
    return "\n".join(chunks), meta


def _read_pdf(path: Path) -> tuple[str, dict]:
    """Metadatos y enlaces de un PDF; el texto completo requiere pypdf (opcional)."""
    raw = path.read_bytes()
    meta: dict = {}
    for key, label in (("Author", "autor"), ("Creator", "creador"), ("Producer", "productor"),
                       ("Title", "titulo"), ("CreationDate", "creado"), ("ModDate", "modificado")):
        m = re.search(rb"/" + key.encode() + rb"\s*\(([^)]{1,200})\)", raw)
        if m:
            meta[label] = m.group(1).decode("latin-1").strip()
    text = " ".join(m.decode("latin-1") for m in re.findall(rb"/URI\s*\(([^)]+)\)", raw))
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        info = reader.metadata or {}
        for key, label in (("/Author", "autor"), ("/Creator", "creador"), ("/Producer", "productor"),
                           ("/CreationDate", "creado")):
            if info.get(key):
                meta[label] = str(info[key])
        text += "\n" + "\n".join((p.extract_text() or "") for p in reader.pages[:300])
    except ImportError:
        meta["aviso"] = "texto del PDF no extraído: instala pypdf (pip install pypdf)"
    except Exception as exc:  # PDF cifrado o dañado: se conservan los datos ya obtenidos
        meta["aviso"] = f"no se pudo leer el contenido: {exc}"
    return text, meta


def _read_image(path: Path) -> tuple[str, dict]:
    from .modules.image_exif import read_exif
    try:
        meta = read_exif(path.read_bytes())
    except Exception as exc:
        return "", {"aviso": f"imagen no legible: {exc}"}
    if meta.get("coords"):
        lat, lon = meta["coords"]
        meta["mapa"] = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
    return "", meta


def _read_eml(path: Path) -> tuple[str, dict]:
    """Cabeceras y cuerpo de un correo guardado (.eml): remitente, ruta de entrega e IP de origen."""
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    meta = {label: str(msg[h]) for h, label in (("From", "de"), ("To", "para"), ("Reply-To", "responder_a"),
                                                  ("Return-Path", "ruta_de_retorno"), ("Subject", "asunto"),
                                                  ("Date", "fecha"), ("Message-ID", "id_mensaje"),
                                                  ("X-Mailer", "cliente"), ("User-Agent", "cliente"),
                                                  ("X-Originating-IP", "ip_de_origen")) if msg[h]}
    received = [str(h) for h in msg.get_all("Received", [])]
    meta["saltos_received"] = str(len(received))
    headers = "\n".join(f"{k}: {v}" for k, v in msg.items())
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""
    return f"{headers}\n{text}", meta


def _html_meta(raw: str) -> dict:
    meta: dict = {}
    title = re.search(r"<title[^>]*>([^<]{1,200})</title>", raw, re.I)
    if title:
        meta["titulo"] = html.unescape(title.group(1).strip())
    for name, label in (("author", "autor"), ("description", "descripcion"), ("generator", "generador"),
                        ("og:site_name", "sitio"), ("twitter:site", "twitter"), ("twitter:creator", "twitter_autor")):
        m = (re.search(rf'<meta[^>]+(?:name|property)=["\']{re.escape(name)}["\'][^>]+content=["\']([^"\']*)', raw, re.I)
             or re.search(rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:name|property)=["\']{re.escape(name)}["\']', raw, re.I))
        if m and m.group(1).strip():
            meta[label] = html.unescape(m.group(1).strip())[:200]
    return meta


def _visible_html(raw: str) -> str:
    """Quita scripts (salvo JSON-LD) y estilos: su contenido es código, no información de la página."""
    raw = re.sub(r"<style\b.*?</style>", " ", raw, flags=re.I | re.S)
    raw = re.sub(r"<svg\b.*?</svg>", " ", raw, flags=re.I | re.S)
    return re.sub(r"<script\b(?![^>]*ld\+json).*?</script>", " ", raw, flags=re.I | re.S)


def _html_links(raw: str, base: str = "") -> str:
    """Convierte mailto:, tel: y href/src en texto plano para que los patrones los detecten."""
    out = []
    for value in re.findall(r'(?:href|src|content)=["\']([^"\']+)["\']', raw, re.I):
        value = html.unescape(value)
        if value.lower().startswith(("mailto:", "tel:")):
            out.append(value.split(":", 1)[1].split("?")[0])
        elif base and not re.match(r"[a-z][a-z0-9+.\-]*:", value, re.I):
            out.append(urljoin(base, value))
        else:
            out.append(value)
    return "\n".join(out)


def from_file(path: Path) -> Findings:
    """Analiza un archivo según su extensión. Un formato desconocido se lee como texto."""
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        return Findings(str(path), notes=[f"{path.name}: supera los 25 MB, omitido"])
    suffix = path.suffix.lower()
    try:
        if suffix in OFFICE_SUFFIXES:
            text, meta = _read_office(path)
        elif suffix == ".pdf":
            text, meta = _read_pdf(path)
        elif suffix in IMAGE_SUFFIXES:
            text, meta = _read_image(path)
        elif suffix == ".eml":
            text, meta = _read_eml(path)
        else:
            raw = path.read_text(encoding="utf-8", errors="replace")
            if suffix in (".html", ".htm"):
                meta = _html_meta(raw)
                raw = _visible_html(raw)
                text = raw + "\n" + _html_links(raw)
            else:
                meta, text = {}, raw
    except (zipfile.BadZipFile, OSError) as exc:
        return Findings(str(path), notes=[f"{path.name}: no se pudo leer ({exc})"])
    found = from_text(text, str(path))
    if meta:
        found.metadata[str(path)] = meta
    return found


def from_folder(folder: Path, recursive: bool = True) -> Findings:
    """Analiza todos los archivos de una carpeta (hasta 2000, sin ocultos)."""
    folder = Path(folder)
    pattern = "**/*" if recursive else "*"
    files = [p for p in sorted(folder.glob(pattern))
             if p.is_file() and not any(part.startswith(".") for part in p.relative_to(folder).parts)]
    total = Findings(str(folder))
    if len(files) > MAX_FILES:
        total.notes.append(f"{len(files)} archivos: se analizan solo los primeros {MAX_FILES}")
    for path in files[:MAX_FILES]:
        total.merge(from_file(path))
    total.notes.append(f"{min(len(files), MAX_FILES)} archivos analizados")
    return total


# ------------------------------------------------------------------ web
async def from_url(http, url: str, pages: int = 1) -> Findings:
    """Descarga una página (y, si `pages` > 1, otras del mismo sitio) y extrae sus datos."""
    start = urlsplit(url)
    host = start.hostname or ""
    queue, seen = deque([url]), {url}
    total = Findings(url)
    fetched = 0
    while queue and fetched < pages:
        current = queue.popleft()
        try:
            resp = await http.get(current, ttl=3600, retries=1)
        except Exception as exc:
            total.notes.append(f"{current}: sin respuesta ({str(exc)[:80]})")
            continue
        if not resp.ok:
            total.notes.append(f"{current}: HTTP {resp.status}")
            continue
        fetched += 1
        raw = resp.text
        meta = _html_meta(raw)
        raw = _visible_html(raw)
        page = from_text(raw + "\n" + _html_links(raw, current), current, own_host=host)
        total.merge(page)
        if meta:
            total.metadata[current] = meta
        for link in re.findall(r'href=["\']([^"\'#]+)', raw, re.I):
            target = urljoin(current, html.unescape(link)).split("#")[0]
            parts = urlsplit(target)
            if (parts.scheme in ("http", "https") and parts.hostname == host and target not in seen
                    and not re.search(r"\.(png|jpe?g|gif|svg|css|js|ico|pdf|zip|mp4|woff2?)(\?|$)", target, re.I)):
                seen.add(target)
                queue.append(target)
    total.notes.append(f"{fetched} página(s) analizada(s)")
    return total


# ------------------------------------------------------------------ salida
def to_targets(found: Findings, limit: int = 25) -> list[tuple[str, Kind, str]]:
    """Datos que vale la pena investigar: (categoría, tipo, valor), de más a menos valioso."""
    out: list[tuple[str, Kind, str]] = []
    for e in found.items.get("emails", []):
        out.append(("emails", Kind.EMAIL, e))
    for p in found.items.get("phones", []):
        out.append(("phones", Kind.PHONE, p))
    for c in found.items.get("crypto", []):
        out.append(("crypto", Kind.CRYPTO, c.split(": ", 1)[1]))
    for ip in found.items.get("ips", []):
        if ipaddress.ip_address(ip).is_global:
            out.append(("ips", Kind.IP, ip))
    for pr in found.items.get("profiles", []):
        site, user = pr.split(": ", 1)
        if site in ("X / Twitter", "Instagram", "TikTok", "GitHub", "Telegram"):
            out.append(("profiles", Kind.USERNAME, user.lstrip("@")))
    for d in found.items.get("domains", []):
        if d not in COMMON_DOMAINS and not is_freemail(d):
            out.append(("domains", Kind.DOMAIN, d))
    return out[:limit]


def export(found: Findings, path: Path) -> Path:
    """Guarda el resultado en JSON o CSV según la extensión del archivo."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["categoria", "valor", "fuente"])
            for cat, values in found.items.items():
                for v in values:
                    writer.writerow([cat, v, found.source])
    else:
        path.write_text(json.dumps({"fuente": found.source, "datos": found.items, "metadatos": found.metadata,
                                    "notas": found.notes}, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def read_stdin_block(read=input) -> str:
    """Lee texto pegado por el usuario hasta una línea vacía doble o fin de entrada."""
    lines, blanks = [], 0
    while True:
        try:
            line = read()
        except EOFError:
            break
        blanks = blanks + 1 if not line.strip() else 0
        if blanks >= 2:
            break
        lines.append(line)
    return "\n".join(lines)
