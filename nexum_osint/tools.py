import json
import re
import zipfile
from importlib import resources
from pathlib import Path

from .core.config import config_dir

CATEGORY_ES = {
    "social media": "Redes sociales", "username": "Alias y personas", "people": "Alias y personas",
    "email address": "Correo", "phone number": "Teléfono", "public records": "Empresas y registros",
    "domain name": "Dominios y red", "network infrastructure": "Dominios y red",
    "geolocation and maps": "Geolocalización", "image and video analysis": "Imágenes y video",
    "blockchain and cryptocurrency": "Criptomonedas", "cyberthreat intelligence": "Amenazas",
    "breached data provider": "Filtraciones", "archiving": "Archivos web", "transport": "Transporte",
    "foundational": "Fundamentos", "foundational osint tools": "Fundamentos", "data extraction": "Extracción de datos",
    "fact checking verification": "Verificación", "conflict": "Conflictos", "language translation": "Idiomas",
    "public media": "Medios", "environment and wildlife": "Medio ambiente",
    "blockchain cryptocurrency": "Criptomonedas", "environment wildlife": "Medio ambiente",
    "fact checking verification": "Verificación",
}


def _category_for(path: str, label: str) -> str:
    if "social-media-osint/" in path:
        return "Redes sociales"
    key = re.sub(r"\s+", " ", re.sub(r"[-/&]", " ", label.lower())).strip()
    key = re.sub(r"\s+osint$", "", key)
    return CATEGORY_ES.get(key) or CATEGORY_ES.get(key.replace(" tools", "")) or label


def user_path() -> Path:
    return config_dir() / "tools_library.json"


def load() -> list[dict]:
    base = json.loads(resources.files("nexum_osint.data").joinpath("tools_catalog.json").read_text(encoding="utf-8"))["tools"]
    for t in base:
        t["origin"] = "NEXUM"
    extra = user_path()
    if extra.exists():
        seen = {re.sub(r"\W", "", t["name"].lower()) for t in base}
        for t in json.loads(extra.read_text(encoding="utf-8")).get("tools", []):
            if re.sub(r"\W", "", t["name"].lower()) not in seen:
                base.append(t)
    return base


def categories(tools: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for t in tools:
        counts[t["category"]] = counts.get(t["category"], 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def search(tools: list[dict], text: str) -> list[dict]:
    words = [w for w in re.split(r"\s+", text.lower().strip()) if w]
    def blob(t):
        return " ".join(str(t.get(k, "")) for k in ("name", "category", "what", "url")).lower()
    return [t for t in tools if all(w in blob(t) for w in words)]


# ---- importación de la OSINT Tools Library (copia local del usuario) ----
def _link(cell: str) -> str:
    m = re.search(r"\]\((https?://[^)\s]+)\)", cell) or re.search(r"(https?://[^\s|)\]]+)", cell)
    return m.group(1) if m else ""


def _clean(cell: str) -> str:
    cell = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cell)
    return re.sub(r"\s+", " ", re.sub(r"[*`]|&#x20;|<[^>]+>", "", cell)).strip()


def parse_tool_page(text: str) -> dict | None:
    title = re.search(r"^#\s+(.+)$", text, re.M)
    rows = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) >= 2:
            rows[_clean(cells[0]).lower()] = cells[1]
    url = _link(rows.get("url", ""))
    if not title or not url:
        return None
    return {"name": _clean(title.group(1)), "url": url, "what": _clean(rows.get("what it does", "")),
            "how": _clean(rows.get("how to use it", "")), "cost": re.sub(r"^Free\b\.?", "Gratis", _clean(rows.get("cost", ""))),
            "account": _clean(rows.get("account required", "")).lower().startswith(("yes", "sí", "si")),
            "origin": "OSINT Tools Library"}


def _read_tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)).replace("\\", "/"): p.read_text(encoding="utf-8", errors="ignore")
            for p in root.rglob("*.md")}


def _read_zip(path: Path) -> dict[str, str]:
    out = {}
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.endswith(".md")]
        marker = next((n[: n.index("osint-tools/")] for n in names if "osint-tools/" in n), "")
        for n in names:
            out[n[len(marker):]] = z.read(n).decode("utf-8", errors="ignore")
    return out


def import_library(source: Path) -> int:
    files = _read_zip(source) if source.suffix.lower() == ".zip" else _read_tree(source)
    tools: dict[str, dict] = {}
    for name, text in files.items():
        if name.startswith("osint-tools/"):
            if (tool := parse_tool_page(text)):
                tool["slug"] = name.rsplit("/", 1)[-1][:-3]
                tools[tool["slug"]] = tool
    if not tools:
        raise ValueError("no se encontraron fichas de herramientas: indica la carpeta o el zip de la biblioteca")
    for name, text in files.items():
        if not name.startswith("tool-categories/") or name.endswith("README.md") and name.count("/") == 1:
            continue
        heading = re.search(r"^#\s+(.+)$", text, re.M)
        label = _clean(heading.group(1)) if heading else name
        category = _category_for(name, label)
        for slug in re.findall(r"osint-tools/([^)\s]+?)\.md", text):
            if slug in tools and "category" not in tools[slug]:
                tools[slug]["category"] = category
    final = []
    for tool in tools.values():
        tool.setdefault("category", "Otras")
        tool.pop("slug", None)
        final.append(tool)
    path = user_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"origin": "OSINT Tools Library (OSINT Newsletter), copia local del usuario",
                                "tools": final}, ensure_ascii=False), encoding="utf-8")
    return len(final)
