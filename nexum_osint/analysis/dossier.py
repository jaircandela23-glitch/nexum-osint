import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone

from ..core.entities import Graph, Kind

NAME_KEYS = ("full_name", "real_name", "display_name", "name", "gravatar_name", "commit_author")
PLACE_KEYS = ("location", "city", "region", "country", "gravatar_location", "ipinfo_city")
ORG_KEYS = ("company", "organization")
DATE_KEYS = {"created": "Cuenta creada", "created_utc": "Cuenta creada", "createdAt": "Cuenta creada",
             "joined": "Se unió", "joined_at": "Se unió", "date_joined": "Se unió",
             "wayback_timestamp": "Primera copia en Wayback", "registration": "Dominio registrado",
             "expiration": "Dominio vence"}


def fold(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()).strip()


def parse_date(value):
    try:
        if isinstance(value, (int, float)):
            value = value / 1000 if value > 1e11 else value
            return datetime.fromtimestamp(value, timezone.utc)
        text = str(value).strip()
        if re.fullmatch(r"\d{14}", text):
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        if re.fullmatch(r"\d{9,13}", text):
            return parse_date(int(text))
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _confidence(mods: set, low: bool) -> str:
    if low:
        return "baja"
    return "alta" if len(mods) >= 2 else "media"


def build(graph: Graph) -> dict:
    bag: dict[str, dict[str, tuple[str, set, bool]]] = defaultdict(dict)

    def add(section, value, mods, low=False):
        value = str(value).strip()
        if not value or len(value) > 120:
            return
        key = fold(value)
        shown, seen, was_low = bag[section].get(key, (value, set(), True))
        bag[section][key] = (shown, seen | set(mods), was_low and low)

    for node in graph.nodes.values():
        if node.attrs.get("manual") or node.attrs.get("darkweb"):
            continue
        mods = node.sources - {"seed"} or {"seed"}
        low = node.attrs.get("confidence") == "baja"
        if node.kind is Kind.NAME:
            add("Nombres", node.value, mods, low)
        elif node.kind is Kind.EMAIL:
            add("Correos", node.value, mods, low)
        elif node.kind is Kind.PHONE:
            add("Teléfonos", node.value, mods, low)
        elif node.kind is Kind.USERNAME:
            add("Alias", node.value, mods, low)
        elif node.kind is Kind.ORG:
            add("Organizaciones", node.value, mods, low)
        elif node.kind is Kind.CRYPTO:
            add("Direcciones cripto", node.value, mods, low)
        elif node.kind is Kind.PROFILE:
            add("Perfiles", f"{node.attrs.get('site', 'perfil')}: {node.value}", mods, low)
        for key in NAME_KEYS:
            if node.attrs.get(key) and isinstance(node.attrs[key], str):
                add("Nombres", node.attrs[key], mods, low)
        for key in PLACE_KEYS:
            if node.attrs.get(key) and isinstance(node.attrs[key], str):
                add("Ubicaciones", node.attrs[key], mods, low)
        for key in ORG_KEYS:
            if node.attrs.get(key) and isinstance(node.attrs[key], str):
                add("Organizaciones", node.attrs[key], mods, low)
        for key in ("blog", "listed_link"):
            if node.attrs.get(key):
                add("Sitios propios", node.attrs[key], mods, low)

    dossier = {}
    for section, items in bag.items():
        rows = [{"valor": shown, "fuentes": sorted(mods), "confianza": _confidence(mods, low)}
                for shown, mods, low in items.values()]
        order = {"alta": 0, "media": 1, "baja": 2}
        rows.sort(key=lambda r: (order[r["confianza"]], r["valor"].lower()))
        dossier[section] = rows
    return dossier


def timeline(graph: Graph) -> list[dict]:
    events = []
    for node in graph.nodes.values():
        for key, label in DATE_KEYS.items():
            if key in node.attrs:
                when = parse_date(node.attrs[key])
                if when and 1990 <= when.year <= datetime.now().year + 2:
                    site = node.attrs.get("site") or node.kind.value
                    events.append({"fecha": when.date().isoformat(), "evento": label,
                                   "detalle": f"{site}: {node.value}"[:110]})
        for item in node.attrs.get("eventos_filtracion") or []:
            if item.get("fecha", "").isdigit() and 1990 <= int(item["fecha"]) <= datetime.now().year:
                events.append({"fecha": item["fecha"], "evento": "Filtración de datos", "detalle": item["detalle"]})
    events.sort(key=lambda e: e["fecha"])
    return events
