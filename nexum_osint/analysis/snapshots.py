import json
import re
from datetime import datetime
from pathlib import Path

from ..core.config import cache_dir


def _dir() -> Path:
    return cache_dir().parent / "nexum-osint" / "snapshots"


def _key(targets: list[str]) -> str:
    return re.sub(r"[^\w.-]+", "_", "_".join(sorted(t.lower() for t in targets)))[:90] or "scan"


def _state(graph) -> dict:
    nodes = sorted(n.key for n in graph.nodes.values() if not n.attrs.get("manual"))
    notes = sorted({f"{n['severity']}|{n['title']}|{n.get('node') or ''}" for n in graph.notes
                    if n["severity"] in ("high", "medium", "warn", "low")})
    return {"nodes": nodes, "notes": notes}


def load(targets: list[str]) -> dict | None:
    try:
        return json.loads((_dir() / f"{_key(targets)}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save(targets: list[str], graph) -> None:
    folder = _dir()
    folder.mkdir(parents=True, exist_ok=True)
    data = {"fecha": datetime.now().isoformat(timespec="minutes"), **_state(graph)}
    (folder / f"{_key(targets)}.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def compare(previous: dict | None, graph) -> dict | None:
    """Diferencias frente a la última investigación de los mismos objetivos."""
    if not previous:
        return None
    now = _state(graph)
    old_nodes, new_nodes = set(previous["nodes"]), set(now["nodes"])
    old_notes, new_notes = set(previous["notes"]), set(now["notes"])
    return {
        "desde": previous["fecha"].replace("T", " "),
        "entidades_nuevas": sorted(new_nodes - old_nodes),
        "entidades_ausentes": sorted(old_nodes - new_nodes),
        "hallazgos_nuevos": [n.split("|")[:2] for n in sorted(new_notes - old_notes)],
        "hallazgos_resueltos": [n.split("|")[:2] for n in sorted(old_notes - new_notes)],
    }
