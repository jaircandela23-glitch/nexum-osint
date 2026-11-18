import json
import os
from datetime import datetime
from pathlib import Path

from .core.config import cache_dir

LIMIT = 50


def path() -> Path:
    return cache_dir().parent / "nexum-osint" / "history.json"


def load() -> list[dict]:
    try:
        return json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def record(targets: list[str], folder: Path, files: list[Path], findings: int) -> None:
    items = load()
    items.insert(0, {"fecha": datetime.now().isoformat(timespec="minutes"), "objetivos": targets,
                     "carpeta": str(folder.resolve()), "archivos": [str(f.resolve()) for f in files],
                     "hallazgos": findings})
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(items[:LIMIT], ensure_ascii=False, indent=1), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
