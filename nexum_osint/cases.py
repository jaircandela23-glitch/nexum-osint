"""Gestor de casos: guarda cada investigación en una base SQLite para continuarla y compararla después."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from .core.config import cache_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    date TEXT NOT NULL, targets TEXT NOT NULL, depth INTEGER, exposure INTEGER, files TEXT);
CREATE TABLE IF NOT EXISTS entities (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, kind TEXT NOT NULL, value TEXT NOT NULL,
    sources TEXT, PRIMARY KEY (run_id, kind, value));
CREATE TABLE IF NOT EXISTS findings (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, severity TEXT NOT NULL, title TEXT NOT NULL);
"""


def default_path() -> Path:
    return cache_dir().parent / "nexum-osint" / "cases.sqlite"


def clean_name(name: str) -> str:
    return re.sub(r"[^\w.\- ]+", "", name).strip()[:60]


class CaseBook:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or default_path())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)   # contiene datos de investigaciones
        except OSError:
            pass

    def close(self) -> None:
        self.db.close()

    def _case_id(self, name: str, create: bool = False) -> int | None:
        row = self.db.execute("SELECT id FROM cases WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
        if row or not create:
            return row[0] if row else None
        cur = self.db.execute("INSERT INTO cases (name, created) VALUES (?, ?)",
                              (name, datetime.now().isoformat(timespec="minutes")))
        return cur.lastrowid

    def add_run(self, name: str, targets: list[str], depth: int, graph, exposure: int | None = None,
                files: list[Path] | None = None) -> int:
        """Guarda una investigación dentro del caso (se crea si no existe) y devuelve su número."""
        name = clean_name(name)
        if not name:
            raise ValueError("el nombre del caso está vacío")
        case_id = self._case_id(name, create=True)
        cur = self.db.execute(
            "INSERT INTO runs (case_id, date, targets, depth, exposure, files) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, datetime.now().isoformat(timespec="minutes"), json.dumps(targets, ensure_ascii=False),
             depth, exposure, json.dumps([str(f) for f in files or []])))
        run_id = cur.lastrowid
        self.db.executemany(
            "INSERT OR IGNORE INTO entities (run_id, kind, value, sources) VALUES (?, ?, ?, ?)",
            [(run_id, n.kind.value, n.value, ",".join(sorted(n.sources))) for n in graph.nodes.values()
             if not n.attrs.get("manual")])
        self.db.executemany(
            "INSERT INTO findings (run_id, severity, title) VALUES (?, ?, ?)",
            [(run_id, f["severity"], f["title"]) for f in graph.notes if f["severity"] in ("high", "medium", "warn", "low")])
        self.db.commit()
        return run_id

    def cases(self) -> list[dict]:
        rows = self.db.execute("""
            SELECT c.name, c.created, COUNT(r.id), MAX(r.date) FROM cases c
            LEFT JOIN runs r ON r.case_id = c.id GROUP BY c.id ORDER BY MAX(r.date) DESC, c.name""").fetchall()
        return [{"caso": n, "creado": c, "investigaciones": k, "ultima": last} for n, c, k, last in rows]

    def runs(self, name: str) -> list[dict]:
        case_id = self._case_id(name)
        if case_id is None:
            return []
        rows = self.db.execute("""
            SELECT r.id, r.date, r.targets, r.depth, r.exposure,
                   (SELECT COUNT(*) FROM entities WHERE run_id = r.id),
                   (SELECT COUNT(*) FROM findings WHERE run_id = r.id AND severity = 'high')
            FROM runs r WHERE r.case_id = ? ORDER BY r.id""", (case_id,)).fetchall()
        return [{"id": i, "fecha": d, "objetivos": json.loads(t), "profundidad": dp, "exposicion": ex,
                 "entidades": ent, "hallazgos_altos": hi} for i, d, t, dp, ex, ent, hi in rows]

    def _state(self, run_id: int) -> tuple[set, set]:
        ents = {(k, v) for k, v in self.db.execute("SELECT kind, value FROM entities WHERE run_id = ?", (run_id,))}
        finds = {(s, t) for s, t in self.db.execute("SELECT severity, title FROM findings WHERE run_id = ?", (run_id,))}
        return ents, finds

    def compare(self, name: str) -> dict | None:
        """Diferencias entre las dos últimas investigaciones del caso."""
        runs = self.runs(name)
        if len(runs) < 2:
            return None
        (old_e, old_f), (new_e, new_f) = self._state(runs[-2]["id"]), self._state(runs[-1]["id"])
        return {"desde": runs[-2]["fecha"], "hasta": runs[-1]["fecha"],
                "entidades_nuevas": sorted(f"{k}:{v}" for k, v in new_e - old_e),
                "entidades_ausentes": sorted(f"{k}:{v}" for k, v in old_e - new_e),
                "hallazgos_nuevos": sorted(f"{s}: {t}" for s, t in new_f - old_f),
                "hallazgos_resueltos": sorted(f"{s}: {t}" for s, t in old_f - new_f)}

    def export(self, name: str, out: Path) -> Path:
        """Vuelca el caso completo (investigaciones, entidades y hallazgos) a un JSON."""
        data = []
        for run in self.runs(name):
            ents = self.db.execute("SELECT kind, value, sources FROM entities WHERE run_id = ? ORDER BY kind, value",
                                   (run["id"],)).fetchall()
            finds = self.db.execute("SELECT severity, title FROM findings WHERE run_id = ?", (run["id"],)).fetchall()
            data.append({**run, "datos": [{"tipo": k, "valor": v, "fuentes": s.split(",")} for k, v, s in ents],
                         "hallazgos": [{"severidad": s, "titulo": t} for s, t in finds]})
        out = Path(out)
        out.write_text(json.dumps({"caso": name, "investigaciones": data}, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        return out

    def delete(self, name: str) -> bool:
        case_id = self._case_id(name)
        if case_id is None:
            return False
        self.db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        self.db.commit()
        return True
