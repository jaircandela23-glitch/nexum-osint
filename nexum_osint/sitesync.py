import json
import re
from datetime import datetime, timezone

from .core.config import config_dir

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
SKIP_CATEGORIES = {"xx nsfw xx"}
CAT_MAP = {"coding": "dev", "tech": "dev", "social": "social", "gaming": "gaming", "hobby": "hobby",
           "finance": "finance", "music": "music", "video": "video", "blog": "blog", "business": "work",
           "dating": "dating", "news": "news", "shopping": "shop", "art": "photo", "images": "photo",
           "political": "social", "health": "health", "security": "sec", "misc": "otros", "archived": "otros"}


def path():
    return config_dir() / "sites_extended.json"


def from_wmn(data: dict) -> list[dict]:
    out = []
    for s in data.get("sites", []):
        cat = (s.get("cat") or "otros").lower()
        if cat in SKIP_CATEGORIES or s.get("valid") is False or "{account}" not in s.get("uri_check", ""):
            continue
        out.append({"name": s["name"], "url": s["uri_check"].replace("{account}", "{u}"),
                    "category": CAT_MAP.get(cat, cat), "check": "wmn",
                    "e_code": s.get("e_code"), "e_string": s.get("e_string"),
                    "m_code": s.get("m_code"), "m_string": s.get("m_string"),
                    "origin": "WhatsMyName"})
    return out


def from_sherlock(data: dict) -> list[dict]:
    out = []
    for name, s in data.items():
        if not isinstance(s, dict) or "url" not in s or "{}" not in s["url"]:
            continue
        kind = s.get("errorType")
        site = {"name": name, "url": s["url"].replace("{}", "{u}"), "category": "otros",
                "regex": s.get("regexCheck"), "origin": "Sherlock"}
        if kind == "status_code":
            site["check"] = "status"
        elif kind == "message":
            msgs = s.get("errorMsg")
            site.update(check="errmsg", errors=[msgs] if isinstance(msgs, str) else msgs or [])
        elif kind == "response_url" and s.get("errorUrl"):
            site.update(check="errurl", error_url=s["errorUrl"].replace("{}", "{u}"))
        else:
            continue
        out.append(site)
    return out


def merge(*lists: list[dict]) -> list[dict]:
    seen, out = set(), []
    for lst in lists:
        for s in lst:
            key = re.sub(r"[^a-z0-9]", "", s["name"].lower())
            if key not in seen:
                seen.add(key)
                out.append(s)
    return out


async def update(http) -> dict:
    wmn = await http.get(WMN_URL, ttl=0)
    sher = await http.get(SHERLOCK_URL, ttl=0)
    lists, counts = [], {}
    if wmn.ok:
        lists.append(from_wmn(wmn.json()))
        counts["WhatsMyName"] = len(lists[-1])
    if sher.ok:
        lists.append(from_sherlock(sher.json()))
        counts["Sherlock"] = len(lists[-1])
    if not lists:
        raise ConnectionError("no se pudo descargar ninguna lista")
    sites = merge(*lists)
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                             "sources": counts, "sites": sites}, ensure_ascii=False), encoding="utf-8")
    return {"total": len(sites), **counts}
