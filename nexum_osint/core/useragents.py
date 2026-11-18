"""Cabeceras de navegador realistas para las comprobaciones de alias, que muchos sitios bloquean si
detectan un cliente automático."""
from __future__ import annotations

import random

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
)
LANGUAGES = ("es-PE,es;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.7", "en-US,en;q=0.9,es;q=0.6", "es-MX,es;q=0.9,en;q=0.8")


def browser_headers(rng: random.Random | None = None) -> dict[str, str]:
    """Un conjunto coherente de cabeceras: el idioma y el agente cambian juntos en cada petición."""
    rng = rng or random
    return {"User-Agent": rng.choice(USER_AGENTS), "Accept-Language": rng.choice(LANGUAGES),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
