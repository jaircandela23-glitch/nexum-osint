"""Cliente HTTP asíncrono con caché, límite de tasa y reintentos.

El transporte real usa httpx, pero se importa de forma perezosa y se puede
reemplazar por cualquier función `fetch` para hacer pruebas sin red.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

from .cache import Cache
from .config import Config
from .useragents import browser_headers
from .ratelimit import RateLimiter


@dataclass
class Response:
    status: int
    text: str
    headers: dict[str, str]
    url: str
    from_cache: bool = False
    content: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.text)


Fetch = Callable[..., Awaitable[Response]]


class Http:
    def __init__(self, config: Config, cache: Cache, limiter: RateLimiter,
                 fetch: Fetch | None = None) -> None:
        self.config = config
        self.cache = cache
        self.limiter = limiter
        self._fetch = fetch
        self._client = None
        self.rotator = None          # TorControl opcional: renueva el circuito cuando un sitio bloquea
        self.blocks_before_rotate = 3
        self._blocks = 0
        self.rotations = 0

    async def _httpx_fetch(self, method: str, url: str, **kw: Any) -> Response:
        if self._client is None:
            import httpx  # import perezoso: solo hace falta con red real

            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                follow_redirects=True,
                proxy=self.config.proxy,
                headers={"User-Agent": self.config.user_agent},
            )
        r = await self._client.request(method, url, **kw)
        return Response(r.status_code, r.text, dict(r.headers), str(r.url), content=r.content)

    async def request(self, method: str, url: str, *, params: dict | None = None,
                      headers: dict | None = None, ttl: float | None = None,
                      retries: int = 2, cache_errors: bool = False,
                      data: dict | str | None = None, rotate_ua: bool = False) -> Response:
        ttl = self.config.cache_ttl if ttl is None else ttl
        if data is not None:   # las peticiones con cuerpo nunca se cachean
            ttl = 0
        key = Cache.make_key(method, url, params)
        if ttl > 0 and (hit := self.cache.get(key)):
            return Response(hit["status"], hit["text"], hit["headers"], url, True)

        host = urlsplit(url).netloc
        fetch = self._fetch or self._httpx_fetch
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            await self.limiter.wait(host)
            try:
                extra = {} if data is None else {"data": data}
                sent = {**browser_headers(), **(headers or {})} if rotate_ua else headers
                resp = await fetch(method, url, params=params, headers=sent, **extra)
            except Exception as exc:  # red caída, timeout, DNS, etc.
                last_exc = exc
                await asyncio.sleep(0.6 * (attempt + 1))
                continue
            if resp.status in (403, 429) and self.rotator and attempt < retries and await self._rotate_on_block():
                continue
            if resp.status in (429, 502, 503, 504) and attempt < retries:
                wait = float(resp.headers.get("retry-after", 1.5 * (attempt + 1)))
                await asyncio.sleep(min(wait, 10))
                continue
            if ttl > 0 and (resp.ok or cache_errors or resp.status == 404):
                self.cache.set(key, {"status": resp.status, "text": resp.text,
                                     "headers": resp.headers}, ttl)
            return resp
        raise ConnectionError(f"{method} {url}: {last_exc}")

    async def _rotate_on_block(self) -> bool:
        """Tras varios bloqueos seguidos (403/429) pide un circuito nuevo a Tor. True si se renovó."""
        self._blocks += 1
        if self._blocks < self.blocks_before_rotate:
            return False
        self._blocks = 0
        if not await self.rotator.renew():
            return False
        self.rotations += 1
        await self.close()   # las conexiones abiertas conservan el circuito anterior
        return True

    async def get(self, url: str, **kw: Any) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Response:
        return await self.request("POST", url, **kw)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
