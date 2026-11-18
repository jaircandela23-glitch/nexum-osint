"""Limitador de tasa por host (token bucket) para respetar las cuotas gratuitas."""
from __future__ import annotations

import asyncio
import time


class Bucket:
    def __init__(self, rate: float, burst: int = 1) -> None:
        self.rate = rate
        self.capacity = max(burst, 1)
        self.tokens = float(self.capacity)
        self.stamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
                self.stamp = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


class RateLimiter:
    """Un bucket por host. Cada módulo declara el ritmo que tolera su API."""

    def __init__(self, default_rate: float = 5.0) -> None:
        self.default_rate = default_rate
        self._buckets: dict[str, Bucket] = {}

    def configure(self, host: str, rate: float, burst: int = 1) -> None:
        self._buckets[host] = Bucket(rate, burst)

    async def wait(self, host: str) -> None:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = self._buckets[host] = Bucket(self.default_rate, burst=2)
        await bucket.take()
