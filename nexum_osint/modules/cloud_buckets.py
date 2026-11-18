"""Buckets de almacenamiento en la nube con nombres derivados del dominio."""
import asyncio

from ..core.entities import Kind
from ..core.module import Module

SUFFIXES = ("", "-dev", "-prod", "-staging", "-backup", "-backups", "-files", "-assets",
            "-static", "-data", "-public", "-media", "-uploads", "-www")


def candidates(domain: str) -> list[str]:
    parts = domain.split(".")
    base = parts[-2] if len(parts) >= 2 and len(parts[-1]) > 2 else parts[0]
    if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        base = parts[-3]          # dominios tipo ejemplo.com.pe
    names = {f"{base}{s}" for s in SUFFIXES} | {domain, domain.replace(".", "-")}
    return sorted(n for n in names if 3 <= len(n) <= 63)


class CloudBuckets(Module):
    name = "cloud_buckets"
    description = "Buckets públicos de S3, Google Cloud y Azure con nombres derivados del dominio"
    consumes = (Kind.DOMAIN,)
    rate = 10
    hosts = ("s3.amazonaws.com", "storage.googleapis.com")
    active = True

    async def run(self, ctx, node):
        if node.depth > 0:
            return
        checks = []
        for name in candidates(node.value):
            checks.append(self._probe(ctx, node, "Amazon S3", f"https://{name}.s3.amazonaws.com/", "<ListBucketResult"))
            checks.append(self._probe(ctx, node, "Google Cloud Storage", f"https://storage.googleapis.com/{name}/", "<ListBucketResult"))
        await asyncio.gather(*checks)

    async def _probe(self, ctx, node, provider, url, marker):
        try:
            resp = await ctx.http.get(url, ttl=3600, retries=0)
        except ConnectionError:
            return
        if resp.status == 200 and marker in resp.text:
            ctx.graph.note(self.name, f"Bucket público con listado abierto ({provider})", url, "high", node)
            ctx.emit(node, Kind.URL, url, "open_bucket", self.name, pivot=False, provider=provider)
        elif resp.status == 403:
            ctx.graph.note(self.name, f"Bucket existente y privado ({provider})", url, "info", node)
