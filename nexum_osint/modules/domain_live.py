"""Módulos que se conectan directamente al dominio (requieren --active)."""
import asyncio
import socket
import ssl
from datetime import datetime, timezone

from ..core.entities import Kind
from ..core.module import Module


def _fetch_cert(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert()


def _name_of(rdn) -> dict:
    return {k: v for part in rdn for k, v in part}


class LiveCertificate(Module):
    name = "tls_cert"
    description = "Certificado TLS que presenta el servidor: emisor, vigencia y nombres alternativos"
    consumes = (Kind.DOMAIN,)
    active = True

    async def run(self, ctx, node):
        loop = asyncio.get_running_loop()
        try:
            cert = await loop.run_in_executor(None, _fetch_cert, node.value)
        except ssl.SSLCertVerificationError as exc:
            ctx.graph.note(self.name, "Certificado TLS no válido", exc.verify_message, "medium", node)
            return
        except (OSError, ssl.SSLError):
            return   # sin HTTPS en el puerto 443
        subject = _name_of(cert.get("subject", ())).get("commonName")
        issuer = _name_of(cert.get("issuer", ())).get("organizationName")
        expires = cert.get("notAfter")
        node.attrs.update({"tls_subject": subject, "tls_issuer": issuer, "tls_expires": expires})
        if expires:
            left = (datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc)
                    - datetime.now(timezone.utc)).days
            if left < 15:
                ctx.graph.note(self.name, "Certificado por vencer o vencido",
                               f"{left} días restantes ({expires})", "medium", node)
        for kind, name in cert.get("subjectAltName", ()):
            if kind != "DNS":
                continue
            name = name.lstrip("*.").lower()
            if name and name != node.value:
                ctx.emit(node, Kind.DOMAIN, name, "cert_san", self.name)
