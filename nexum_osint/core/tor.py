"""Renovación de circuito de Tor (señal NEWNYM) por el puerto de control, sin dependencias externas."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

MIN_INTERVAL = 10.0   # Tor limita las señales NEWNYM; pedir más seguido no sirve de nada


class TorControl:
    def __init__(self, host: str = "127.0.0.1", port: int = 9051, password: str | None = None) -> None:
        self.host, self.port, self.password = host, port, password
        self._last = 0.0

    @classmethod
    def from_setting(cls, setting: str, password: str | None = None) -> "TorControl":
        """Acepta «puerto» o «host:puerto»."""
        host, _, port = setting.rpartition(":")
        return cls(host or "127.0.0.1", int(port), password)

    async def _command(self, reader, writer, line: str) -> list[str]:
        writer.write(line.encode() + b"\r\n")
        await writer.drain()
        lines = []
        while True:
            raw = (await asyncio.wait_for(reader.readline(), 5)).decode(errors="replace").rstrip("\r\n")
            lines.append(raw)
            if len(raw) < 4 or raw[3] == " ":   # «250 OK»: la última línea de una respuesta lleva espacio
                return lines

    async def _authenticate(self, reader, writer) -> None:
        info = await self._command(reader, writer, "PROTOCOLINFO 1")
        methods = next((ln for ln in info if "AUTH METHODS=" in ln), "")
        if self.password is not None:
            escaped = self.password.replace("\\", "\\\\").replace('"', '\\"')
            reply = await self._command(reader, writer, f'AUTHENTICATE "{escaped}"')
        elif "COOKIE" in methods and 'COOKIEFILE="' in methods:
            cookie = Path(methods.split('COOKIEFILE="', 1)[1].split('"', 1)[0]).read_bytes().hex()
            reply = await self._command(reader, writer, f"AUTHENTICATE {cookie}")
        else:
            reply = await self._command(reader, writer, "AUTHENTICATE")
        if not reply[-1].startswith("250"):
            raise PermissionError(reply[-1])

    async def renew(self) -> bool:
        """Pide un circuito nuevo. Devuelve False si Tor no responde o rechaza la autenticación."""
        wait = MIN_INTERVAL - (time.monotonic() - self._last)
        if self._last and wait > 0:
            await asyncio.sleep(wait)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), 5)
        except (OSError, asyncio.TimeoutError):
            return False
        try:
            await self._authenticate(reader, writer)
            reply = await self._command(reader, writer, "SIGNAL NEWNYM")
            await self._command(reader, writer, "QUIT")
            self._last = time.monotonic()
            return reply[-1].startswith("250")
        except (OSError, asyncio.TimeoutError, PermissionError, ValueError):
            return False
        finally:
            writer.close()
