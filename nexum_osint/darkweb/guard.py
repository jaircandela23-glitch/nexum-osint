"""Verificaciones obligatorias antes de usar las funciones de dark web."""
from __future__ import annotations

import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

VPN_PREFIXES = ("tun", "tap", "wg", "ppp", "nordlynx", "proton", "mullvad", "utun", "ipsec")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    blocking: bool = True


class Probes:
    """Acceso al sistema aislado en una clase para poder probarlo sin tocar la máquina."""

    def platform(self) -> str:
        return sys.platform

    def os_release(self) -> str:
        try:
            return Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def tor_port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False

    def interfaces(self) -> list[str]:
        try:
            return [p.name for p in Path("/sys/class/net").iterdir()]
        except OSError:
            return []


def is_kali(os_release_text: str) -> bool:
    fields = dict(line.split("=", 1) for line in os_release_text.splitlines() if "=" in line)
    ident = fields.get("ID", "").strip('"').lower()
    like = fields.get("ID_LIKE", "").strip('"').lower()
    return ident == "kali" or "kali" in like


def vpn_interfaces(names: list[str]) -> list[str]:
    return [n for n in names if n.lower().startswith(VPN_PREFIXES)]


def static_checks(tor_proxy: str, *, force_env: bool = False, no_vpn: bool = False,
                  probes: Probes | None = None) -> list[Check]:
    p = probes or Probes()
    checks: list[Check] = []

    linux = p.platform().startswith("linux")
    checks.append(Check("Sistema operativo Linux", linux,
                        "Linux detectado" if linux else f"Sistema no compatible: {p.platform()}",
                        "Esta función solo se ejecuta en Kali Linux."))

    kali = is_kali(p.os_release())
    checks.append(Check("Kali Linux", kali or force_env,
                        "Kali Linux detectado" if kali else (
                            "Distribución distinta de Kali (omitido por --force-env, sin soporte)" if force_env
                            else "No se detectó Kali Linux"),
                        "Ejecuta la herramienta desde Kali Linux (máquina virtual recomendada)."))

    parts = urlsplit(tor_proxy)
    host, port = parts.hostname or "127.0.0.1", parts.port or 9050
    tor_up = p.tor_port_open(host, port)
    checks.append(Check("Servicio Tor activo", tor_up,
                        f"Tor escuchando en {host}:{port}" if tor_up else f"Nada escucha en {host}:{port}",
                        "sudo apt install -y tor && sudo systemctl enable --now tor"))

    vpns = vpn_interfaces(p.interfaces())
    checks.append(Check("VPN activa", bool(vpns) or no_vpn,
                        f"Interfaz de VPN: {', '.join(vpns)}" if vpns else (
                            "Sin VPN (omitido por --sin-vpn bajo tu responsabilidad)" if no_vpn
                            else "No se detectó ninguna interfaz de VPN (tun/wg/ppp)"),
                        "sudo openvpn --config tu.ovpn --daemon   |   sudo wg-quick up wg0"))
    return checks


async def tor_check(tor_http) -> Check:
    """Confirma con el servicio oficial del Proyecto Tor que el tráfico sale por Tor."""
    try:
        r = await tor_http.get("https://check.torproject.org/api/ip", ttl=0, retries=1)
        data = r.json() if r.ok else {}
    except Exception as exc:
        return Check("Tráfico saliendo por Tor", False, f"No se pudo verificar: {exc}",
                     "Revisa que Tor esté activo y que `httpx[socks]` esté instalado.")
    ok = bool(data.get("IsTor"))
    return Check("Tráfico saliendo por Tor", ok,
                 f"Confirmado por check.torproject.org (IP de salida {data.get('IP', '?')})" if ok
                 else "El tráfico NO sale por Tor", "Verifica la configuración del proxy en config.toml.")


def acknowledged(flag: bool, ask: Callable[[str], str] = input) -> bool:
    if flag:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        return ask("\nEscribe ACEPTO para confirmar que leíste y entiendes la advertencia: ").strip().upper() == "ACEPTO"
    except EOFError:
        return False
