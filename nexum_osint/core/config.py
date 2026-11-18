"""Configuración: archivo TOML opcional y variables de entorno para las API keys."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "nexum-osint"


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "nexum-osint"


@dataclass
class Config:
    keys: dict[str, str] = field(default_factory=dict)
    timeout: float = 20.0
    user_agent: str = "NEXUM-OSINT/3.1 (+https://github.com/jaircandela23-glitch/nexum-osint)"
    proxy: str | None = None
    cache_ttl: float = 6 * 3600
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    tor_control: str = "127.0.0.1:9051"
    tor_control_password: str | None = None

    def key(self, name: str) -> str | None:
        """Busca una API key en el entorno (NEXUM_<NOMBRE>) y luego en el TOML."""
        env = os.environ.get(f"NEXUM_{name.upper()}")
        return env or self.keys.get(name.lower())

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = path or config_dir() / "config.toml"
        cfg = cls()
        cfg.tor_control_password = os.environ.get("NEXUM_TOR_CONTROL_PASSWORD") or None
        if path.exists():
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            cfg.keys = {k.lower(): str(v) for k, v in data.get("keys", {}).items()}
            net = data.get("network", {})
            cfg.timeout = float(net.get("timeout", cfg.timeout))
            cfg.proxy = net.get("proxy") or None
            cfg.cache_ttl = float(net.get("cache_ttl", cfg.cache_ttl))
            cfg.tor_proxy = net.get("tor_proxy", cfg.tor_proxy)
            cfg.tor_control = str(net.get("tor_control", cfg.tor_control))
            cfg.tor_control_password = net.get("tor_control_password") or None
        return cfg
