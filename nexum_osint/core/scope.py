"""Alcance de un escaneo: qué dominios pertenecen al objetivo y cuáles son infraestructura ajena.

Sin esto, un correo @hotmail.com o un MX de un proveedor se tratarían como objetivos
propios y el escaneo se expandiría a miles de dominios que no tienen relación con la persona.
"""
from __future__ import annotations

FREEMAIL = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com", "outlook.es",
    "live.com", "msn.com", "yahoo.com", "yahoo.es", "ymail.com", "icloud.com", "me.com",
    "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com",
    "yandex.com", "yandex.ru", "tutanota.com", "fastmail.com",
})


def root_of(host: str) -> str:
    host = host.lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def is_freemail(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in FREEMAIL)


def in_scope(host: str, roots: set[str]) -> bool:
    host = host.lower()
    return any(host == r or host.endswith("." + r) for r in roots)
