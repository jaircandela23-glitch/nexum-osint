"""Entidades y grafo de relaciones.

Todo lo que descubre la herramienta (dominios, IPs, correos, usuarios...)
se guarda como nodo de un grafo. Las relaciones entre nodos son lo que
permite correlacionar resultados en lugar de devolver listas planas.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Kind(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"
    PROFILE = "profile"
    ASN = "asn"
    URL = "url"
    ORG = "org"
    PHONE = "phone"
    NAME = "name"
    DOC = "doc"
    CRYPTO = "crypto"


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9().\s-]{5,17}[0-9]$")
NAME_RE = re.compile(r"^[^\W\d_]{2,}(?:[ '.-]+[^\W\d_]{1,}){1,5}\.?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _b58_ok(addr: str) -> bool:
    import hashlib
    n = 0
    for ch in addr:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    return len(raw) == 25 and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_ok(addr: str) -> bool:
    if addr != addr.lower():
        return False
    hrp, _, data = addr.rpartition("1")
    try:
        vals = [BECH.index(c) for c in data]
    except ValueError:
        return False
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + vals:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk in (1, 0x2bc830a3)


def crypto_kind(value: str) -> str | None:
    if ETH_RE.match(value):
        return "ethereum"
    if BTC_RE.match(value):
        ok = _bech32_ok(value) if value.startswith("bc1") else _b58_ok(value)
        return "bitcoin" if ok else None
    return None


def normalize(kind: Kind, value: str) -> str:
    value = value.strip()
    if kind is Kind.PHONE:
        digits = re.sub(r"[^0-9+]", "", value)
        if not digits.lstrip("+").isdigit() or not (7 <= len(digits.lstrip("+")) <= 15):
            raise ValueError(f"número inválido: {value}")
        return digits if digits.startswith("+") else "+" + digits
    if kind is Kind.DOMAIN:
        return value.lower().rstrip(".").removeprefix("*.")
    if kind is Kind.EMAIL:
        return value.lower()
    if kind is Kind.IP:
        return str(ipaddress.ip_address(value))
    if kind is Kind.USERNAME:
        return value.lstrip("@")
    if kind is Kind.NAME:
        value = re.sub(r"\s+", " ", value)
        if len(value) < 3:
            raise ValueError(f"nombre demasiado corto: {value}")
        return value
    if kind is Kind.CRYPTO:
        if not crypto_kind(value):
            raise ValueError(f"dirección cripto inválida: {value}")
        return value.lower() if value.startswith(("0x", "bc1")) else value
    if kind is Kind.DOC:
        value = re.sub(r"[\s.\-]", "", value).upper()
        if not re.fullmatch(r"[A-Z0-9]{5,20}", value):
            raise ValueError(f"documento inválido: {value}")
        return value
    if kind is Kind.ASN:
        return "AS" + re.sub(r"(?i)^as", "", value)
    return value


_SECOND_LEVEL = {"com", "co", "org", "net", "gob", "gov", "edu", "ac", "mil", "nom", "or", "ne"}


def registrable(domain: str) -> str:
    """Dominio registrable aproximado (sin lista pública de sufijos).

    Cubre casos comunes como .com.pe, .gob.pe o .co.uk; para casos exóticos
    el módulo simplemente consulta un dominio de más, sin consecuencias graves.
    """
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def guess_kind(raw: str) -> Kind:
    """Deduce qué tipo de objetivo es una cadena."""
    raw = raw.strip()
    try:
        ipaddress.ip_address(raw)
        return Kind.IP
    except ValueError:
        pass
    if EMAIL_RE.match(raw):
        return Kind.EMAIL
    if crypto_kind(raw):
        return Kind.CRYPTO
    if re.match(r"^https?://", raw, re.I):
        return Kind.URL
    digits_only = re.sub(r"[^0-9+]", "", raw)
    if PHONE_RE.match(raw) and len(digits_only.lstrip("+")) >= 8 and not DOMAIN_RE.match(raw.lower()):
        return Kind.PHONE
    if DOMAIN_RE.match(raw.lower()):
        return Kind.DOMAIN
    if NAME_RE.match(raw):
        return Kind.NAME
    return Kind.USERNAME


@dataclass
class Node:
    kind: Kind
    value: str
    attrs: dict[str, Any] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)
    depth: int = 0

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.value}"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    relation: str
    source: str


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: set[Edge] = set()
        self.notes: list[dict[str, Any]] = []

    def add(self, kind: Kind, value: str, source: str = "seed", depth: int = 0,
            **attrs: Any) -> tuple[Node, bool]:
        """Agrega un nodo o lo fusiona con el existente. Devuelve (nodo, es_nuevo)."""
        value = normalize(kind, value)
        key = f"{kind.value}:{value}"
        node = self.nodes.get(key)
        created = node is None
        if node is None:
            node = Node(kind, value, depth=depth)
            self.nodes[key] = node
        else:
            node.depth = min(node.depth, depth)
        node.sources.add(source)
        for name, val in attrs.items():
            if val in (None, "", [], {}):
                continue
            node.attrs[name] = val
        return node, created

    def link(self, a: Node, b: Node, relation: str, source: str) -> None:
        if a.key != b.key:
            self.edges.add(Edge(a.key, b.key, relation, source))

    def note(self, source: str, title: str, detail: str = "", severity: str = "info",
             node: Node | None = None) -> None:
        self.notes.append({
            "source": source,
            "title": title,
            "detail": detail,
            "severity": severity,
            "node": node.key if node else None,
        })

    def neighbors(self, key: str) -> list[tuple[str, str]]:
        out = []
        for e in self.edges:
            if e.src == key:
                out.append((e.dst, e.relation))
            elif e.dst == key:
                out.append((e.src, e.relation))
        return out

    def by_kind(self) -> dict[Kind, list[Node]]:
        groups: dict[Kind, list[Node]] = defaultdict(list)
        for node in self.nodes.values():
            groups[node.kind].append(node)
        for items in groups.values():
            items.sort(key=lambda n: n.value)
        return groups

    def correlations(self) -> list[dict[str, Any]]:
        """Busca patrones que conectan entidades entre sí."""
        found: list[dict[str, Any]] = []

        # Infraestructura compartida: una IP a la que apuntan varios dominios.
        by_ip: dict[str, set[str]] = defaultdict(set)
        for e in self.edges:
            if e.relation == "resolves_to" and e.dst.startswith("ip:"):
                by_ip[e.dst].add(e.src)
        for ip, domains in sorted(by_ip.items()):
            if len(domains) >= 2:
                found.append({
                    "type": "shared_infrastructure",
                    "title": f"{len(domains)} dominios comparten {ip.split(':', 1)[1]}",
                    "entities": sorted(domains | {ip}),
                    "confidence": "media",
                })

        # Entidades confirmadas por varias fuentes independientes.
        for node in self.nodes.values():
            external = node.sources - {"seed"}
            if len(external) >= 3 and node.kind is not Kind.URL:
                found.append({
                    "type": "multi_source",
                    "title": f"{node.value} aparece en {len(external)} fuentes",
                    "entities": [node.key],
                    "confidence": "alta",
                    "evidence": sorted(external),
                })

        # Nodos puente que conectan varios tipos de entidad.
        for node in self.nodes.values():
            kinds = {n.split(":", 1)[0] for n, _ in self.neighbors(node.key)}
            if len(kinds) >= 3:
                found.append({
                    "type": "hub",
                    "title": f"{node.value} conecta {len(kinds)} tipos de entidad",
                    "entities": [node.key],
                    "confidence": "media",
                    "evidence": sorted(kinds),
                })

        # Huella digital: muchos perfiles asociados a un mismo alias.
        profiles = [n for n in self.nodes.values() if n.kind is Kind.PROFILE]
        if len(profiles) >= 3:
            found.append({
                "type": "footprint",
                "title": f"Huella digital con {len(profiles)} perfiles detectados",
                "entities": sorted(p.key for p in profiles),
                "confidence": "media",
            })
        found.extend(analytics_correlations(self))
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.key,
                    "kind": n.kind.value,
                    "value": n.value,
                    "depth": n.depth,
                    "sources": sorted(n.sources),
                    "attrs": n.attrs,
                }
                for n in sorted(self.nodes.values(), key=lambda n: n.key)
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "relation": e.relation, "source": e.source}
                for e in sorted(self.edges, key=lambda e: (e.src, e.dst, e.relation))
            ],
            "notes": self.notes,
            "correlations": self.correlations(),
        }


def analytics_correlations(graph: "Graph") -> list[dict]:
    by_id: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes.values():
        for tag in node.attrs.get("analytics", []) or []:
            by_id[tag].add(node.key)
    return [{"type": "shared_analytics", "title": f"{len(keys)} sitios comparten el identificador {tag}",
             "entities": sorted(keys), "confidence": "alta"}
            for tag, keys in sorted(by_id.items()) if len(keys) >= 2]
