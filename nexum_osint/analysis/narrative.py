from ..core.entities import Kind

NOUNS = {Kind.EMAIL: "correo", Kind.PHONE: "teléfono", Kind.USERNAME: "alias", Kind.NAME: "nombre", Kind.DOMAIN: "dominio",
         Kind.IP: "IP", Kind.PROFILE: "perfil", Kind.ORG: "organización", Kind.CRYPTO: "dirección cripto"}


def plural(word: str, n: int) -> str:
    if n == 1:
        return word
    return word + ("es" if word.endswith(("l", "r", "n")) else "s") if word != "IP" else "IP"


def resumen(graph, targets: list[str], expo: dict) -> str:
    groups = graph.by_kind()
    shown = [f"{len(v)} {plural(NOUNS[k], len(v))}" for k, v in groups.items()
             if k in NOUNS and any(not n.attrs.get("manual") for n in v)]
    total = sum(1 for n in graph.nodes.values() if not n.attrs.get("manual"))
    parts = [f"Se investigó {', '.join(targets[:3])}{' y otros objetivos' if len(targets) > 3 else ''} y se {'reunió' if total == 1 else 'reunieron'} "
             f"{total} {'entidad' if total == 1 else 'entidades'}" + (f" ({', '.join(shown[:6])})." if shown else ".")]
    parts.append(f"El nivel de exposición es {expo['nivel'].lower()} ({expo['puntaje']}/100), con "
                 f"{expo['criticos']} hallazgo(s) crítico(s) y {expo['medios']} de gravedad media.")
    if expo["factores"]:
        parts.append("Lo más relevante: " + "; ".join(expo["factores"][:3]) + ".")
    manual = sum(1 for n in graph.nodes.values() if n.attrs.get("manual"))
    if manual:
        parts.append(f"Hay {manual} consultas manuales preparadas para fuentes sin acceso automático.")
    return " ".join(parts)
