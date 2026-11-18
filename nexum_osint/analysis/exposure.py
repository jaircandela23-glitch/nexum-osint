import math

WEIGHTS = {"high": 14, "medium": 5, "warn": 3, "low": 0.5, "info": 0}
LEVELS = ((20, "Bajo"), (45, "Moderado"), (70, "Alto"), (101, "Crítico"))


def score(graph) -> dict:
    """Puntaje 0-100 de exposición a partir de la gravedad de los hallazgos.

    La suma ponderada se comprime con una curva de saturación: los primeros hallazgos
    pesan mucho y los siguientes cada vez menos, para que 40 avisos menores no igualen
    a una filtración con contraseñas.
    """
    raw = sum(WEIGHTS.get(n["severity"], 0) for n in graph.notes)
    value = round(100 * (1 - math.exp(-raw / 45)))
    level = next(label for limit, label in LEVELS if value < limit)
    top = sorted((n for n in graph.notes if n["severity"] in ("high", "medium")),
                 key=lambda n: (-WEIGHTS[n["severity"]], n["title"]))[:5]
    return {"puntaje": value, "nivel": level, "factores": [n["title"] for n in top],
            "criticos": sum(1 for n in graph.notes if n["severity"] == "high"),
            "medios": sum(1 for n in graph.notes if n["severity"] == "medium")}
