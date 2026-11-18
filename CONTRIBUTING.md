# Contribuir a NEXUM OSINT

Gracias por el interés en mejorar la herramienta.

## Antes de abrir un issue

- Incluye el comando exacto que ejecutaste y la salida completa (`--no-cache`
  ayuda a descartar que sea un problema de caché).
- Si es un módulo el que falla, indica cuál (`nexum-osint modules` los lista).

## Agregar una fuente nueva

Cada fuente es un módulo independiente. No hace falta tocar el núcleo:

1. Copia `plugin_template.py` dentro de `nexum_osint/modules/`.
2. Dale un `name` único, define qué tipo de entidad consume (`consumes`) y
   qué host(s) usa para el límite de tasa (`hosts`).
3. Implementa `run(self, ctx, node)`: usa `ctx.http.get(...)` para consultar,
   `node.attrs[...]` para guardar datos sobre la entidad, `ctx.emit(...)`
   para descubrir y pivotar a nuevas entidades, y `ctx.graph.note(...)` para
   dejar un hallazgo visible en los reportes.
4. Agrega una prueba en `tests/test_v2.py` usando `tests/fakes.py` para
   simular la respuesta de la API (el proyecto no corre pruebas contra
   servicios reales).

## Estilo

- Python 3.11+, tipado donde aporte claridad, sin dependencias nuevas salvo
  que el módulo las necesite de verdad.
- Si una fuente requiere API key, decláralo con `needs_key` (obligatoria) u
  `optional_key` (amplía cuota) — nunca hardcodees una key.
- Todo módulo debe degradarse con elegancia: si la fuente falla o no hay
  key, el resto del escaneo debe seguir funcionando.

## Pruebas

```bash
python3 -m unittest discover -s tests -t .
```

Deben pasar sin conexión a internet.
