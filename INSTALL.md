# Instalación

NEXUM OSINT funciona en **Kali Linux**, **Termux (Android)**, Debian/Ubuntu, Arch, Fedora y macOS.
El instalador detecta el sistema y prepara todo.

## Kali Linux, Debian y Ubuntu

```bash
unzip nexum-osint-v3.3.1.zip
cd nexum-osint
chmod +x install.sh
./install.sh
```

Instala `python3`, `python3-venv` y `python3-pip`, crea un entorno aislado en
`~/.local/share/nexum-osint/venv`, deja el comando en `~/.local/bin` y descarga las listas ampliadas
de sitios. Con `./install.sh --darkweb` instala además Tor, torsocks, proxychains4, OpenVPN y WireGuard.

Si `nexum-osint` no se encuentra, agrega el directorio al `PATH`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

## Termux (Android)

```bash
pkg update -y && pkg install -y unzip
unzip nexum-osint-v3.3.1.zip
cd nexum-osint
chmod +x install.sh
./install.sh
```

El instalador usa `pkg` para Python, Pillow, libxml2, libxslt y OpenSSL, crea el entorno virtual con acceso a
esos paquetes y deja el comando en `$PREFIX/bin`. Después de instalar, abre una sesión nueva o ejecuta
`hash -r`.

La dark web no está disponible en Termux. Para usarla, ejecuta la herramienta en Kali Linux (máquina virtual
o NetHunter) siguiendo `nexum-osint darkweb guide`.

Consejos para pantallas pequeñas: en vertical se muestra un logotipo compacto; gira el teléfono o reduce
el tamaño de letra para ver el logotipo completo y las tablas anchas.

## Diagnóstico y librerías

```bash
nexum-osint doctor            # estado de Python, librerías y herramientas, con los pasos para tu sistema
nexum-osint doctor --fix      # instala las librerías de Python que falten
nexum-osint doctor --darkweb  # además comprueba Tor, torsocks, proxychains, OpenVPN y WireGuard
```

| Librería | Para qué | Nivel |
|---|---|---|
| `httpx[socks]` | Todas las consultas de red | Requerida |
| `rich` | Menú y tablas | Requerida |
| `jinja2` | Reportes HTML | Requerida |
| `reportlab` | Reportes PDF | Recomendada |
| `Pillow` | Metadatos EXIF | Recomendada |
| `phonenumbers` | Datos de teléfonos | Recomendada |
| `socksio` | Conexión por Tor | Dark web |

Si al arrancar falta una librería imprescindible, la herramienta lo indica y ofrece instalarla.

## Primer uso

```bash
nexum-osint                      # menú interactivo
nexum-osint setup                # API keys gratuitas (opcional)
nexum-osint scan ejemplo.com     # primer escaneo
```

Los reportes se guardan en `nexum_reports/`, dentro del directorio desde el que ejecutes el comando.

## Instalación manual

```bash
python3 -m venv ~/nexum-venv
~/nexum-venv/bin/pip install --upgrade pip
~/nexum-venv/bin/pip install .
~/nexum-venv/bin/nexum-osint doctor
```

En Termux agrega `--system-site-packages` al crear el entorno y ejecuta antes `pkg install python-pillow`.

## Verificar la instalación

```bash
python3 -m unittest discover -s tests -t .
```

Debe terminar en `OK` con 156 pruebas. No usan red real.

## Actualizar

Descomprime la versión nueva y vuelve a ejecutar `./install.sh`. Tu configuración y tus keys en
`~/.config/nexum-osint/` se conservan.

## Desinstalar

```bash
./uninstall.sh              # quita el programa y conserva tu configuración
./uninstall.sh --purge      # quita también configuración, keys, caché e historial
```

## Solución de problemas

| Síntoma | Solución |
|---|---|
| `Permission denied` al ejecutar `./install.sh` | `chmod +x install.sh` |
| `apt update` falla con «El tamaño del fichero no es el esperado» o 404 | El espejo de Kali está desincronizado. El instalador continúa solo; para arreglarlo: `sudo apt clean && sudo apt update`, o espera unas horas |
| `externally-managed-environment` al usar pip | Kali protege el Python del sistema: usa `./install.sh`, que crea un entorno aislado |
| `ensurepip is not available` | `sudo apt install python3-venv` |
| `command not found: nexum-osint` | Agrega el directorio del comando al `PATH` (ver arriba) |
| `Se necesita Python 3.11 o superior` | Actualiza el sistema (`sudo apt full-upgrade`) o, en Termux, `pkg upgrade python` |
| Termux: falla la instalación de Pillow | `pkg install python-pillow` y repite `./install.sh` |
| Termux: no se abre el reporte HTML | Instala `pkg install termux-api` o abre el archivo desde el gestor de archivos |
| Falla la descarga de sitios | Sin red se usa la lista incluida; reintenta con `nexum-osint sites --update` |
| Módulo omitido por falta de key | Normal: configura la key con `nexum-osint setup` o ignóralo |
| Módulo omitido por ser activo | Agrega `--active` (solo sobre objetivos propios o autorizados) |
| Dark web: «entorno no verificado» | `nexum-osint darkweb guide` y `nexum-osint darkweb check` |
