<pre align="center">
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ███╗
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║████╗ ████║
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║██╔████╔██║
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║██║╚██╔╝██║
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝
                 ╔═╗╔═╗╦╔╗╔╔╦╗
                 ║ ║╚═╗║║║║ ║
                 ╚═╝╚═╝╩╝╚╝ ╩
</pre>

<p align="center">
Framework de inteligencia de fuentes abiertas<br>
modular · asíncrono · con correlación de entidades en grafo
</p>

<p align="center">
<img alt="Licencia MIT" src="https://img.shields.io/badge/licencia-MIT-1f3a5f?style=flat-square">
<img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-1f3a5f?style=flat-square">
<img alt="Kali Linux" src="https://img.shields.io/badge/plataforma-Kali%20Linux-1f3a5f?style=flat-square">
<img alt="Versión 3.2.0" src="https://img.shields.io/badge/versi%C3%B3n-3.3.1-1f3a5f?style=flat-square">
</p>

| | |
|---|---|
| **Autor** | Jair Muñoz Candela (J@ir.d3v) |
| **Cargo** | Fundador de NEXUM Intelligence Systems |
| **Ubicación** | Lima, Perú |
| **Código** | https://github.com/jaircandela23-glitch/nexum-osint |
| **Contacto** | jair.candela23@hotmail.com |

## Contenido

[Qué es](#qué-es) · [Instalación](#instalación) · [Uso](#uso) · [Módulos](#módulos) ·
[Directorio de herramientas](#directorio-de-herramientas) · [API keys](#api-keys) · [Dark web](#dark-web) ·
[Reportes](#reportes) · [Arquitectura](#arquitectura) · [Desarrollo](#desarrollo) ·
[Uso responsable](#uso-responsable) · [Créditos y licencias](#créditos-y-licencias)

## Qué es

NEXUM OSINT parte de un dato (nombre, teléfono, correo, alias, documento, empresa, dominio, IP,
URL o dirección de criptomoneda), consulta fuentes públicas gratuitas, relaciona lo que encuentra
y lo entrega en un expediente con su nivel de confianza.

- **80 módulos**, 69 de ellos sin ninguna API key. Lista completa en [`docs/MODULES.md`](docs/MODULES.md).
- **Cerca de 1.000 sitios** para verificar alias: 212 incluidos y el resto de WhatsMyName y Sherlock
  con `nexum-osint sites --update`. Cada coincidencia se contrasta contra un alias inexistente.
- **Expediente consolidado** con nombres, correos, ubicaciones, empresas y perfiles, y una línea de tiempo.
- **Directorio de herramientas OSINT** con más de 60 entradas propias y la opción de importar la
  OSINT Tools Library (más de 340 fichas adicionales).
- **Reportes** en HTML con grafo, PDF, Markdown, JSON, CSV y GraphML (Gephi, Maltego).
- **Puntuación de exposición** de 0 a 100 con resumen ejecutivo y **comparación con la investigación anterior**:
  muestra qué entidades y hallazgos son nuevos o ya no aparecen.
- **Vigilancia** periódica de un dato, con aviso de cambios.
- **Instalación guiada** para Termux y Kali Linux, y un diagnóstico (`nexum-osint doctor`) que instala las
  librerías que falten según el sistema donde lo ejecutes.
- **Dark web** con verificación obligatoria del entorno: Kali, Tor y VPN.

Cada línea de un reporte sale de una consulta real a una fuente pública. Lo que no tiene API gratuita
se entrega como enlace de consulta manual, marcado como tal.

### Qué no hace

- No devuelve el titular de un teléfono ni de un DNI o cédula: esos datos no son públicos.
- No consulta los flujos de recuperación de cuentas ni bases de datos filtradas de personas privadas.
- No accede al contenido de sitios `.onion`: solo consulta índices de búsqueda.

Los resultados sobre personas pueden ser homónimos. Confirma cada dato con una segunda fuente.

## Instalación

El instalador detecta el sistema, instala los paquetes que necesita y deja el comando `nexum-osint`.

### Kali Linux, Debian y Ubuntu

```bash
unzip nexum-osint-v3.3.1.zip && cd nexum-osint
chmod +x install.sh && ./install.sh
# con herramientas de dark web (Tor, VPN, proxychains):
./install.sh --darkweb
```

### Termux (Android)

```bash
pkg update -y && pkg install -y unzip
unzip nexum-osint-v3.3.1.zip && cd nexum-osint
chmod +x install.sh && ./install.sh
```

En Termux, Pillow se instala con `pkg` (el instalador lo hace) y el comando queda en `$PREFIX/bin`. La
dark web no está disponible en Termux: usa Kali Linux (máquina virtual o NetHunter).

### Diagnóstico de dependencias

```bash
nexum-osint doctor              # revisa Python, librerías y herramientas, y dice qué hacer en tu sistema
nexum-osint doctor --fix        # instala las librerías de Python que falten
nexum-osint doctor --darkweb    # incluye Tor, proxychains y VPN
```

Si al arrancar falta una librería imprescindible, la herramienta lo avisa, muestra los comandos que
corresponden a tu sistema y ofrece instalarla. Más detalles y solución de problemas en [`INSTALL.md`](INSTALL.md).

## Uso

### Menú interactivo

```bash
nexum-osint
```

El menú muestra el logotipo y el estado de la herramienta, y agrupa las opciones en cuatro secciones: **Investigar** (rápida, por tipo de dato o completa),
**Herramientas** (directorio, dark web, reportes anteriores, vigilancia), **Configuración** y **Información**.
La investigación rápida detecta sola el tipo de dato. Cada búsqueda pregunta la profundidad
(solo el dato, estándar o profunda) y guarda un historial para volver a abrir los reportes.

### Línea de comandos

| Objetivo | Ejemplo | Qué se consulta |
|---|---|---|
| Nombre | `nexum-osint scan "Nombre Apellido"` | Buscadores, redes, registros, Wikidata, ORCID, GitHub |
| Teléfono | `nexum-osint scan +51987654321` | Validez, tipo de línea, operador original, región, reputación y enlaces de consulta |
| Correo | `nexum-osint scan persona@dominio.com` | Filtraciones con detalle y riesgo, GitHub, PGP, Gravatar, reputación |
| Alias | `nexum-osint scan miAlias -t username` | Cerca de 1.000 sitios y APIs de GitHub, GitLab, Reddit, Keybase y otras |
| Documento | `nexum-osint scan 20131312955 -t doc` | Tipo y dígito verificador (RUC, NIT) y consultas oficiales |
| Empresa | `nexum-osint scan "Razón Social" -t org` | GLEIF, registros mercantiles, sanciones y búsquedas dirigidas |
| Dominio | `nexum-osint scan ejemplo.com -d 2` | Subdominios de más de 10 fuentes, DNS, RDAP, historial y reputación |
| IP | `nexum-osint scan 203.0.113.10` | Titular del bloque, ASN, listas de ataque, servicios y reputación |
| URL o imagen | `nexum-osint scan https://sitio.com/foto.jpg --active` | Copia en Wayback, búsqueda inversa y metadatos EXIF |
| Criptomoneda | `nexum-osint scan 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | Saldo y actividad (Bitcoin), exploradores y reportes de estafa |

Muchos objetivos desde un archivo (uno por línea, `#` para comentarios):

```bash
nexum-osint scan -i objetivos.txt -f html,md
```

Varios datos de la misma persona o empresa en un solo expediente:

```bash
nexum-osint scan "Nombre Apellido" +51987654321 persona@dominio.com miAlias ejemplo.com -f html,pdf,md
```

Opciones principales: `-d` profundidad · `-m` solo estos módulos · `-x` excluir módulos ·
`-f` formatos (`html,json,csv,pdf,md,graphml`) · `-o` carpeta de salida · `--active` módulos activos ·
`--permute` alias probables a partir de un nombre · `--darkweb` búsqueda en dark web.

Vigilar un dato cada cierto tiempo y ver qué cambia:

```bash
nexum-osint watch ejemplo.com --cada 60 -f html,md
```

Otros comandos:

```bash
nexum-osint tools              # directorio de herramientas
nexum-osint tools search telegram
nexum-osint tools import ~/Descargas/OSINT-Tools-Library.zip
nexum-osint doctor             # diagnóstico e instalación de librerías
nexum-osint setup              # asistente de API keys
nexum-osint apis               # APIs gratuitas y su estado
nexum-osint modules            # módulos disponibles
nexum-osint sites --update     # descarga WhatsMyName y Sherlock
nexum-osint about              # autor, licencia y agradecimientos
```

## Módulos

Ocho módulos son **activos**: contactan directamente al objetivo y solo se ejecutan con `--active`.
Úsalos únicamente sobre sistemas propios o con autorización escrita.

| Módulo activo | Qué hace |
|---|---|
| `tls_cert` | Certificado del servidor: emisor, vencimiento y nombres alternativos |
| `subdomain_brute` | Más de 200 subdominios comunes por DNS-over-HTTPS, con detección de comodín |
| `takeover` | CNAME hacia servicios sin reclamar (GitHub Pages, S3, Heroku, Azure...) |
| `cloud_buckets` | Buckets de S3 y Google Cloud con nombres derivados del dominio |
| `web_fingerprint` | Tecnologías, cabeceras de seguridad, contactos y analítica del sitio |
| `exposed_files` | Archivos sensibles accesibles por error: `.git`, `.env`, copias y volcados |
| `image_exif` | Metadatos EXIF de una imagen |
| `lookalikes` | Dominios parecidos ya registrados: errores de tipeo, homoglifos y otros TLD |

### Instagram

El módulo `instagram` (pasivo, con key) lee solo lo que el titular decidió publicar: nombre, biografía, enlace y contacto de empresa.
No consulta los flujos de recuperación de cuenta. Requiere la cookie `sessionid` de una **cuenta secundaria**:
inicia sesión en instagram.com, copia `sessionid` desde las herramientas del navegador y guárdala con
`nexum-osint setup`. Instagram puede limitar sesiones con consultas automatizadas y su uso va contra los
términos del servicio, por eso no debes usar tu cuenta principal.

## Extracción de datos

Además de investigar un objetivo, NEXUM saca datos de material que ya tienes: documentos, carpetas,
correos guardados, páginas web o texto copiado.

```bash
nexum-osint extract informe.docx                  # un archivo
nexum-osint extract ./caso/ -o hallazgos.csv      # una carpeta completa, guardando el resultado
nexum-osint extract https://ejemplo.com --pages 8 # una página y hasta 7 más del mismo sitio
cat notas.txt | nexum-osint extract - --scan      # texto por la entrada estándar, y se investiga lo hallado
```

Detecta correos, teléfonos (con indicativo y móviles peruanos de 9 dígitos), cuentas de X, Instagram,
Facebook, LinkedIn, TikTok, GitHub, Telegram y YouTube, enlaces, dominios, IP, direcciones de Bitcoin y
Ethereum, RUC, hashes y CVE. Las criptomonedas se validan por su suma de verificación y los RUC por su
dígito verificador; los correos con terminaciones inexistentes y las IP de loopback se descartan. En una
página web solo se listan los enlaces que salen de ella, no su navegación interna ni sus recursos.

| Formato | Metadatos |
|---|---|
| Word, Excel, PowerPoint | autor, última persona que lo modificó, empresa, aplicación, fechas; también enlaces ocultos |
| PDF | autor, productor, fechas (texto completo con `pypdf` instalado) |
| Imágenes | cámara, software, fecha y coordenadas GPS con enlace al mapa |
| Correo `.eml` | remitente, ruta de retorno, IP de origen y cada salto `Received` |
| HTML y texto | título, autor, generador, redes declaradas |

Con `--scan` los datos extraídos pasan a `scan`. Descargar una página es una consulta directa al sitio:
úsala solo con autorización.

## Casos de investigación

Cada investigación puede guardarse en un caso (una base SQLite en tu carpeta de datos, con permisos
solo para tu usuario) para retomarla y ver qué cambió.

```bash
nexum-osint scan ejemplo.com --caso "Cliente Lima"     # guarda esta investigación en el caso
nexum-osint casos                                      # lista los casos
nexum-osint casos "Cliente Lima" --comparar            # qué apareció y qué dejó de aparecer
nexum-osint casos "Cliente Lima" --exportar caso.json  # el caso completo, para otras herramientas
```

## Dorks y búsquedas avanzadas

El módulo `dorks` genera, para dominios, correos y alias, las búsquedas avanzadas más útiles (documentos
expuestos, directorios abiertos, copias y registros, subdominios indexados, menciones y código público) como
enlaces listos para abrir en Google, Bing y DuckDuckGo. El módulo `dork_results` ejecuta las más relevantes en
DuckDuckGo con pausas aleatorias y lista los resultados; si el buscador impone un límite, lo avisa y los
enlaces de `dorks` siguen disponibles.

## Bloqueos y rotación

Las comprobaciones de alias usan cabeceras de navegador que cambian en cada petición. Si un sitio responde
403 o 429 varias veces seguidas, `--rotar-tor` (con `--proxy socks5h://127.0.0.1:9050`) pide a Tor un
circuito nuevo por el puerto de control (9051, configurable con `tor_control` y `tor_control_password`, o con la
variable `NEXUM_TOR_CONTROL_PASSWORD`) y reintenta. Cada perfil de alias lleva su nivel de confianza:
**confirmado** si el sitio distingue un alias real de uno inexistente o su página nombra el alias, y
**probable** si solo respondió distinto a un alias inventado.

## Directorio de herramientas

`nexum-osint tools` abre un catálogo por categoría con enlace, uso, costo y si exige cuenta.
Trae una selección propia de más de 60 herramientas gratuitas. Para ampliarlo con la
[OSINT Tools Library](https://osintnewsletter.com/) (OSINT Newsletter), descarga tu copia e impórtala:

```bash
nexum-osint tools import OSINT-Tools-Library-GitBook.zip
```

La importación se guarda solo en tu equipo (`~/.config/nexum-osint/tools_library.json`); el contenido
de esa biblioteca no se redistribuye con este proyecto.

## API keys

La mayoría de los módulos no necesita ninguna. Para ampliar la cobertura hay 14 servicios con plan
gratuito. Las keys son personales y por eso no vienen incluidas.

```bash
nexum-osint setup
```

El asistente muestra qué habilita cada servicio, su plan gratuito y el enlace de registro. Las keys se
guardan en `~/.config/nexum-osint/config.toml` con permisos 600. También sirven variables de entorno
(`NEXUM_VIRUSTOTAL=...`). Un módulo sin su key se omite y el escaneo continúa.

## Dark web

Consulta índices de servicios `.onion` (Ahmia por defecto) a través de Tor para detectar menciones de un
dominio, correo, alias, nombre o teléfono. Solo se ejecuta si se cumple todo esto:

1. Linux y distribución Kali.
2. Servicio Tor activo.
3. Tráfico confirmado por Tor con `check.torproject.org`.
4. Interfaz de VPN activa (`tun`, `wg`, `ppp`...).
5. Advertencia aceptada (`--acepto-riesgos` o escribiendo ACEPTO).

Si algo falla, no continúa y muestra el comando para corregirlo.

```bash
nexum-osint darkweb guide     # instalación y configuración del entorno
nexum-osint darkweb check     # verificación
nexum-osint darkweb search "empresa.com" --acepto-riesgos
```

Usa una máquina virtual aislada con snapshot, sin carpetas compartidas. No abras enlaces `.onion` fuera
de Tor Browser ni descargues archivos.

## Reportes

Cada investigación genera, a elección: **HTML** (expediente, hallazgos, correlaciones, línea de tiempo,
grafo interactivo), **PDF**, **Markdown**, **JSON**, **CSV** y **GraphML**.

Cada reporte abre con un **resumen ejecutivo** y una **puntuación de exposición** (Bajo, Moderado, Alto o
Crítico) que pondera la gravedad de los hallazgos. Si ya investigaste los mismos objetivos, añade una sección
de **cambios** frente a la última vez.

El **expediente consolidado** reúne nombres, correos, teléfonos, alias, ubicaciones, organizaciones y
perfiles de todas las fuentes. La confianza es *alta* si dos o más fuentes independientes coinciden, *media*
si viene de una y *baja* si es una deducción.

## Arquitectura

```
nexum_osint/
  core/       motor asíncrono, grafo de entidades, HTTP con caché y límite de tasa
  modules/    una fuente por archivo; se descubren solos
  analysis/   expediente consolidado y línea de tiempo
  reporting/  HTML, PDF, Markdown, JSON, CSV, GraphML
  darkweb/    verificación de entorno, guía e índices
  data/       sitios, APIs, catálogo de herramientas
```

Un dato produce entidades; cada entidad se consulta con los módulos que la aceptan, hasta la profundidad
indicada. Los dominios de proveedores de correo y los servidores ajenos al objetivo no se expanden.

## Desarrollo

```bash
python3 -m unittest discover -s tests -t .
```

206 pruebas que no usan red real. Para añadir una fuente copia `plugin_template.py` a
`~/.config/nexum-osint/plugins/`; el helper `nexum_osint.core.links.manual(...)` agrega enlaces de consulta
manual a los reportes. Guía de contribución en [`CONTRIBUTING.md`](CONTRIBUTING.md) y política de seguridad
en [`SECURITY.md`](SECURITY.md).

## Uso responsable

Investigación autorizada, seguridad defensiva, periodismo y verificación de exposición propia o de
clientes. Consulta solo fuentes públicas. El tratamiento de datos personales está regulado (en Perú, la
Ley 29733 de Protección de Datos Personales): define una finalidad legítima y no uses los resultados para
acosar, estafar ni dañar a nadie.

## Créditos y licencias

**NEXUM OSINT** es obra de **Jair Muñoz Candela**, fundador de **NEXUM Intelligence Systems**, y se
distribuye bajo licencia MIT. La licencia exige conservar el aviso de autoría en toda copia o derivado.

| Proyecto | Autoría | Licencia | Aporte |
|---|---|---|---|
| SpiderFoot | Steve Micallef y colaboradores | MIT | Referencia de fuentes y técnicas pasivas |
| Toutatis | megadose | GPL-3.0 | Referencia del perfil público de Instagram; sin código reutilizado |
| WhatsMyName | WebBreacher y colaboradores | CC BY-SA 4.0 | Lista de sitios, descargada por el usuario |
| Sherlock | Sherlock Project | MIT | Lista de sitios, descargada por el usuario |
| XposedOrNot | XposedOrNot y HackUnderway | MIT | API y referencia de filtraciones de correo |
| OSINT Tools Library | OSINT Newsletter | sin licencia declarada | Directorio opcional importado por el usuario |
| libphonenumber | Google | Apache-2.0 | Validación de numeración telefónica |

Detalle en [`CREDITS.md`](CREDITS.md) y [`NOTICE`](NOTICE).
