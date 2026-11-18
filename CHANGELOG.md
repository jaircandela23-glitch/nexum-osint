# Changelog

## 3.4.0

- Comando `extract` y sección **Extracción** del menú: datos y metadatos de archivos (Office, PDF, imágenes,
  correo `.eml`, HTML, texto), carpetas, páginas web con rastreo opcional y texto pegado.
- Gestor de casos en SQLite: `scan --caso`, `casos` para listar, comparar y exportar.
- Módulos `dorks` (enlaces de búsquedas avanzadas) y `dork_results` (resultados en vivo desde DuckDuckGo).
- Nivel de confianza (confirmado o probable) en cada perfil de alias.
- `--rotar-tor`: renovación automática del circuito de Tor tras bloqueos, sin dependencias nuevas.
- Cabeceras de navegador rotativas en las comprobaciones de alias.
- 206 pruebas automatizadas.

## 3.3.1

- Instalador: un fallo de `apt update` (por ejemplo un espejo de Kali desincronizado) ya no detiene la
  instalación. Si Python 3.11+ con venv ya está instalado, se omiten los paquetes del sistema y la
  instalación es mucho más rápida. Los fallos de apt, pacman o dnf se avisan y se continúa.
- Las herramientas de dark web (`--darkweb`) se instalan aparte y, si fallan, muestran el comando manual.

## 3.3.0

- Logotipo grande de la herramienta con degradado cian a violeta, y versión compacta para pantallas
  estrechas. La paleta se aplica al menú, las tablas, los paneles y el reporte HTML.
- Instalador para Termux, Kali Linux, Debian/Ubuntu, Arch, Fedora y macOS: detecta el sistema, instala los
  paquetes necesarios y deja el comando en la ruta correcta. `--darkweb` instala Tor y VPN en Kali/Debian.
- `nexum-osint doctor`: diagnóstico del entorno, guía por sistema e instalación de librerías con `--fix`.
  Al arrancar, comprueba lo imprescindible y ofrece instalarlo.
- Puntuación de exposición de 0 a 100 y resumen ejecutivo en consola, HTML, PDF, Markdown y JSON.
- Comparación con la investigación anterior de los mismos objetivos: entidades y hallazgos nuevos o resueltos.
- `nexum-osint watch`: repite una investigación cada cierto tiempo (también desde el menú).
- Carga de objetivos desde archivo (`scan -i`).
- `email_provider`: proveedor del buzón deducido de los servidores MX.
- En Termux, los reportes y enlaces se abren con `termux-open`.
- 156 pruebas, incluidas las de instalación en modo simulado para Termux y Debian/Kali.

## 3.2.0

De 66 a 77 módulos, directorio de herramientas y menú rediseñado.

- Menú principal rediseñado: cabecera con estado, secciones, investigación rápida con detección
  de tipo, selección de profundidad e historial de reportes anteriores.
- Directorio de herramientas OSINT (`nexum-osint tools`): 67 herramientas propias en 13 categorías,
  búsqueda, detalle y apertura del enlace. Importa la OSINT Tools Library desde la copia del usuario.
- Filtraciones de correo con detalle (`xposedornot`): fecha, registros, datos expuestos, riesgo y
  contraseñas; las filtraciones se suman a la línea de tiempo.
- Teléfono: validación, tipo de línea, operador original, región y zonas horarias (`phone_libphone`).
- Reputación: listas públicas de ataques por IP (`ip_blocklists`) y de phishing por dominio (`domain_blocklists`).
- Red: titular y contactos del bloque de la IP (`ip_rdap`), PeeringDB para sistemas autónomos.
- Subdominios y archivos: Anubis, RapidDNS y Common Crawl; dominios del mismo nombre (`domainsdb`).
- Correo: dominios desechables (`email_disposable`).
- Activo: archivos sensibles expuestos (`exposed_files`).
- Instagram: se eliminó la consulta de pistas de recuperación ofuscadas. El módulo lee solo los datos
  que el titular publica.
- Presentación: datos del autor, créditos y licencias de terceros reorganizados; `docs/MODULES.md`
  generado con `nexum-osint modules --markdown`.

## 3.1.2

Correcciones a partir de una prueba con red real.

- Alcance del escaneo: los dominios de proveedores de correo (hotmail, gmail...) ya no se
  expanden. Antes, un correo @hotmail.com generaba más de 7.000 dominios irrelevantes.
- Los servidores ajenos al objetivo (NS, MX de terceros) solo se resuelven por DNS; los módulos
  activos y de pivoteo masivo se ejecutan únicamente sobre el dominio del objetivo y sus subdominios.
- `crtsh`: si crt.sh no responde, se usa Cert Spotter como fuente alterna.
- `web_fingerprint`: un fallo de conexión al pedir `robots.txt` ya no se reporta como error.
- El resumen de consola muestra país, tipo de línea y bloque original de los teléfonos.

## 3.1.1

- Menú principal rediseñado: logotipo NEXUM OSINT y opciones agrupadas por sección.
- El PDF se omite con un aviso si falta `reportlab`, en vez de abortar el escaneo.
- Pruebas: la de confirmación de advertencia y la de integridad de sitios ya no dependen del terminal ni de la lista descargada por el usuario.

## 3.1.0

De 52 a 66 módulos. Las fuentes nuevas se escribieron tomando como referencia los
servicios y técnicas de SpiderFoot y Toutatis (ver `CREDITS.md`).

- Instagram: perfil público y pistas de recuperación ofuscadas (`instagram`, requiere `sessionid`).
- Dominio, pasivo: claves PGP (`pgp_keys`), DNS pasivo de Robtex (`robtex_domain`),
  listas negras (`dnsbl_domain`) y metadatos de documentos publicados, leídos desde
  copias de Wayback Machine (`doc_metadata`).
- Dominio, activo (`--active`): certificado TLS en vivo (`tls_cert`), diccionario de
  subdominios con detección de comodín (`subdomain_brute`), dominios parecidos (`lookalikes`),
  subdominios secuestrables (`takeover`) y buckets abiertos de S3 y Google Cloud (`cloud_buckets`).
- IP: listas negras de spam y abuso (`dnsbl_ip`), nombres de host de Robtex (`robtex_ip`)
  y ediciones anónimas en Wikipedia (`wiki_ip`).
- Alias: cuenta de Wikipedia (`wiki_user`).
- Núcleo: el cliente HTTP admite peticiones POST con cuerpo (sin caché).
- Créditos: comando `about` con agradecimientos y datos de contacto opcionales.
- Documentación: `INSTALL.md`, `CREDITS.md` y `uninstall.sh`.
- 95 pruebas automatizadas.

## 3.0.0

- Alias: `sites --update` incorpora WhatsMyName y Sherlock (casi 1.000 sitios) con
  detección por código, texto, mensaje de error y redirección.
- Expediente consolidado con nivel de confianza y línea de tiempo en todos los reportes.
- Nuevos objetivos: empresa (`-t org`, GLEIF) y direcciones de criptomoneda
  (Bitcoin con saldo y actividad; Bitcoin y Ethereum con exploradores y reportes de estafa).
- Huella web activa: tecnologías, cabeceras de seguridad, correos, teléfonos y redes
  publicados, identificadores de analítica (con correlación entre sitios), robots.txt y security.txt.
- Metadatos EXIF de imágenes, incluidas coordenadas GPS.
- Red: titular y prefijos del ASN, contacto de abuso de la IP, otros dominios en la misma IP.
- Exportación a Markdown y GraphML.
- Menú ampliado y 77 pruebas automatizadas.

## 2.0.0

Ampliación mayor: de 10 a 43 módulos y de 42 a 212 sitios.

- Nuevos tipos de objetivo: nombre completo, documento (`-t doc`) y URL/imagen.
- Menú interactivo (`nexum-osint`) y comandos `setup`, `apis`, `about`.
- Correo: filtraciones públicas (XposedOrNot, LeakCheck), MX y dominios
  desechables, cuentas y commits de GitHub, Hunter.io e IPQualityScore (key gratuita).
- Alias: GitHub (con correos expuestos en commits), GitLab, Reddit, Keybase,
  Hacker News, Dev.to, Docker Hub, Lichess, Chess.com, Bluesky y npm.
- Teléfono: enlaces de consulta manual, Veriphone e IPQualityScore (key gratuita).
- Nombres: búsquedas dirigidas, registros oficiales y mercantiles, Wikidata,
  ORCID, GitHub y alias probables (`--permute`).
- Documentos: validación de RUC y NIT, enlaces a consultas oficiales.
- Dominios: URLScan, AlienVault OTX, HackerTarget, VirusTotal, SecurityTrails, Hunter.io.
- IP: relé Tor, OTX, AbuseIPDB, ipinfo, GreyNoise, VirusTotal.
- Dark web: guía de entorno, verificación obligatoria (Kali, Tor, VPN) y
  búsqueda en índices .onion.
- Reportes rediseñados: perfiles agrupados, consultas manuales, menciones de dark web.
- 60 pruebas automatizadas.

## 1.0.0

Primera versión pública.
