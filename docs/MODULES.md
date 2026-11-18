# Módulos de NEXUM OSINT v3.4.0

80 módulos. Los activos solo se ejecutan con `--active`; los de dark web, con `--darkweb`.

## Entrada: asn

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `peeringdb` | pasivo | sin key | Organización, sitio web y políticas de interconexión del sistema autónomo (PeeringDB, sin key) |
| `ripestat_asn` | pasivo | sin key | Titular y prefijos anunciados de un sistema autónomo (RIPEstat, sin key) |

## Entrada: crypto

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `btc_address` | pasivo | sin key | Saldo, movimientos y actividad de una dirección Bitcoin (mempool.space, sin key) |
| `crypto_links` | pasivo | sin key | Exploradores de bloques, reportes de estafas y búsquedas de la dirección |

## Entrada: doc

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `id_links` | pasivo | sin key | Enlaces a consultas oficiales públicas según el tipo de documento |
| `id_validate` | pasivo | sin key | Detecta el tipo de documento por formato y valida dígitos verificadores (RUC, NIT) |

## Entrada: domain

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `anubis` | pasivo | sin key | Subdominios del dominio según la base abierta de Anubis (sin key) |
| `cloud_buckets` | activo | sin key | Buckets públicos de S3, Google Cloud y Azure con nombres derivados del dominio |
| `commoncrawl` | pasivo | sin key | URLs y archivos del dominio rastreados por Common Crawl (sin key) |
| `crtsh` | pasivo | sin key | Subdominios y certificados emitidos (Certificate Transparency) |
| `dns` | pasivo | sin key | Registros A/AAAA/MX/NS/TXT/CNAME y análisis de SPF/DMARC |
| `dnsbl_domain` | pasivo | sin key | ¿El dominio figura en listas negras de spam o malware? (Spamhaus DBL...) |
| `doc_metadata` | pasivo | sin key | Autores, usuarios y software en metadatos de documentos públicos (vía Wayback) |
| `domain_blocklists` | pasivo | sin key | ¿El dominio figura en listas de phishing y malware? (OpenPhish, URLhaus, StevenBlack) |
| `domainsdb` | pasivo | sin key | Dominios registrados con nombre parecido en otras extensiones (DomainsDB, sin key) |
| `exposed_files` | activo | sin key | Archivos sensibles accesibles por error (.git, .env, copias y volcados). Activo, solo el dominio base |
| `hackertarget` | pasivo | sin key | Subdominios e IPs por búsqueda de hosts (HackerTarget, gratis con cuota diaria) |
| `hunter_domain` | pasivo | requiere hunter | Correos públicos asociados al dominio (Hunter.io, key gratuita) |
| `lookalikes` | activo | sin key | Dominios similares ya registrados (errores de tipeo, homoglifos, otros TLD) |
| `otx_domain` | pasivo | opcional otx | DNS pasivo histórico y reputación del dominio (AlienVault OTX, sin key) |
| `rapiddns` | pasivo | sin key | Subdominios del dominio desde RapidDNS (sin key) |
| `rdap_domain` | pasivo | sin key | Registrador, fechas de registro/expiración y servidores de nombres |
| `robtex_domain` | pasivo | sin key | DNS pasivo del dominio: IPs y servidores asociados (Robtex) |
| `securitytrails` | pasivo | requiere securitytrails | Subdominios históricos (SecurityTrails, key gratuita) |
| `subdomain_brute` | activo | sin key | Subdominios comunes por diccionario (DNS-over-HTTPS) con detección de comodín |
| `takeover` | activo | sin key | CNAME hacia servicios externos sin reclamar (GitHub Pages, S3, Heroku, Azure...) |
| `tls_cert` | activo | sin key | Certificado TLS que presenta el servidor: emisor, vigencia y nombres alternativos |
| `urlscan` | pasivo | opcional urlscan | Escaneos públicos del dominio: IPs, servidores y URLs vistas (urlscan.io, sin key) |
| `vt_domain` | pasivo | requiere virustotal | Reputación del dominio y subdominios (VirusTotal, key gratuita) |
| `wayback` | pasivo | sin key | Primera y última captura archivada y URLs históricas interesantes |
| `web_fingerprint` | activo | sin key | Tecnologías, cabeceras de seguridad, contactos, redes y analítica de la web del dominio |

## Entrada: domain, email, username

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `dork_results` | pasivo | sin key | Ejecuta las búsquedas avanzadas más útiles en DuckDuckGo y lista los resultados (sin key) |
| `dorks` | pasivo | sin key | Búsquedas avanzadas listas para abrir en Google, Bing y DuckDuckGo (documentos, directorios, menciones) |

## Entrada: email

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `email_checks` | pasivo | sin key | Sintaxis, dominio desechable y servidores MX (DNS-over-HTTPS) |
| `email_disposable` | pasivo | sin key | ¿El dominio del correo es de buzones desechables? (Kickbox abierto, sin key) |
| `email_domain` | pasivo | sin key | Extrae el usuario y el dominio del correo y los usa como pivote |
| `email_provider` | pasivo | sin key | Proveedor del buzón (Google, Microsoft, Proton...) deducido de los servidores MX |
| `emailrep` | pasivo | opcional emailrep | Reputación del correo, brechas conocidas y perfiles vistos (emailrep.io) |
| `github_email` | pasivo | opcional github | Commits y cuentas de GitHub asociados a un correo (búsqueda pública) |
| `gravatar` | pasivo | sin key | Perfil público de Gravatar asociado al correo (nombre, cuentas enlazadas) |
| `hunter_email` | pasivo | requiere hunter | Verificación de entregabilidad del correo (Hunter.io, key gratuita) |
| `ipqs_email` | pasivo | requiere ipqs | Puntuación de fraude, filtración y validez del correo (IPQualityScore, key gratuita) |
| `leakcheck` | pasivo | sin key | Filtraciones y tipo de dato expuesto (LeakCheck API pública, gratis y sin key) |
| `xposedornot` | pasivo | sin key | Filtraciones públicas del correo con detalle: fecha, registros, datos y riesgo (XposedOrNot, sin key) |

## Entrada: email, domain

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `pgp_keys` | pasivo | sin key | Claves PGP publicadas para el correo o el dominio (keyserver.ubuntu.com) |

## Entrada: email, domain, username, name, phone

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `darkweb_index` | dark web | sin key | Menciones del objetivo en índices .onion vía Tor (requiere --darkweb y entorno verificado) |

## Entrada: ip

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `abuseipdb` | pasivo | requiere abuseipdb | Puntuación de abuso y reportes de la IP (AbuseIPDB, key gratuita) |
| `dnsbl_ip` | pasivo | sin key | ¿La IP figura en listas negras de spam o abuso? (Spamhaus, SpamCop, DroneBL...) |
| `greynoise` | pasivo | opcional greynoise | ¿La IP escanea Internet de forma masiva? (GreyNoise Community, key opcional) |
| `internetdb` | pasivo | sin key | Puertos abiertos, CPEs, hostnames y CVEs de una IP (datos pasivos) |
| `ip_abuse_contact` | pasivo | sin key | Contacto de abuso oficial del bloque de la IP (RIPEstat, sin key) |
| `ip_blocklists` | pasivo | sin key | ¿La IP figura en listas públicas de ataques? (blocklist.de, CINS, Emerging Threats, GreenSnow, Feodo) |
| `ip_rdap` | pasivo | sin key | Titular registrado del bloque de la IP y contactos públicos (RDAP, sin key) |
| `ipgeo` | pasivo | sin key | País, ciudad, ISP, ASN y banderas de proxy/hosting |
| `ipinfo` | pasivo | requiere ipinfo | Ubicación, organización y hostname de la IP (ipinfo.io, token gratuito) |
| `otx_ip` | pasivo | opcional otx | Reportes de amenazas y reputación de la IP (AlienVault OTX, sin key) |
| `reverse_ip` | pasivo | sin key | Otros dominios alojados en la misma IP (HackerTarget, gratis con cuota diaria) |
| `robtex_ip` | pasivo | sin key | Nombres de host vistos en la IP y su red (Robtex) |
| `tor_relay` | pasivo | sin key | Indica si la IP es un relé o salida de la red Tor (Onionoo, sin key) |
| `vt_ip` | pasivo | requiere virustotal | Reputación de la IP (VirusTotal, key gratuita) |
| `wiki_ip` | pasivo | sin key | Artículos de Wikipedia editados de forma anónima desde la IP |

## Entrada: name

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `name_github` | pasivo | opcional github | Cuentas de GitHub cuyo nombre público coincide |
| `name_links` | pasivo | sin key | Búsquedas dirigidas del nombre en buscadores, redes, registros y bases abiertas |
| `name_orcid` | pasivo | sin key | Investigadores con ese nombre en ORCID (registro público) |
| `name_variants` | pasivo | sin key | Genera alias probables a partir del nombre y los verifica (activar con --permute) |
| `name_wikidata` | pasivo | sin key | Entidades públicas con ese nombre en Wikidata |

## Entrada: org

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `org_gleif` | pasivo | sin key | Entidades legales registradas con ese nombre (GLEIF, base global de LEI, sin key) |
| `org_links` | pasivo | sin key | Registros mercantiles, listas de sanciones y búsquedas dirigidas de la organización |

## Entrada: phone

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `ipqs_phone` | pasivo | requiere ipqs | Riesgo, VOIP, abuso reciente y filtraciones del número (IPQualityScore, key gratuita) |
| `phone` | pasivo | opcional numverify | Validación, país/operador por plan de numeración, área y huso horario |
| `phone_libphone` | pasivo | sin key | Validación, tipo de línea, operador original y región con la base de libphonenumber |
| `phone_links` | pasivo | sin key | Enlaces de consulta manual: mensajería, directorios y búsquedas dirigidas del número |
| `veriphone` | pasivo | requiere veriphone | Validez, tipo de línea y operador en vivo (Veriphone, key gratuita) |

## Entrada: url

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `image_exif` | activo | sin key | Descarga la imagen y lee sus metadatos EXIF: cámara, fecha y coordenadas GPS |
| `url_intel` | pasivo | sin key | Dominio de la URL, copia en Wayback y búsqueda inversa si es una imagen |

## Entrada: username

| Módulo | Modo | API key | Qué hace |
|---|---|---|---|
| `github_user` | pasivo | opcional github | Perfil de GitHub: nombre, empresa, ubicación, sitio web y correos en commits públicos |
| `instagram` | pasivo | requiere instagram_session | Perfil de Instagram: nombre, biografía, enlaces y contacto publicado por el titular |
| `profile_apis` | pasivo | sin key | Consulta directa a APIs públicas (GitLab, Reddit, Keybase, HN, Dev.to, Docker Hub, Lichess, Chess.com, Bluesky, npm) |
| `username_sites` | pasivo | sin key | Comprueba un alias en cientos de sitios y descarta falsos positivos |
| `wiki_user` | pasivo | sin key | Cuenta de Wikipedia con ese alias: fecha de alta y cantidad de ediciones |

