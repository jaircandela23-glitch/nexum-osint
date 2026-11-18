"""Textos de advertencia y guía de configuración para trabajar con Tor desde Kali Linux."""

WARNING = """\
ADVERTENCIA - BÚSQUEDA EN DARK WEB

Esta función consulta índices de servicios .onion a través de la red Tor.
NEXUM OSINT solo hace búsquedas en índices: no descarga, no abre y no
ejecuta contenido de sitios .onion.

Antes de continuar debes entender que:

  1. Los resultados pueden incluir contenido ilegal, violento o perturbador.
     Los títulos y fragmentos no están filtrados.
  2. Tu seguridad depende de tu entorno. Úsala solo desde una máquina
     virtual de Kali Linux aislada, con Tor activo y una VPN, sin sesiones
     iniciadas de tus cuentas personales y sin carpetas compartidas.
  3. No abras los enlaces .onion fuera de Tor Browser. No descargues archivos.
  4. Su uso es para investigación autorizada, defensa y verificación de
     exposición propia o de clientes con contrato. Acceder, comprar, vender
     o distribuir material ilícito es delito y no es lo que hace esta
     herramienta ni lo que se espera de quien la usa.
  5. Eres el único responsable del uso que le des.
"""

GUIDE = """\
GUÍA DE ENTORNO PARA DARK WEB (Kali Linux)

1) Aislar el entorno
   - Usa Kali en una máquina virtual (VirtualBox o VMware), red en modo NAT.
   - Desactiva carpetas compartidas y portapapeles compartido.
   - Toma un snapshot limpio antes de empezar y restáuralo al terminar.
   - No inicies sesión en cuentas personales dentro de esa máquina.

2) Instalar las herramientas
   sudo apt update
   sudo apt install -y tor torsocks proxychains4 openvpn wireguard-tools curl
   sudo apt install -y torbrowser-launcher        # solo si necesitas navegar manualmente

3) Activar Tor
   sudo systemctl enable --now tor
   systemctl status tor --no-pager
   curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
   # La respuesta debe contener  "IsTor":true

4) Activar una VPN (antes de iniciar Tor para tu conexión de salida)
   sudo openvpn --config /ruta/a/tu.ovpn --daemon
   # o con WireGuard:
   sudo wg-quick up wg0
   ip link show | grep -E "tun|wg|ppp"            # debe aparecer una interfaz de VPN

5) Opcional: enrutar otras herramientas por Tor
   sudo nano /etc/proxychains4.conf               # deja:  strict_chain  y  socks5 127.0.0.1 9050
   proxychains4 -q curl https://check.torproject.org/api/ip

6) Verificar con NEXUM OSINT
   nexum-osint darkweb check

7) Usar
   nexum-osint darkweb search "empresa.com" --acepto-riesgos
   nexum-osint scan empresa.com --darkweb --acepto-riesgos

Buenas prácticas
   - Busca solo datos propios o de clientes autorizados (dominios, correos corporativos, marcas).
   - Trata cualquier hallazgo como indicio: confírmalo por una fuente legítima antes de actuar.
   - Si aparecen credenciales de un cliente, repórtalas al cliente; no las pruebes.
   - Al terminar: cierra Tor y la VPN, y restaura el snapshot.
"""
