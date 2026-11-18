#!/usr/bin/env bash
# Instalador de NEXUM OSINT para Termux, Kali Linux, Debian/Ubuntu, Arch, Fedora y macOS.
# Uso: ./install.sh [--darkweb]     (--darkweb instala Tor, VPN y proxychains en Kali/Debian)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DARKWEB=0
[ "${1:-}" = "--darkweb" ] && DARKWEB=1

say()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { printf '    $ %s\n' "$*"; if [ "${NEXUM_DRY_RUN:-0}" = "1" ]; then return 0; fi; "$@"; }
# Igual que run, pero un fallo (por ejemplo un espejo de apt desincronizado) no detiene la instalación.
try()  { run "$@" || { warn "Falló: $*"; return 1; }; }

# Python con venv y pip ya presentes: no hace falta tocar los paquetes del sistema.
python_ready() {
    command -v "$1" >/dev/null 2>&1 && "$1" -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 11))' 2>/dev/null
}

# --- entorno ---------------------------------------------------------------
detect_env() {
    if [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == *com.termux* ]]; then echo termux; return; fi
    if [ "$(uname -s)" = "Darwin" ]; then echo macos; return; fi
    local id="" like=""
    if [ -r /etc/os-release ]; then . /etc/os-release; id="${ID:-}"; like="${ID_LIKE:-}"; fi
    case "$id $like" in
        *kali*) echo kali ;;
        *arch*) echo arch ;;
        *fedora*|*rhel*|*centos*) echo fedora ;;
        *debian*|*ubuntu*) echo debian ;;
        *) echo otro ;;
    esac
}
ENV_NAME="$(detect_env)"
case "$ENV_NAME" in
    termux) say "Entorno: Termux (Android)" ;;
    kali)   say "Entorno: Kali Linux" ;;
    debian) say "Entorno: Debian / Ubuntu" ;;
    arch)   say "Entorno: Arch Linux" ;;
    fedora) say "Entorno: Fedora / RHEL" ;;
    macos)  say "Entorno: macOS" ;;
    *)      warn "Entorno no reconocido: se intentará con python3 ya instalado" ;;
esac

SUDO=""
if [ "$ENV_NAME" != "termux" ] && [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && SUDO="sudo" || warn "No hay sudo: los paquetes del sistema deberás instalarlos tú."
fi

[ -n "${NEXUM_SUDO:-}" ] && SUDO="$NEXUM_SUDO"

# --- paquetes del sistema --------------------------------------------------
say "Revisando paquetes del sistema"
NEED_SYSTEM=1
case "$ENV_NAME" in
    kali|debian|arch|fedora)
        if [ "${NEXUM_FORCE_SYSTEM:-0}" != "1" ] && python_ready python3; then
            ok "Python 3.11+ con venv ya está instalado: se omite la actualización de paquetes"
            NEED_SYSTEM=0
        fi ;;
esac
if [ "$NEED_SYSTEM" = "1" ]; then
    case "$ENV_NAME" in
        termux)
            try pkg update -y
            run pkg install -y python python-pillow libxml2 libxslt openssl git ;;
        kali|debian)
            try $SUDO apt-get update || warn "apt no pudo actualizar los índices (¿espejo desincronizado?). Se intenta con los índices actuales. Si persiste: sudo apt clean && sudo apt update"
            try $SUDO apt-get install -y python3 python3-venv python3-pip libjpeg-dev zlib1g-dev || true ;;
        arch)   try $SUDO pacman -Sy --needed --noconfirm python python-pip || true ;;
        fedora) try $SUDO dnf install -y python3 python3-pip || true ;;
        macos)  command -v brew >/dev/null && try brew install python || warn "Instala Homebrew o Python 3.11+ manualmente" ;;
    esac
fi
if [ "$DARKWEB" = "1" ] && [[ "$ENV_NAME" == kali || "$ENV_NAME" == debian ]]; then
    say "Instalando herramientas de dark web (Tor, VPN, proxychains)"
    try $SUDO apt-get update || true
    try $SUDO apt-get install -y tor torsocks proxychains4 openvpn wireguard-tools curl \
        || warn "No se pudieron instalar. Hazlo luego a mano: sudo apt install -y tor torsocks proxychains4 openvpn wireguard-tools"
    try $SUDO systemctl enable --now tor || warn "No se pudo iniciar Tor: ejecuta 'sudo systemctl start tor'"
fi

PY="python3"; [ "$ENV_NAME" = "termux" ] && PY="python"
command -v "$PY" >/dev/null || die "Falta $PY. Instálalo con el gestor de paquetes de tu sistema y repite ./install.sh"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "Se necesita Python 3.11 o superior ($("$PY" --version))"

# --- entorno virtual y programa -------------------------------------------
APP="$HOME/.local/share/nexum-osint"
VENV="$APP/venv"
VENV_ARGS=""
[ "$ENV_NAME" = "termux" ] && VENV_ARGS="--system-site-packages"   # para usar python-pillow de pkg
say "Creando entorno virtual en $VENV"
mkdir -p "$APP"
"$PY" -m venv $VENV_ARGS "$VENV" || die "No se pudo crear el entorno virtual. En Kali/Debian: sudo apt install -y python3-venv"
run "$VENV/bin/pip" install --quiet --upgrade pip
say "Instalando NEXUM OSINT y sus librerías"
run "$VENV/bin/pip" install --quiet "$DIR"

BIN="$HOME/.local/bin"; [ "$ENV_NAME" = "termux" ] && BIN="$PREFIX/bin"
mkdir -p "$BIN" "$HOME/.config/nexum-osint/plugins"
ln -sf "$VENV/bin/nexum-osint" "$BIN/nexum-osint"
[ -f "$HOME/.config/nexum-osint/config.toml" ] || cp "$DIR/config.example.toml" "$HOME/.config/nexum-osint/config.toml"
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) warn "Agrega $BIN a tu PATH:  echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.\$(basename \"\$SHELL\")rc" ;;
esac

# --- verificación y listas -------------------------------------------------
say "Verificando el entorno"
"$VENV/bin/nexum-osint" doctor || warn "Revisa lo que indica el diagnóstico y ejecuta: nexum-osint doctor --fix"
say "Descargando listas ampliadas de sitios"
"$VENV/bin/nexum-osint" sites --update >/dev/null 2>&1 \
    && ok "Lista de sitios actualizada" \
    || warn "Sin conexión: se usa la lista incluida. Reintenta con: nexum-osint sites --update"

ok "Instalación completa"
echo "    nexum-osint              menú interactivo"
echo "    nexum-osint setup        configurar API keys gratuitas"
echo "    nexum-osint doctor       diagnóstico del entorno"
[ "$ENV_NAME" = "termux" ] && echo "    Dark web: no disponible en Termux (usa Kali Linux)"
[ "$DARKWEB" = "0" ] && [ "$ENV_NAME" != "termux" ] && echo "    nexum-osint darkweb guide   preparar Tor y VPN (o ./install.sh --darkweb)"
exit 0
