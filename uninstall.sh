#!/usr/bin/env bash
# Desinstalador. Por defecto conserva la configuración y las API keys.
set -euo pipefail

APP="$HOME/.local/share/nexum-osint"
BIN="$HOME/.local/bin"
[ -n "${PREFIX:-}" ] && [[ "$PREFIX" == *com.termux* ]] && BIN="$PREFIX/bin"

rm -f "$BIN/nexum-osint" "$HOME/.local/bin/nexum-osint"
rm -rf "$APP"
echo "[+] NEXUM OSINT desinstalado."

if [ "${1:-}" = "--purge" ]; then
    rm -rf "$HOME/.config/nexum-osint" "$HOME/.cache/nexum-osint"
    echo "[+] Configuración, keys y caché eliminadas."
else
    echo "[*] Se conservó ~/.config/nexum-osint (usa --purge para borrarla)."
fi
