#!/bin/sh
# Установка «PGP — ключи и шифрование» в меню приложений и на рабочий стол.
# Запускать от своего пользователя:  sh install.sh
set -e

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
BIN="$HOME/.local/bin/pgp-paste"
APPS="$HOME/.local/share/applications"
DESK="$HOME/Desktop"

if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg не найден. Установи: sudo apt install gnupg" >&2
    exit 1
fi

if ! python3 -c 'import gi; gi.require_version("Gtk","3.0")' 2>/dev/null; then
    echo "Нет PyGObject/GTK3. Установи: sudo apt install python3-gi gir1.2-gtk-3.0" >&2
    exit 1
fi

mkdir -p "$HOME/.local/bin" "$APPS"
install -m 755 "$SRC_DIR/pgp-paste.py" "$BIN"

DESKTOP="$APPS/pgp-paste.desktop"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=PGP — ключи и шифрование
Comment=Импорт PGP-ключа из письма, шифрование и расшифровка текста
Exec=$BIN
Icon=application-pgp-keys
Terminal=false
Categories=Utility;Security;
Keywords=pgp;gpg;key;encrypt;ключ;шифрование;
EOF
chmod 644 "$DESKTOP"

if [ -d "$DESK" ]; then
    cp "$DESKTOP" "$DESK/pgp-paste.desktop"
    chmod 755 "$DESK/pgp-paste.desktop"
    # GNOME: пометить как доверенный, иначе на рабочем столе будет «не запускается»
    gio set "$DESK/pgp-paste.desktop" metadata::trusted true 2>/dev/null || true
fi

update-desktop-database "$APPS" 2>/dev/null || true

echo "готово:"
echo "  $BIN"
echo "  $DESKTOP"
[ -f "$DESK/pgp-paste.desktop" ] && echo "  $DESK/pgp-paste.desktop"
echo
echo "Проверить запуск:  $BIN"
