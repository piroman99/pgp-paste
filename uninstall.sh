#!/bin/sh
# Удаление «PGP — ключи и шифрование» из меню и с рабочего стола.
# Сами ключи в ~/.gnupg НЕ трогаются.
set -e

BIN="$HOME/.local/bin/pgp-paste"
APPS="$HOME/.local/share/applications/pgp-paste.desktop"
DESK="$HOME/Desktop/pgp-paste.desktop"

[ -f "$BIN" ] && rm -f "$BIN" && echo "удалён $BIN"
[ -f "$APPS" ] && rm -f "$APPS" && echo "удалён $APPS"
[ -f "$DESK" ] && rm -f "$DESK" && echo "удалён $DESK"

update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "готово. Ключи в ~/.gnupg остались на месте."
