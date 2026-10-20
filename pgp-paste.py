#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PGP — вставить ключ / зашифровать текст.

Две вкладки:
  1. «Ключ»  — вставить ключ из письма и импортировать (без файлов).
  2. «Текст» — зашифровать текст коллеге или расшифровать присланное.

Запуск:  python3 pgp-paste.py
Ключи кладутся в обычную связку пользователя (~/.gnupg).
"""
import os
import shutil
import subprocess
import sys
import tempfile

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gtk  # noqa: E402

APP_TITLE = "PGP — ключи и шифрование"
PASSPHRASE_HINT = (
    "Если на ключе есть пароль, gpg спросит его отдельным окном "
    "(pinentry) — это нормально."
)


# ---------------------------------------------------------------- gpg helpers
def _env(gnupghome=None):
    env = os.environ.copy()
    if gnupghome:
        env["GNUPGHOME"] = gnupghome
    env.setdefault("LC_ALL", "C.UTF-8")
    return env


def _run(args, data=b"", gnupghome=None, batch=True):
    cmd = ["gpg"] + (["--batch"] if batch else []) + args
    return subprocess.run(
        cmd, input=data, capture_output=True, env=_env(gnupghome)
    )


def _fmt_epoch(val):
    try:
        import datetime
        return datetime.datetime.utcfromtimestamp(int(val)).strftime("%Y-%m-%d")
    except Exception:
        return val or "?"


def _group_fpr(fp):
    fp = (fp or "").upper()
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


# ------------------------------------------------------------------- keyring
def list_public_keys(gnupghome=None):
    """[(fpr, uid, has_encr)] из публичной связки."""
    p = _run(["--with-colons", "--fingerprint", "--list-keys"], gnupghome=gnupghome)
    blocks, cur = [], None
    for raw in p.stdout.decode("utf-8", "replace").splitlines():
        if raw.startswith("pub:"):
            cur = {"fpr": None, "uid": None, "encr": False}
            blocks.append(cur)
        elif cur is None:
            continue
        elif raw.startswith("fpr:") and cur["fpr"] is None:
            cur["fpr"] = raw.split(":")[9]
        elif raw.startswith("uid:") and cur["uid"] is None:
            cur["uid"] = raw.split(":")[9]
        elif raw.startswith("sub:") and "e" in raw.split(":")[11]:
            cur["encr"] = True
    return [(b["fpr"], b["uid"] or "?", b["encr"]) for b in blocks if b["fpr"]]


def own_secret_keys(gnupghome=None):
    """[(fpr, uid)] своих секретных ключей."""
    p = _run(["--with-colons", "--fingerprint", "--list-secret-keys"], gnupghome=gnupghome)
    blocks, cur = [], None
    for raw in p.stdout.decode("utf-8", "replace").splitlines():
        if raw.startswith("sec:"):
            cur = {"fpr": None, "uid": None}
            blocks.append(cur)
        elif cur is None:
            continue
        elif raw.startswith("fpr:") and cur["fpr"] is None:
            cur["fpr"] = raw.split(":")[9]
        elif raw.startswith("uid:") and cur["uid"] is None:
            cur["uid"] = raw.split(":")[9]
    return [(b["fpr"], b["uid"] or "?") for b in blocks if b["fpr"]]


def own_public_key(gnupghome=None):
    keys = own_secret_keys(gnupghome)
    if not keys:
        return None, "Своих секретных ключей не найдено."
    fpr = keys[0][0]
    p = _run(["--armor", "--export", fpr], gnupghome=gnupghome)
    if p.returncode != 0 or not p.stdout.strip():
        return None, (p.stderr or b"export failed").decode("utf-8", "replace")
    return p.stdout.decode(), "Публичный ключ %s скопирован в буфер." % _group_fpr(fpr)


# ---------------------------------------------------------------------- keys
def gpg_import(text, gnupghome=None):
    """Импорт ключа из текста. -> (rc, сообщение)"""
    if not text.strip():
        return 1, "Пусто: вставь ключ (блок от BEGIN до END)."
    p = _run(["--import"], data=text.encode("utf-8", "replace"), gnupghome=gnupghome)
    out = (p.stderr or p.stdout).decode("utf-8", "replace").strip()
    return p.returncode, out


def gpg_inspect(text):
    """Импорт во временную связку и описание содержимого. Реальный keyring не трогает."""
    tmp = tempfile.mkdtemp(prefix="pgp-paste-")
    try:
        os.chmod(tmp, 0o700)
        rc, out = gpg_import(text, gnupghome=tmp)
        if rc != 0:
            return rc, out
        p = _run(["--with-colons", "--fingerprint"], gnupghome=tmp)
        lines = []
        for raw in p.stdout.decode("utf-8", "replace").splitlines():
            f = raw.split(":")
            if raw.startswith("pub:"):
                lines.append("ключ: algo %s, %s бит, создан %s" % (f[3], f[2], _fmt_epoch(f[5])))
            elif raw.startswith("sub:"):
                if "e" in f[11]:
                    lines.append("  подключ шифрования: algo %s, %s бит" % (f[3], f[2]))
            elif raw.startswith("uid:"):
                lines.append("  uid: %s" % f[9])
            elif raw.startswith("fpr:"):
                lines.append("  отпечаток: %s" % _group_fpr(f[9]))
        return 0, "\n".join(lines) if lines else "Ключей не найдено."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------- encrypt/decrypt
def encrypt_text(text, recipients, sign_fpr=None, gnupghome=None):
    """Зашифровать (и при желании подписать). -> (rc, результат|ошибка)"""
    if not text.strip():
        return 1, "Пусто: нечего шифровать."
    if not recipients:
        return 1, "Не выбран получатель."
    args = ["--yes", "--no-tty", "--armor", "--trust-model", "always", "--output", "-"]
    for r in recipients:
        args += ["--recipient", r]
    if sign_fpr:
        args += ["--local-user", sign_fpr, "--sign", "--encrypt"]
    else:
        args += ["--encrypt"]
    p = _run(args, data=text.encode("utf-8"), gnupghome=gnupghome, batch=False)
    if p.returncode != 0:
        return p.returncode, (p.stderr or b"encrypt failed").decode("utf-8", "replace").strip()
    return 0, p.stdout.decode("utf-8", "replace")


def decrypt_text(armored, gnupghome=None):
    """Расшифровать. -> (rc, текст|ошибка, инфо о подписи)

    Важно: gpg выходит с кодом != 0, если расшифровал, но не смог проверить
    подпись (нет ключа автора). Поэтому успех определяем по наличию stdout.
    """
    if not armored.strip():
        return 1, "Пусто: нечего расшифровывать.", ""
    p = _run(["--yes", "--no-tty", "--decrypt"], data=armored.encode("utf-8"),
             gnupghome=gnupghome, batch=False)
    info = (p.stderr or b"").decode("utf-8", "replace").strip()
    out = (p.stdout or b"").decode("utf-8", "replace")
    if out.strip():
        return 0, out, info
    return (p.returncode or 1), info or "decrypt failed", info


def signature_verdict(info, decrypted=True):
    """Человеческая оценка блока подписи из stderr gpg (LC_ALL=C.UTF-8).

    decrypted=False — расшифровка не удалась, оценивать нечего; тогда отдаём
    только причины отказа, а не «без подписи».
    """
    low = (info or "").lower()
    if "no secret key" in low or "секретный ключ" in low and "нет" in low:
        return "нет подходящего секретного ключа — сообщение не тебе"
    if "crc error" in low or "decryption failed" in low or "integrity check failed" in low:
        return "текст повреждён или подменён (ошибка целостности)"
    if ("no valid openpgp data" in low or "не найдено действительных" in low
            or "decrypt_message failed" in low):
        return "это не PGP-сообщение"
    if "bad signature" in low or "плохая подпись" in low or "bogus signature" in low:
        return "ПОДПИСЬ НЕВЕРНА — текст могли подменить"
    if "good signature" in low or "хорошая подпись" in low:
        if "warn" in low or "not certified" in low:
            return "подпись верна, но ключ автора не помечен как доверенный"
        return "подпись ПРОВЕРЕНА"
    if "no public key" in low or "не найден открытый ключ" in low:
        return "подпись есть, но ключ автора не импортирован — сверить не с чем"
    if "signature" in low or "подпись" in low:
        return "подпись не проверена"
    return "без подписи" if decrypted else ""


# ------------------------------------------------------------------------ GUI
class Window(Gtk.Window):
    def __init__(self):
        super().__init__(title=APP_TITLE)
        self.set_default_size(840, 620)
        self.set_border_width(10)
        self.connect("destroy", self._on_destroy)

        nb = Gtk.Notebook()
        self.add(nb)
        nb.append_page(self.build_key_tab(), Gtk.Label(label="Ключ"))
        nb.append_page(self.build_text_tab(), Gtk.Label(label="Текст"))
        self.show_all()

    # ------------------------------------------------------------ tab: key
    def build_key_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(8)

        head = Gtk.Label()
        head.set_markup(
            "<b>Вставь ключ из письма</b> (Ctrl+V) — блок от "
            "<tt>BEGIN PGP PUBLIC KEY BLOCK</tt> до <tt>END</tt>.\n"
            "Файл создавать не нужно. «Проверить» ничего не меняет, "
            "«Импортировать» добавляет ключ в связку."
        )
        head.set_line_wrap(True)
        head.set_xalign(0)
        box.pack_start(head, False, False, 0)

        self.key_input = self.make_textview(mono=True)
        box.pack_start(self.scroll(self.key_input), True, True, 0)

        row = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL)
        row.set_layout(Gtk.ButtonBoxStyle.END)
        row.set_spacing(8)
        for label, cb in (
            ("Проверить", self.on_inspect),
            ("Импортировать", self.on_import),
            ("Из файла…", self.on_from_file),
            ("Мой ключ в буфер", self.on_copy_own),
        ):
            b = Gtk.Button(label=label)
            b.connect("clicked", cb)
            row.add(b)
        box.pack_start(row, False, False, 0)

        self.key_result = self.make_textview(mono=True, editable=False)
        box.pack_start(self.scroll(self.key_result, height=150), True, True, 0)
        self.say_key("Готово. Вставь ключ в верхнее поле.")
        return box

    # ----------------------------------------------------------- tab: text
    def build_text_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(8)

        head = Gtk.Label()
        head.set_markup(
            "<b>Кому</b> — выбираешь получателя, пишешь текст, жмёшь «Зашифровать».\n"
            "Обратно: вставляешь <tt>BEGIN PGP MESSAGE</tt> и жмёшь «Расшифровать».\n"
            "<small>%s</small>" % PASSPHRASE_HINT
        )
        head.set_line_wrap(True)
        head.set_xalign(0)
        box.pack_start(head, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row.pack_start(Gtk.Label(label="Кому:"), False, False, 0)
        self.recip = Gtk.ComboBoxText()
        self.recip.set_hexpand(True)
        row.pack_start(self.recip, True, True, 0)

        self.sign_chk = Gtk.CheckButton(label="Подписать")
        self.sign_chk.set_active(True)
        row.pack_start(self.sign_chk, False, False, 0)

        b_refresh = Gtk.Button(label="Обновить")
        b_refresh.connect("clicked", lambda *_: self.reload_keys())
        row.pack_start(b_refresh, False, False, 0)
        box.pack_start(row, False, False, 0)

        self.text_input = self.make_textview()
        box.pack_start(self.scroll(self.text_input, height=150), True, True, 0)

        row2 = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL)
        row2.set_layout(Gtk.ButtonBoxStyle.END)
        row2.set_spacing(8)
        for label, cb in (
            ("Зашифровать", self.on_encrypt),
            ("Расшифровать", self.on_decrypt),
            ("Копировать", self.on_copy_result),
            ("Очистить", self.on_clear),
        ):
            b = Gtk.Button(label=label)
            b.connect("clicked", cb)
            row2.add(b)
        box.pack_start(row2, False, False, 0)

        self.text_result = self.make_textview(mono=True)
        box.pack_start(self.scroll(self.text_result, height=150), True, True, 0)

        self.status = Gtk.Label()
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        box.pack_start(self.status, False, False, 0)

        self._keys = []
        self.reload_keys()
        return box

    def _on_destroy(self, *_a):
        if Gtk.main_level() > 0:
            Gtk.main_quit()

    # ------------------------------------------------------------- widgets
    @staticmethod
    def make_textview(mono=False, editable=True):
        tv = Gtk.TextView()
        tv.set_monospace(mono)
        tv.set_editable(editable)
        tv.set_cursor_visible(editable)
        tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        tv.set_left_margin(6)
        tv.set_right_margin(6)
        tv.set_top_margin(6)
        tv.set_bottom_margin(6)
        return tv

    @staticmethod
    def scroll(child, height=None):
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        if height:
            sw.set_min_content_height(height)
        sw.add(child)
        return sw

    @staticmethod
    def read(tv):
        buf = tv.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)

    @staticmethod
    def write(tv, text):
        tv.get_buffer().set_text(text or "")

    @staticmethod
    def clipboard_set(text):
        cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        cb.set_text(text, -1)
        cb.store()

    def say_key(self, msg):
        self.write(self.key_result, msg)

    def say(self, msg, markup=None):
        if markup:
            self.status.set_markup(markup)
        else:
            self.status.set_text(msg or "")

    # -------------------------------------------------------------- actions
    def reload_keys(self):
        try:
            mine = {fpr for fpr, _ in own_secret_keys()}
            self._keys = [k for k in list_public_keys()
                          if k[2] and k[0] not in mine]
        except Exception as e:
            self._keys = []
            self.say("Не смог прочитать связку: %s" % e)
        self.recip.remove_all()
        for fpr, uid, _ in self._keys:
            short = uid if len(uid) <= 34 else uid[:33] + "…"
            self.recip.append(fpr, "%s · %s" % (short, _group_fpr(fpr)[-9:]))
            self.recip.set_tooltip_text("%s\nотпечаток: %s" % (uid, _group_fpr(fpr)))
        if self._keys:
            self.recip.set_active(0)
        else:
            self.say("Нет чужих ключей с подключом шифрования — импортируй на вкладке «Ключ».")

    def on_inspect(self, _w):
        rc, out = gpg_inspect(self.read(self.key_input))
        self.say_key(("— проверка (ничего не импортировано) —\n" if rc == 0 else "— ошибка —\n") + out)

    def on_import(self, _w):
        rc, out = gpg_import(self.read(self.key_input))
        self.say_key(("— импорт —\n" if rc == 0 else "— ошибка импорта —\n") + out)
        if rc == 0:
            self.key_input.get_buffer().set_text("")
            self.reload_keys()

    def on_from_file(self, _w):
        dlg = Gtk.FileChooserDialog(title="Выбери файл с ключом", parent=self,
                                    action=Gtk.FileChooserAction.OPEN)
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        f = Gtk.FileFilter()
        f.set_name("Ключи (*.asc, *.gpg, *.key)")
        for pat in ("*.asc", "*.gpg", "*.key", "*.txt"):
            f.add_pattern(pat)
        dlg.add_filter(f)
        if dlg.run() == Gtk.ResponseType.OK:
            path = dlg.get_filename()
            dlg.destroy()
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    data = fh.read()
            except OSError as e:
                self.say_key("Не смог прочитать %s: %s" % (path, e))
                return
            self.key_input.get_buffer().set_text(data)
            self.on_import(None)
        else:
            dlg.destroy()

    def on_copy_own(self, _w):
        key, msg = own_public_key()
        if key:
            self.clipboard_set(key)
        self.say_key(msg)

    def _sign_fpr(self):
        if not self.sign_chk.get_active():
            return None
        keys = own_secret_keys()
        return keys[0][0] if keys else None

    def on_encrypt(self, _w):
        fpr = self.recip.get_active_id()
        if not fpr:
            self.say("Выбери получателя (или импортируй его ключ).")
            return
        rc, out = encrypt_text(self.read(self.text_input), [fpr], self._sign_fpr())
        if rc != 0:
            self.say("Ошибка шифрования: %s" % out.splitlines()[-1] if out else "ошибка")
            self.write(self.text_result, out)
            return
        self.write(self.text_result, out)
        self.say("Зашифровано. Результат ниже — можно копировать в письмо/чат.")

    def on_decrypt(self, _w):
        rc, out, info = decrypt_text(self.read(self.text_input))
        verdict = signature_verdict(info, decrypted=(rc == 0))
        if rc != 0:
            self.write(self.text_result, out)
            if verdict:
                self.say("Не расшифровалось — %s" % verdict)
            else:
                self.say(out.splitlines()[0] if out.strip() else "Не расшифровалось.")
            return
        self.write(self.text_result, out)
        tail = ("\n\n— gpg —\n" + info) if info else ""
        self.say("Расшифровано. %s" % verdict)
        if tail:
            buf = self.text_result.get_buffer()
            buf.insert(buf.get_end_iter(), tail)

    def on_copy_result(self, _w):
        txt = self.read(self.text_result)
        if not txt.strip():
            self.say("Результат пуст.")
            return
        self.clipboard_set(txt)
        self.say("Скопировано в буфер.")

    def on_clear(self, _w):
        self.text_input.get_buffer().set_text("")
        self.text_result.get_buffer().set_text("")
        self.say("")


def main():
    if shutil.which("gpg") is None:
        print("gpg не найден", file=sys.stderr)
        return 1
    ok, _ = Gtk.init_check(sys.argv)
    if not ok:
        print("Нет графического дисплея (DISPLAY/WAYLAND_DISPLAY пусты).\n"
              "Запускай из своей сессии, а не из песочницы.", file=sys.stderr)
        return 1
    win = Window()
    win.present()
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
