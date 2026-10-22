"""
Arsip Sandi — versi Python (GUI Tkinter)
=========================================
Port dari alat HTML "Arsip Sandi" (Caesar, Vigenere, XOR, RSA, Super
Enkripsi) ke aplikasi desktop Python, dengan tampilan yang meniru
desain "buku sandi" gelap dari versi web-nya. Hanya memakai pustaka
bawaan Python (tkinter) — tidak perlu instalasi tambahan.

Jalankan:
    python arsip_sandi_gui.py
"""

import tkinter as tk

# ---------------------------------------------------------------------------
# Palet warna & font, meniru variabel CSS pada versi web
# ---------------------------------------------------------------------------

INK = "#efe6cf"
INK_DIM = "#b9ab86"
PAPER = "#e9dfc4"
PAPER_LINE = "#c9bb96"
BASE = "#171f1a"
BASE2 = "#1e2822"
WAX = "#a3402c"
WAX_HOVER = "#b64b34"
WAX_DIM = "#7c3122"
BRASS = "#b08d3e"
CELL_PLAIN = "#20291f"
CELL_KEY = "#2a2018"
CELL_OUT = "#241d29"
OUT_TEXT = "#d9c8e6"
PAPER_TEXT = "#241d15"

SERIF = ("Georgia", 21, "bold")
SERIF_SM = ("Georgia", 12, "italic")
MONO = ("Consolas", 11)
MONO_SM = ("Consolas", 9)
MONO_BOLD = ("Consolas", 13, "bold")

A = ord("A")


# ---------------------------------------------------------------------------
# Logika sandi (murni, tanpa Tkinter) — sama seperti versi HTML
# ---------------------------------------------------------------------------

def is_letter(ch):
    return len(ch) == 1 and "A" <= ch.upper() <= "Z"


def shift_letter(ch, n):
    p = ord(ch.upper()) - A
    return chr((p + n) % 26 + A)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def mod_inverse(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def caesar(text, shift, encode):
    applied = shift if encode else -shift
    out, rows = [], []
    for ch in text.upper():
        if not is_letter(ch):
            out.append(ch)
            rows.append((ch, "", "", ch))
            continue
        o = shift_letter(ch, applied)
        out.append(o)
        sign = "+" if encode else "-"
        rows.append((ch, str(shift), f"{sign}{shift}", o))
    return "".join(out), rows


def vigenere(text, key, encode):
    key = "".join(c for c in key.upper() if c.isalpha())
    if not key:
        raise ValueError("Kata kunci harus berisi huruf.")
    ki = 0
    out, rows = [], []
    for ch in text.upper():
        if not is_letter(ch):
            out.append(ch)
            rows.append((ch, "", "", ch))
            continue
        k = ord(key[ki % len(key)]) - A
        glyph = key[ki % len(key)]
        ki += 1
        o = shift_letter(ch, k if encode else -k)
        out.append(o)
        sign = "+" if encode else "-"
        rows.append((ch, glyph, f"{sign}{k}", o))
    return "".join(out), rows


def xor_encode(text, key):
    if not key:
        raise ValueError("Kata kunci tidak boleh kosong.")
    out, rows = [], []
    for i, ch in enumerate(text):
        kc = ord(key[i % len(key)])
        xc = ord(ch) ^ kc
        out.append(f"{xc:02X}")
        glyph = "\u2423" if ch == " " else ch
        rows.append((glyph, key[i % len(key)], f"{xc:02X}"))
    return " ".join(out), rows


def xor_decode(hex_text, key):
    if not key:
        raise ValueError("Kata kunci tidak boleh kosong.")
    tokens = hex_text.split()
    out, rows = [], []
    for i, tok in enumerate(tokens):
        try:
            xc = int(tok, 16)
        except ValueError:
            raise ValueError(f'"{tok}" bukan pasangan heksadesimal yang valid.')
        kc = ord(key[i % len(key)])
        ch = chr(xc ^ kc)
        out.append(ch)
        glyph = "\u2423" if ch == " " else ch
        rows.append((tok.upper(), key[i % len(key)], glyph))
    return "".join(out), rows


def rsa_setup(p, q, e):
    if not is_prime(p) or not is_prime(q) or p == q:
        raise ValueError("p dan q harus dua bilangan prima yang berbeda.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError(f"e harus koprima dengan (p-1)x(q-1) = {phi}.")
    return n, phi, mod_inverse(e, phi)


def rsa_encrypt(text, e, n):
    out, rows = [], []
    for raw in text:
        ch = raw.upper()
        if ch == " ":
            out.append("/")
            rows.append(("(spasi)", "", "/"))
            continue
        if not is_letter(ch):
            continue
        m = ord(ch) - A
        if m >= n:
            raise ValueError(f"n = {n} terlalu kecil untuk huruf ini — perbesar p atau q.")
        c = pow(m, e, n)
        out.append(str(c))
        rows.append((ch, str(m), str(c)))
    return " ".join(out), rows


def rsa_decrypt(text, d, n):
    out, rows = [], []
    for tok in text.split():
        if tok == "/":
            out.append(" ")
            rows.append(("/", "", "(spasi)"))
            continue
        try:
            c = int(tok)
        except ValueError:
            raise ValueError(f'"{tok}" bukan angka yang valid.')
        if c >= n:
            raise ValueError(f'Angka sandi "{tok}" tidak valid untuk n = {n}.')
        m = pow(c, d, n)
        letter = chr(A + (m % 26))
        out.append(letter)
        rows.append((tok, str(m), letter))
    return "".join(out), rows


def rail_pattern(length, rails):
    row, direction, pattern = 0, 1, []
    for _ in range(length):
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return pattern


def rail_encode(text, rails):
    pattern = rail_pattern(len(text), rails)
    rows_text = ["" for _ in range(rails)]
    for ch, r in zip(text, pattern):
        rows_text[r] += ch
    return "".join(rows_text), pattern


def rail_decode(text, rails):
    pattern = rail_pattern(len(text), rails)
    counts = [pattern.count(r) for r in range(rails)]
    rows_text, idx = [], 0
    for c in counts:
        rows_text.append(text[idx: idx + c])
        idx += c
    ptr = [0] * rails
    result = []
    for r in pattern:
        result.append(rows_text[r][ptr[r]])
        ptr[r] += 1
    return "".join(result), pattern


def super_encrypt(text, key, rails):
    stage1, rows1 = vigenere(text, key, True)
    stage2, pattern = rail_encode(stage1, rails)
    return stage2, stage1, rows1, pattern


def super_decrypt(text, key, rails):
    stage1, pattern = rail_decode(text, rails)
    stage2, rows2 = vigenere(stage1, key, False)
    return stage2, stage1, rows2, pattern


# ---------------------------------------------------------------------------
# Definisi 5 sandi (setara array CIPHERS pada versi HTML)
# ---------------------------------------------------------------------------

CIPHERS = [
    {"id": "caesar", "num": "C-03", "title": "Sandi Caesar", "sub": "Sandi geser tunggal",
     "desc": "Semua huruf digeser sebanyak n posisi ke arah yang sama, memakai satu angka geseran tetap.",
     "fields": [("shift", "jumlah geseran (0-25)", "3")],
     "sample": "HEI ANTEK ANTEK ASING", "kind": "sub"},
    {"id": "vigenere", "num": "V-26", "title": "Sandi Vigenere", "sub": "Sandi kunci-berulang",
     "desc": "Setiap huruf pesan digeser sebesar posisi huruf kunci yang bersesuaian — kunci diulang sepanjang pesan.",
     "fields": [("key", "kata kunci", "YOGYAKARTA")],
     "sample": "SELAMAT DATANG DI YOGYAKARTA", "kind": "sub"},
    {"id": "xor", "num": "X-07", "title": "Sandi XOR", "sub": "Sandi bit eksklusif",
     "desc": "Tiap karakter dikombinasikan dengan karakter kunci lewat operasi XOR bit demi bit; hasilnya ditulis sebagai heksadesimal.",
     "fields": [("key", "kata kunci", "KUNCI")],
     "sample": "Hei antek antek asing", "kind": "xor"},
    {"id": "rsa", "num": "R-17", "title": "Sandi RSA", "sub": "Kunci publik & privat",
     "desc": "Tiap huruf diubah jadi angka m, disandikan dengan c = m^e mod n. Untuk memecahkan: m = c^d mod n, n = p x q.",
     "fields": [("p", "p (prima)", "3"), ("q", "q (prima)", "11"), ("e", "e (kunci publik)", "7")],
     "sample": "HEI", "kind": "rsa"},
    {"id": "super", "num": "S-99", "title": "Super Enkripsi", "sub": "Substitusi + transposisi",
     "desc": "Pesan disandikan dua tahap: digeser dulu dengan Vigenere, lalu hasilnya disusun ulang dengan pola zig-zag pagar.",
     "fields": [("key", "kata kunci Vigenere", "KUNCI"), ("rails", "jumlah baris pagar (2-6)", "3")],
     "sample": "SELAMAT DATANG DI YOGYAKARTA", "kind": "super"},
]


# ---------------------------------------------------------------------------
# Aplikasi Tkinter
# ---------------------------------------------------------------------------

class ArsipSandiApp:
    def __init__(self, root):
        self.root = root
        self.mode = "encode"
        self.current = CIPHERS[0]
        self.field_vars = {}
        self.tab_buttons = {}

        root.title("Arsip Sandi")
        root.configure(bg=BASE)
        root.geometry("760x900")
        root.minsize(620, 700)

        self._build_header()
        self._build_tabs()
        self._build_desc()
        self._build_mode()
        self._build_fields()
        self._build_text_area()
        self._build_run_button()
        self._build_grid_section()
        self._build_result_box()

        self.select_cipher("caesar")

    # -- bangun antarmuka statis -----------------------------------------

    def _build_header(self):
        top = tk.Frame(self.root, bg=BASE)
        top.pack(fill="x", padx=24, pady=(20, 0))
        tk.Label(top, text="arsip sandi", bg=BASE, fg=INK_DIM, font=MONO_SM).pack(anchor="e")
        self.title_lbl = tk.Label(top, text="", bg=BASE, fg=INK, font=SERIF, anchor="w")
        self.title_lbl.pack(fill="x")
        self.sub_lbl = tk.Label(top, text="", bg=BASE, fg=BRASS, font=SERIF_SM, anchor="w")
        self.sub_lbl.pack(fill="x", pady=(0, 10))

    def _build_tabs(self):
        row = tk.Frame(self.root, bg=BASE)
        row.pack(fill="x", padx=24, pady=(4, 12))
        for c in CIPHERS:
            b = tk.Button(row, text=f"{c['num']}  {c['title'].replace('Sandi ', '')}",
                          font=MONO_SM, bg=BASE2, fg=INK_DIM, activebackground=WAX,
                          activeforeground="#1c110d", relief="flat", padx=10, pady=6,
                          cursor="hand2", command=lambda cid=c["id"]: self.select_cipher(cid))
            b.pack(side="left", padx=(0, 6))
            self.tab_buttons[c["id"]] = b

    def _build_desc(self):
        self.desc_lbl = tk.Label(self.root, text="", bg=BASE, fg=INK_DIM, font=MONO_SM,
                                  wraplength=680, justify="left", anchor="w")
        self.desc_lbl.pack(fill="x", padx=24, pady=(0, 14))

    def _build_mode(self):
        wrap = tk.Frame(self.root, bg=PAPER_LINE)
        wrap.pack(anchor="w", padx=24, pady=(0, 14))
        self.btn_encode = tk.Button(wrap, text="Sandikan", font=MONO, bg=WAX, fg="#1c110d",
                                     relief="flat", padx=16, pady=7, cursor="hand2",
                                     command=lambda: self.set_mode("encode"))
        self.btn_decode = tk.Button(wrap, text="Pecahkan", font=MONO, bg=BASE2, fg=INK_DIM,
                                     relief="flat", padx=16, pady=7, cursor="hand2",
                                     command=lambda: self.set_mode("decode"))
        self.btn_encode.pack(side="left", padx=(1, 1), pady=1)
        self.btn_decode.pack(side="left", padx=(0, 1), pady=1)

    def _build_fields(self):
        self.fields_frame = tk.Frame(self.root, bg=BASE)
        self.fields_frame.pack(fill="x", padx=24)
        self.rsa_info = tk.Label(self.root, text="", bg=BASE, fg=INK_DIM, font=MONO_SM, anchor="w")

    def _build_text_area(self):
        wrap = tk.Frame(self.root, bg=BASE)
        wrap.pack(fill="x", padx=24, pady=(4, 12))
        self.text_label = tk.Label(wrap, text="teks asli", bg=BASE, fg=BRASS, font=MONO_SM, anchor="w")
        self.text_label.pack(fill="x")
        self.text_widget = tk.Text(wrap, height=3, bg=BASE2, fg=PAPER, insertbackground=PAPER,
                                    font=MONO, relief="flat", wrap="word",
                                    highlightthickness=1, highlightbackground=PAPER_LINE,
                                    highlightcolor=BRASS, padx=10, pady=8)
        self.text_widget.pack(fill="x")

    def _build_run_button(self):
        self.run_btn = tk.Button(self.root, text="Jalankan Proses \u25b6", font=MONO_BOLD,
                                  bg=WAX, fg="#1c110d", activebackground=WAX_HOVER,
                                  relief="flat", pady=10, cursor="hand2", command=self.process)
        self.run_btn.pack(fill="x", padx=24, pady=(0, 20))

    def _build_grid_section(self):
        tk.Label(self.root, text="proses tiap huruf", bg=BASE, fg=INK_DIM, font=MONO_SM,
                 anchor="w").pack(fill="x", padx=24)
        tk.Frame(self.root, bg=PAPER_LINE, height=1).pack(fill="x", padx=24, pady=(6, 10))

        outer = tk.Frame(self.root, bg=BASE)
        outer.pack(fill="x", padx=24, pady=(0, 20))
        self.canvas = tk.Canvas(outer, bg=BASE, highlightthickness=0, height=40)
        hbar = tk.Scrollbar(outer, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=hbar.set)
        self.canvas.pack(fill="x")
        hbar.pack(fill="x")
        self.inner = tk.Frame(self.canvas, bg=BASE)
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<Shift-MouseWheel>", self._on_wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<Shift-MouseWheel>"))

    def _on_wheel(self, event):
        self.canvas.xview_scroll(int(-1 * (event.delta / 60)), "units")

    def _build_result_box(self):
        tk.Label(self.root, text="hasil sandi", bg=BASE, fg=INK_DIM, font=MONO_SM,
                 anchor="w").pack(fill="x", padx=24)
        tk.Frame(self.root, bg=PAPER_LINE, height=1).pack(fill="x", padx=24, pady=(6, 10))
        box = tk.Frame(self.root, bg=PAPER)
        box.pack(fill="x", padx=24, pady=(0, 24))
        self.result_lbl = tk.Label(box, text="HASIL PENYANDIAN", bg=PAPER, fg=WAX_DIM,
                                    font=MONO_SM, anchor="w")
        self.result_lbl.pack(fill="x", padx=16, pady=(14, 4))
        self.result_text = tk.Label(box, text="\u2014", bg=PAPER, fg=PAPER_TEXT, font=MONO_BOLD,
                                     wraplength=650, justify="left", anchor="w")
        self.result_text.pack(fill="x", padx=16, pady=(0, 14))

    # -- ganti sandi aktif --------------------------------------------------

    def select_cipher(self, cid):
        self.current = next(c for c in CIPHERS if c["id"] == cid)
        for k, b in self.tab_buttons.items():
            active = k == cid
            b.configure(bg=WAX if active else BASE2, fg="#1c110d" if active else INK_DIM)

        self.title_lbl.configure(text=self.current["title"])
        self.sub_lbl.configure(text=self.current["sub"])
        self.desc_lbl.configure(text=self.current["desc"])

        for w in self.fields_frame.winfo_children():
            w.destroy()
        self.field_vars = {}
        for fid, label, default in self.current["fields"]:
            cell = tk.Frame(self.fields_frame, bg=BASE)
            cell.pack(side="left", padx=(0, 14), pady=(0, 14), anchor="n")
            tk.Label(cell, text=label, bg=BASE, fg=BRASS, font=MONO_SM, anchor="w").pack(fill="x")
            var = tk.StringVar(value=default)
            tk.Entry(cell, textvariable=var, bg=BASE2, fg=PAPER, insertbackground=PAPER,
                      font=MONO, relief="flat", highlightthickness=1,
                      highlightbackground=PAPER_LINE, highlightcolor=BRASS, width=16).pack()
            self.field_vars[fid] = var

        if self.current["kind"] == "rsa":
            self.rsa_info.pack(fill="x", padx=24, pady=(0, 14))
        else:
            self.rsa_info.pack_forget()

        labels = {"xor": "teks (encode) / heksadesimal (decode)",
                  "rsa": "teks (encode) / angka sandi (decode)"}
        self.text_label.configure(text=labels.get(self.current["kind"], "teks asli"))

        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", self.current["sample"])

        self.set_mode("encode")

    def set_mode(self, m):
        self.mode = m
        self.btn_encode.configure(bg=WAX if m == "encode" else BASE2,
                                   fg="#1c110d" if m == "encode" else INK_DIM)
        self.btn_decode.configure(bg=WAX if m == "decode" else BASE2,
                                   fg="#1c110d" if m == "decode" else INK_DIM)
        self.result_lbl.configure(text="HASIL PENYANDIAN" if m == "encode" else "HASIL PEMECAHAN")
        self.process()

    def get_field(self, fid):
        return self.field_vars[fid].get().strip()

    # -- render area "proses tiap huruf" ------------------------------------

    def _clear_inner(self):
        for w in self.inner.winfo_children():
            w.destroy()

    def _refresh_scroll(self):
        self.inner.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"),
                               height=self.inner.winfo_reqheight())

    def make_grid_frame(self, parent, rows, headers, classes, wide=False):
        cell_bg = {"plain": CELL_PLAIN, "key": CELL_KEY, "out": CELL_OUT, "shift": BASE}
        cell_fg = {"plain": PAPER, "key": BRASS, "out": OUT_TEXT, "shift": INK_DIM}
        cell_w = 6 if wide else 3
        frame = tk.Frame(parent, bg=BASE)
        tags = tk.Frame(frame, bg=BASE)
        tags.pack(side="left")
        for h in headers:
            tk.Label(tags, text=h, bg=BASE, fg=INK_DIM, font=MONO_SM, width=10,
                      anchor="w").pack(fill="x", pady=1)
        cols = tk.Frame(frame, bg=BASE)
        cols.pack(side="left")
        for row in rows:
            blank = row[1] == "" and len(row) == 4  # kolom "kunci" kosong = huruf lolos apa adanya
            col = tk.Frame(cols, bg=BASE)
            col.pack(side="left", padx=1)
            for i, val in enumerate(row):
                cls = classes[i]
                if blank and i != 0:
                    lbl = tk.Label(col, text="", bg=BASE, width=cell_w, font=MONO_SM)
                elif blank:
                    lbl = tk.Label(col, text=val, bg=BASE, fg=INK_DIM, width=cell_w, font=MONO)
                else:
                    lbl = tk.Label(col, text=val, bg=cell_bg[cls], fg=cell_fg[cls],
                                    width=cell_w, font=MONO_SM if cls == "shift" else MONO)
                lbl.pack(pady=1)
        return frame

    def make_zigzag_frame(self, parent, text, pattern, rails):
        frame = tk.Frame(parent, bg=BASE)
        tags = tk.Frame(frame, bg=BASE)
        tags.pack(side="left")
        for r in range(rails):
            tk.Label(tags, text=f"baris {r + 1}", bg=BASE, fg=INK_DIM, font=MONO_SM,
                      width=10, anchor="w").pack(fill="x", pady=1)
        cols = tk.Frame(frame, bg=BASE)
        cols.pack(side="left")
        for i, ch in enumerate(text):
            col = tk.Frame(cols, bg=BASE)
            col.pack(side="left", padx=1)
            for r in range(rails):
                if pattern[i] == r:
                    tk.Label(col, text=ch, bg=CELL_OUT, fg=OUT_TEXT, width=3, font=MONO).pack(pady=1)
                else:
                    tk.Label(col, text="", bg=BASE, width=3, font=MONO).pack(pady=1)
        return frame

    def render_single(self, frame_builder):
        self._clear_inner()
        frame_builder(self.inner).pack(anchor="w")
        self._refresh_scroll()

    def render_double(self, label1, builder1, label2, builder2):
        self._clear_inner()
        tk.Label(self.inner, text=label1, bg=BASE, fg=BRASS, font=MONO_SM,
                  anchor="w").pack(fill="x", pady=(0, 6))
        builder1(self.inner).pack(anchor="w", pady=(0, 14))
        tk.Label(self.inner, text=label2, bg=BASE, fg=BRASS, font=MONO_SM,
                  anchor="w").pack(fill="x", pady=(0, 6))
        builder2(self.inner).pack(anchor="w")
        self._refresh_scroll()

    def show_error(self, msg):
        self._clear_inner()
        tk.Label(self.inner, text=msg, bg=BASE, fg=INK_DIM, font=("Georgia", 11, "italic"),
                  anchor="w", wraplength=650, justify="left").pack(anchor="w")
        self._refresh_scroll()
        self.result_text.configure(text="\u2014")

    def set_result(self, text):
        self.result_text.configure(text=text if text else "\u2014")

    # -- proses tiap sandi ---------------------------------------------------

    def process(self):
        text = self.text_widget.get("1.0", "end-1c")
        if not text.strip():
            self.show_error("Isi teks yang ingin diproses.")
            return
        try:
            kind = self.current["kind"]
            if kind == "sub":
                self._process_sub(text)
            elif kind == "xor":
                self._process_xor(text)
            elif kind == "rsa":
                self._process_rsa(text)
            elif kind == "super":
                self._process_super(text)
        except Exception as err:
            self.show_error(str(err))

    def _process_sub(self, text):
        encode = self.mode == "encode"
        if self.current["id"] == "caesar":
            shift = int(self.get_field("shift") or 0)
            output, rows = caesar(text, shift, encode)
        else:
            output, rows = vigenere(text, self.get_field("key"), encode)
        headers, classes = ["asli", "kunci", "geser", "hasil"], ["plain", "key", "shift", "out"]
        self.render_single(lambda p: self.make_grid_frame(p, rows, headers, classes))
        self.set_result(output)

    def _process_xor(self, text):
        key = self.get_field("key")
        if self.mode == "encode":
            output, rows = xor_encode(text, key)
            headers = ["asli", "kunci", "hasil (hex)"]
        else:
            output, rows = xor_decode(text, key)
            headers = ["sandi (hex)", "kunci", "hasil"]
        self.render_single(lambda p: self.make_grid_frame(p, rows, headers, ["plain", "key", "out"]))
        self.set_result(output)

    def _process_rsa(self, text):
        p, q, e = int(self.get_field("p")), int(self.get_field("q")), int(self.get_field("e"))
        n, phi, d = rsa_setup(p, q, e)
        self.rsa_info.configure(text=f"n = {p}x{q} = {n}    phi(n) = {phi}    d = {d}")
        if self.mode == "encode":
            output, rows = rsa_encrypt(text, e, n)
            headers = ["huruf", "m", "c"]
        else:
            output, rows = rsa_decrypt(text, d, n)
            headers = ["c", "m", "huruf"]
        self.render_single(lambda p_: self.make_grid_frame(p_, rows, headers, ["plain", "key", "out"], wide=True))
        self.set_result(output)

    def _process_super(self, text):
        key = self.get_field("key")
        rails = int(self.get_field("rails") or 3)
        if rails < 2:
            rails = 2
        headers, classes = ["asli", "kunci", "geser", "hasil"], ["plain", "key", "shift", "out"]
        if self.mode == "encode":
            output, stage1, rows1, pattern = super_encrypt(text, key, rails)
            self.render_double(
                "tahap 1 — substitusi Vigenere", lambda p: self.make_grid_frame(p, rows1, headers, classes),
                "tahap 2 — transposisi pagar", lambda p: self.make_zigzag_frame(p, stage1, pattern, rails))
        else:
            output, stage1, rows2, pattern = super_decrypt(text, key, rails)
            self.render_double(
                "tahap 1 — balik transposisi pagar", lambda p: self.make_zigzag_frame(p, stage1, pattern, rails),
                "tahap 2 — balik substitusi Vigenere", lambda p: self.make_grid_frame(p, rows2, headers, classes))
        self.set_result(output)


if __name__ == "__main__":
    root = tk.Tk()
    app = ArsipSandiApp(root)
    root.mainloop()
