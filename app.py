import hashlib
import hmac
import html
import io
import json
import os
import random
import sqlite3
import struct
import time
import zlib

import streamlit as st
from streamlit_option_menu import option_menu

# ---------------------------------------------
# ALGORITMA KLASIK & MODERN (tidak diubah)
# ---------------------------------------------

def caesar_cipher(text, shift, mode):
    result = ""
    process_log = []
    shift = shift if mode == "encrypt" else -shift

    for char in text:
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
            process_log.append(f"'{char}' -> Geser {shift} -> '{new_char}'")
        else:
            result += char
            process_log.append(f"'{char}' -> Tetap -> '{char}'")

    return result, process_log


def vigenere_cipher(text, key, mode):
    result = ""
    process_log = []
    key = key.upper()
    key_idx = 0

    for char in text:
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            start = ord("A") if char.isupper() else ord("a")
            key_char = key[key_idx % len(key)]
            shift = ord(key_char.upper()) - ord("A") if key_char.isalpha() else ord(key_char) % 26
            if mode == "decrypt":
                shift = -shift
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
            process_log.append(
                f"'{char}' + Kunci '{key_char}' (Shift {shift}) -> '{new_char}'"
            )
            key_idx += 1
        else:
            result += char
            process_log.append(f"'{char}' -> Tetap -> '{char}'")

    return result, process_log


def rc4(data, key):
    S = list(range(256))
    j = 0
    process_log = ["--- Inisialisasi KSA (Key Scheduling) ---"]
    key_bytes = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    process_log.append("KSA Selesai. State S diacak.")

    process_log.append("--- PRGA & XOR Stream ---")
    i = j = 0
    result = []
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        char_val = ord(char) if isinstance(char, str) else char
        cipher_val = char_val ^ K
        result.append(cipher_val)
        process_log.append(
            f"Data: {char_val} XOR Kunci Stream: {K} -> Hasil: {cipher_val}"
        )

    return result, process_log


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return -1


def rsa_process(text_or_ints, p, q, mode):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while gcd(e, phi) != 1:
        e += 1
    d = mod_inverse(e, phi)

    process_log = [
        f"Parameter: p={p}, q={q}",
        f"Modulus (n) = {n}",
        f"Totient (phi) = {phi}",
        f"Kunci Publik (e) = {e}",
        f"Kunci Privat (d) = {d}",
    ]

    result = []
    if mode == "encrypt":
        process_log.append("--- Proses Enkripsi (C = M^e mod n) ---")
        for char in text_or_ints:
            m = ord(char) if isinstance(char, str) else char
            c = pow(m, e, n)
            result.append(c)
            process_log.append(f"M: {m} -> {m}^{e} mod {n} = {c}")
    else:
        process_log.append("--- Proses Dekripsi (M = C^d mod n) ---")
        for c in text_or_ints:
            m = pow(c, d, n)
            result.append(m)
            process_log.append(f"C: {c} -> {c}^{d} mod {n} = {m}")

    return result, process_log


# ---------------------------------------------
# FITUR BARU 1: AES-128 (untuk enkripsi file)
# Implementasi manual AES-128 ECB mode
# ---------------------------------------------

AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
AES_INV_SBOX = [0]*256
for i,v in enumerate(AES_SBOX):
    AES_INV_SBOX[v] = i

AES_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _aes_xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def _aes_gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _sub_bytes(state):
    return [AES_SBOX[b] for b in state]

def _inv_sub_bytes(state):
    return [AES_INV_SBOX[b] for b in state]

def _shift_rows(s):
    return [
        s[0],s[5],s[10],s[15],
        s[4],s[9],s[14],s[3],
        s[8],s[13],s[2],s[7],
        s[12],s[1],s[6],s[11],
    ]

def _inv_shift_rows(s):
    return [
        s[0],s[13],s[10],s[7],
        s[4],s[1],s[14],s[11],
        s[8],s[5],s[2],s[15],
        s[12],s[9],s[6],s[3],
    ]

def _mix_col(col):
    a,b,c,d = col
    return [
        _aes_gmul(a,2)^_aes_gmul(b,3)^c^d,
        a^_aes_gmul(b,2)^_aes_gmul(c,3)^d,
        a^b^_aes_gmul(c,2)^_aes_gmul(d,3),
        _aes_gmul(a,3)^b^c^_aes_gmul(d,2),
    ]

def _inv_mix_col(col):
    a,b,c,d = col
    return [
        _aes_gmul(a,14)^_aes_gmul(b,11)^_aes_gmul(c,13)^_aes_gmul(d,9),
        _aes_gmul(a,9)^_aes_gmul(b,14)^_aes_gmul(c,11)^_aes_gmul(d,13),
        _aes_gmul(a,13)^_aes_gmul(b,9)^_aes_gmul(c,14)^_aes_gmul(d,11),
        _aes_gmul(a,11)^_aes_gmul(b,13)^_aes_gmul(c,9)^_aes_gmul(d,14),
    ]

def _mix_columns(state):
    out = []
    for c in range(4):
        col = [state[c*4+r] for r in range(4)]
        out += _mix_col(col)
    return out

def _inv_mix_columns(state):
    out = []
    for c in range(4):
        col = [state[c*4+r] for r in range(4)]
        out += _inv_mix_col(col)
    return out

def _add_round_key(state, rk, rnd):
    return [state[i] ^ rk[rnd*16 + i] for i in range(16)]

def _key_expansion(key_bytes):
    w = list(key_bytes[:16])
    for i in range(4, 44):
        temp = w[(i-1)*4:i*4]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= AES_RCON[i//4]
        prev = w[(i-4)*4:(i-3)*4]
        w += [temp[j]^prev[j] for j in range(4)]
    # convert word-major to column-major for each round
    rk = []
    for rnd in range(11):
        block = w[rnd*16:(rnd+1)*16]
        # columns: c0=bytes 0-3, c1=4-7, c2=8-11, c3=12-15
        # state is column-major: col0_row0, col0_row1, col0_row2, col0_row3, col1_row0, ...
        col_major = []
        for c in range(4):
            for r in range(4):
                col_major.append(block[r*4+c])
        rk += col_major
    return rk

def _aes_encrypt_block(block16, rk):
    state = []
    for c in range(4):
        for r in range(4):
            state.append(block16[r*4+c])
    state = _add_round_key(state, rk, 0)
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rk, rnd)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rk, 10)
    out = [0]*16
    for c in range(4):
        for r in range(4):
            out[r*4+c] = state[c*4+r]
    return bytes(out)

def _aes_decrypt_block(block16, rk):
    state = []
    for c in range(4):
        for r in range(4):
            state.append(block16[r*4+c])
    state = _add_round_key(state, rk, 10)
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rk, rnd)
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rk, 0)
    out = [0]*16
    for c in range(4):
        for r in range(4):
            out[r*4+c] = state[c*4+r]
    return bytes(out)

def aes_encrypt(data: bytes, key_str: str) -> bytes:
    """AES-128 ECB encrypt with PKCS#7 padding."""
    key_bytes = hashlib.md5(key_str.encode()).digest()  # 16-byte key dari MD5
    rk = _key_expansion(key_bytes)
    # PKCS#7 padding
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)
    result = b""
    for i in range(0, len(data), 16):
        result += _aes_encrypt_block(data[i:i+16], rk)
    return result

def aes_decrypt(data: bytes, key_str: str) -> bytes:
    """AES-128 ECB decrypt with PKCS#7 unpadding."""
    key_bytes = hashlib.md5(key_str.encode()).digest()
    rk = _key_expansion(key_bytes)
    result = b""
    for i in range(0, len(data), 16):
        result += _aes_decrypt_block(data[i:i+16], rk)
    # Remove PKCS#7 padding
    pad = result[-1]
    return result[:-pad]


# ---------------------------------------------
# FITUR BARU 2: STEGANOGRAFI LSB (PNG/BMP)
# ---------------------------------------------

def _read_png_pixels(data: bytes):
    """Extract raw pixel bytes from uncompressed PNG IDAT (simplified, works for small images)."""
    raise NotImplementedError

def steg_encode_lsb(image_bytes: bytes, message: str) -> bytes:
    """
    Sembunyikan pesan dalam gambar menggunakan metode LSB pada byte pixel.
    Bekerja pada raw bytes (BMP atau PNG). Untuk PNG digunakan header passthrough.
    Kembalikan bytes gambar yang sudah disisipi pesan.
    """
    msg_bytes = (message + "\x00").encode("utf-8")
    msg_bits = "".join(f"{b:08b}" for b in msg_bytes)
    img = bytearray(image_bytes)

    # Cari offset pixel data (untuk BMP: offset di byte 10-13, untuk PNG: skip 8-byte signature + chunks)
    # Pendekatan sederhana: ubah LSB setiap byte mulai dari byte ke-54 (BMP header standard)
    offset = 54  # BMP standar
    if image_bytes[:4] == b'\x89PNG':
        # Untuk PNG, embed setelah signature + IHDR chunk (sederhana: offset tetap 33)
        offset = 41

    if offset + len(msg_bits) > len(img):
        raise ValueError(f"Gambar terlalu kecil. Butuh minimal {offset + len(msg_bits)} byte kapasitas.")

    for i, bit in enumerate(msg_bits):
        img[offset + i] = (img[offset + i] & 0xFE) | int(bit)

    return bytes(img)


def steg_decode_lsb(image_bytes: bytes) -> str:
    """Ekstrak pesan tersembunyi dari gambar LSB."""
    img = bytearray(image_bytes)
    offset = 54
    if image_bytes[:4] == b'\x89PNG':
        offset = 41

    bits = ""
    msg = ""
    for i in range(offset, len(img)):
        bits += str(img[i] & 1)
        if len(bits) == 8:
            char = chr(int(bits, 2))
            if char == "\x00":
                break
            msg += char
            bits = ""
    return msg


# ---------------------------------------------
# FITUR BARU 3: BLOCKCHAIN SEDERHANA
# ---------------------------------------------

def _hash_block(block: dict) -> str:
    block_copy = {k: v for k, v in block.items() if k != "hash"}
    block_str = json.dumps(block_copy, sort_keys=True)
    return hashlib.sha256(block_str.encode()).hexdigest()

def create_genesis_block() -> dict:
    block = {
        "index": 0,
        "timestamp": "2026-01-01T00:00:00",
        "data": "Genesis Block",
        "prev_hash": "0" * 64,
    }
    block["hash"] = _hash_block(block)
    return block

def add_block(chain: list, data: str) -> dict:
    prev = chain[-1]
    block = {
        "index": len(chain),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "data": data,
        "prev_hash": prev["hash"],
    }
    block["hash"] = _hash_block(block)
    return block

def validate_chain(chain: list) -> tuple:
    """Validasi integritas chain. Return (valid: bool, detail: list)."""
    details = []
    valid = True
    for i in range(1, len(chain)):
        blk = chain[i]
        prev = chain[i-1]
        recalc = _hash_block(blk)
        ok_hash = recalc == blk["hash"]
        ok_link = blk["prev_hash"] == prev["hash"]
        status = "OK" if (ok_hash and ok_link) else "ERROR"
        if not (ok_hash and ok_link):
            valid = False
        details.append(f"{status} Blok #{blk['index']} - hash {'OK' if ok_hash else 'INVALID'}, link {'OK' if ok_link else 'BROKEN'}")
    return valid, details


# ---------------------------------------------
# FITUR BARU 4: ENKRIPSI DATABASE (SQLite)
# Pesan dienkripsi dengan RC4 sebelum disimpan
# ---------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pesan_kripto.db")

def _db_init():
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "CREATE TABLE IF NOT EXISTS pesan "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, ciphertext TEXT, ts TEXT)"
    )
    con.commit()
    return con

def db_simpan_pesan(label: str, plaintext: str, key: str):
    """Enkripsi plaintext dengan RC4 lalu simpan hex ke DB."""
    cipher_bytes, _ = rc4(plaintext, key)
    hex_str = " ".join(f"{b:02x}" for b in cipher_bytes)
    con = _db_init()
    con.execute(
        "INSERT INTO pesan (label, ciphertext, ts) VALUES (?, ?, ?)",
        (label, hex_str, time.strftime("%Y-%m-%d %H:%M:%S"))
    )
    con.commit()
    con.close()

def db_baca_pesan(key: str) -> list:
    """Baca semua pesan dari DB dan dekripsi."""
    con = _db_init()
    rows = con.execute("SELECT id, label, ciphertext, ts FROM pesan ORDER BY id").fetchall()
    con.close()
    result = []
    for row in rows:
        rid, label, hex_str, ts = row
        try:
            cipher_bytes = [int(x, 16) for x in hex_str.split()]
            plain_bytes, _ = rc4(cipher_bytes, key)
            plaintext = "".join(chr(b) for b in plain_bytes)
        except Exception:
            plaintext = "(gagal dekripsi)"
        result.append({"id": rid, "label": label, "plaintext": plaintext, "ts": ts, "ciphertext": hex_str})
    return result

def db_hapus_pesan(pid: int):
    con = _db_init()
    con.execute("DELETE FROM pesan WHERE id = ?", (pid,))
    con.commit()
    con.close()


# ---------------------------------------------
# FITUR BARU 5: AUTENTIKASI LOGIN (SHA-256)
# ---------------------------------------------

# Password default di-hash SHA-256. Untuk demo: password = "admin123"
DEFAULT_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
DEFAULT_USERNAME = "admin"

def check_login(username: str, password: str) -> bool:
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == DEFAULT_USERNAME and hmac.compare_digest(pwd_hash, DEFAULT_PASSWORD_HASH)


# ---------------------------------------------
# PAGE CONFIG & GLOBAL CSS
# ---------------------------------------------

st.set_page_config(
    page_title="Modul Kriptosistem",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --bg: #F4F5FB;
    --surface: #FFFFFF;
    --ink: #0B1020;
    --muted: #667085;
    --line: #E4E7F0;
    --primary: #6366F1;
    --primary-dark: #4F46E5;
    --accent: #8B5CF6;
    --side: #0B1020;
    --side-2: #151B33;
    --ok: #16A34A;
    --warn: #D97706;
    --shadow: 0 1px 2px rgba(16,24,40,.04), 0 8px 24px rgba(16,24,40,.06);
}

html, body, [class*="css"], .stApp {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}
.stApp { background: var(--bg); color: var(--ink); }

/* Sembunyikan chrome bawaan Streamlit */
#MainMenu, footer { visibility: hidden; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stDecoration"] { display: none; }

.block-container {
    padding-top: 1.6rem;
    padding-bottom: 3rem;
    max-width: 1180px;
    animation: fadeInUp .35s cubic-bezier(.16,1,.3,1) both;
}
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* --------- Teks umum (pastikan terbaca di tema gelap/terang) --------- */
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 { color: var(--ink); letter-spacing: -0.01em; }
[data-testid="stWidgetLabel"] p, [data-testid="stWidgetLabel"] label {
    color: var(--ink) !important; font-weight: 600; font-size: .85rem;
}
[data-testid="stCaptionContainer"], .stApp small { color: var(--muted) !important; }
.stApp [data-testid="stMarkdownContainer"] p { color: var(--ink); }

/* --------- Header --------- */
.header-box {
    position: relative; overflow: hidden;
    background: linear-gradient(120deg, #312E81 0%, #4F46E5 45%, #8B5CF6 100%);
    border-radius: 18px; padding: 1.6rem 1.9rem; margin-bottom: 1.1rem;
    display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
    box-shadow: 0 12px 32px rgba(79,70,229,.28);
}
.header-box::before, .header-box::after {
    content: ""; position: absolute; border-radius: 50%; background: rgba(255,255,255,.08);
}
.header-box::before { width: 220px; height: 220px; right: -60px; top: -90px; }
.header-box::after  { width: 140px; height: 140px; right: 120px; bottom: -80px; }
.header-box h1 {
    font-size: 1.55rem; font-weight: 800; margin: 0; color: #FFFFFF !important; letter-spacing: -0.02em;
}
.header-box p { margin: .3rem 0 0; color: rgba(255,255,255,.82) !important; font-size: .9rem; }
.header-pills { display: flex; gap: .5rem; flex-wrap: wrap; position: relative; z-index: 1; }
.pill {
    background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.28);
    color: #fff; padding: .35rem .8rem; border-radius: 999px; font-size: .75rem; font-weight: 600;
    backdrop-filter: blur(6px);
}

/* --------- Sidebar --------- */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, var(--side) 0%, var(--side-2) 100%);
    border-right: 1px solid rgba(255,255,255,.06);
}
[data-testid="stSidebar"] * { color: #E2E8F0; }
.brand { display: flex; align-items: center; gap: .75rem; padding: .4rem .25rem 1rem; }
.brand-logo {
    width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; font-size: 1.3rem;
    background: linear-gradient(135deg, #6366F1, #8B5CF6); box-shadow: 0 6px 16px rgba(99,102,241,.45);
}
.brand-name { font-weight: 800; font-size: 1.05rem; color: #FFFFFF !important; line-height: 1.1; }
.brand-sub  { font-size: .72rem; color: #94A3B8 !important; margin-top: 2px; }
.nav-label {
    font-size: .68rem; text-transform: uppercase; letter-spacing: .12em; color: #64748B !important;
    font-weight: 700; padding: .2rem .5rem .4rem;
}
.side-user {
    display: flex; align-items: center; gap: .6rem; padding: .65rem .8rem; margin: .5rem 0 .6rem;
    background: rgba(255,255,255,.05); border: 1px solid rgba(255,255,255,.08); border-radius: 10px;
    font-size: .82rem; color: #CBD5E1 !important;
}
.side-user .dot { width: 8px; height: 8px; border-radius: 50%; background: #22C55E; box-shadow: 0 0 0 3px rgba(34,197,94,.25); }
[data-testid="stSidebar"] div.stButton > button {
    background: transparent; color: #FCA5A5 !important; border: 1px solid rgba(252,165,165,.35);
    box-shadow: none;
}
[data-testid="stSidebar"] div.stButton > button:hover {
    background: rgba(239,68,68,.12); border-color: #F87171; color: #FEE2E2 !important; transform: none;
}

/* --------- Kartu algoritma --------- */
.algo-card {
    background: var(--surface); border-radius: 14px; padding: 1.1rem 1.3rem;
    border: 1px solid var(--line); border-left: 4px solid var(--primary);
    margin-bottom: 1.1rem; box-shadow: var(--shadow);
}
.algo-card.k-klasik { border-left-color: #2563EB; }
.algo-card.k-modern { border-left-color: #16A34A; }
.algo-card.k-new    { border-left-color: #D97706; }
.algo-header { display: flex; align-items: center; gap: .6rem; margin-bottom: .4rem; flex-wrap: wrap; }
.algo-card h3 { margin: 0; font-size: 1.15rem; font-weight: 700; color: var(--ink) !important; }
.algo-card p  { color: var(--muted) !important; font-size: .9rem; line-height: 1.55; margin: 0; }

.badge {
    display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 999px;
    font-size: .66rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
}
.badge-klasik { background: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; }
.badge-modern { background: #F0FDF4; color: #16A34A; border: 1px solid #BBF7D0; }
.badge-new    { background: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; }

/* --------- Input --------- */
.stTextArea textarea, .stTextInput input, .stNumberInput input {
    background: #FFFFFF !important; color: var(--ink) !important;
    border: 1px solid var(--line) !important; border-radius: 10px !important;
    font-size: .92rem;
}
.stTextArea textarea::placeholder, .stTextInput input::placeholder { color: #98A2B3 !important; }
.stTextArea textarea:focus, .stTextInput input:focus, .stNumberInput input:focus {
    border-color: var(--primary) !important; box-shadow: 0 0 0 3px rgba(99,102,241,.18) !important;
}
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="base-input"] {
    background: #FFFFFF !important; border-radius: 10px !important;
}
[data-testid="stNumberInput"] button { background: #F8FAFC !important; color: var(--ink) !important; }

/* File uploader */
[data-testid="stFileUploaderDropzone"] {
    background: #FFFFFF; border: 2px dashed #C7CCF5; border-radius: 14px; transition: all .15s ease;
}
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--primary); background: #F5F6FF; }
[data-testid="stFileUploaderDropzone"] * { color: var(--muted) !important; }
[data-testid="stFileUploaderDropzone"] button { color: var(--primary-dark) !important; }

/* Radio sebagai segmented control */
div[role="radiogroup"] { gap: .35rem; }
div[role="radiogroup"] > label {
    background: #FFFFFF; border: 1px solid var(--line); border-radius: 10px;
    padding: .4rem .9rem; transition: all .15s ease; cursor: pointer;
}
div[role="radiogroup"] > label:hover { border-color: var(--primary); }
div[role="radiogroup"] > label:has(input:checked) {
    background: linear-gradient(135deg, #6366F1, #8B5CF6); border-color: transparent;
    box-shadow: 0 6px 14px rgba(99,102,241,.3);
}
div[role="radiogroup"] > label:has(input:checked) p { color: #FFFFFF !important; font-weight: 700; }
div[role="radiogroup"] > label > div:first-child { display: none; }

/* --------- Tombol --------- */
div.stButton > button, div.stFormSubmitButton > button, div.stDownloadButton > button {
    background: linear-gradient(135deg, #6366F1, #7C3AED); color: #FFFFFF !important; border: none;
    border-radius: 10px; padding: .6rem 1.2rem; font-weight: 600; font-size: .9rem; width: 100%;
    box-shadow: 0 6px 16px rgba(99,102,241,.28); transition: all .15s ease;
}
div.stButton > button:hover, div.stFormSubmitButton > button:hover, div.stDownloadButton > button:hover {
    filter: brightness(1.08); transform: translateY(-1px); color: #FFFFFF !important;
    box-shadow: 0 10px 22px rgba(99,102,241,.38);
}
div.stButton > button:active { transform: translateY(0); }
div.stButton > button p, div.stFormSubmitButton > button p, div.stDownloadButton > button p { color: #FFFFFF !important; }

/* --------- Hasil & log --------- */
.result-title { font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 1rem 0 .4rem; }
.result-box {
    background: #0F172A; border-radius: 12px; border-left: 4px solid #22D3EE;
    padding: 1rem 1.2rem; font-family: 'JetBrains Mono', monospace; font-size: .9rem;
    color: #E2E8F0; word-wrap: break-word; white-space: pre-wrap; box-shadow: var(--shadow);
}
.log-line {
    font-family: 'JetBrains Mono', monospace; font-size: .8rem; padding: .3rem 0;
    border-bottom: 1px dashed var(--line); color: #334155;
}

/* --------- Pipeline --------- */
.pipeline { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; margin-bottom: 1rem; }
.pipeline-step {
    background: #FFFFFF; color: var(--ink); padding: .4rem .85rem; border-radius: 999px;
    font-size: .8rem; font-weight: 600; border: 1px solid var(--line); box-shadow: 0 1px 2px rgba(16,24,40,.05);
}
.pipeline-arrow { color: var(--primary); font-weight: 700; }

/* --------- Expander --------- */
[data-testid="stExpander"] {
    background: #FFFFFF; border: 1px solid var(--line) !important; border-radius: 12px; box-shadow: var(--shadow);
}
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: var(--ink) !important; font-weight: 600; }
[data-testid="stExpander"] p, [data-testid="stExpander"] li, [data-testid="stExpander"] span,
[data-testid="stExpander"] td, [data-testid="stExpander"] th { color: var(--ink); }
[data-testid="stExpander"] pre, [data-testid="stExpander"] [data-testid="stCode"] pre,
[data-testid="stExpander"] [data-testid="stCodeBlock"] pre {
    background: #0F172A !important; border-radius: 10px;
}
[data-testid="stExpander"] pre code, [data-testid="stExpander"] pre span,
[data-testid="stExpander"] [data-testid="stCode"] span, [data-testid="stExpander"] [data-testid="stCodeBlock"] span {
    color: #E2E8F0 !important; -webkit-text-fill-color: #E2E8F0 !important;
}
[data-testid="stExpander"] code { background: #EEF0FF; color: #4338CA !important; border-radius: 6px; padding: 1px 6px; }

/* --------- Tabs --------- */
.stTabs [data-baseweb="tab-list"] { gap: .4rem; border-bottom: 1px solid var(--line); }
.stTabs [data-baseweb="tab"] {
    background: transparent; border-radius: 10px 10px 0 0; padding: .5rem 1rem; color: var(--muted); font-weight: 600;
}
.stTabs [aria-selected="true"] { color: var(--primary-dark) !important; background: #EEF0FF; }
.stTabs [data-baseweb="tab-highlight"] { background: var(--primary) !important; }

/* --------- Alert --------- */
[data-testid="stAlert"] { border-radius: 12px; border: 1px solid var(--line); }
[data-testid="stAlert"] p { color: inherit !important; }

/* --------- Login --------- */
.login-hero { text-align: center; margin: 2.2rem 0 1.2rem; }
.login-logo {
    width: 68px; height: 68px; margin: 0 auto 1rem; border-radius: 20px; display: grid; place-items: center; font-size: 2rem;
    background: linear-gradient(135deg, #6366F1, #8B5CF6); box-shadow: 0 14px 34px rgba(99,102,241,.45);
}
.login-hero h2 { font-size: 1.6rem; font-weight: 800; margin: 0 0 .3rem; color: var(--ink) !important; }
.login-hero p  { color: var(--muted) !important; font-size: .9rem; margin: 0; }
[data-testid="stForm"] {
    background: #FFFFFF; border: 1px solid var(--line); border-radius: 18px; padding: 1.6rem 1.7rem;
    box-shadow: 0 20px 50px rgba(16,24,40,.10);
}
.login-hint {
    text-align: center; margin-top: 1rem; font-size: .8rem; color: var(--muted) !important;
    background: #FFFFFF; border: 1px dashed #C7CCF5; border-radius: 12px; padding: .7rem;
}
.login-hint code { background: #EEF0FF; color: #4338CA; padding: 1px 6px; border-radius: 6px; }

/* --------- Blockchain --------- */
.chain-stats { display: flex; gap: .75rem; flex-wrap: wrap; margin: .6rem 0 1rem; }
.stat {
    background: #FFFFFF; border: 1px solid var(--line); border-radius: 12px; padding: .7rem 1.1rem; min-width: 130px; box-shadow: var(--shadow);
}
.stat .n { font-size: 1.4rem; font-weight: 800; color: var(--primary-dark); line-height: 1.1; }
.stat .l { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; font-weight: 600; }
.blk-wrap { position: relative; padding-left: 26px; }
.blk-wrap::before {
    content: ""; position: absolute; left: 8px; top: 8px; bottom: 8px; width: 2px;
    background: linear-gradient(180deg, #6366F1, #C7CCF5);
}
.blk-card {
    position: relative; background: #FFFFFF; border: 1px solid var(--line); border-radius: 12px;
    padding: .85rem 1.1rem; margin-bottom: .75rem; font-size: .82rem; color: var(--ink);
    font-family: 'JetBrains Mono', monospace; box-shadow: var(--shadow);
}
.blk-card::before {
    content: ""; position: absolute; left: -24px; top: 18px; width: 12px; height: 12px; border-radius: 50%;
    background: #6366F1; border: 3px solid var(--bg); box-shadow: 0 0 0 2px #6366F1;
}
.blk-card.genesis::before { background: #D97706; box-shadow: 0 0 0 2px #D97706; }
.blk-card .blk-idx { font-weight: 800; color: var(--primary-dark); font-size: .9rem; }
.blk-card .blk-hash { color: var(--muted); word-break: break-all; font-size: .76rem; }
.blk-card .blk-data { margin: .35rem 0; color: var(--ink); }

hr { border-color: var(--line) !important; }

</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------
# SESSION STATE
# ---------------------------------------------

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "blockchain" not in st.session_state:
    st.session_state.blockchain = [create_genesis_block()]


# ---------------------------------------------
# HALAMAN LOGIN
# ---------------------------------------------

if not st.session_state.logged_in:
    st.markdown(
        """
        <div class="login-hero">
            <div class="login-logo"></div>
            <h2>KriptoLab</h2>
            <p>Masuk untuk mengakses modul kriptosistem.<br/>Password divalidasi dengan SHA-256.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    _l, _m, _r = st.columns([1, 1.2, 1])
    with _m:
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="admin")
            password = st.text_input("Password", type="password", placeholder="--------")
            submitted = st.form_submit_button("Masuk")

        if submitted:
            if check_login(username, password):
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("Username atau password salah.")

        st.markdown(
            f"""
            <div class="login-hint">
                Demo: <code>admin</code> / <code>admin123</code><br/>
                SHA-256: <code>{DEFAULT_PASSWORD_HASH[:20]}...</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.stop()


# ---------------------------------------------
# HEADER (hanya tampil saat sudah login)
# ---------------------------------------------

st.markdown(
    f"""
<div class="header-box">
    <div style="position:relative;z-index:1;">
        <h1>Sistem Kriptografi Interaktif</h1>
        <p>Pelajari algoritma klasik, modern, dan teknik keamanan data secara langsung.</p>
    </div>
    <div class="header-pills">
        <span class="pill">[MODUL] {9} modul</span>
        <span class="pill">[LOCKED] Sesi aktif</span>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

menu_options = [
    "Caesar Cipher",
    "Vigenere Cipher",
    "RC4",
    "RSA",
    "Super Enkripsi",
    "Enkripsi File (AES)",
    "Steganografi",
    "Enkripsi Database",
    "Blockchain",
]

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-logo"></div>
            <div>
                <div class="brand-name">KriptoLab</div>
                <div class="brand-sub">Modul Kriptosistem</div>
            </div>
        </div>
        <div class="nav-label">Menu</div>
        """,
        unsafe_allow_html=True,
    )
    selected = option_menu(
        menu_title=None,
        options=menu_options,
        icons=["type", "key", "shuffle", "shield-lock", "layers",
               "file-earmark-lock", "image", "database", "link-45deg"],
        default_index=0,
        orientation="vertical",
        styles={
            "container": {"padding": "0", "background-color": "transparent"},
            "icon": {"font-size": "15px", "color": "#818CF8"},
            "nav-link": {
                "font-size": "14px", "font-weight": "500",
                "color": "#CBD5E1", "text-align": "left",
                "margin": "3px 0", "padding": "10px 12px", "border-radius": "10px",
                "--hover-color": "rgba(255,255,255,0.07)",
            },
            "nav-link-selected": {
                "background": "linear-gradient(135deg, #6366F1, #8B5CF6)",
                "color": "#FFFFFF", "font-weight": "600",
                "box-shadow": "0 6px 16px rgba(99,102,241,0.35)",
            },
        },
    )
    st.markdown(
        '<div class="side-user"><span class="dot"></span> Masuk sebagai <b>admin</b></div>',
        unsafe_allow_html=True,
    )
    if st.button("[LOGOUT] Logout", key="btn_logout"):
        st.session_state.logged_in = False
        st.rerun()

TEXT_ALGOS = ("Caesar Cipher", "Vigenere Cipher", "RC4", "RSA", "Super Enkripsi")
if selected in TEXT_ALGOS:
    _mc, _hc = st.columns([2, 3])
    with _mc:
        mode_choice = st.radio("Mode Operasi", ["Enkripsi", "Dekripsi"], horizontal=True, key="mode_op")
    with _hc:
        st.caption("Buka **Detail Proses** di bawah hasil untuk memahami langkah kerja algoritmanya.")
    is_encrypt = mode_choice == "Enkripsi"
else:
    is_encrypt = True

algo_info = {
    "Caesar Cipher": (
        "Caesar Cipher", "klasik",
        "Menggeser karakter berdasarkan nilai pergeseran tetap dalam alfabet.",
    ),
    "Vigenere Cipher": (
        "Vigenere Cipher", "klasik",
        "Menggunakan kunci alfabetik berulang untuk pergeseran karakter.",
    ),
    "RC4": (
        "RC4", "modern",
        "Stream cipher pembangkit keystream pseudorandom yang di-XOR dengan data.",
    ),
    "RSA": (
        "RSA", "modern",
        "Kriptografi asimetris berbasis eksponensial modular dan bilangan prima.",
    ),
    "Super Enkripsi": (
        "Super Enkripsi", "modern",
        "Penggabungan berlapis dari Caesar, Vigenere, RC4, dan RSA secara berurutan.",
    ),
    "Enkripsi File (AES)": (
        "Enkripsi File - AES-128", "new",
        "Enkripsi/dekripsi file dengan AES-128 ECB + PKCS#7. Algoritma berbeda dari enkripsi teks.",
    ),
    "Steganografi": (
        "Steganografi LSB", "new",
        "Sembunyikan pesan teks di dalam file gambar BMP/PNG menggunakan teknik Least Significant Bit.",
    ),
    "Enkripsi Database": (
        "Enkripsi Database", "new",
        "Pesan penting dienkripsi dengan RC4 sebelum disimpan ke database SQLite lokal.",
    ),
    "Blockchain": (
        "Blockchain Sederhana", "new",
        "Aset penting diamankan dalam struktur chain berbasis SHA-256 yang tidak dapat dimanipulasi.",
    ),
}


def render_algo_card(key):
    name, kind, desc = algo_info[key]
    badge_class = "badge-klasik" if kind == "klasik" else ("badge-modern" if kind == "modern" else "badge-new")
    st.markdown(
        f"""
    <div class="algo-card k-{kind}">
        <div class="algo-header">
            <span class="badge {badge_class}">{kind}</span>
            <h3>{name}</h3>
        </div>
        <p>{desc}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_result(title, content):
    st.markdown(f'<div class="result-title">{html.escape(title)}</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="result-box">{html.escape(str(content))}</div>', unsafe_allow_html=True
    )


def render_logs(logs):
    with st.expander(f"Detail Proses ({len(logs)} langkah)"):
        for log in logs:
            st.markdown(
                f'<div class="log-line">{html.escape(str(log))}</div>', unsafe_allow_html=True
            )


# ---------------------------------------------
# KONTEN UTAMA
# ---------------------------------------------


# -- Caesar Cipher ----------------------------
if selected == "Caesar Cipher":
    render_algo_card("Caesar Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area("Input Teks:", height=130, placeholder="Masukkan teks...")
    with col_side:
        shift = st.number_input("Nilai Shift:", min_value=1, max_value=25, value=3)
        st.caption("Jumlah nilai pergeseran (1-25).")
        st.write("")
        btn = st.button("Proses Caesar", key="btn_caesar")

    if btn:
        res, logs = caesar_cipher(text, shift, "encrypt" if is_encrypt else "decrypt")
        render_result("Hasil Output", res if res else "(kosong)")
        render_logs(logs)

# -- Vigenere Cipher --------------------------
elif selected == "Vigenere Cipher":
    render_algo_card("Vigenere Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area("Input Teks:", height=130, placeholder="Masukkan teks...")
    with col_side:
        key = st.text_input("Kunci : ", value="KUNCI")
        st.caption("Kunci alfabetik berulang.")
        st.write("")
        btn = st.button("Proses Vigenere", key="btn_vigenere")

    if btn:
        if not key:
            st.error("Kunci tidak boleh kosong")
        else:
            res, logs = vigenere_cipher(text, key, "encrypt" if is_encrypt else "decrypt")
            render_result("Hasil Output", res if res else "(kosong)")
            render_logs(logs)

# -- RC4 --------------------------------------
elif selected == "RC4":
    render_algo_card("RC4")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = "Input Teks:" if is_encrypt else "Input Hex (Pisah Spasi):"
        placeholder = "Masukkan teks..." if is_encrypt else "Contoh: 4a 6f 1c"
        text = st.text_area(label, height=130, placeholder=placeholder)
    with col_side:
        key = st.text_input("Kunci RC4:", value="SECRET")
        st.caption("Kunci string untuk inisialisasi state.")
        st.write("")
        btn = st.button("Proses RC4", key="btn_rc4")

    if btn:
        try:
            text_input = [int(x, 16) for x in text.split()] if not is_encrypt else text
            res, logs = rc4(text_input, key)
            final_res = (" ".join([hex(x)[2:].zfill(2) for x in res])
                         if is_encrypt else "".join([chr(x) for x in res]))
            render_result("Hasil Output", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error("Format input dekripsi tidak valid. Gunakan format Hexadesimal dipisah spasi.")

# -- RSA --------------------------------------
elif selected == "RSA":
    render_algo_card("RSA")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = "Input Teks:" if is_encrypt else "Input Angka (Pisah Spasi):"
        placeholder = "Masukkan teks..." if is_encrypt else "Contoh: 120 45 200"
        text = st.text_area(label, height=130, placeholder=placeholder)
    with col_side:
        sub1, sub2 = st.columns(2)
        with sub1:
            p = st.number_input("Prima p:", value=17)
        with sub2:
            q = st.number_input("Prima q:", value=19)
        st.caption(f"Modulus (n = p x q): **{p * q}**")
        btn = st.button("Proses RSA", key="btn_rsa")

    if btn:
        try:
            text_input = [int(x) for x in text.split()] if not is_encrypt else text
            res, logs = rsa_process(text_input, p, q, "encrypt" if is_encrypt else "decrypt")
            final_res = (" ".join([str(x) for x in res])
                         if is_encrypt else "".join([chr(x) for x in res]))
            render_result("Hasil Output", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error("Kesalahan komputasi RSA. Pastikan nilai (p x q) > 255.")

# -- Super Enkripsi ---------------------------
elif selected == "Super Enkripsi":
    render_algo_card("Super Enkripsi")

    if is_encrypt:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. Caesar</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">2. Vigenere</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">3. RC4</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">4. RSA</div>
        </div>"""
    else:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. RSA</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">2. RC4</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">3. Vigenere</div><div class="pipeline-arrow">-></div>
            <div class="pipeline-step">4. Caesar</div>
        </div>"""

    st.markdown(pipeline_html, unsafe_allow_html=True)

    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = "Input Teks:" if is_encrypt else "Input Angka Enkripsi (Pisah Spasi):"
        text = st.text_area(label, height=210, placeholder="Masukkan teks...")
    with col_side:
        c1, c2 = st.columns(2)
        with c1:
            c_shift = st.number_input("Shift Caesar:", value=3)
            v_key = st.text_input("Kunci Vigenere:", value="KUNCI")
        with c2:
            rc4_key = st.text_input("Kunci RC4:", value="SECRET")
            p = st.number_input("RSA p:", value=17)
        q = st.number_input("RSA q:", value=19)
        btn = st.button("Proses Super Enkripsi", key="btn_super")

    if btn:
        try:
            if is_encrypt:
                out_c, _ = caesar_cipher(text, c_shift, "encrypt")
                out_v, _ = vigenere_cipher(out_c, v_key, "encrypt")
                out_r, _ = rc4(out_v, rc4_key)
                out_rsa, _ = rsa_process(out_r, p, q, "encrypt")
                final_res = " ".join([str(x) for x in out_rsa])
                render_result("Hasil Super Enkripsi", final_res)
                with st.expander("Detail Tahapan Enkripsi (1 - 4)"):
                    t1, t2, t3, t4 = st.tabs(["1. Caesar", "2. Vigenere", "3. RC4", "4. RSA"])
                    with t1: st.code(out_c)
                    with t2: st.code(out_v)
                    with t3: st.code(" ".join([hex(x)[2:] for x in out_r]))
                    with t4: st.code(final_res)
            else:
                text_input = [int(x) for x in text.split()]
                out_rsa, _ = rsa_process(text_input, p, q, "decrypt")
                out_r, _ = rc4(out_rsa, rc4_key)
                out_r_str = "".join([chr(x) for x in out_r])
                out_v, _ = vigenere_cipher(out_r_str, v_key, "decrypt")
                out_c, _ = caesar_cipher(out_v, c_shift, "decrypt")
                render_result("Hasil Super Dekripsi", out_c)
        except Exception:
            st.error("Gagal memproses Super Enkripsi. Pastikan parameter kunci dan format input sesuai.")

# -- Enkripsi File (AES-128) ------------------
elif selected == "Enkripsi File (AES)":
    render_algo_card("Enkripsi File (AES)")

    st.info("Upload file apapun. File akan dienkripsi/didekripsi menggunakan **AES-128 ECB** - algoritma berbeda dari enkripsi teks.", icon="Info:")

    col1, col2 = st.columns([3, 2])
    with col1:
        uploaded = st.file_uploader(
            "Upload File",
            type=None,
            help="Pilih file apapun (teks, gambar, dokumen, dll.)"
        )
    with col2:
        aes_key = st.text_input("Kunci AES:", value="kunci_rahasia_123", help="Kunci akan di-hash MD5 menjadi 128-bit.")
        aes_mode = st.radio("Mode:", ["Enkripsi", "Dekripsi"], horizontal=True)
        btn_aes = st.button("Proses AES", key="btn_aes")

    if btn_aes:
        if uploaded is None:
            st.error("Silakan upload file terlebih dahulu.")
        else:
            file_bytes = uploaded.read()
            try:
                if aes_mode == "Enkripsi":
                    result_bytes = aes_encrypt(file_bytes, aes_key)
                    out_name = uploaded.name + ".enc"
                    st.success(f"File berhasil dienkripsi! ({len(file_bytes)} -> {len(result_bytes)} bytes)")
                else:
                    result_bytes = aes_decrypt(file_bytes, aes_key)
                    out_name = uploaded.name.removesuffix(".enc") if uploaded.name.endswith(".enc") else "decrypted_" + uploaded.name
                    st.success(f"File berhasil didekripsi! ({len(file_bytes)} -> {len(result_bytes)} bytes)")

                st.download_button(
                    label=f"Download {out_name}",
                    data=result_bytes,
                    file_name=out_name,
                    mime="application/octet-stream",
                )
                with st.expander("Detail AES"):
                    key_bytes = hashlib.md5(aes_key.encode()).digest()
                    st.markdown(f"**Kunci input:** `{aes_key}`")
                    st.markdown(f"**MD5 -> 128-bit key:** `{key_bytes.hex()}`")
                    st.markdown(f"**Mode:** AES-128 ECB + PKCS#7 Padding")
                    st.markdown(f"**Ukuran input:** {len(file_bytes)} bytes -> **Output:** {len(result_bytes)} bytes")
            except Exception as ex:
                st.error(f"Gagal memproses file: {ex}")

# -- Steganografi -----------------------------
elif selected == "Steganografi":
    render_algo_card("Steganografi")

    st.info("Sembunyikan atau ekstrak pesan dari gambar **BMP/PNG** menggunakan metode **LSB (Least Significant Bit)**.", icon="Info:")

    steg_tab1, steg_tab2 = st.tabs(["Sembunyikan Pesan", "Ekstrak Pesan"])

    with steg_tab1:
        col1, col2 = st.columns([3, 2])
        with col1:
            img_file = st.file_uploader("Upload Gambar (BMP/PNG)", type=["bmp", "png"], key="steg_enc_img")
        with col2:
            secret_msg = st.text_area("Pesan Rahasia:", height=100, placeholder="Pesan yang akan disembunyikan...")
            btn_hide = st.button("Sembunyikan Pesan", key="btn_steg_enc")

        if btn_hide:
            if img_file is None:
                st.error("Silakan upload gambar terlebih dahulu.")
            elif not secret_msg.strip():
                st.error("Pesan tidak boleh kosong.")
            else:
                try:
                    img_bytes = img_file.read()
                    result_img = steg_encode_lsb(img_bytes, secret_msg)
                    st.success(f"Pesan berhasil disembunyikan! ({len(secret_msg)} karakter, {len(secret_msg)*8} bit LSB diubah)")
                    st.download_button(
                        label="Download Gambar Stego",
                        data=result_img,
                        file_name="stego_" + img_file.name,
                        mime="image/bmp" if img_file.name.endswith(".bmp") else "image/png",
                    )
                    with st.expander("Detail Proses LSB"):
                        msg_bytes = (secret_msg + "\x00").encode("utf-8")
                        msg_bits = "".join(f"{b:08b}" for b in msg_bytes)
                        st.markdown(f"**Panjang pesan:** {len(secret_msg)} karakter -> {len(msg_bytes)} byte -> **{len(msg_bits)} bit**")
                        st.markdown(f"**Offset pixel awal:** byte ke-54 (BMP) / byte ke-41 (PNG)")
                        st.markdown(f"**Metode:** ubah bit terakhir (LSB) setiap byte pixel")
                        st.code(msg_bits[:64] + "..." if len(msg_bits) > 64 else msg_bits, language="text")
                except ValueError as ve:
                    st.error(str(ve))
                except Exception as ex:
                    st.error(f"Gagal menyembunyikan pesan: {ex}")

    with steg_tab2:
        col1, col2 = st.columns([3, 2])
        with col1:
            img_file2 = st.file_uploader("Upload Gambar Stego (BMP/PNG)", type=["bmp", "png"], key="steg_dec_img")
        with col2:
            btn_extract = st.button("Ekstrak Pesan", key="btn_steg_dec")

        if btn_extract:
            if img_file2 is None:
                st.error("Silakan upload gambar stego terlebih dahulu.")
            else:
                try:
                    img_bytes2 = img_file2.read()
                    extracted = steg_decode_lsb(img_bytes2)
                    if extracted:
                        render_result("Pesan Tersembunyi Ditemukan", extracted)
                    else:
                        st.warning("Tidak ditemukan pesan tersembunyi pada gambar ini.")
                except Exception as ex:
                    st.error(f"Gagal mengekstrak pesan: {ex}")

# -- Enkripsi Database -------------------------
elif selected == "Enkripsi Database":
    render_algo_card("Enkripsi Database")

    st.info(
        "Pesan penting dienkripsi menggunakan **RC4** sebelum disimpan ke database **SQLite** lokal. "
        "Gunakan kunci yang sama untuk membaca pesan.",
        icon="i"
    )

    db_tab1, db_tab2 = st.tabs(["Simpan Pesan", "Lihat & Kelola"])

    with db_tab1:
        col1, col2 = st.columns([3, 2])
        with col1:
            db_label = st.text_input("Label / Judul Pesan:", placeholder="Contoh: Kunci Brankas, Token API...")
            db_msg = st.text_area("Isi Pesan Rahasia:", height=130, placeholder="Pesan yang akan dienkripsi dan disimpan...")
        with col2:
            db_key = st.text_input("Kunci Enkripsi:", value="kunci_db", type="password")
            st.caption("Kunci RC4 untuk enkripsi pesan di database.")
            st.write("")
            btn_save = st.button("Simpan ke Database", key="btn_db_save")

        if btn_save:
            if not db_label.strip():
                st.error("Label tidak boleh kosong.")
            elif not db_msg.strip():
                st.error("Isi pesan tidak boleh kosong.")
            elif not db_key.strip():
                st.error("Kunci tidak boleh kosong.")
            else:
                try:
                    db_simpan_pesan(db_label, db_msg, db_key)
                    st.success(f"Pesan '{db_label}' berhasil dienkripsi dan disimpan ke database!")
                    cipher_bytes, _ = rc4(db_msg, db_key)
                    hex_preview = " ".join(f"{b:02x}" for b in cipher_bytes[:16])
                    st.caption(f"Preview ciphertext (16 byte pertama): `{hex_preview}...`")
                except Exception as ex:
                    st.error(f"Gagal menyimpan: {ex}")

    with db_tab2:
        col_key, col_btn = st.columns([3, 1])
        with col_key:
            read_key = st.text_input("Kunci untuk Baca:", value="kunci_db", type="password", key="db_read_key")
        with col_btn:
            st.write("")
            btn_read = st.button("[UNLOCKED] Tampilkan", key="btn_db_read")

        if btn_read or "db_rows" in st.session_state:
            try:
                rows = db_baca_pesan(read_key)
                st.session_state["db_rows"] = rows
            except Exception as ex:
                st.error(f"Gagal membaca: {ex}")
                rows = []

            rows = st.session_state.get("db_rows", [])
            if not rows:
                st.info("Database kosong. Belum ada pesan yang tersimpan.")
            else:
                st.markdown(f"**{len(rows)} pesan tersimpan:**")
                for row in rows:
                    with st.expander(f"#{row['id']} - {row['label']} ({row['ts']})"):
                        st.markdown(f"**Plaintext:** `{row['plaintext']}`")
                        st.markdown(f"**Ciphertext (hex):** `{row['ciphertext'][:60]}...`")
                        if st.button(f"[HAPUS] Hapus #{row['id']}", key=f"del_{row['id']}"):
                            db_hapus_pesan(row["id"])
                            del st.session_state["db_rows"]
                            st.rerun()

# -- Blockchain -------------------------------
elif selected == "Blockchain":
    render_algo_card("Blockchain")

    st.info(
        "Tambahkan aset/data penting ke dalam **blockchain sederhana**. "
        "Setiap blok di-hash SHA-256 dan terhubung ke blok sebelumnya - "
        "perubahan apapun pada data lama akan terdeteksi.",
        icon="!"
    )

    col1, col2 = st.columns([3, 2])
    with col1:
        chain_data = st.text_area(
            "Data / Aset yang Diamankan:",
            height=100,
            placeholder="Contoh: Sertifikat X, Token Z, Hash dokumen penting..."
        )
    with col2:
        btn_add = st.button("Tambah Blok", key="btn_chain_add")
        btn_val = st.button("Validasi Chain", key="btn_chain_val")
        btn_reset = st.button("Reset Chain", key="btn_chain_reset")

    if btn_add:
        if not chain_data.strip():
            st.error("Data tidak boleh kosong.")
        else:
            new_blk = add_block(st.session_state.blockchain, chain_data)
            st.session_state.blockchain.append(new_blk)
            st.success(f"Blok #{new_blk['index']} berhasil ditambahkan!")

    if btn_val:
        chain = st.session_state.blockchain
        valid, details = validate_chain(chain)
        if valid:
            st.success("Chain valid! Semua blok terhubung dengan benar.")
        else:
            st.error("Chain TIDAK valid! Terdapat blok yang dimanipulasi.")
        for d in details:
            st.markdown(d)

    if btn_reset:
        st.session_state.blockchain = [create_genesis_block()]
        st.success("Chain direset ke Genesis Block.")
        st.rerun()

    _chain = st.session_state.blockchain
    _ok, _ = validate_chain(_chain)
    st.markdown(
        f"""
        <div class="chain-stats">
            <div class="stat"><div class="n">{len(_chain)}</div><div class="l">Total blok</div></div>
            <div class="stat"><div class="n">{'OK' if _ok else 'NOT OKE'}</div><div class="l">Integritas</div></div>
            <div class="stat"><div class="n">SHA-256</div><div class="l">Fungsi hash</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    blocks_html = ""
    for blk in reversed(_chain):
        is_genesis = blk["index"] == 0
        label = "Genesis Block" if is_genesis else f" Blok #{blk['index']}"
        blocks_html += f"""
        <div class="blk-card {'genesis' if is_genesis else ''}">
            <span class="blk-idx">{label}</span>
            &nbsp;.&nbsp; <span style="color:#667085">{html.escape(blk['timestamp'])}</span>
            <div class="blk-data"><b>Data:</b> {html.escape(str(blk['data']))}</div>
            <span class="blk-hash">Hash: {blk['hash']}</span><br/>
            <span class="blk-hash">Prev: {blk['prev_hash'][:32]}...</span>
        </div>"""
    st.markdown(f'<div class="blk-wrap">{blocks_html}</div>', unsafe_allow_html=True)
