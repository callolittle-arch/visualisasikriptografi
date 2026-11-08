import hashlib
import hmac
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

# ─────────────────────────────────────────────
# ALGORITMA KLASIK & MODERN (tidak diubah)
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# FITUR BARU 1: AES-128 (untuk enkripsi file)
# Implementasi manual AES-128 ECB mode
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# FITUR BARU 2: STEGANOGRAFI LSB (PNG/BMP)
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# FITUR BARU 3: BLOCKCHAIN SEDERHANA
# ─────────────────────────────────────────────

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
        status = "✅" if (ok_hash and ok_link) else "❌"
        if not (ok_hash and ok_link):
            valid = False
        details.append(f"{status} Blok #{blk['index']} — hash {'OK' if ok_hash else 'INVALID'}, link {'OK' if ok_link else 'BROKEN'}")
    return valid, details


# ─────────────────────────────────────────────
# FITUR BARU 4: ENKRIPSI DATABASE (SQLite)
# Pesan dienkripsi dengan RC4 sebelum disimpan
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# FITUR BARU 5: AUTENTIKASI LOGIN (SHA-256)
# ─────────────────────────────────────────────

# Password default di-hash SHA-256. Untuk demo: password = "admin123"
DEFAULT_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
DEFAULT_USERNAME = "admin"

def check_login(username: str, password: str) -> bool:
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == DEFAULT_USERNAME and hmac.compare_digest(pwd_hash, DEFAULT_PASSWORD_HASH)


# ─────────────────────────────────────────────
# PAGE CONFIG & GLOBAL CSS
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="Modul Kriptosistem",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #0F172A;
    }

    .main {
        background-color: #F8FAFC;
    }

    .animate-fade {
        animation: fadeInUp 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(10px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    .header-box {
        background: #94A3B8;
        padding: 1.25rem 1.75rem;
        border-radius: 12px;
        color: white;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .header-box h1 {
        font-size: 1.35rem;
        font-weight: 700;
        margin: 0;
        letter-spacing: -0.02em;
        color: #FFFFFF;
    }

    [data-testid="stSidebar"] { background-color: #0F172A; }
    [data-testid="stSidebar"] * { color: #F8FAFC; }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2 {
        color: #F8FAFC; font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem;
    }

    .algo-card {
        background: #FFFFFF; border-radius: 10px;
        padding: 1rem 1.25rem; border: 1px solid #E2E8F0; margin-bottom: 1rem;
    }
    .algo-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem; }
    .algo-card h3 { margin: 0; font-size: 1.1rem; font-weight: 600; color: #0F172A; }
    .algo-card p  { color: #64748B; font-size: 0.875rem; line-height: 1.45; margin: 0; }

    .badge {
        display: inline-flex; align-items: center;
        padding: 2px 8px; border-radius: 4px;
        font-size: 0.7rem; font-weight: 600;
        letter-spacing: 0.03em; text-transform: uppercase;
    }
    .badge-klasik { background: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; }
    .badge-modern { background: #F0FDF4; color: #16A34A; border: 1px solid #BBF7D0; }
    .badge-new    { background: #FEF3C7; color: #D97706; border: 1px solid #FDE68A; }

    div.stButton > button {
        background: #2563EB; color: white; border: none;
        border-radius: 8px; padding: 0.55rem 1.25rem;
        font-weight: 500; font-size: 0.9rem; width: 100%;
        transition: all 0.15s ease;
    }
    div.stButton > button:hover { background: #1D4ED8; color: white; }

    div[data-testid="stPopover"] > div > button {
        background: #1E293B; color: #F8FAFC;
        border: 1px solid #334155; border-radius: 8px; font-weight: 500;
    }
    div[data-testid="stPopover"] > div > button:hover {
        background: #334155; color: white; border-color: #475569;
    }

    .result-box {
        background: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 8px;
        padding: 0.85rem 1rem;
        font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
        color: #0F172A; word-wrap: break-word; white-space: pre-wrap;
    }

    .log-line {
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
        padding: 0.2rem 0; border-bottom: 1px solid #F1F5F9; color: #000000;
    }

    .pipeline {
        display: flex; align-items: center; gap: 0.5rem;
        flex-wrap: wrap; margin-bottom: 1rem;
    }
    .pipeline-step {
        background: #FFFFFF; color: #0F172A;
        padding: 0.3rem 0.75rem; border-radius: 6px;
        font-size: 0.8rem; font-weight: 500; border: 1px solid #E2E8F0;
    }
    .pipeline-arrow { color: #94A3B8; font-weight: 600; font-size: 0.85rem; }

    div[data-testid="stExpander"] { color: #E2E8F0; }
    div[data-testid="stExpander"] p,
    div[data-testid="stExpander"] li,
    div[data-testid="stExpander"] span { color: #FFFFFF !important; }
    div[data-testid="stExpander"] pre,
    div[data-testid="stExpander"] code { color: #FFFFFF !important; background-color: #1E293B !important; }
    div[data-testid="stExpander"] p,
    div[data-testid="stExpander"] span,
    div[data-testid="stExpander"] div,
    div[data-testid="stExpander"] td,
    div[data-testid="stExpander"] th,
    div[data-testid="stExpander"] li,
    div[data-testid="stExpander"] code {
        color: #FFFFFF !important; opacity: 1 !important; font-weight: 400 !important;
    }
    div[data-testid="stExpander"] [data-testid="stCodeBlock"],
    div[data-testid="stExpander"] [data-testid="stCodeBlock"] pre,
    div[data-testid="stExpander"] [data-testid="stCodeBlock"] code,
    div[data-testid="stExpander"] [data-testid="stCodeBlock"] span,
    div[data-testid="stExpander"] div[data-testid="stCode"] pre,
    div[data-testid="stExpander"] div[data-testid="stCode"] code,
    div[data-testid="stExpander"] div[data-testid="stCode"] span {
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        opacity: 1 !important; font-weight: 400 !important; text-shadow: none !important;
    }
    div[data-testid="stExpander"] [data-testid="stCodeBlock"] pre,
    div[data-testid="stExpander"] div[data-testid="stCode"] pre {
        background: #1E2925 !important; background-color: #1E2925 !important;
    }

    /* Login card */
    .login-card {
        max-width: 400px; margin: 4rem auto;
        background: #FFFFFF; border-radius: 16px;
        padding: 2rem 2.5rem; border: 1px solid #E2E8F0;
        box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    .login-card h2 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.25rem; color: #0F172A; }
    .login-card p  { color: #64748B; font-size: 0.85rem; margin-bottom: 1.5rem; }

    /* Blockchain block card */
    .blk-card {
        background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;
        padding: 0.75rem 1rem; margin-bottom: 0.5rem; font-size: 0.82rem;
        font-family: 'JetBrains Mono', monospace;
    }
    .blk-card .blk-idx { font-weight: 700; color: #2563EB; font-size: 0.85rem; }
    .blk-card .blk-hash { color: #64748B; word-break: break-all; }
</style>
""",
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "blockchain" not in st.session_state:
    st.session_state.blockchain = [create_genesis_block()]


# ─────────────────────────────────────────────
# HALAMAN LOGIN
# ─────────────────────────────────────────────

if not st.session_state.logged_in:
    st.markdown(
        """
        <div class="login-card">
            <h2>🔐 Kriptosistem Login</h2>
            <p>Masukkan kredensial untuk mengakses sistem. Password divalidasi dengan SHA-256.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        submitted = st.form_submit_button("Masuk")

    if submitted:
        if check_login(username, password):
            st.session_state.logged_in = True
            st.success("Login berhasil! Mengalihkan...")
            st.rerun()
        else:
            st.error("Username atau password salah.")

    st.caption("💡 Demo: username `admin` / password `admin123`")
    st.caption(f"Hash SHA-256 password default: `{DEFAULT_PASSWORD_HASH[:32]}...`")
    st.stop()


# ─────────────────────────────────────────────
# HEADER (hanya tampil saat sudah login)
# ─────────────────────────────────────────────

st.markdown(
    """
<div class="header-box">
    <h1>Sistem Kriptografi Interaktif</h1>
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
    st.markdown("## Navigasi")
    selected = option_menu(
        menu_title=None,
        options=menu_options,
        default_index=0,
        orientation="vertical",
        styles={
            "container": {"padding": "4px", "background-color": "#0F172A"},
            "icon": {"display": "none"},
            "nav-link": {
                "font-size": "14px", "font-weight": "500",
                "color": "#94A3B8", "text-align": "left",
                "margin": "4px 0", "border-radius": "8px",
                "--hover-color": "#1E293B",
            },
            "nav-link-selected": {
                "background-color": "#94A3B8", "color": "#FFFFFF", "font-weight": "600",
            },
        },
    )
    st.markdown("---")
    if st.button("🚪 Logout", key="btn_logout"):
        st.session_state.logged_in = False
        st.rerun()

with st.popover("Mode Operasi"):
    is_decrypt_toggle = st.toggle("Dekripsi", value=False)
    is_encrypt = not is_decrypt_toggle
    st.markdown(
        '<p style="color: white;"><b>Aktif</b> : <b>Dekripsi</b>.</p>',
        unsafe_allow_html=True)
    st.markdown(
        """
        <p style="color: white;">---------------------------</p>
        <p style="color: white;">
            Buka bagian <b>#Lihat Proses#</b> di bawah hasil untuk memahami langkah kerja algoritmanya.
        </p>
        """,
        unsafe_allow_html=True
    )

algo_info = {
    "Caesar Cipher": (
        "Caesar Cipher", "klasik",
        "Menggeser karakter berdasarkan nilai pergeseran tetap dalam alfabet.",
    ),
    "Vigenere Cipher": (
        "Vigenère Cipher", "klasik",
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
        "Penggabungan berlapis dari Caesar, Vigenère, RC4, dan RSA secara berurutan.",
    ),
    "Enkripsi File (AES)": (
        "Enkripsi File — AES-128", "new",
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
    <div class="algo-card">
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
    st.markdown(f"##### {title}")
    st.markdown(
        f'<div class="result-box">{content}</div>', unsafe_allow_html=True
    )


def render_logs(logs):
    with st.expander("Detail Proses Executed"):
        for log in logs:
            st.markdown(
                f'<div class="log-line">{log}</div>', unsafe_allow_html=True
            )


# ─────────────────────────────────────────────
# KONTEN UTAMA
# ─────────────────────────────────────────────

st.markdown('<div class="animate-fade">', unsafe_allow_html=True)

# ── Caesar Cipher ────────────────────────────
if selected == "Caesar Cipher":
    render_algo_card("Caesar Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area("Input Teks:", height=130, placeholder="Masukkan teks...")
    with col_side:
        shift = st.number_input("Nilai Shift:", min_value=1, max_value=25, value=3)
        st.caption("Jumlah nilai pergeseran (1–25).")
        st.write("")
        btn = st.button("Proses Caesar", key="btn_caesar")

    if btn:
        res, logs = caesar_cipher(text, shift, "encrypt" if is_encrypt else "decrypt")
        render_result("Hasil Output", res if res else "(kosong)")
        render_logs(logs)

# ── Vigenere Cipher ──────────────────────────
elif selected == "Vigenere Cipher":
    render_algo_card("Vigenere Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area("Input Teks:", height=130, placeholder="Masukkan teks...")
    with col_side:
        key = st.text_input("Kunci : ", value="KUNCI")
        st.caption("Kunci alfabetik berulang.")
        st.write("")
        btn = st.button("Proses Vigenère", key="btn_vigenere")

    if btn:
        if not key:
            st.error("Kunci tidak boleh kosong")
        else:
            res, logs = vigenere_cipher(text, key, "encrypt" if is_encrypt else "decrypt")
            render_result("Hasil Output", res if res else "(kosong)")
            render_logs(logs)

# ── RC4 ──────────────────────────────────────
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

# ── RSA ──────────────────────────────────────
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
        st.caption(f"Modulus (n = p × q): **{p * q}**")
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
            st.error("Kesalahan komputasi RSA. Pastikan nilai (p × q) > 255.")

# ── Super Enkripsi ───────────────────────────
elif selected == "Super Enkripsi":
    render_algo_card("Super Enkripsi")

    if is_encrypt:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. Caesar</div><div class="pipeline-arrow">→</div>
            <div class="pipeline-step">2. Vigenère</div><div class="pipeline-arrow">→</div>
            <div class="pipeline-step">3. RC4</div><div class="pipeline-arrow">→</div>
            <div class="pipeline-step">4. RSA</div>
        </div>"""
    else:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. RSA</div><div class="pipeline-arrow">→</div>
            <div class="pipeline-step">2. RC4</div><div class="pipeline-arrow">→</div>
            <div class="pipeline-step">3. Vigenère</div><div class="pipeline-arrow">→</div>
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
            v_key = st.text_input("Kunci Vigenère:", value="KUNCI")
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
                    t1, t2, t3, t4 = st.tabs(["1. Caesar", "2. Vigenère", "3. RC4", "4. RSA"])
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

# ── Enkripsi File (AES-128) ──────────────────
elif selected == "Enkripsi File (AES)":
    render_algo_card("Enkripsi File (AES)")

    st.info("📁 Upload file apapun. File akan dienkripsi/didekripsi menggunakan **AES-128 ECB** — algoritma berbeda dari enkripsi teks.", icon="ℹ️")

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
                    st.success(f"✅ File berhasil dienkripsi! ({len(file_bytes)} → {len(result_bytes)} bytes)")
                else:
                    result_bytes = aes_decrypt(file_bytes, aes_key)
                    out_name = uploaded.name.removesuffix(".enc") if uploaded.name.endswith(".enc") else "decrypted_" + uploaded.name
                    st.success(f"✅ File berhasil didekripsi! ({len(file_bytes)} → {len(result_bytes)} bytes)")

                st.download_button(
                    label=f"⬇️ Download {out_name}",
                    data=result_bytes,
                    file_name=out_name,
                    mime="application/octet-stream",
                )
                with st.expander("Detail AES"):
                    key_bytes = hashlib.md5(aes_key.encode()).digest()
                    st.markdown(f"**Kunci input:** `{aes_key}`")
                    st.markdown(f"**MD5 → 128-bit key:** `{key_bytes.hex()}`")
                    st.markdown(f"**Mode:** AES-128 ECB + PKCS#7 Padding")
                    st.markdown(f"**Ukuran input:** {len(file_bytes)} bytes → **Output:** {len(result_bytes)} bytes")
            except Exception as ex:
                st.error(f"Gagal memproses file: {ex}")

# ── Steganografi ─────────────────────────────
elif selected == "Steganografi":
    render_algo_card("Steganografi")

    st.info("🖼️ Sembunyikan atau ekstrak pesan dari gambar **BMP/PNG** menggunakan metode **LSB (Least Significant Bit)**.", icon="ℹ️")

    steg_tab1, steg_tab2 = st.tabs(["🔒 Sembunyikan Pesan", "🔓 Ekstrak Pesan"])

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
                    st.success(f"✅ Pesan berhasil disembunyikan! ({len(secret_msg)} karakter, {len(secret_msg)*8} bit LSB diubah)")
                    st.download_button(
                        label="⬇️ Download Gambar Stego",
                        data=result_img,
                        file_name="stego_" + img_file.name,
                        mime="image/bmp" if img_file.name.endswith(".bmp") else "image/png",
                    )
                    with st.expander("Detail Proses LSB"):
                        msg_bytes = (secret_msg + "\x00").encode("utf-8")
                        msg_bits = "".join(f"{b:08b}" for b in msg_bytes)
                        st.markdown(f"**Panjang pesan:** {len(secret_msg)} karakter → {len(msg_bytes)} byte → **{len(msg_bits)} bit**")
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

# ── Enkripsi Database ─────────────────────────
elif selected == "Enkripsi Database":
    render_algo_card("Enkripsi Database")

    st.info(
        "💾 Pesan penting dienkripsi menggunakan **RC4** sebelum disimpan ke database **SQLite** lokal. "
        "Gunakan kunci yang sama untuk membaca pesan.",
        icon="ℹ️"
    )

    db_tab1, db_tab2 = st.tabs(["➕ Simpan Pesan", "📋 Lihat & Kelola"])

    with db_tab1:
        col1, col2 = st.columns([3, 2])
        with col1:
            db_label = st.text_input("Label / Judul Pesan:", placeholder="Contoh: Kunci Brankas, Token API...")
            db_msg = st.text_area("Isi Pesan Rahasia:", height=130, placeholder="Pesan yang akan dienkripsi dan disimpan...")
        with col2:
            db_key = st.text_input("Kunci Enkripsi:", value="kunci_db", type="password")
            st.caption("Kunci RC4 untuk enkripsi pesan di database.")
            st.write("")
            btn_save = st.button("💾 Simpan ke Database", key="btn_db_save")

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
                    st.success(f"✅ Pesan '{db_label}' berhasil dienkripsi dan disimpan ke database!")
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
            btn_read = st.button("🔓 Tampilkan", key="btn_db_read")

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
                    with st.expander(f"#{row['id']} — {row['label']} ({row['ts']})"):
                        st.markdown(f"**Plaintext:** `{row['plaintext']}`")
                        st.markdown(f"**Ciphertext (hex):** `{row['ciphertext'][:60]}...`")
                        if st.button(f"🗑️ Hapus #{row['id']}", key=f"del_{row['id']}"):
                            db_hapus_pesan(row["id"])
                            del st.session_state["db_rows"]
                            st.rerun()

# ── Blockchain ───────────────────────────────
elif selected == "Blockchain":
    render_algo_card("Blockchain")

    st.info(
        "⛓️ Tambahkan aset/data penting ke dalam **blockchain sederhana**. "
        "Setiap blok di-hash SHA-256 dan terhubung ke blok sebelumnya — "
        "perubahan apapun pada data lama akan terdeteksi.",
        icon="ℹ️"
    )

    col1, col2 = st.columns([3, 2])
    with col1:
        chain_data = st.text_area(
            "Data / Aset yang Diamankan:",
            height=100,
            placeholder="Contoh: Sertifikat X, Token Z, Hash dokumen penting..."
        )
    with col2:
        btn_add = st.button("➕ Tambah Blok", key="btn_chain_add")
        btn_val = st.button("🔍 Validasi Chain", key="btn_chain_val")
        btn_reset = st.button("🗑️ Reset Chain", key="btn_chain_reset")

    if btn_add:
        if not chain_data.strip():
            st.error("Data tidak boleh kosong.")
        else:
            new_blk = add_block(st.session_state.blockchain, chain_data)
            st.session_state.blockchain.append(new_blk)
            st.success(f"✅ Blok #{new_blk['index']} berhasil ditambahkan!")

    if btn_val:
        chain = st.session_state.blockchain
        valid, details = validate_chain(chain)
        if valid:
            st.success("✅ Chain valid! Semua blok terhubung dengan benar.")
        else:
            st.error("❌ Chain TIDAK valid! Terdapat blok yang dimanipulasi.")
        for d in details:
            st.markdown(d)

    if btn_reset:
        st.session_state.blockchain = [create_genesis_block()]
        st.success("Chain direset ke Genesis Block.")
        st.rerun()

    st.markdown(f"**Chain saat ini: {len(st.session_state.blockchain)} blok**")
    st.markdown("---")

    for blk in reversed(st.session_state.blockchain):
        is_genesis = blk["index"] == 0
        label = "🏁 Genesis Block" if is_genesis else f"📦 Blok #{blk['index']}"
        st.markdown(
            f"""
            <div class="blk-card">
                <span class="blk-idx">{label}</span>
                &nbsp;·&nbsp; <span style="color:#64748B">{blk['timestamp']}</span><br/>
                <b>Data:</b> {blk['data']}<br/>
                <span class="blk-hash">Hash: {blk['hash']}</span><br/>
                <span class="blk-hash" style="font-size:0.77rem;">Prev: {blk['prev_hash'][:32]}...</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("</div>", unsafe_allow_html=True)
