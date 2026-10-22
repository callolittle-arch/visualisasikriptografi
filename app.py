import random
import time
import streamlit as st
from streamlit_option_menu import option_menu



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

        # Ambil karakter kunci yang berupa huruf
        key_char = key[key_idx % len(key)]

        # Jika karakter kunci bukan huruf, gunakan nilai ASCII-nya
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


st.set_page_config(
    page_title="Modul Kriptosistem",
    layout="wide",
    initial_sidebar_state="collapsed",
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

    /* Animasi saat perpindahan menu */
    .animate-fade {
        animation: fadeInUp 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    /* Header Ringkas */
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
        color: #BB6464;
    }

    /* Navbar Wrapper */
    .navbar-wrap {
        background: #0F172A;
        border-radius: 12px;
        padding: 4px;
        margin-bottom: 1.25rem;
    }

    /* Card Algoritma */
    .algo-card {
        background: #FFFFFF;
        border-radius: 10px;
        padding: 1rem 1.25rem;
        border: 1px solid #E2E8F0;
        margin-bottom: 1rem;
    }
    .algo-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.35rem;
    }
    .algo-card h3 {
        margin: 0;
        font-size: 1.1rem;
        font-weight: 600;
        color: #0F172A;
    }
    .algo-card p {
        color: #64748B;
        font-size: 0.875rem;
        line-height: 1.45;
        margin: 0;
    }

    /* Badge Klasik & Modern Minimalis */
    .badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        text-transform: uppercase;
    }
    .badge-klasik {
        background: #EFF6FF;
        color: #2563EB;
        border: 1px solid #BFDBFE;
    }
    .badge-modern {
        background: #F0FDF4;
        color: #16A34A;
        border: 1px solid #BBF7D0;
    }

    /* Styling Button Utama */
    div.stButton > button {
        background: #2563EB;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.55rem 1.25rem;
        font-weight: 500;
        font-size: 0.9rem;
        width: 100%;
        transition: all 0.15s ease;
    }
    div.stButton > button:hover {
        background: #1D4ED8;
        color: white;
    }

    /* Popover Toggle Mode */
    div[data-testid="stPopover"] > div > button {
        background: #1E293B;
        color: #F8FAFC;
        border: 1px solid #334155;
        border-radius: 8px;
        font-weight: 500;
    }
    div[data-testid="stPopover"] > div > button:hover {
        background: #334155;
        color: white;
        border-color: #475569;
    }

    /* Output Box */
    .result-box {
        background: #F1F5F9;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 0.85rem 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        color: #0F172A;
        word-wrap: break-word;
        white-space: pre-wrap;
    }

    .log-line {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        padding: 0.2rem 0;
        border-bottom: 1px solid #F1F5F9;
        color: #475569;
    }

    /* Pipeline Super Enkripsi */
    .pipeline {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
        margin-bottom: 1rem;
    }
    .pipeline-step {
        background: #FFFFFF;
        color: #0F172A;
        padding: 0.3rem 0.75rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 500;
        border: 1px solid #E2E8F0;
    }
    .pipeline-arrow {
        color: #94A3B8;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    div[data-testid="stExpander"] {
        color: #E2E8F0;
    }
    
    div[data-testid="stExpander"] p,
    div[data-testid="stExpander"] li,
    div[data-testid="stExpander"] span {
        color: #FFFFFF !important;
    }
    
    div[data-testid="stExpander"] pre,
    div[data-testid="stExpander"] code {
        color: #FFFFFF !important;
        background-color: #1E293B !important;
    }

    div[data-testid="stExpander"] p,
    div[data-testid="stExpander"] span,
    div[data-testid="stExpander"] div,
    div[data-testid="stExpander"] td,
    div[data-testid="stExpander"] th,
    div[data-testid="stExpander"] li,
    div[data-testid="stExpander"] code {
        color: #FFFFFF !important;
        opacity: 1 !important;
        font-weight: 400 !important;
}
</style>
""",
    unsafe_allow_html=True,
)

# Header
st.markdown(
    """
<div class="header-box">
    <h1>Sistem kripto interaktif</h1>
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
]

nav_col, toggler_col = st.columns([5.5, 1.5])

with nav_col:
    st.markdown('<div class="navbar-wrap">', unsafe_allow_html=True)
    selected = option_menu(
        menu_title=None,
        options=menu_options,
        default_index=0,
        orientation="horizontal",
        styles={
            "container": {
                "padding": "0px",
                "background-color": "transparent",
            },
            "icon": {"display": "none"},
            "nav-link": {
                "font-size": "13px",
                "font-weight": "500",
                "color": "#94A3B8",
                "text-align": "center",
                "margin": "2px",
                "border-radius": "8px",
                "--hover-color": "#1E293B",
            },
            "nav-link-selected": {
                "background-color": "#94A3B8",
                "color": "#FFFFFF",
                "font-weight": "600",
            },
        },
    )
    st.markdown("</div>", unsafe_allow_html=True)

with toggler_col:
    with st.popover("Mode Operasi", use_container_width=True):
        is_decrypt_toggle = st.toggle("Dekripsi", value=False)
        is_encrypt = not is_decrypt_toggle
        st.markdown(
            '<p style="color: white;"<b>Aktif<b> : <b>Dekripsi</b>.</p>',
            unsafe_allow_html=True)

        st.markdown(
            '<p style="color: white;">Buka bagian #Lihat Proses# di bawah hasil untuk memahami langkah kerja algoritmanya.</p>',
            unsafe_allow_html=True
        )
algo_info = {
    "Caesar Cipher": (
        "Caesar Cipher",
        "klasik",
        "Menggeser karakter berdasarkan nilai pergeseran tetap dalam alfabet.",
    ),
    "Vigenere Cipher": (
        "Vigenère Cipher",
        "klasik",
        "Menggunakan kunci alfabetik berulang untuk pergeseran karakter.",
    ),
    "RC4": (
        "RC4",
        "modern",
        "Stream cipher pembangkit keystream pseudorandom yang di-XOR dengan data.",
    ),
    "RSA": (
        "RSA",
        "modern",
        "Kriptografi asimetris berbasis eksponensial modular dan bilangan prima.",
    ),
    "Super Enkripsi": (
        "Super Enkripsi",
        "modern",
        "Penggabungan berlapis dari Caesar, Vigenère, RC4, dan RSA secara berurutan.",
    ),
}


def render_algo_card(key):
    name, kind, desc = algo_info[key]
    badge_class = "badge-klasik" if kind == "klasik" else "badge-modern"
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


# Container utama dengan animasi fade
st.markdown('<div class="animate-fade">', unsafe_allow_html=True)

# Layout input seragam (3:2) untuk semua tab
if selected == "Caesar Cipher":
    render_algo_card("Caesar Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area(
            "Input Teks:", height=130, placeholder="Masukkan teks..."
        )
    with col_side:
        shift = st.number_input(
            "Nilai Shift:", min_value=1, max_value=25, value=3
        )
        st.caption("Jumlah nilai pergeseran (1–25).")
        st.write("")
        btn = st.button("Proses Caesar", key="btn_caesar")

    if btn:
        res, logs = caesar_cipher(
            text, shift, "encrypt" if is_encrypt else "decrypt"
        )
        render_result("Hasil Output", res if res else "(kosong)")
        render_logs(logs)

elif selected == "Vigenere Cipher":
    render_algo_card("Vigenere Cipher")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        text = st.text_area(
            "Input Teks:", height=130, placeholder="Masukkan teks..."
        )
    with col_side:
        key = st.text_input("Kunci (Huruf):", value="KUNCI")
        st.caption("Kunci alfabetik berulang.")
        st.write("")
        btn = st.button("Proses Vigenère", key="btn_vigenere")

    if btn:
        if not key:
            st.error("Kunci tidak boleh kosong!")
        else:
            res, logs = vigenere_cipher(
                text, key, "encrypt" if is_encrypt else "decrypt"
            )
            render_result("Hasil Output", res if res else "(kosong)")
            render_logs(logs)

elif selected == "RC4":
    render_algo_card("RC4")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = "Input Teks:" if is_encrypt else "Input Hex (Pisah Spasi):"
        placeholder = (
            "Masukkan teks..." if is_encrypt else "Contoh: 4a 6f 1c"
        )
        text = st.text_area(label, height=130, placeholder=placeholder)
    with col_side:
        key = st.text_input("Kunci RC4:", value="SECRET")
        st.caption("Kunci string untuk inisialisasi state.")
        st.write("")
        btn = st.button("Proses RC4", key="btn_rc4")

    if btn:
        try:
            if not is_encrypt:
                text_input = [int(x, 16) for x in text.split()]
            else:
                text_input = text

            res, logs = rc4(text_input, key)

            if is_encrypt:
                final_res = " ".join([hex(x)[2:].zfill(2) for x in res])
            else:
                final_res = "".join([chr(x) for x in res])

            render_result("Hasil Output", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error(
                "Format input dekripsi tidak valid. Gunakan format Hexadesimal dipisah spasi."
            )

elif selected == "RSA":
    render_algo_card("RSA")
    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = "Input Teks:" if is_encrypt else "Input Angka (Pisah Spasi):"
        placeholder = (
            "Masukkan teks..." if is_encrypt else "Contoh: 120 45 200"
        )
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
            if not is_encrypt:
                text_input = [int(x) for x in text.split()]
            else:
                text_input = text

            res, logs = rsa_process(
                text_input, p, q, "encrypt" if is_encrypt else "decrypt"
            )

            if is_encrypt:
                final_res = " ".join([str(x) for x in res])
            else:
                final_res = "".join([chr(x) for x in res])

            render_result("Hasil Output", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error(
                "Kesalahan komputasi RSA. Pastikan nilai (p × q) > 255."
            )

elif selected == "Super Enkripsi":
    render_algo_card("Super Enkripsi")

    # Urutan proses menyesuaikan mode operasi:
    # Enkripsi: Caesar → Vigenère → RC4 → RSA
    # Dekripsi: RSA → RC4 → Vigenère → Caesar
    if is_encrypt:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. Caesar</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">2. Vigenère</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">3. RC4</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">4. RSA</div>
        </div>
        """
    else:
        pipeline_html = """
        <div class="pipeline">
            <div class="pipeline-step">1. RSA</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">2. RC4</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">3. Vigenère</div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-step">4. Caesar</div>
        </div>
        """

    st.markdown(pipeline_html, unsafe_allow_html=True)

    col_input, col_side = st.columns([3, 2])
    with col_input:
        label = (
            "Input Teks:"
            if is_encrypt
            else "Input Angka Enkripsi (Pisah Spasi):"
        )
        text = st.text_area(
            label, height=210, placeholder="Masukkan teks..."
        )
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
                import streamlit as st

# ==========================================
# 1. LOGIKA ALGORITMA KRIPTOGRAFI
# ==========================================

def caesar_cipher(text: str, shift: int, mode: str):
    """
    Caesar Cipher berbasis Alfabet (mengpertahankan huruf besar/kecil & karakter khusus)
    """
    result = []
    process_log = []
    effective_shift = shift if mode == "encrypt" else -shift

    for char in text:
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            new_code = (ord(char) - start + effective_shift) % 26 + start
            new_char = chr(new_code)
            result.append(new_char)
            process_log.append(f"'{char}' → Geser {shift} → '{new_char}'")
        else:
            result.append(char)
            process_log.append(f"'{char}' → Tetap (Simbol/Spasi)")

    return "".join(result), process_log


def vigenere_cipher(text: str, key: str, mode: str):
    """
    Universal Vigenère Cipher: Mendukung SEMUA Karakter (Huruf, Spasi, Angka, Simbol)
    Berbasis pergeseran Modulo 256 byte/ASCII.
    """
    if not key:
        key = "KEY"
    
    result = []
    process_log = []

    for i, char in enumerate(text):
        char_code = ord(char)
        key_char = key[i % len(key)]
        key_shift = ord(key_char)

        if mode == "encrypt":
            new_code = (char_code + key_shift) % 256
        else:
            new_code = (char_code - key_shift + 256) % 256

        new_char = chr(new_code)
        result.append(new_char)
        process_log.append(
            f"Karakter '{char}' + Kunci '{key_char}' (Shift {key_shift}) → Hasil '{new_char}'"
        )

    return "".join(result), process_log


def rc4_cipher(data_bytes: list, key_str: str):
    """
    RC4 Stream Cipher (KSA & PRGA dengan operasi XOR)
    """
    process_log = ["--- Inisialisasi KSA (Key Scheduling Algorithm) ---"]
    S = list(range(256))
    key_bytes = [ord(c) for c in key_str]
    
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    process_log.append("KSA Selesai. State Array S diacak.")

    process_log.append("--- PRGA & Operasi XOR ---")
    i = j = 0
    result_bytes = []

    for byte_val in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]

        cipher_val = byte_val ^ K
        result_bytes.append(cipher_val)
        process_log.append(f"Byte: {byte_val} XOR Keystream: {K} → Hasil: {cipher_val}")

    return result_bytes, process_log


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return 1


def rsa_process(input_values: list, p: int, q: int, mode: str):
    """
    Kriptografi Asimetris RSA (C = M^e mod n  |  M = C^d mod n)
    """
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1 and e < phi:
        e += 1
    d = mod_inverse(e, phi)

    process_log = [
        f"Parameter: p={p}, q={q}",
        f"Modulus (n) = {n}",
        f"Totient (phi) = {phi}",
        f"Kunci Publik (e) = {e}",
        f"Kunci Privat (d) = {d}",
    ]

    results = []
    if mode == "encrypt":
        process_log.append("--- Enkripsi RSA (C = M^e mod n) ---")
        for val in input_values:
            c = pow(val, e, n)
            results.append(c)
            process_log.append(f"M: {val} → {val}^{e} mod {n} = {c}")
    else:
        process_log.append("--- Dekripsi RSA (M = C^d mod n) ---")
        for val in input_values:
            m = pow(val, d, n)
            results.append(m)
            process_log.append(f"C: {val} → {val}^{d} mod {n} = {m}")

    return results, process_log


# ==========================================
# 2. CONFIG & STYLING HITAM-PUTIH (MONOCHROME)
# ==========================================

st.set_page_config(
    page_title="Modul Kriptosistem Interaktif",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS Monokromatik & Golden Ratio Layouting
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
        color: #0F172A;
    }

    .main {
        background-color: #FAFAFA;
    }

    /* Top Navigation Header */
    .app-header {
        background: #09090B;
        color: #FAFAFA;
        padding: 1.25rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border: 1px solid #27272A;
    }
    .app-header h1 {
        font-size: 1.3rem;
        font-weight: 700;
        margin: 0;
        color: #FFFFFF;
        letter-spacing: -0.02em;
    }
    .app-header p {
        font-size: 0.8rem;
        color: #A1A1AA;
        margin: 0;
    }

    /* Algorithm Info Card */
    .info-card {
        background: #FFFFFF;
        border: 1px solid #E4E4E7;
        border-radius: 10px;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
    }
    .badge-mono {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.68rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: #F4F4F5;
        color: #18181B;
        border: 1px solid #E4E4E7;
        margin-bottom: 0.35rem;
    }

    /* Buttons Styling */
    div.stButton > button {
        background: #09090B !important;
        color: #FFFFFF !important;
        border: 1px solid #09090B !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.25rem !important;
        font-weight: 600 !important;
        font-size: 0.875rem !important;
        width: 100% !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button:hover {
        background: #27272A !important;
        border-color: #27272A !important;
        color: #FFFFFF !important;
    }

    /* Output Box */
    .output-box {
        background: #F4F4F5;
        border: 1px solid #E4E4E7;
        border-radius: 8px;
        padding: 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.875rem;
        color: #09090B;
        word-break: break-all;
        white-space: pre-wrap;
        min-height: 100px;
    }

    .log-item {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #52525B;
        padding: 0.25rem 0;
        border-bottom: 1px solid #F4F4F5;
    }

    /* Pipeline Component */
    .pipeline-container {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
        margin-top: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
    }
    .pipeline-item {
        background: #F4F4F5;
        border: 1px solid #E4E4E7;
        padding: 0.25rem 0.6rem;
        border-radius: 4px;
        color: #18181B;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header Utama
st.markdown(
    """
    <div class="app-header">
        <div>
            <h1>Sistem Kriptosistem Interaktif</h1>
            <p>Penerapan Kriptografi Klasik & Modern</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Menu Navigasi Utama
menu_options = ["Caesar Cipher", "Vigenère Cipher", "RC4", "RSA", "Super Enkripsi"]
selected_tab = st.radio("Pilih Algoritma:", menu_options, horizontal=True)

# Toggle Mode Operasi (Enkripsi / Dekripsi)
col_mode1, col_mode2 = st.columns([1, 4])
with col_mode1:
    op_mode = st.radio("Mode Operasi:", ["Enkripsi", "Dekripsi"], horizontal=True)
    is_encrypt = op_mode == "Enkripsi"

st.divider()

# Information Database
algo_info = {
    "Caesar Cipher": ("Klasik", "Menggeser karakter berdasarkan nilai pergeseran tetap dalam alfabet."),
    "Vigenère Cipher": ("Klasik", "Menggunakan kunci berulang untuk menggeser karakter secara dinamis. Mendukung huruf, angka, spasi & simbol."),
    "RC4": ("Modern", "Stream cipher berbasis pembangkitan keystream pseudo-random melalui KSA & PRGA lalu di-XOR dengan data."),
    "RSA": ("Modern", "Kriptografi asimetris berbasis faktorisasi dua bilangan prima (p & q) serta eksponensial modular."),
    "Super Enkripsi": ("Modern (Gabungan)", "Penggabungan bertingkat 4 lapisan: Caesar → Vigenère → RC4 → RSA secara berurutan."),
}

kind, desc = algo_info[selected_tab]
st.markdown(
    f"""
    <div class="info-card">
        <span class="badge-mono">{kind}</span>
        <h3 style="margin: 0; font-size: 1.1rem; font-weight: 700;">{selected_tab}</h3>
        <p style="margin: 0.25rem 0 0 0; font-size: 0.85rem; color: #71717A;">{desc}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if selected_tab == "Super Enkripsi":
    st.markdown(
        """
        <div class="pipeline-container" style="margin-bottom: 1.25rem;">
            <span style="font-weight: 600;">Alur Eksekusi:</span>
            <span class="pipeline-item">1. Caesar</span> →
            <span class="pipeline-item">2. Vigenère</span> →
            <span class="pipeline-item">3. RC4</span> →
            <span class="pipeline-item">4. RSA</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ==========================================
# 3. GOLDEN RATIO LAYOUT (Major 1.618 : Minor 1)
# ==========================================
col_major, col_minor = st.columns([1.618, 1])

# --- MAJOR COLUMN: Input & Pengaturan Parameter ---
with col_major:
    st.subheader("Input & Parameter")

    # Dynamic Labels & Placeholders based on Mode
    if not is_encrypt:
        if selected_tab == "RC4":
            input_label = "Input Hexadesimal (Dipisah Spasi):"
            placeholder = "Contoh: 4a 6f 1c 3e..."
        elif selected_tab in ["RSA", "Super Enkripsi"]:
            input_label = "Input Angka Cipher (Dipisah Spasi):"
            placeholder = "Contoh: 120 45 200 89..."
        else:
            input_label = "Input Ciphertext:"
            placeholder = "Masukkan teks terenkripsi..."
    else:
        input_label = "Input Teks (Plaintext):"
        placeholder = "Ketik pesan rahasia di sini (mendukung spasi & simbol)..."

    input_text = st.text_area(input_label, height=140, placeholder=placeholder)

    # Dynamic Parameter Inputs
    if selected_tab == "Caesar Cipher":
        shift_val = st.number_input("Nilai Shift (1–25):", min_value=1, max_value=25, value=3)

    elif selected_tab == "Vigenère Cipher":
        vigenere_key = st.text_input("Kunci Vigenère (Bebas Karakter & Spasi):", value="KUNCI123!")

    elif selected_tab == "RC4":
        rc4_key = st.text_input("Kunci String RC4:", value="SECRET")

    elif selected_tab == "RSA":
        col_p, col_q = st.columns(2)
        with col_p:
            rsa_p = st.number_input("Prima p:", value=17, min_value=2)
        with col_q:
            rsa_q = st.number_input("Prima q:", value=19, min_value=2)
        st.caption(f"Estimasi Modulus (n = p × q): **{rsa_p * rsa_q}**")

    elif selected_tab == "Super Enkripsi":
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            super_shift = st.number_input("Shift Caesar:", value=3)
            super_vkey = st.text_input("Kunci Vigenère:", value="KUNCI")
        with col_s2:
            super_rkey = st.text_input("Kunci RC4:", value="SECRET")
            col_sp, col_sq = st.columns(2)
            with col_sp:
                super_p = st.number_input("RSA p:", value=17)
            with col_sq:
                super_q = st.number_input("RSA q:", value=19)

    btn_process = st.button(f"Proses {op_mode}")

# --- MINOR COLUMN: Output Result & Computation Logs ---
with col_minor:
    st.subheader("Hasil & Komputasi")

    if btn_process:
        if not input_text.strip():
            st.error("Error: Masukkan teks input terlebih dahulu!")
        else:
            try:
                output_str = ""
                logs = []
                mode_str = "encrypt" if is_encrypt else "decrypt"

                # 1. Caesar Execution
                if selected_tab == "Caesar Cipher":
                    output_str, logs = caesar_cipher(input_text, shift_val, mode_str)

                # 2. Vigenère Execution
                elif selected_tab == "Vigenère Cipher":
                    output_str, logs = vigenere_cipher(input_text, vigenere_key, mode_str)

                # 3. RC4 Execution
                elif selected_tab == "RC4":
                    if is_encrypt:
                        bytes_in = [ord(c) for c in input_text]
                        res_bytes, logs = rc4_cipher(bytes_in, rc4_key)
                        output_str = " ".join([f"{b:02x}" for b in res_bytes])
                    else:
                        hex_vals = input_text.strip().split()
                        bytes_in = [int(h, 16) for h in hex_vals]
                        res_bytes, logs = rc4_cipher(bytes_in, rc4_key)
                        output_str = "".join([chr(b) for b in res_bytes])

                # 4. RSA Execution
                elif selected_tab == "RSA":
                    if rsa_p * rsa_q <= 255:
                        st.warning("Peringatan: Disarankan (p × q) > 255 agar nilai ASCII lengkap.")
                    
                    if is_encrypt:
                        bytes_in = [ord(c) for c in input_text]
                        res_ints, logs = rsa_process(bytes_in, rsa_p, rsa_q, "encrypt")
                        output_str = " ".join([str(i) for i in res_ints])
                    else:
                        ints_in = [int(x) for x in input_text.strip().split()]
                        res_ints, logs = rsa_process(ints_in, rsa_p, rsa_q, "decrypt")
                        output_str = "".join([chr(i) for i in res_ints])

                # 5. Super Encryption Execution
                elif selected_tab == "Super Enkripsi":
                    if is_encrypt:
                        # Enkripsi: Caesar -> Vigenere -> RC4 -> RSA
                        c1, _ = caesar_cipher(input_text, super_shift, "encrypt")
                        c2, _ = vigenere_cipher(c1, super_vkey, "encrypt")
                        c2_bytes = [ord(c) for c in c2]
                        c3_bytes, _ = rc4_cipher(c2_bytes, super_rkey)
                        c4_ints, logs_rsa = rsa_process(c3_bytes, super_p, super_q, "encrypt")

                        output_str = " ".join([str(x) for x in c4_ints])
                        logs = ["=== 1. Caesar Cipher selesai ===",
                                "=== 2. Vigenère Cipher selesai ===",
                                "=== 3. RC4 Stream Cipher selesai ===",
                                "=== 4. RSA Encryption ==="] + logs_rsa
                    else:
                        # Dekripsi: RSA -> RC4 -> Vigenere -> Caesar
                        ints_in = [int(x) for x in input_text.strip().split()]
                        d1_bytes, logs_rsa = rsa_process(ints_in, super_p, super_q, "decrypt")
                        d2_bytes, _ = rc4_cipher(d1_bytes, super_rkey)
                        d2_str = "".join([chr(b) for b in d2_bytes])
                        d3_str, _ = vigenere_cipher(d2_str, super_vkey, "decrypt")
                        d4_str, _ = caesar_cipher(d3_str, super_shift, "decrypt")

                        output_str = d4_str
                        logs = ["=== 1. RSA Decrypt selesai ===",
                                "=== 2. RC4 Decrypt selesai ===",
                                "=== 3. Vigenère Decrypt selesai ===",
                                "=== 4. Caesar Decrypt selesai ==="] + logs_rsa

import streamlit as st

# ==========================================
# 1. LOGIKA ALGORITMA KRIPTOGRAFI
# ==========================================

def caesar_cipher(text: str, shift: int, mode: str):
    """
    Caesar Cipher: Menggeser alfabet (menjaga huruf besar/kecil) & mempertahankan simbol/spasi.
    """
    result = []
    process_log = []
    effective_shift = shift if mode == "encrypt" else -shift

    for char in text:
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            new_code = (ord(char) - start + effective_shift) % 26 + start
            new_char = chr(new_code)
            result.append(new_char)
            process_log.append(f"'{char}' → Geser {shift} → '{new_char}'")
        else:
            result.append(char)
            process_log.append(f"'{char}' → Tetap (Simbol/Spasi)")

    return "".join(result), process_log


def vigenere_cipher(text: str, key: str, mode: str):
    """
    Universal Vigenère Cipher: Mendukung SEMUA Karakter (Huruf, Spasi, Angka, Simbol)
    Berbasis pergeseran Modulo 256 byte/ASCII. Tidak memerlukan `.isalpha()`.
    """
    if not key:
        key = "KEY"

    result = []
    process_log = []

    for i, char in enumerate(text):
        char_code = ord(char)
        key_char = key[i % len(key)]
        key_shift = ord(key_char)

        if mode == "encrypt":
            new_code = (char_code + key_shift) % 256
        else:
            new_code = (char_code - key_shift + 256) % 256

        new_char = chr(new_code)
        result.append(new_char)
        process_log.append(
            f"Karakter '{char}' + Kunci '{key_char}' (Shift {key_shift}) → Hasil '{new_char}'"
        )

    return "".join(result), process_log


def rc4_cipher(data_bytes: list, key_str: str):
    """
    RC4 Stream Cipher (KSA & PRGA dengan operasi XOR)
    """
    process_log = ["--- Inisialisasi KSA (Key Scheduling Algorithm) ---"]
    S = list(range(256))
    key_bytes = [ord(c) for c in key_str] if key_str else [1]

    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    process_log.append("KSA Selesai. State Array S diacak.")

    process_log.append("--- PRGA & Operasi XOR ---")
    i = j = 0
    result_bytes = []

    for byte_val in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]

        cipher_val = byte_val ^ K
        result_bytes.append(cipher_val)
        process_log.append(f"Byte: {byte_val} XOR Keystream: {K} → Hasil: {cipher_val}")

    return result_bytes, process_log


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return 1


def rsa_process(input_values: list, p: int, q: int, mode: str):
    """
    Kriptografi Asimetris RSA (C = M^e mod n  |  M = C^d mod n)
    """
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1 and e < phi:
        e += 1
    d = mod_inverse(e, phi)

    process_log = [
        f"Parameter: p={p}, q={q}",
        f"Modulus (n) = {n}",
        f"Totient (phi) = {phi}",
        f"Kunci Publik (e) = {e}",
        f"Kunci Privat (d) = {d}",
    ]

    results = []
    if mode == "encrypt":
        process_log.append("--- Enkripsi RSA (C = M^e mod n) ---")
        for val in input_values:
            c = pow(val, e, n)
            results.append(c)
            process_log.append(f"M: {val} → {val}^{e} mod {n} = {c}")
    else:
        process_log.append("--- Dekripsi RSA (M = C^d mod n) ---")
        for val in input_values:
            m = pow(val, d, n)
            results.append(m)
            process_log.append(f"C: {val} → {val}^{d} mod {n} = {m}")

    return results, process_log


# ==========================================
# 2. STREAMLIT CONFIG & CUSTOM STYLING (BLACK-WHITE MONOCHROME)
# ==========================================

st.set_page_config(
    page_title="Modul Kriptosistem Interaktif",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
        color: #0F172A;
    }

    .main {
        background-color: #FAFAFA;
    }

    /* Top Header Bar */
    .app-header {
        background: #09090B;
        color: #FAFAFA;
        padding: 1.25rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border: 1px solid #27272A;
    }
    .app-header h1 {
        font-size: 1.3rem;
        font-weight: 700;
        margin: 0;
        color: #FFFFFF;
        letter-spacing: -0.02em;
    }
    .app-header p {
        font-size: 0.8rem;
        color: #A1A1AA;
        margin: 0;
    }

    /* Card Information Header */
    .info-card {
        background: #FFFFFF;
        border: 1px solid #E4E4E7;
        border-radius: 10px;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
    }
    .badge-mono {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.68rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        background: #F4F4F5;
        color: #18181B;
        border: 1px solid #E4E4E7;
        margin-bottom: 0.35rem;
    }

    /* Custom Streamlit Buttons */
    div.stButton > button {
        background: #09090B !important;
        color: #FFFFFF !important;
        border: 1px solid #09090B !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.25rem !important;
        font-weight: 600 !important;
        font-size: 0.875rem !important;
        width: 100% !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button:hover {
        background: #27272A !important;
        border-color: #27272A !important;
        color: #FFFFFF !important;
    }

    /* Output Box Styling */
    .output-box {
        background: #F4F4F5;
        border: 1px solid #E4E4E7;
        border-radius: 8px;
        padding: 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.875rem;
        color: #09090B;
        word-break: break-all;
        white-space: pre-wrap;
        min-height: 100px;
    }

    .log-item {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #52525B;
        padding: 0.25rem 0;
        border-bottom: 1px solid #F4F4F5;
    }

    /* Pipeline Component */
    .pipeline-container {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
        margin-top: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
    }
    .pipeline-item {
        background: #F4F4F5;
        border: 1px solid #E4E4E7;
        padding: 0.25rem 0.6rem;
        border-radius: 4px;
        color: #18181B;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header Utama
st.markdown(
    """
    <div class="app-header">
        <div>
            <h1>Sistem Kriptosistem Interaktif</h1>
            <p>Penerapan Kriptografi Klasik & Modern</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ==========================================
# 3. NAVIGASI UTAMA & MODE OPERASI
# ==========================================

menu_options = ["Caesar Cipher", "Vigenère Cipher", "RC4", "RSA", "Super Enkripsi"]
selected_tab = st.radio("Pilih Algoritma:", menu_options, horizontal=True)

col_mode1, _ = st.columns([2, 3])
with col_mode1:
    op_mode = st.radio("Mode Operasi:", ["Enkripsi", "Dekripsi"], horizontal=True)
    is_encrypt = op_mode == "Enkripsi"

st.divider()

# Information Card Data
algo_info = {
    "Caesar Cipher": ("Klasik", "Menggeser karakter berdasarkan nilai pergeseran tetap dalam alfabet."),
    "Vigenère Cipher": ("Klasik", "Menggunakan kunci berulang untuk pergeseran karakter dinamis. Mendukung huruf, angka, spasi & simbol."),
    "RC4": ("Modern", "Stream cipher berbasis pembangkitan keystream pseudo-random melalui KSA & PRGA lalu di-XOR dengan data."),
    "RSA": ("Modern", "Kriptografi asimetris berbasis faktorisasi dua bilangan prima (p & q) serta eksponensial modular."),
    "Super Enkripsi": ("Modern (Gabungan)", "Penggabungan bertingkat 4 lapisan: Caesar → Vigenère → RC4 → RSA secara berurutan."),
}

kind, desc = algo_info[selected_tab]
st.markdown(
    f"""
    <div class="info-card">
        <span class="badge-mono">{kind}</span>
        <h3 style="margin: 0; font-size: 1.1rem; font-weight: 700;">{selected_tab}</h3>
        <p style="margin: 0.25rem 0 0 0; font-size: 0.85rem; color: #71717A;">{desc}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if selected_tab == "Super Enkripsi":
    st.markdown(
        """
        <div class="pipeline-container" style="margin-bottom: 1.25rem;">
            <span style="font-weight: 600;">Alur Eksekusi:</span>
            <span class="pipeline-item">1. Caesar</span> →
            <span class="pipeline-item">2. Vigenère</span> →
            <span class="pipeline-item">3. RC4</span> →
            <span class="pipeline-item">4. RSA</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ==========================================
# 4. GOLDEN RATIO LAYOUT (Major 1.618 : Minor 1)
# ==========================================

col_major, col_minor = st.columns([1.618, 1])

# --- MAJOR COLUMN: Input & Parameter ---
with col_major:
    st.subheader("Input & Parameter")

    # Dynamic Labels & Placeholders based on Mode
    if not is_encrypt:
        if selected_tab == "RC4":
            input_label = "Input Hexadesimal (Dipisah Spasi):"
            placeholder = "Contoh: 4a 6f 1c 3e..."
        elif selected_tab in ["RSA", "Super Enkripsi"]:
            input_label = "Input Angka Cipher (Dipisah Spasi):"
            placeholder = "Contoh: 120 45 200 89..."
        else:
            input_label = "Input Ciphertext:"
            placeholder = "Masukkan teks terenkripsi..."
    else:
        input_label = "Input Teks (Plaintext):"
        placeholder = "Ketik pesan rahasia di sini (mendukung spasi, angka & simbol)..."

    input_text = st.text_area(input_label, height=140, placeholder=placeholder)

    # Dynamic Parameter Inputs
    if selected_tab == "Caesar Cipher":
        shift_val = st.number_input("Nilai Shift (1–25):", min_value=1, max_value=25, value=3)

    elif selected_tab == "Vigenère Cipher":
        vigenere_key = st.text_input("Kunci Vigenère (Bebas Karakter, Spasi & Simbol):", value="KUNCI123!")

    elif selected_tab == "RC4":
        rc4_key = st.text_input("Kunci String RC4:", value="SECRET")

    elif selected_tab == "RSA":
        col_p, col_q = st.columns(2)
        with col_p:
            rsa_p = st.number_input("Prima p:", value=17, min_value=2)
        with col_q:
            rsa_q = st.number_input("Prima q:", value=19, min_value=2)
        st.caption(f"Estimasi Modulus (n = p × q): **{rsa_p * rsa_q}**")

    elif selected_tab == "Super Enkripsi":
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            super_shift = st.number_input("Shift Caesar:", value=3)
            super_vkey = st.text_input("Kunci Vigenère:", value="KUNCI123!")
        with col_s2:
            super_rkey = st.text_input("Kunci RC4:", value="SECRET")
            col_sp, col_sq = st.columns(2)
            with col_sp:
                super_p = st.number_input("RSA p:", value=17, min_value=2)
            with col_sq:
                super_q = st.number_input("RSA q:", value=19, min_value=2)

    btn_process = st.button(f"Proses {op_mode}")

# --- MINOR COLUMN: Hasil Executed & Logs ---
with col_minor:
    st.subheader("Hasil & Komputasi")

    if btn_process:
        if not input_text.strip():
            st.error("Error: Masukkan teks input terlebih dahulu!")
        else:
            try:
                output_str = ""
                logs = []
                mode_str = "encrypt" if is_encrypt else "decrypt"

                # 1. Caesar Execution
                if selected_tab == "Caesar Cipher":
                    output_str, logs = caesar_cipher(input_text, shift_val, mode_str)

                # 2. Vigenère Execution
                elif selected_tab == "Vigenère Cipher":
                    output_str, logs = vigenere_cipher(input_text, vigenere_key, mode_str)

                # 3. RC4 Execution
                elif selected_tab == "RC4":
                    if is_encrypt:
                        bytes_in = [ord(c) for c in input_text]
                        res_bytes, logs = rc4_cipher(bytes_in, rc4_key)
                        output_str = " ".join([f"{b:02x}" for b in res_bytes])
                    else:
                        hex_vals = input_text.strip().split()
                        bytes_in = [int(h, 16) for h in hex_vals]
                        res_bytes, logs = rc4_cipher(bytes_in, rc4_key)
                        output_str = "".join([chr(b) for b in res_bytes])

                # 4. RSA Execution
                elif selected_tab == "RSA":
                    if rsa_p * rsa_q <= 255:
                        st.warning("Peringatan: Disarankan (p × q) > 255 agar nilai ASCII lengkap.")

                    if is_encrypt:
                        bytes_in = [ord(c) for c in input_text]
                        res_ints, logs = rsa_process(bytes_in, rsa_p, rsa_q, "encrypt")
                        output_str = " ".join([str(i) for i in res_ints])
                    else:
                        ints_in = [int(x) for x in input_text.strip().split()]
                        res_ints, logs = rsa_process(ints_in, rsa_p, rsa_q, "decrypt")
                        output_str = "".join([chr(i) for i in res_ints])

                # 5. Super Encryption Execution
                elif selected_tab == "Super Enkripsi":
                    if is_encrypt:
                        # Enkripsi: Caesar -> Vigenere -> RC4 -> RSA
                        c1, _ = caesar_cipher(input_text, super_shift, "encrypt")
                        c2, _ = vigenere_cipher(c1, super_vkey, "encrypt")
                        c2_bytes = [ord(c) for c in c2]
                        c3_bytes, _ = rc4_cipher(c2_bytes, super_rkey)
                        c4_ints, logs_rsa = rsa_process(c3_bytes, super_p, super_q, "encrypt")

                        output_str = " ".join([str(x) for x in c4_ints])
                        logs = [
                            "=== 1. Caesar Cipher Selesai ===",
                            "=== 2. Vigenère Cipher Selesai ===",
                            "=== 3. RC4 Stream Cipher Selesai ===",
                            "=== 4. RSA Encryption ===",
                        ] + logs_rsa
                    else:
                        # Dekripsi: RSA -> RC4 -> Vigenere -> Caesar
                        ints_in = [int(x) for x in input_text.strip().split()]
                        d1_bytes, logs_rsa = rsa_process(ints_in, super_p, super_q, "decrypt")
                        d2_bytes, _ = rc4_cipher(d1_bytes, super_rkey)
                        d2_str = "".join([chr(b) for b in d2_bytes])
                        d3_str, _ = vigenere_cipher(d2_str, super_vkey, "decrypt")
                        d4_str, _ = caesar_cipher(d3_str, super_shift, "decrypt")

                        output_str = d4_str
                        logs = [
                            "=== 1. RSA Decrypt Selesai ===",
                            "=== 2. RC4 Decrypt Selesai ===",
                            "=== 3. Vigenère Decrypt Selesai ===",
                            "=== 4. Caesar Decrypt Selesai ===",
                        ] + logs_rsa

                # Display Output Result
                st.markdown(f'<div class="output-box">{output_str}</div>', unsafe_allow_html=True)

                # Display Computation Logs
                with st.expander(f"Rincian Langkah Komputasi ({len(logs)})"):
                    for log in logs:
                        st.markdown(f'<div class="log-item">{log}</div>', unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Terjadi Kesalahan Pemrosesan: {str(e)}")
    else:
        st.markdown(
            '<div class="output-box" style="color: #A1A1AA;">(Hasil eksekusi akan muncul di sini)</div>',
            unsafe_allow_html=True,
        )
