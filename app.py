import random
import time
import streamlit as st
from streamlit_option_menu import option_menu

#caesar
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
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            shift = ord(key[key_idx % len(key)]) - ord("A")
            if mode == "decrypt":
                shift = -shift

            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
            process_log.append(
                f"'{char}' + Kunci '{key[key_idx % len(key)]}' (Shift {shift}) -> '{new_char}'"
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


# ==========================================
# CONFIG & STYLING
# ==========================================
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
        background: #0F172A;
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
        color: #F8FAFC;
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
</style>
""",
    unsafe_allow_html=True,
)

# Header
st.markdown(
    """
<div class="header-box">
    <h1>Modul Kriptosistem Interaktif</h1>
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
                "background-color": "#2563EB",
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
        st.caption(
            f"Status: **{'Enkripsi' if is_encrypt else 'Dekripsi'}** aktif."
        )

mode = "Enkripsi" if is_encrypt else "Dekripsi"

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
        if not key.isalpha():
            st.error("Kunci harus berupa huruf!")
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

    st.markdown(
        """
    <div class="pipeline">
        <div class="pipeline-step">1. Caesar</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">2. Vigenère</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">3. RC4</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">4. RSA</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

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

                with st.expander("Detail Tahapan Enkripsi (1 - 4)"):
                    t1, t2, t3, t4 = st.tabs(
                        ["1. Caesar", "2. Vigenère", "3. RC4", "4. RSA"]
                    )
                    with t1:
                        st.code(out_c)
                    with t2:
                        st.code(out_v)
                    with t3:
                        st.code(" ".join([hex(x)[2:] for x in out_r]))
                    with t4:
                        st.code(final_res)
            else:
                text_input = [int(x) for x in text.split()]
                out_rsa, _ = rsa_process(text_input, p, q, "decrypt")
                out_r, _ = rc4(out_rsa, rc4_key)
                out_r_str = "".join([chr(x) for x in out_r])
                out_v, _ = vigenere_cipher(out_r_str, v_key, "decrypt")
                out_c, _ = caesar_cipher(out_v, c_shift, "decrypt")

                render_result("Hasil Super Dekripsi", out_c)

        except Exception:
            st.error(
                "Gagal memproses Super Enkripsi. Pastikan parameter kunci dan format input sesuai."
            )

st.markdown("</div>", unsafe_allow_html=True)
