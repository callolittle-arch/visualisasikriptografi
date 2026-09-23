import streamlit as st
from streamlit_option_menu import option_menu
import random
import time

#caesar 
def caesar_cipher(text, shift, mode):
    result = ""
    process_log = []
    shift = shift if mode == 'encrypt' else -shift

    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
            process_log.append(f"'{char}' -> Geser {shift} -> '{new_char}'")
        else:
            result += char
            process_log.append(f"'{char}' -> Tetap -> '{char}'")

    return result, process_log

#vignere
def vigenere_cipher(text, key, mode):
    result = ""
    process_log = []
    key = key.upper()
    key_idx = 0

    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            if mode == 'decrypt':
                shift = -shift

            new_char = chr((ord(char) - start + shift) % 26 + start)
            result += new_char
            process_log.append(f"'{char}' + Kunci '{key[key_idx % len(key)]}' (Shift {shift}) -> '{new_char}'")
            key_idx += 1
        else:
            result += char
            process_log.append(f"'{char}' -> Tetap -> '{char}'")

    return result, process_log

#rc4
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
        process_log.append(f"Data: {char_val} XOR Kunci Stream: {K} -> Hasil: {cipher_val}")

    return result, process_log

#Rsa
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
        f"Kunci Privat (d) = {d}"
    ]

    result = []
    if mode == 'encrypt':
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
    page_title="APLIKASI INTERAKTIF KRIPTO :v",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Poppins', sans-serif;
    }

    .main {
        background: linear-gradient(180deg, #fdfbff 0%, #f6f4ff 100%);
    }

    /* Hero header */
    .hero-box {
        background: linear-gradient(120deg, #6C5CE7 0%, #8E7CFF 45%, #A78BFA 100%);
        padding: 2rem 2.2rem;
        border-radius: 20px;
        color: white;
        margin-bottom: 1rem;
        box-shadow: 0 10px 30px rgba(108, 92, 231, 0.25);
    }
    .hero-box h1 {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.3rem;
    }
    .hero-box p {
        font-size: 1rem;
        opacity: 0.92;
        margin: 0;
    }

    /* Navbar wrapper supaya menyatu dengan tema ungu */
    .navbar-wrap {
        background: #2D2A4A;
        border-radius: 14px;
        padding: 0.3rem 0.6rem;
        margin-bottom: 1.2rem;
        box-shadow: 0 6px 16px rgba(45, 42, 74, 0.25);
    }

    /* Kartu info algoritma */
    .algo-card {
        background: white;
        border-radius: 16px;
        padding: 1.2rem 1.4rem;
        border: 1px solid #ECE9FF;
        box-shadow: 0 4px 14px rgba(108, 92, 231, 0.06);
        margin-bottom: 1.2rem;
    }
    .algo-card h3 {
        margin-top: 0;
        color: #4B3FCF;
    }
    .algo-card p {
        color: #555;
        font-size: 0.93rem;
        line-height: 1.5;
    }

    .badge {
        display: inline-block;
        padding: 0.25rem 0.7rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.4rem;
    }
    .badge-klasik { background: #FFF1E6; color: #E67E22; }
    .badge-modern { background: #E6F7EF; color: #1E9E6B; }

    div.stButton > button {
        background: linear-gradient(120deg, #6C5CE7, #8E7CFF);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.6rem 1.6rem;
        font-weight: 600;
        font-size: 0.95rem;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
        box-shadow: 0 6px 16px rgba(108, 92, 231, 0.3);
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 22px rgba(108, 92, 231, 0.4);
        color: white;
    }

    /* Tombol toggler mode operasi, dibuat mirip navbar-toggler Bootstrap */
    div[data-testid="stPopover"] > div > button {
        background: #ffffff22;
        color: white;
        border: 1px solid #ffffff55;
        border-radius: 10px;
        font-weight: 600;
    }
    div[data-testid="stPopover"] > div > button:hover {
        background: #ffffff33;
        border-color: #ffffff88;
        color: white;
    }

    .result-box {
        background: #F3F1FF;
        border-left: 5px solid #6C5CE7;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        font-family: 'Fira Code', monospace;
        font-size: 0.95rem;
        word-wrap: break-word;
        white-space: pre-wrap;
        color: #2D2A4A;
    }

    .log-line {
        font-family: 'Fira Code', monospace;
        font-size: 0.82rem;
        padding: 0.15rem 0;
        border-bottom: 1px dashed #eee;
        color: #444;
    }

    .pipeline {
        display: flex;
        align-items: center;
        gap: 0.4rem;
        flex-wrap: wrap;
        margin: 0.6rem 0 1rem 0;
    }
    .pipeline-step {
        background: #F3F1FF;
        color: #4B3FCF;
        padding: 0.4rem 0.9rem;
        border-radius: 999px;
        font-weight: 600;
        font-size: 0.85rem;
        border: 1px solid #DCD6FF;
    }
    .pipeline-arrow {
        color: #A78BFA;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

#hero
st.markdown("""
<div class="hero-box">
    <h1>Aplikasi kriptografi</h1>
</div>
""", unsafe_allow_html=True)

menu_options = [
    "Caesar Cipher",
    "Vigenere Cipher",
    "RC4",
    "RSA",
    "Super Enkripsi",
]

nav_col, toggler_col = st.columns([6, 1.3])

with nav_col:
    st.markdown('<div class="navbar-wrap">', unsafe_allow_html=True)
    selected = option_menu(
        menu_title=None,
        options=menu_options,
        default_index=0,
        orientation="horizontal",
        styles={
            "container": {"padding": "4px 6px", "background-color": "#2D2A4A"},
            "icon": {"color": "#C9C3FF", "font-size": "15px"},
            "nav-link": {
                "font-size": "14px",
                "font-weight": "600",
                "color": "#EFEDFF",
                "text-align": "center",
                "margin": "2px",
                "border-radius": "10px",
                "--hover-color": "#3d3966",
            },
            "nav-link-selected": {
                "background": "linear-gradient(120deg, #6C5CE7, #8E7CFF)",
                "color": "white",
            },
        },
    )
    st.markdown('</div>', unsafe_allow_html=True)


with toggler_col:
    st.write("")  # sedikit spacer supaya sejajar vertikal dengan navbar
    with st.popover("Mode", use_container_width=True):
        st.markdown("**Mode Operasi**")
        is_decrypt_toggle = st.toggle("Mode Dekripsi", value=False)
        is_encrypt = not is_decrypt_toggle
        st.caption("Nonaktif = **Enkripsi**, Aktif = **Dekripsi**.")
        st.caption(" Buka bagian #Lihat Proses di bawah hasil untuk memahami langkah kerja algoritmanya.")

mode = "Enkripsi" if is_encrypt else "Dekripsi"
st.caption(f"Mode aktif saat ini: **{mode}**")

algo_info = {
    "Caesar Cipher": ("Caesar Cipher", "klasik", "Menggeser setiap huruf sejauh N posisi dalam alfabet. Sederhana, mudah dipahami, tapi mudah dipecahkan."),
    "Vigenere Cipher": ("Vigenère Cipher", "klasik", "Mengembangkan Caesar dengan kunci berupa kata setiap huruf digeser berdasarkan huruf kunci yang berulang."),
    "RC4": ("RC4", "modern", "Stream cipher yang menghasilkan aliran byte semu acak (keystream) dari kunci, lalu di-XOR dengan data asli."),
    "RSA": ("RSA", "modern", "Kriptografi asimetris berbasis bilangan prima besar, menggunakan pasangan kunci publik dan privat."),
    "Super Enkripsi": ("Super Enkripsi", "modern", "Menggabungkan keempat algoritma secara berurutan untuk lapisan keamanan berlapis."),
}

def render_algo_card(key):
    name, kind, desc = algo_info[key]
    badge_class = "badge-klasik" if kind == "klasik" else "badge-modern"
    badge_text = "Klasik" if kind == "klasik" else " Modern"
    st.markdown(f"""
    <div class="algo-card">
        <span class="badge {badge_class}">{badge_text}</span>
        <h3>{name}</h3>
        <p>{desc}</p>
    </div>
    """, unsafe_allow_html=True)

def render_result(title, content):
    st.markdown(f"#### {title}")
    st.markdown(f'<div class="result-box">{content}</div>', unsafe_allow_html=True)

def render_logs(logs):
    with st.expander("Lihat Proses Algoritma"):
        for log in logs:
            st.markdown(f'<div class="log-line">{log}</div>', unsafe_allow_html=True)


if selected == "Caesar Cipher":
    render_algo_card("Caesar Cipher")
    col_input, col_side = st.columns([2, 1])
    with col_input:
        text = st.text_area("Masukkan Teks:", height=120, placeholder="Contoh: Halo Dunia")
    with col_side:
        shift = st.number_input("Nilai Pergeseran (Shift):", min_value=1, max_value=25, value=3)
        st.caption(f"Setiap huruf akan digeser **{shift} posisi** dalam alfabet.")

    if st.button("Proses Sekarang", key="btn_caesar"):
        with st.spinner("Sedang memproses teksmu..."):
            time.sleep(0.3)
            res, logs = caesar_cipher(text, shift, 'encrypt' if is_encrypt else 'decrypt')
        render_result("Hasil", res if res else "(kosong)")
        render_logs(logs)

elif selected == "Vigenere Cipher":
    render_algo_card("Vigenere Cipher")
    col_input, col_side = st.columns([2, 1])
    with col_input:
        text = st.text_area("Masukkan Teks:", height=120, placeholder="Contoh: Rahasia Negara")
    with col_side:
        key = st.text_input("Kunci (Huruf):", value="KUNCI")
        st.caption("Kunci akan diulang untuk mencocokkan panjang teks.")

    if st.button("Proses Sekarang", key="btn_vigenere"):
        if not key.isalpha():
            st.error("Kunci harus berupa huruf tanpa spasi atau angka!")
        else:
            with st.spinner("Sedang memproses teksmu..."):
                time.sleep(0.3)
                res, logs = vigenere_cipher(text, key, 'encrypt' if is_encrypt else 'decrypt')
            render_result("Hasil", res if res else "(kosong)")
            render_logs(logs)

elif selected == "RC4":
    render_algo_card("RC4")
    col_input, col_side = st.columns([2, 1])
    with col_input:
        label = "Masukkan Teks:" if is_encrypt else "Masukkan Hex (dipisah spasi):"
        placeholder = "Contoh: Data Rahasia" if is_encrypt else "Contoh: 4a 6f 1c"
        text = st.text_area(label, height=120, placeholder=placeholder)
    with col_side:
        key = st.text_input("Kunci RC4:", value="SECRET")
        st.caption("Kunci digunakan untuk membangkitkan aliran byte acak (keystream).")

    if st.button("Proses Sekarang", key="btn_rc4"):
        try:
            with st.spinner("Menjalankan KSA & PRGA..."):
                time.sleep(0.3)
                if not is_encrypt:
                    text_input = [int(x, 16) for x in text.split()]
                else:
                    text_input = text

                res, logs = rc4(text_input, key)

                if is_encrypt:
                    final_res = " ".join([hex(x)[2:].zfill(2) for x in res])
                else:
                    final_res = "".join([chr(x) for x in res])

            render_result("Hasil", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error("Format input dekripsi salah. Pastikan berupa Hexadesimal dipisah spasi, contoh: `4a 6f 1c`.")

elif selected == "RSA":
    render_algo_card("RSA")
    st.info("Menggunakan bilangan prima kecil agar proses matematis lebih mudah dipahami secara manual.")

    label = "Masukkan Teks:" if is_encrypt else " Masukkan Angka (dipisah spasi):"
    placeholder = "Contoh: Halo" if is_encrypt else "Contoh: 120 45 200"
    text = st.text_area(label, height=100, placeholder=placeholder)

    col1, col2 = st.columns(2)
    with col1:
        p = st.number_input("Bilangan Prima 1 (p):", value=17)
    with col2:
        q = st.number_input("Bilangan Prima 2 (q):", value=19)
    st.caption(f"Modulus n = p × q = **{p * q}** — pastikan lebih besar dari nilai ASCII karakter (>255) untuk hasil yang aman.")

    if st.button("Proses Sekarang", key="btn_rsa"):
        try:
            with st.spinner("Menghitung kunci publik & privat..."):
                time.sleep(0.3)
                if not is_encrypt:
                    text_input = [int(x) for x in text.split()]
                else:
                    text_input = text

                res, logs = rsa_process(text_input, p, q, 'encrypt' if is_encrypt else 'decrypt')

                if is_encrypt:
                    final_res = " ".join([str(x) for x in res])
                else:
                    final_res = "".join([chr(x) for x in res])

            render_result("Hasil", final_res if final_res else "(kosong)")
            render_logs(logs)
        except Exception:
            st.error("Terjadi kesalahan komputasi. Pastikan nilai (p × q) lebih besar dari nilai ASCII karakter (>255).")

elif selected == "Super Enkripsi":
    render_algo_card("Super Enkripsi")

    st.markdown("""
    <div class="pipeline">
        <div class="pipeline-step"> Caesar</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step"> Vigenère</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step"> RC4</div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step"> RSA</div>
    </div>
    """, unsafe_allow_html=True)

    label = "Masukkan Teks:" if is_encrypt else " Masukkan Angka Hasil Enkripsi (dipisah spasi):"
    text = st.text_area(label, height=110)

    col1, col2 = st.columns(2)
    with col1:
        c_shift = st.number_input("Shift Caesar:", value=3)
        v_key = st.text_input("Kunci Vigenère:", value="KUNCI")
    with col2:
        rc4_key = st.text_input(" Kunci RC4:", value="SECRET")
        p = st.number_input(" RSA p:", value=17)
        q = st.number_input(" RSA q:", value=19)

    if st.button(" Proses Super Enkripsi", key="btn_super"):
        try:
            if is_encrypt:
                with st.spinner("Melewati 4 lapis enkripsi "):
                    time.sleep(0.4)
                    out_c, log_c = caesar_cipher(text, c_shift, 'encrypt')
                    out_v, log_v = vigenere_cipher(out_c, v_key, 'encrypt')
                    out_r, log_r = rc4(out_v, rc4_key)
                    out_rsa, log_rsa = rsa_process(out_r, p, q, 'encrypt')
                    final_res = " ".join([str(x) for x in out_rsa])

                render_result("Hasil Akhir Super Enkripsi", final_res)

                with st.expander("Lihat Proses Algoritma Secara Detail (Tahap 1 - 4)"):
                    t1, t2, t3, t4 = st.tabs(["1. Caesar", "2. Vigenère", "3. RC4", "4. RSA"])
                    with t1:
                        st.write(out_c)
                    with t2:
                        st.write(out_v)
                    with t3:
                        st.write(" ".join([hex(x)[2:] for x in out_r]))
                    with t4:
                        st.write(final_res)
            else:
                with st.spinner("Membalik 4 lapis enkripsi..."):
                    time.sleep(0.4)
                    text_input = [int(x) for x in text.split()]
                    out_rsa, _ = rsa_process(text_input, p, q, 'decrypt')
                    out_r, _ = rc4(out_rsa, rc4_key)
                    out_r_str = "".join([chr(x) for x in out_r])
                    out_v, _ = vigenere_cipher(out_r_str, v_key, 'decrypt')
                    out_c, _ = caesar_cipher(out_v, c_shift, 'decrypt')

                render_result("Hasil Akhir Super Dekripsi", out_c)

        except Exception:
            st.error("Terjadi kesalahan. Pastikan input dekripsi valid dan parameter kunci sama persis dengan saat enkripsi.")

st.markdown("---")