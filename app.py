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
