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
