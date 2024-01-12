import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from base64 import b64encode
from io import BytesIO
import os

def generate_random_key():
    return os.urandom(16)

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(nonce + tag + ciphertext)

def hash_data(data):
    hash_object = SHA256.new(data=data)
    return hash_object.hexdigest()

def main():
    st.title("File Encryption")

    key = generate_random_key()
    st.subheader("Generated Key:")
    st.text(b64encode(key).decode('utf-8'))
    st.markdown(get_text_file_downloader_html(b64encode(key).decode('utf-8'), "Generated_Key"), unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Choose a file for encryption")

    if uploaded_file:
        file_content = uploaded_file.read()

        st.subheader("Original File Content:")
        st.text(f"File Size: {len(file_content)} bytes")

        encrypted_data = encrypt(file_content, key)

        st.subheader("Download Encrypted File:")
        st.markdown(get_binary_file_downloader_html(encrypted_data, "Encrypted_File", uploaded_file.type), unsafe_allow_html=True)

        original_hash = hash_data(file_content)
        encrypted_hash = hash_data(encrypted_data)
        st.write("Original File Hash:", original_hash)
        st.write("Encrypted File Hash:", encrypted_hash)

def get_binary_file_downloader_html(bin_data, file_label, file_extension):
    bin_file_io = BytesIO(bin_data)
    href = f"<a href='data:application/octet-stream;base64,{b64encode(bin_data).decode('utf-8')}' download='{file_label}.{file_extension}'>Download {file_label}</a>"
    return href

def get_text_file_downloader_html(text_data, file_label):
    href = f"<a href='data:text/plain;base64,{b64encode(text_data.encode('utf-8')).decode('utf-8')}' download='{file_label}.txt'>Download {file_label}</a>"
    return href

if __name__ == "__main__":
    main()