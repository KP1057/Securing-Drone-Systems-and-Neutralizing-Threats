import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from base64 import b64decode
from io import BytesIO
import os

def decrypt(encrypted_data, key):
    data = b64decode(encrypted_data)
    cipher = AES.new(key, AES.MODE_EAX, nonce=data[:16])
    decrypted_data = cipher.decrypt_and_verify(data[32:], data[16:32])
    return decrypted_data

def hash_data(data):
    hash_object = SHA256.new(data=data)
    return hash_object.hexdigest()

def main():
    st.title("File Decryption")

    custom_key = st.text_input("Enter the decryption key (16 bytes)", max_chars=32)
    if custom_key:
        key = b64decode(custom_key)[:16]  # Decode the base64 key and take the first 16 bytes
    else:
        st.error("Please enter the decryption key.")
        return