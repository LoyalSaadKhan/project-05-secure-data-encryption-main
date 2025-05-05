import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet, InvalidToken

# ---------- File Paths ----------
DATA_FILE = 'stored_data.json'
KEY_FILE = 'fernet.key'

# ---------- Persistent Key Setup ----------
def load_fernet_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

fernet_key = load_fernet_key()
cipher = Fernet(fernet_key)

# ---------- Load & Save ----------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# ---------- Streamlit Setup ----------
st.set_page_config(page_title="Secure Data Vault", page_icon="🔐", layout="centered")

# Initialize session states
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

# ---------- Utilities ----------
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(username, passkey):
    data = st.session_state.stored_data[username]
    if data["attempts"] >= 3:
        return "locked"
    if hash_text(passkey) == data["passkey"]:
        try:
            decrypted = cipher.decrypt(data["encrypted"].encode()).decode()
            data["attempts"] = 0
            save_data(st.session_state.stored_data)
            return decrypted
        except InvalidToken:
            data["attempts"] += 1
            save_data(st.session_state.stored_data)
            return None
    else:
        data["attempts"] += 1
        save_data(st.session_state.stored_data)
        return None

# ---------- Register ----------
def register():
    st.subheader("📝 Register")
    new_user = st.text_input("New Username")
    new_pass = st.text_input("New Password", type="password")
    if st.button("Register"):
        if new_user in st.session_state.stored_data:
            st.error("🚫 Username already exists!")
        elif new_user and new_pass:
            st.session_state.stored_data[new_user] = {
                "password": hash_text(new_pass),
                "encrypted": "",
                "passkey": "",
                "attempts": 0
            }
            save_data(st.session_state.stored_data)
            st.success("✅ Registration successful! Please login.")
        else:
            st.warning("⚠️ Please fill all fields.")

# ---------- Login ----------
def login():
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        data = st.session_state.stored_data.get(user)
        if data and data["password"] == hash_text(pwd):
            st.session_state.logged_in_user = user
            st.success("✅ Logged in!")
            st.rerun()
        else:
            st.error("❌ Invalid credentials!")

# ---------- Store Data ----------
def store_data():
    st.subheader("📂 Store Data")
    data = st.text_area("Enter secret data:")
    passkey = st.text_input("Set passkey:", type="password")
    if st.button("Encrypt & Save"):
        if data and passkey:
            encrypted = encrypt_data(data)
            st.session_state.stored_data[st.session_state_]()
