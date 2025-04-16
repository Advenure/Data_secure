import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Load or generate encryption key (simulated cache for demo purposes)
@st.cache_data
def load_key():
    return Fernet.generate_key()

KEY = load_key()
cipher = Fernet(KEY)

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user_id": {"encrypted_text": "...", "passkey": "..."}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'choice' not in st.session_state:
    st.session_state.choice = "Home"

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text:
            if value["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.choice))

# Store the current page choice
st.session_state.choice = choice

# Home
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    identifier = st.text_input("Enter a unique ID for your data (e.g., user1_data):")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if identifier and user_data and passkey:
            if identifier in st.session_state.stored_data:
                st.warning("⚠️ This ID already exists! Use a different one.")
            else:
                hashed_pass = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                st.session_state.stored_data[identifier] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_pass
                }
                st.success("✅ Data stored securely!")
                st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ All fields are required!")

# Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    identifier = st.text_input("Enter your data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if identifier and passkey:
            if identifier in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[identifier]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                        st.session_state.choice = "Login"
                        st.experimental_rerun()
            else:
                st.error("❌ No data found with this ID.")
        else:
            st.error("⚠️ Both fields are required!")

# Login (Master Password)
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure method in production
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! You may now try again.")
        else:
            st.error("❌ Incorrect password!")
