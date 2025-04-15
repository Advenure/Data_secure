import streamlit as st
import hashlib 
from cryptography.fernet import Fernet

# Generate a key (this should be securely stored in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # {"user_data": {"encrypted_text": "...", "passkey": "..."}}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text:
            if value["passkey"] == hashed_passkey:
                failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()

    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    identifier = st.text_input("Enter a unique ID for your data (e.g., user1_data):")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if identifier and user_data and passkey:
            if identifier in stored_data:
                st.warning("⚠️ This ID already exists! Use a different one.")
            else:
                hashed_pass = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                stored_data[identifier] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_pass
                }
                st.success("✅ Data stored securely!")
                st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    identifier = st.text_input("Enter your data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if identifier and passkey:
            if identifier in stored_data:
                encrypted_text = stored_data[identifier]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                        st.switch_page("Login")  # or use st.experimental_rerun()
            else:
                st.error("❌ No data found with this ID.")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # For demo
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! You may now try again.")
        else:
            st.error("❌ Incorrect password!")
