import streamlit as st
import random
import string
import pyperclip
import os
import base64
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation
    
    return ''.join(random.choice(characters) for _ in range(length))

def encrypt_password(password):
    return base64.b64encode(password.encode()).decode()

def decrypt_password(encrypted_password):
    return base64.b64decode(encrypted_password.encode()).decode()

def save_password_to_file(password, filename):
    with open(filename, 'w') as file:
        file.write(password)

def load_password_from_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def check_password_strength(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase the length to at least 8 characters.")
    if not any(char.isupper() for char in password):
        suggestions.append("Include at least one uppercase letter.")
    if not any(char.isdigit() for char in password):
        suggestions.append("Include at least one number.")
    if not any(char in string.punctuation for char in password):
        suggestions.append("Include at least one special character.")
    
    if not suggestions:
        return "Your password is strong! ✅"
    return "Suggestions to improve password strength:\n- " + "\n- ".join(suggestions)

st.set_page_config(page_title="🔐 Password Strength Checker", layout="centered")
st.title("🔐 Password Strength Checker")

st.sidebar.header("🔑 Password Generator")
length = st.sidebar.slider("Select password length", min_value=6, max_value=32, value=12)
use_uppercase = st.sidebar.checkbox("Include Uppercase Letters")
use_numbers = st.sidebar.checkbox("Include Numbers")
use_special_chars = st.sidebar.checkbox("Include Special Characters")

generated_password = ""
encrypted_password = ""
decrypted_password = ""
saved_password = ""

if st.sidebar.button("Generate Password"):
    generated_password = generate_password(length, use_uppercase, use_numbers, use_special_chars)
    st.sidebar.success("Password generated successfully!")
    st.sidebar.text_input("Generated Password", generated_password, key="password_display", disabled=True)
    
    if st.sidebar.button("Copy to Clipboard"):
        pyperclip.copy(generated_password)
        st.sidebar.success("Password copied to clipboard!")

st.subheader("🔍 Password Strength Checker")
user_password = st.text_input("Enter your password to check strength:", type="password")

if user_password:
    strength_message = check_password_strength(user_password)
    st.info(strength_message)

    if st.button("Encrypt Password"):
        encrypted_password = encrypt_password(user_password)
        st.text_input("Encrypted Password", encrypted_password, key="encrypted_password_display", disabled=True)
    
    if encrypted_password and st.button("Decrypt Password"):
        decrypted_password = decrypt_password(encrypted_password)
        st.text_input("Decrypted Password", decrypted_password, key="decrypted_password_display", disabled=True)
    
    filename = "password.txt"
    if st.button("Save Password to File"):
        save_password_to_file(user_password, filename)
        st.success(f"Password saved to {filename}")
    
    if st.button("Load Password from File"):
        saved_password = load_password_from_file(filename)
        st.text_input("Saved Password", saved_password, key="saved_password_display", disabled=True)
