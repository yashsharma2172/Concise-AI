import streamlit as st
import requests
import json
import fitz  # PyMuPDF
import bcrypt
from supabase import create_client, Client
from dotenv import load_dotenv
import os

load_dotenv()

# Get Supabase credentials from environment variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.2"

# ========== Validate Credentials ==========
if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("Supabase credentials not found. Please set SUPABASE_URL and SUPABASE_KEY.")
    st.stop()

# ========== Connect to Supabase ==========
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ========== Auth Helpers ==========
def get_user(username):
    response = supabase.table("users").select("*").eq("username", username).execute()
    return response.data[0] if response.data else None

def register_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    supabase.table("users").insert({"username": username, "password": hashed_password}).execute()

def validate_credentials(username, password):
    return username.isalnum() and len(username) >= 3 and len(password) >= 6

def login_register():
    st.set_page_config(page_title="Login / Register", layout="centered")
    st.title("🔐 Login / Register")

    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "Login"
    if "username_input" not in st.session_state:
        st.session_state.username_input = ""
    if "password_input" not in st.session_state:
        st.session_state.password_input = ""

    def switch_mode():
        st.session_state.username_input = ""
        st.session_state.password_input = ""

    st.radio(
        "Select Option",
        ["Login", "Register"],
        horizontal=True,
        key="auth_mode",
        on_change=switch_mode
    )

    username = st.text_input("Username", key="username_input")
    password = st.text_input("Password", type="password", key="password_input")

    if st.session_state.auth_mode == "Login":
        if st.button("Login", use_container_width=True):
            user = get_user(username)
            if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success(f"Welcome, {username}!")
                st.rerun()
            else:
                st.error("Invalid username or password")
    else:
        if st.button("Register", use_container_width=True):
            if get_user(username):
                st.warning("Username already exists.")
            elif not validate_credentials(username, password):
                st.error("Username must be alphanumeric and ≥ 3 chars. Password ≥ 6 chars.")
            else:
                register_user(username, password)
                st.success("Registration successful! You can now log in.")

# ========== Prompt Builder ==========
def build_prompt(text):
    return f"""
You are a smart and concise summarization assistant. Summarize the following paragraph into a short, clear, and informative summary. Focus on the key points, avoid repetition, and ensure the summary captures the essence of the text.

Text:
\"\"\"
{text}
\"\"\"

Summary:
"""

# ========== PDF Extractor ==========
def extract_text_from_pdf(uploaded_file):
    doc = fitz.open(stream=uploaded_file.read(), filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    return text.strip()

# ========== Login Check ==========
if "logged_in" not in st.session_state or not st.session_state["logged_in"]:
    login_register()
    st.stop()

# ========== Main App ==========
st.set_page_config(page_title="Text Summarizer", layout="wide")

# Sidebar - Settings
st.sidebar.title("⚙ Settings")
theme_color = st.sidebar.selectbox("🎨 Color Theme", ["Blue", "Green", "Purple", "Orange", "Gray"])
model_name = st.sidebar.selectbox("🤖 Select Model", ["phi4:latest", "llama3.2"], index=0)
input_type = st.sidebar.radio("Input Type", ["Text Input", "Upload PDF"])
api_url = st.sidebar.text_input("Ollama API URL", value=OLLAMA_URL)

# Theme color mapping
color_map = {
    "Blue": "#3498db", "Green": "#2ecc71", "Purple": "#9b59b6",
    "Orange": "#e67e22", "Gray": "#7f8c8d"
}
highlight_color = color_map.get(theme_color, "#3498db")

# Global styling
st.markdown(f"""
    <style>
        html, body, [class*="css"] {{
            color: {highlight_color} !important;
        }}
        .stTextInput > label, .stTextArea > label, .stFileUploader > label {{
            color: {highlight_color} !important;
        }}
        .stButton button {{
            background-color: {highlight_color} !important;
            color: white !important;
            border-radius: 8px !important;
        }}
    </style>
""", unsafe_allow_html=True)

# Header
st.markdown(f"<h1 style='color:{highlight_color};'>📚 Concise-AI: Document Summarizer </h1>", unsafe_allow_html=True)
st.markdown("Summarize text or PDF documents using the locally running Ollama models with real-time streaming results.")

# Logout and Clear Buttons
col_logout, col_clear = st.columns([1, 1])
with col_logout:
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.clear()
        st.rerun()

with col_clear:
    if st.button("🗑 Clear All", use_container_width=True):
        st.rerun()

# Input Section
st.markdown(f"<h3 style='color:{highlight_color};'>📝 Input Section</h3>", unsafe_allow_html=True)
input_text = ""

if input_type == "Text Input":
    input_text = st.text_area("Enter text to summarize", height=200)
else:
    uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")
    if uploaded_file:
        input_text = extract_text_from_pdf(uploaded_file)
        st.success(f"✅ Extracted {len(input_text.split())} words from PDF")

# Summarize
if st.button("Summarize", use_container_width=True):
    if not input_text.strip():
        st.warning("Please enter some text to summarize.")
    else:
        st.markdown(f"<h3 style='color:{highlight_color};'>🔍 Summary</h3>", unsafe_allow_html=True)
        with st.spinner("Summarizing..."):
            prompt = build_prompt(input_text)
            try:
                response = requests.post(
                    api_url,
                    json={
                        "model": model_name,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": True
                    },
                    stream=True
                )

                summary = ""
                placeholder = st.empty()
                for line in response.iter_lines():
                    if line:
                        line_data = json.loads(line.decode('utf-8'))
                        if 'message' in line_data and 'content' in line_data['message']:
                            chunk = line_data['message']['content']
                            summary += chunk
                            placeholder.write(summary)  # Unstyled plain summary

                # Analysis
                st.markdown(f"<h3 style='color:{highlight_color};'>📊 Text Analysis</h3>", unsafe_allow_html=True)
                original_words = len(input_text.split())
                summary_words = len(summary.split())
                summary_chars = len(summary)
                compression = (1 - (summary_words / original_words)) * 100 if original_words else 0

                col1, col2, col3 = st.columns(3)
                col1.metric("Word Count", summary_words)
                col2.metric("Character Count", summary_chars)
                col3.metric("Compression", f"{compression:.1f}%")

                st.download_button("💾 Download Summary", summary, file_name="summary.txt")
            except Exception as e:
                st.error(f"Error: {e}")
