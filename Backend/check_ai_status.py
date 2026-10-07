import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load .env
backend_dir = Path(__file__).resolve().parent.parent
load_dotenv(backend_dir / ".env")
load_dotenv(backend_dir / "app" / ".env")

from app.ai_assistant import ask_cybertwin_ai

openai_key = os.getenv("OPENAI_API_KEY")
gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
openai_model = os.getenv("OPENAI_MODEL", "gpt-6-astra")
gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

print("=" * 60)
print("        CYBERATLAS LIVE AI HEALTH & MODEL DIAGNOSTIC")
print("=" * 60)
print(f"1. OpenAI Key     : {'Configured (' + openai_key[:12] + '...)' if openai_key else 'Missing'}")
print(f"   Target Model   : {openai_model}")
print(f"2. Gemini Key     : {'Configured (' + gemini_key[:12] + '...)' if gemini_key else 'Not set in .env'}")
print(f"   Target Model   : {gemini_model}")
print("-" * 60)
print("[*] Running test inquiry through AI Copilot...")

res = ask_cybertwin_ai("How do I block unauthorized ingress on port 3306?")

print(f"-> Active Provider  : {res.get('provider')}")
print(f"-> Model Utilized   : {res.get('model')}")
print(f"-> Response Status  : {res.get('status')}")
print(f"-> Target Exposure  : {res.get('target_vulnerability')}")
print("-" * 60)
print("GENERATED TECHNICAL REMEDIATION SCRIPT PREVIEW:")
print(res.get("remediation_script_ps1", "")[:280] + "...")
print("=" * 60)
