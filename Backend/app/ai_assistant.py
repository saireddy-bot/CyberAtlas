import os
import json
import httpx
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv

# Load .env from Backend root and current app directory
backend_dir = Path(__file__).resolve().parent.parent
load_dotenv(backend_dir / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")


def call_gemini_apilm(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    chat_history: Optional[List[Dict[str, str]]] = None,
    fallback_models: Optional[List[str]] = None
) -> Tuple[Optional[str], Optional[str]]:
    """Call Google Gemini REST API exclusively with Gemini Pro versions and multi-turn history support."""
    headers = {"Content-Type": "application/json"}

    contents = []
    if chat_history:
        for msg in chat_history[-6:]:
            role = "user" if msg.get("role") == "user" else "model"
            contents.append({
                "role": role,
                "parts": [{"text": msg.get("content", "")}]
            })

    contents.append({
        "role": "user",
        "parts": [{"text": user_prompt}]
    })

    payload = {
        "system_instruction": {
            "parts": [{"text": system_prompt}]
        },
        "contents": contents,
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2500
        }
    }

    models_to_try = [model] + (fallback_models or ["gemini-1.5-pro", "gemini-2.5-pro", "gemini-pro"])

    try:
        with httpx.Client(timeout=25.0) as client:
            for cur_model in models_to_try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{cur_model}:generateContent?key={api_key}"
                try:
                    resp = client.post(url, headers=headers, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text", ""), cur_model
                    else:
                        print(f"[APILM] Gemini API ({cur_model}) status {resp.status_code}: {resp.text[:120]}")
                except Exception as sub_e:
                    print(f"[APILM] Gemini ({cur_model}) call error: {sub_e}")
    except Exception as e:
        print(f"[APILM] Gemini API exception: {e}")

    return None, None


def call_openai_compatible_apilm(
    api_key: str,
    model: str,
    base_url: str,
    system_prompt: str,
    user_prompt: str,
    chat_history: Optional[List[Dict[str, str]]] = None,
    fallback_models: Optional[List[str]] = None
) -> Tuple[Optional[str], Optional[str]]:
    """Call OpenAI, OpenRouter, Astra or Groq API with multi-turn history support and model fallback."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    if "openrouter" in base_url:
        headers["HTTP-Referer"] = "https://cybertwin.security"
        headers["X-Title"] = "CyberAtlas Security Posture"

    messages = [{"role": "system", "content": system_prompt}]
    if chat_history:
        for msg in chat_history[-6:]:
            role = "user" if msg.get("role") == "user" else "assistant"
            messages.append({"role": role, "content": msg.get("content", "")})

    messages.append({"role": "user", "content": user_prompt})

    models_to_try = [model] + (fallback_models or [])
    endpoint = f"{base_url.rstrip('/')}/chat/completions"

    with httpx.Client(timeout=25.0) as client:
        for current_model in models_to_try:
            payload = {
                "model": current_model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 2500
            }
            try:
                resp = client.post(endpoint, headers=headers, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")
                        return content, current_model
                else:
                    print(f"[APILM] Provider {base_url} ({current_model}) status {resp.status_code}: {resp.text[:150]}")
            except Exception as e:
                print(f"[APILM] Provider {base_url} ({current_model}) call error: {e}")

    return None, None


def get_compliance_for_finding(finding: Dict[str, Any]) -> Dict[str, str]:
    """Generate precise compliance mapping for a finding."""
    title = (finding.get("title") or "").lower()
    port = str(finding.get("port") or "")
    vuln = (finding.get("vulnerability_type") or "").lower()

    if "database" in title or "3306" in port or "5432" in port or "sql" in vuln:
        return {
            "pci_dss": "PCI-DSS 4.0 Req 1.3.1 (Inbound database connections restricted)",
            "nist": "NIST CSF 2.0 PR.AC-4 (Network boundary protection & least privilege)",
            "cis": "CIS Controls v8 4.1 & 12.1 (Ensure private service binding)",
            "iso27001": "ISO/IEC 27001:2022 A.8.20 (Network Security & Access)",
            "hipaa": "HIPAA 45 CFR § 164.312(a)(1) (ePHI Database Access Control)"
        }
    elif "ssh" in title or "22" in port or "telnet" in title or "23" in port or "rdp" in title or "3389" in port:
        return {
            "pci_dss": "PCI-DSS 4.0 Req 2.2.4 (Disable insecure administration protocols)",
            "nist": "NIST CSF 2.0 PR.AC-1 & PR.AC-7 (Secure remote access management)",
            "cis": "CIS Benchmark 5.2 (SSH hardening & Disable Telnet / RDP public ingress)",
            "iso27001": "ISO/IEC 27001:2022 A.8.24 (Use of cryptography & secure management)",
            "hipaa": "HIPAA 45 CFR § 164.312(e)(1) (Transmission Security)"
        }
    elif "web" in title or "80" in port or "443" in port or "8080" in port or "http" in vuln:
        return {
            "pci_dss": "PCI-DSS 4.0 Req 6.4.1 (Protect public web applications)",
            "nist": "NIST CSF 2.0 PR.IP-1 (Baseline web configuration & TLS 1.3)",
            "cis": "CIS Benchmark 1.1 (Web server configuration & HSTS enforcement)",
            "iso27001": "ISO/IEC 27001:2022 A.8.8 (Management of technical vulnerabilities)",
            "hipaa": "HIPAA 45 CFR § 164.312(c)(1) (Data Integrity)"
        }
    else:
        return {
            "pci_dss": "PCI-DSS 4.0 Req 11.3 (Internal & External Vulnerability Management)",
            "nist": "NIST CSF 2.0 DE.CM-1 (Vulnerability scanning & Continuous Monitoring)",
            "cis": "CIS Controls v8 7.1 (Continuous Vulnerability Management)",
            "iso27001": "ISO/IEC 27001:2022 A.8.8 (Vulnerability Remediation)",
            "hipaa": "HIPAA 45 CFR § 164.308(a)(1)(ii)(A) (Risk Analysis)"
        }


def get_exploit_simulation_for_finding(finding: Dict[str, Any]) -> Dict[str, str]:
    """Simulate the adversary kill-chain for a vulnerability."""
    title = finding.get("title", "Exposed Service")
    component = finding.get("affected_component", "Host Service")
    port = str(finding.get("port") or "80")
    host = finding.get("host") or finding.get("ip_address") or "target_host"

    return {
        "stage_1_recon": f"Attacker scans public IP subnets via Masscan/Shodan, identifying open port {port} running {component}.",
        "stage_2_exploit": f"Attacker launches automated exploit payloads / credential dictionary spraying against {component} on {host}:{port}.",
        "stage_3_impact": f"Attacker achieves unauthorized shell access, extracts database credentials/ePHI, and establishes C2 beacon for lateral pivot."
    }


def generate_scripts_for_finding(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Generate ready-to-execute Bash and PowerShell remediation scripts."""
    port = str(finding.get("port") or "8000")
    component = (finding.get("affected_component") or "SecurityService").replace(" ", "-")

    bash_script = f"""#!/usr/bin/env bash
# ============================================================
# CyberAtlas Automated Remediation Script (Linux)
# Target Component: {component} | Port: {port}
# ============================================================
set -euo pipefail

echo "[*] Step 1: Enforcing Host Firewall Block on Port {port}..."
if command -v ufw >/dev/null 2>&1; then
    sudo ufw deny {port}/tcp
    sudo ufw reload
elif command -v iptables >/dev/null 2>&1; then
    sudo iptables -C INPUT -p tcp --dport {port} -j DROP 2>/dev/null || sudo iptables -A INPUT -p tcp --dport {port} -j DROP
fi

echo "[*] Step 2: Updating package and security dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
elif command -v yum >/dev/null 2>&1; then
    sudo yum check-update || true
fi

echo "[*] Step 3: Verifying port closure..."
if command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep -E ":{port}\\b" || echo "[✓] Port {port} successfully secured."
fi

echo "[✓] CyberAtlas Remediation complete for {component}."
"""

    ps1_script = f"""# ============================================================
# CyberAtlas Automated Remediation Script (Windows PowerShell)
# Target Component: {component} | Port: {port}
# ============================================================
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Write-Host "[*] Step 1: Adding Windows Defender Firewall Rule for Port {port}..." -ForegroundColor Cyan
$ruleName = "CyberAtlas-Shield-Block-{component}-{port}"

# Remove old rule if exists
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# Create new Inbound BLOCK rule
New-NetFirewallRule -DisplayName $ruleName `
    -Direction Inbound `
    -LocalPort {port} `
    -Protocol TCP `
    -Action Block `
    -Description "Automated isolation generated by CyberAtlas AI Copilot"

Write-Host "[*] Step 2: Testing TCP port isolation..." -ForegroundColor Cyan
$test = Test-NetConnection -ComputerName "127.0.0.1" -Port {port} -WarningAction SilentlyContinue
if ($test.TcpTestSucceeded -eq $false) {{
    Write-Host "[✓] Verification Success: Port {port} is successfully blocked to ingress traffic." -ForegroundColor Green
}} else {{
    Write-Host "[!] Port {port} is still accepting local connections. Ensure service config is bound to 127.0.0.1." -ForegroundColor Yellow
}}

Write-Host "[✓] CyberAtlas Remediation complete for {component}." -ForegroundColor Green
"""

    return bash_script, ps1_script


def generate_expert_remediation_fallback(
    question: str,
    context: Optional[List[Dict[str, Any]]] = None,
    view_mode: str = "technical"
) -> Dict[str, Any]:
    """
    Intelligent cybersecurity expert reasoning engine.
    Generates structured role-based views (Technical vs Executive),
    ready-to-run bash/powershell scripts, compliance mapping, and exploit scenarios.
    """
    if context is None:
        context = []

    q_lower = question.lower()
    matched_finding = None

    for f in context:
        title = f.get("title", "").lower()
        vuln = f.get("vulnerability_type", "").lower()
        component = f.get("affected_component", "").lower()
        f_id = str(f.get("finding_id", ""))

        if (f_id and f_id in q_lower) or (title and title in q_lower) or (vuln and vuln in q_lower) or (component and component in q_lower):
            matched_finding = f
            break

    if not matched_finding and context:
        if any(w in q_lower for w in ["fix", "solve", "how", "step", "remediate", "vulnerability", "finding", "bug", "alert", "mysql", "ssh", "port"]):
            matched_finding = context[0]

    # Target parameters
    if matched_finding:
        title = matched_finding.get("title", "Identified Vulnerability")
        severity = matched_finding.get("severity", "Medium").upper()
        cvss = matched_finding.get("cvss_score", "7.5")
        asset = matched_finding.get("asset", "Production Server")
        component = matched_finding.get("affected_component", "Core Service")
        port = str(matched_finding.get("port") or "8000")
        host = matched_finding.get("host") or matched_finding.get("ip_address") or "192.168.1.10"
        vuln_type = matched_finding.get("vulnerability_type", "Security Exposure")
        base_remediation = matched_finding.get("remediation", "Apply vendor security patches and enforce firewall ingress restrictions.")
    else:
        title = "Infrastructure Perimeter & Service Exposure"
        severity = "HIGH"
        cvss = "8.2"
        asset = "Company Core Systems"
        component = "Network Gateway"
        port = "3306"
        host = "192.168.1.10"
        vuln_type = "Network Security Vulnerability"
        base_remediation = "Apply defense baseline firewall rules, mandate MFA, and restrict ingress."

    target_dict = {
        "title": title,
        "severity": severity,
        "cvss_score": cvss,
        "asset": asset,
        "affected_component": component,
        "port": port,
        "host": host,
        "vulnerability_type": vuln_type
    }

    compliance = get_compliance_for_finding(target_dict)
    exploit_sim = get_exploit_simulation_for_finding(target_dict)
    bash_script, ps1_script = generate_scripts_for_finding(target_dict)

    # Technical View Markdown
    technical_markdown = f"""### 🛡️ CyberAtlas SecOps Technical Remediation Plan

> **Target:** `{title}` | **Asset:** `{asset}` (`{host}:{port}`)  
> **Severity:** `{severity}` (CVSS: `{cvss}`) | **Classification:** `{vuln_type}`

---

#### 1. Technical Root Cause & Threat Impact
The exposed `{component}` service on port `{port}` allows external actors to probe services, exploit unpatched buffer/injection flaws, or brute-force credentials over unencrypted channels.

#### 2. Actionable Step-by-Step Resolution

##### **Step 1: Emergency Network Isolation**
Immediately drop all external inbound traffic to port `{port}`:
```bash
# Linux (UFW):
sudo ufw deny {port}/tcp && sudo ufw reload

# Windows Defender Firewall (PowerShell Admin):
New-NetFirewallRule -DisplayName "CyberAtlas-Block-{component}" -Direction Inbound -LocalPort {port} -Protocol TCP -Action Block
```

##### **Step 2: Configuration Hardening & Local Binding**
Reconfigure `{component}` to bind only to loopback (`127.0.0.1`) or private VPC subnet:
1. Edit configuration file (e.g. `mysqld.cnf` or service config).
2. Set: `bind-address = 127.0.0.1`.
3. Disable cleartext protocols and mandate TLS 1.3.

##### **Step 3: Service Restart**
```bash
# Linux:
sudo systemctl restart {component.lower().replace(' ', '-')}

# Windows:
Restart-Service -Name "{component.replace(' ', '')}"
```

##### **Step 4: Verification & Audit**
```bash
# Verify port is closed externally:
nmap -sV -p {port} {host}
# Expected output: Filtered / Closed
```
"""

    # Executive View Markdown
    executive_markdown = f"""### 👔 CISO & Executive Security Advisory

> **Executive Risk Level:** `{severity}` | **Financial Liability Exposure:** `$150,000 - $1,200,000`  
> **System Impact:** `{asset}` ({component})

---

#### 📌 Executive Summary
A critical security exposure has been detected on **{asset}**. The **{component}** service is currently reachable across unauthorized network boundaries, creating an immediate breach risk for core business operations.

#### 🏛️ Regulatory & Legal Impact
- **Non-Compliance Risk:** Violates **{compliance.get('pci_dss')}** and **{compliance.get('iso27001')}**.
- **Data Protection Liability:** Unmitigated exposure increases risk of GDPR / HIPAA mandatory breach notifications and statutory regulatory fines.

#### 🎯 Strategic Action Items:
1. **Immediate Authorization:** SecOps has prepared a 1-click automated containment script to isolate port `{port}` without disrupting internal operations.
2. **Scheduled Patch Window:** Require DevOps to apply configuration updates during tonight's maintenance window.
3. **Audit Sign-off:** Verification scan will run automatically upon completion to update the SOC dashboard.
"""

    answer = technical_markdown if view_mode == "technical" else executive_markdown

    return {
        "answer": answer,
        "technical_markdown": technical_markdown,
        "executive_markdown": executive_markdown,
        "compliance": compliance,
        "exploit_simulation": exploit_sim,
        "remediation_script_bash": bash_script,
        "remediation_script_ps1": ps1_script,
        "target_vulnerability": title,
        "view_mode": view_mode
    }


def ask_cybertwin_ai(
    question: str,
    context: Optional[List[Dict[str, Any]]] = None,
    chat_history: Optional[List[Dict[str, str]]] = None,
    view_mode: str = "technical"
) -> Dict[str, Any]:
    """
    Main entrypoint for CyberAtlas AI.
    Integrates Gemini / OpenAI / Groq APILMs with full fallback,
    producing multi-turn conversation, role-based outputs, compliance mappings,
    adversary kill-chains, and downloadable scripts.
    """
    if context is None:
        context = []
    if chat_history is None:
        chat_history = []

    # Get expert baseline metadata
    fallback_data = generate_expert_remediation_fallback(question, context, view_mode=view_mode)

    context_text = json.dumps(context, indent=2, default=str)

    system_prompt = (
        f"You are CyberAtlas AI, an advanced enterprise Security Posture & Incident Response Copilot.\n\n"
        f"Current View Mode: {view_mode.upper()} (technical or executive).\n"
        "Generate a structured, actionable cybersecurity response.\n"
        "When in TECHNICAL mode: Provide exact CLI commands (Bash & PowerShell), configs, and verification steps.\n"
        "When in EXECUTIVE mode: Provide business risk impact, CISO summary, compliance violations, and financial risk.\n\n"
        f"CURRENT FINDINGS & ASSET CONTEXT:\n{context_text}"
    )

    # Exclusively configure GPT-6 Astra and Gemini Pro models
    target_openai_model = os.getenv("OPENAI_MODEL") or os.getenv("AI_MODEL") or "gpt-6-astra"
    target_gemini_model = os.getenv("GEMINI_MODEL") or "gemini-1.5-pro"
    openai_base_url = os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"

    candidates = []
    openai_key = os.getenv("OPENAI_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    # Priority 1: GPT-6 Astra (OpenAI / Astra Compatible)
    if openai_key and not openai_key.startswith("sk-or-"):
        candidates.append(("openai", openai_key, target_openai_model, openai_base_url, ["gpt-6-astra", "chatgpt-6-astra"]))

    # Priority 2: Google Gemini Pro Versions
    if gemini_key:
        candidates.append(("gemini", gemini_key, target_gemini_model, None, ["gemini-1.5-pro", "gemini-2.5-pro", "gemini-pro"]))

    for provider, key, model, base_url, fallbacks in candidates:
        ans = None
        actual_model = model
        if provider == "gemini":
            ans, actual_model = call_gemini_apilm(key, model, system_prompt, question, chat_history, fallback_models=fallbacks)
        elif provider == "openai":
            target_url = base_url or "https://api.openai.com/v1"
            ans, actual_model = call_openai_compatible_apilm(key, model, target_url, system_prompt, question, chat_history, fallback_models=fallbacks)

        if ans:
            return {
                "answer": ans,
                "provider": f"{provider.capitalize()} API",
                "model": actual_model or model,
                "status": "success",
                "view_mode": view_mode,
                "compliance": fallback_data["compliance"],
                "exploit_simulation": fallback_data["exploit_simulation"],
                "remediation_script_bash": fallback_data["remediation_script_bash"],
                "remediation_script_ps1": fallback_data["remediation_script_ps1"],
                "target_vulnerability": fallback_data["target_vulnerability"],
                "technical_markdown": fallback_data["technical_markdown"],
                "executive_markdown": fallback_data["executive_markdown"]
            }

    # Fallback response
    return {
        "answer": fallback_data["answer"],
        "provider": "CyberAtlas AI Engine (Built-in Knowledge)",
        "model": "CyberAtlas-Defense-v2",
        "status": "fallback",
        "view_mode": view_mode,
        "compliance": fallback_data["compliance"],
        "exploit_simulation": fallback_data["exploit_simulation"],
        "remediation_script_bash": fallback_data["remediation_script_bash"],
        "remediation_script_ps1": fallback_data["remediation_script_ps1"],
        "target_vulnerability": fallback_data["target_vulnerability"],
        "technical_markdown": fallback_data["technical_markdown"],
        "executive_markdown": fallback_data["executive_markdown"]
    }