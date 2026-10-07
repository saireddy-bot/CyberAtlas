import React, { useState } from "react";

export default function LoginGateway({ onLoginSuccess, apiUrl }) {
  const [authMode, setAuthMode] = useState("credentials"); // "credentials" | "personas"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  // 2FA Challenge State
  const [mfaChallenge, setMfaChallenge] = useState(null); // { email, tempToken, user }
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);

  // Company Onboarding Registration State
  const [regCompanyName, setRegCompanyName] = useState("");
  const [regAdminName, setRegAdminName] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regIndustry, setRegIndustry] = useState("Enterprise Technology");
  const [regLoading, setRegLoading] = useState(false);
  const [regSuccess, setRegSuccess] = useState("");

  const handleRegisterSubmit = async (e) => {
    e?.preventDefault();
    setErrorMessage("");
    setRegSuccess("");

    if (!regCompanyName || !regAdminName || !regEmail || !regPassword) {
      setErrorMessage("Please complete all registration fields.");
      return;
    }

    if (regPassword.length < 6) {
      setErrorMessage("Password must be at least 6 characters.");
      return;
    }

    setRegLoading(true);
    try {
      const res = await fetch(`${apiUrl}/auth/register-company`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company_name: regCompanyName,
          admin_name: regAdminName,
          email: regEmail,
          password: regPassword,
          industry: regIndustry
        })
      });

      const data = await res.json();
      if (res.ok && data.status === "success") {
        setRegSuccess(`Organization '${regCompanyName}' registered! Launching SOC...`);
        setTimeout(() => {
          onLoginSuccess(data.user, data.token, true);
        }, 1200);
      } else {
        setErrorMessage(data.detail || "Registration failed.");
      }
    } catch (err) {
      setErrorMessage("Failed to connect to CyberAtlas onboarding service.");
    } finally {
      setRegLoading(false);
    }
  };


  // Pre-configured Demo Personas
  const DEMO_PERSONAS = [
    {
      id: 1,
      name: "Sai Reddy",
      email: "sai.reddy@cyberatlas.soc",
      password: "admin123",
      role: "SOC Lead / Admin",
      department: "SOC Operations",
      color: "#06b6d4",
      mfa: true,
      badge: "SUPERADMIN ACCESS"
    },
    {
      id: 2,
      name: "Sarah Connor",
      email: "sarah.c@cyberatlas.soc",
      password: "analyst123",
      role: "Senior Threat Analyst",
      department: "Threat Intelligence",
      color: "#8b5cf6",
      mfa: true,
      badge: "TIER-2 ANALYST"
    },
    {
      id: 3,
      name: "David Chen",
      email: "d.chen@cyberatlas.soc",
      password: "responder123",
      role: "Tier-1 Incident Responder",
      department: "SOC Operations",
      color: "#10b981",
      mfa: true,
      badge: "INCIDENT RESPONSE"
    },
    {
      id: 4,
      name: "Elena Rostova",
      email: "elena.r@cyberatlas.soc",
      password: "audit123",
      role: "Compliance Auditor",
      department: "Compliance & GRC",
      color: "#f59e0b",
      mfa: true,
      badge: "READ-ONLY GRC"
    }
  ];

  // Submit standard login
  const handleLoginSubmit = async (e) => {
    e?.preventDefault();
    setErrorMessage("");
    if (!email || !password) {
      setErrorMessage("Please enter both operator identifier and access key.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${apiUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim(),
          password: password.trim(),
          remember_me: rememberMe
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Authentication failed. Check credentials.");
      }

      if (data.mfa_required) {
        // Step into 2FA verification challenge
        setMfaChallenge({
          email: data.user.email,
          tempToken: data.temp_token,
          user: data.user
        });
      } else {
        // Direct success
        onLoginSuccess(data.user, data.token, rememberMe);
      }
    } catch (err) {
      setErrorMessage(err.message || "Unable to reach CyberAtlas Authentication Gateway.");
    } finally {
      setLoading(false);
    }
  };

  // 1-Click Persona Login
  const handlePersonaClick = (persona) => {
    setEmail(persona.email);
    setPassword(persona.password);
    setErrorMessage("");

    // Quick direct auth
    setLoading(true);
    fetch(`${apiUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: persona.email,
        password: persona.password,
        remember_me: rememberMe
      })
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.mfa_required) {
          setMfaChallenge({
            email: data.user.email,
            tempToken: data.temp_token,
            user: data.user
          });
        } else if (data.status === "success") {
          onLoginSuccess(data.user, data.token, rememberMe);
        } else {
          setErrorMessage(data.detail || "Authentication error");
        }
      })
      .catch((err) => {
        setErrorMessage("Gateway error during quick login.");
      })
      .finally(() => setLoading(false));
  };

  // Submit 2FA verification
  const handleMfaSubmit = async (e) => {
    e?.preventDefault();
    if (!mfaCode || mfaCode.length < 4) {
      setErrorMessage("Please enter a valid 6-digit verification code.");
      return;
    }

    setMfaLoading(true);
    setErrorMessage("");
    try {
      const res = await fetch(`${apiUrl}/auth/verify-mfa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: mfaChallenge.email,
          mfa_code: mfaCode.trim(),
          temp_token: mfaChallenge.tempToken
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Invalid 2FA challenge code.");
      }

      onLoginSuccess(data.user, data.token, rememberMe);
    } catch (err) {
      setErrorMessage(err.message || "Failed to verify 2FA challenge.");
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "radial-gradient(ellipse at 50% 15%, #0f244a 0%, #070b14 70%)",
        color: "#f1f5f9",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        padding: "20px",
        position: "relative",
        overflow: "hidden"
      }}
    >
      {/* BACKGROUND SCI-FI GRID OVERLAY */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundImage:
            "linear-gradient(rgba(56, 189, 248, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(56, 189, 248, 0.04) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
          pointerEvents: "none",
          zIndex: 1
        }}
      />

      {/* GLOWING AMBIENT RADAR RING */}
      <div
        style={{
          position: "absolute",
          width: "600px",
          height: "600px",
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(56, 189, 248, 0.08) 0%, transparent 70%)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          pointerEvents: "none",
          zIndex: 1
        }}
      />

      {/* LOGIN CARD CONTAINER */}
      <div
        style={{
          position: "relative",
          zIndex: 10,
          width: "100%",
          maxWidth: "480px",
          background: "rgba(10, 16, 31, 0.85)",
          backdropFilter: "blur(16px)",
          border: "1px solid rgba(56, 189, 248, 0.3)",
          borderRadius: "16px",
          padding: "32px 28px",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.7), 0 0 25px rgba(56, 189, 248, 0.2)"
        }}
      >
        {/* BRAND EMBLEM & HEADER */}
        <div style={{ textAlign: "center", marginBottom: "24px" }}>
          <div
            style={{
              width: "56px",
              height: "56px",
              margin: "0 auto 12px",
              borderRadius: "14px",
              background: "linear-gradient(135deg, rgba(56, 189, 248, 0.2) 0%, rgba(2, 132, 199, 0.4) 100%)",
              border: "1px solid #38bdf8",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 20px rgba(56, 189, 248, 0.4)"
            }}
          >
            <svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="#38bdf8" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" stroke="#38bdf8" strokeWidth="2.5" />
            </svg>
          </div>

          <h1
            style={{
              fontSize: "24px",
              fontWeight: "900",
              letterSpacing: "2px",
              margin: 0,
              background: "linear-gradient(180deg, #ffffff 0%, #38bdf8 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent"
            }}
          >
            CYBERATLAS
          </h1>
          <p style={{ color: "#94a3b8", fontSize: "12px", margin: "4px 0 0 0", letterSpacing: "0.5px" }}>
            Autonomous Enterprise Security Operations Center
          </p>

          {/* TELEMETRY STATUS PILLS */}
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              gap: "8px",
              marginTop: "12px",
              fontSize: "10.5px",
              fontWeight: "600"
            }}
          >
            <span
              style={{
                background: "rgba(16, 185, 129, 0.12)",
                color: "#10b981",
                border: "1px solid rgba(16, 185, 129, 0.3)",
                padding: "2px 8px",
                borderRadius: "12px"
              }}
            >
              ● Zero-Trust Gate Active
            </span>
            <span
              style={{
                background: "rgba(56, 189, 248, 0.12)",
                color: "#38bdf8",
                border: "1px solid rgba(56, 189, 248, 0.3)",
                padding: "2px 8px",
                borderRadius: "12px"
              }}
            >
              🔒 256-Bit TLS Validated
            </span>
          </div>
        </div>

        {/* ERROR NOTIFICATION BANNER */}
        {errorMessage && (
          <div
            style={{
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid #ef4444",
              color: "#fca5a5",
              padding: "10px 14px",
              borderRadius: "8px",
              fontSize: "12px",
              marginBottom: "16px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              animation: "fadeIn 0.2s ease-in"
            }}
          >
            <span>⚠️</span>
            <span>{errorMessage}</span>
          </div>
        )}

        {/* 2FA CHALLENGE DIALOG */}
        {mfaChallenge ? (
          <div>
            <div
              style={{
                background: "rgba(56, 189, 248, 0.08)",
                border: "1px solid rgba(56, 189, 248, 0.25)",
                borderRadius: "8px",
                padding: "16px",
                marginBottom: "20px",
                textAlign: "center"
              }}
            >
              <div style={{ fontSize: "28px", marginBottom: "6px" }}>🛡️</div>
              <h3 style={{ margin: "0 0 4px 0", fontSize: "15px", fontWeight: "700", color: "#38bdf8" }}>
                Two-Factor Security Challenge
              </h3>
              <p style={{ margin: 0, fontSize: "12px", color: "#94a3b8" }}>
                Enter the 6-digit TOTP authenticator code or use demo code <strong style={{ color: "#38bdf8" }}>123456</strong> for <strong>{mfaChallenge.user?.full_name}</strong>.
              </p>
            </div>

            <form onSubmit={handleMfaSubmit}>
              <div style={{ marginBottom: "18px" }}>
                <label style={{ display: "block", fontSize: "11.5px", color: "#94a3b8", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  6-Digit Verification Code
                </label>
                <input
                  type="text"
                  autoFocus
                  maxLength={6}
                  placeholder="e.g. 123456"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                  style={{
                    width: "100%",
                    background: "#070b14",
                    border: "1px solid #38bdf8",
                    color: "#38bdf8",
                    padding: "12px",
                    borderRadius: "8px",
                    fontSize: "22px",
                    letterSpacing: "8px",
                    textAlign: "center",
                    fontFamily: "monospace",
                    fontWeight: "bold",
                    outline: "none",
                    boxShadow: "0 0 12px rgba(56, 189, 248, 0.2)"
                  }}
                />
              </div>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  type="button"
                  onClick={() => {
                    setMfaChallenge(null);
                    setMfaCode("");
                  }}
                  style={{
                    flex: 1,
                    background: "transparent",
                    border: "1px solid #334155",
                    color: "#94a3b8",
                    padding: "10px",
                    borderRadius: "8px",
                    fontSize: "12px",
                    cursor: "pointer"
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={mfaLoading}
                  style={{
                    flex: 2,
                    background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                    border: "1px solid #38bdf8",
                    color: "#fff",
                    padding: "10px",
                    borderRadius: "8px",
                    fontSize: "13px",
                    fontWeight: "700",
                    cursor: "pointer",
                    boxShadow: "0 0 15px rgba(56, 189, 248, 0.3)"
                  }}
                >
                  {mfaLoading ? "Verifying..." : "Unlock Terminal ➔"}
                </button>
              </div>
            </form>
          </div>
        ) : (
          <div>
            {/* LOGIN MODE TABS */}
            <div
              style={{
                display: "flex",
                background: "rgba(7, 11, 20, 0.8)",
                borderRadius: "8px",
                padding: "3px",
                marginBottom: "20px",
                border: "1px solid rgba(255, 255, 255, 0.06)",
                gap: "4px"
              }}
            >
              <button
                type="button"
                onClick={() => setAuthMode("credentials")}
                style={{
                  flex: 1,
                  background: authMode === "credentials" ? "#1e293b" : "transparent",
                  color: authMode === "credentials" ? "#38bdf8" : "#94a3b8",
                  border: "none",
                  padding: "8px 4px",
                  borderRadius: "6px",
                  fontSize: "11.5px",
                  fontWeight: "600",
                  cursor: "pointer",
                  transition: "all 0.2s ease"
                }}
              >
                🔐 Sign In
              </button>
              <button
                type="button"
                onClick={() => setAuthMode("register")}
                style={{
                  flex: 1.1,
                  background: authMode === "register" ? "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)" : "transparent",
                  color: authMode === "register" ? "#fff" : "#94a3b8",
                  border: authMode === "register" ? "1px solid #38bdf8" : "none",
                  padding: "8px 4px",
                  borderRadius: "6px",
                  fontSize: "11.5px",
                  fontWeight: "700",
                  cursor: "pointer",
                  transition: "all 0.2s ease"
                }}
              >
                🏢 Register Company
              </button>
              <button
                type="button"
                onClick={() => setAuthMode("personas")}
                style={{
                  flex: 1,
                  background: authMode === "personas" ? "#1e293b" : "transparent",
                  color: authMode === "personas" ? "#38bdf8" : "#94a3b8",
                  border: "none",
                  padding: "8px 4px",
                  borderRadius: "6px",
                  fontSize: "11.5px",
                  fontWeight: "600",
                  cursor: "pointer",
                  transition: "all 0.2s ease"
                }}
              >
                ⚡ Demo Roles
              </button>
            </div>

            {/* TAB 1: STANDARD CREDENTIALS */}
            {authMode === "credentials" && (
              <form onSubmit={handleLoginSubmit}>
                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "11.5px", color: "#94a3b8", marginBottom: "6px" }}>
                    Operator Identifier / Email
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. sai.reddy@cyberatlas.soc (or 'admin')"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={{
                      width: "100%",
                      background: "#070b14",
                      border: "1px solid #1e293b",
                      color: "#fff",
                      padding: "10px 14px",
                      borderRadius: "8px",
                      fontSize: "13px",
                      outline: "none",
                      boxSizing: "border-box"
                    }}
                  />
                </div>

                <div style={{ marginBottom: "14px" }}>
                  <label style={{ display: "block", fontSize: "11.5px", color: "#94a3b8", marginBottom: "6px" }}>
                    Access Security Key / Password
                  </label>
                  <div style={{ position: "relative" }}>
                    <input
                      type={showPassword ? "text" : "password"}
                      required
                      placeholder="e.g. admin123"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      style={{
                        width: "100%",
                        background: "#070b14",
                        border: "1px solid #1e293b",
                        color: "#fff",
                        padding: "10px 14px",
                        paddingRight: "40px",
                        borderRadius: "8px",
                        fontSize: "13px",
                        outline: "none",
                        boxSizing: "border-box"
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: "absolute",
                        right: "10px",
                        top: "50%",
                        transform: "translateY(-50%)",
                        background: "transparent",
                        border: "none",
                        color: "#64748b",
                        cursor: "pointer",
                        fontSize: "14px"
                      }}
                    >
                      {showPassword ? "🙈" : "👁️"}
                    </button>
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "20px",
                    fontSize: "11.5px",
                    color: "#94a3b8"
                  }}
                >
                  <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      style={{ accentColor: "#38bdf8" }}
                    />
                    Remember this terminal session
                  </label>
                  <span style={{ color: "#38bdf8", cursor: "pointer" }} onClick={() => setAuthMode("register")}>
                    New Company?
                  </span>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    width: "100%",
                    background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                    border: "1px solid #38bdf8",
                    color: "#fff",
                    padding: "11px",
                    borderRadius: "8px",
                    fontSize: "13.5px",
                    fontWeight: "700",
                    cursor: "pointer",
                    boxShadow: "0 0 15px rgba(56, 189, 248, 0.35)",
                    transition: "all 0.2s ease"
                  }}
                >
                  {loading ? "Authenticating Operator..." : "Authenticate & Launch SOC ➔"}
                </button>
              </form>
            )}

            {/* TAB 2: REGISTER NEW COMPANY */}
            {authMode === "register" && (
              <form onSubmit={handleRegisterSubmit}>
                {regSuccess ? (
                  <div
                    style={{
                      background: "rgba(16, 185, 129, 0.15)",
                      border: "1px solid #10b981",
                      borderRadius: "8px",
                      padding: "16px",
                      textAlign: "center",
                      color: "#6ee7b7",
                      fontSize: "13px"
                    }}
                  >
                    <div style={{ fontSize: "24px", marginBottom: "8px" }}>🎉</div>
                    <strong>{regSuccess}</strong>
                  </div>
                ) : (
                  <>
                    <div style={{ marginBottom: "12px" }}>
                      <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>
                        Company / Client Organization Name *
                      </label>
                      <input
                        type="text"
                        required
                        placeholder="e.g. Apex Global Technologies"
                        value={regCompanyName}
                        onChange={(e) => setRegCompanyName(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#070b14",
                          border: "1px solid #1e293b",
                          color: "#fff",
                          padding: "9px 12px",
                          borderRadius: "8px",
                          fontSize: "12.5px",
                          outline: "none",
                          boxSizing: "border-box"
                        }}
                      />
                    </div>

                    <div style={{ display: "flex", gap: "10px", marginBottom: "12px" }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>
                          Master Admin Name *
                        </label>
                        <input
                          type="text"
                          required
                          placeholder="e.g. Vikram Patel"
                          value={regAdminName}
                          onChange={(e) => setRegAdminName(e.target.value)}
                          style={{
                            width: "100%",
                            background: "#070b14",
                            border: "1px solid #1e293b",
                            color: "#fff",
                            padding: "9px 12px",
                            borderRadius: "8px",
                            fontSize: "12.5px",
                            outline: "none",
                            boxSizing: "border-box"
                          }}
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>
                          Primary Industry
                        </label>
                        <select
                          value={regIndustry}
                          onChange={(e) => setRegIndustry(e.target.value)}
                          style={{
                            width: "100%",
                            background: "#070b14",
                            border: "1px solid #1e293b",
                            color: "#38bdf8",
                            padding: "9px 8px",
                            borderRadius: "8px",
                            fontSize: "11.5px",
                            outline: "none",
                            boxSizing: "border-box"
                          }}
                        >
                          <option value="Enterprise Technology">Enterprise Tech & SaaS</option>
                          <option value="Banking & Finance">Banking & Financial</option>
                          <option value="Healthcare">Healthcare & Bio</option>
                          <option value="Government & Defense">Government & Defense</option>
                          <option value="Energy & Infrastructure">Energy & Utilities</option>
                        </select>
                      </div>
                    </div>

                    <div style={{ marginBottom: "12px" }}>
                      <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>
                        Corporate Work Email *
                      </label>
                      <input
                        type="email"
                        required
                        placeholder="e.g. admin@apexglobal.com"
                        value={regEmail}
                        onChange={(e) => setRegEmail(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#070b14",
                          border: "1px solid #1e293b",
                          color: "#fff",
                          padding: "9px 12px",
                          borderRadius: "8px",
                          fontSize: "12.5px",
                          outline: "none",
                          boxSizing: "border-box"
                        }}
                      />
                    </div>

                    <div style={{ marginBottom: "18px" }}>
                      <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>
                        Master Security Password (Min 6 chars) *
                      </label>
                      <input
                        type="password"
                        required
                        placeholder="Create strong master password"
                        value={regPassword}
                        onChange={(e) => setRegPassword(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#070b14",
                          border: "1px solid #1e293b",
                          color: "#fff",
                          padding: "9px 12px",
                          borderRadius: "8px",
                          fontSize: "12.5px",
                          outline: "none",
                          boxSizing: "border-box"
                        }}
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={regLoading}
                      style={{
                        width: "100%",
                        background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                        border: "1px solid #38bdf8",
                        color: "#fff",
                        padding: "11px",
                        borderRadius: "8px",
                        fontSize: "13px",
                        fontWeight: "700",
                        cursor: "pointer",
                        boxShadow: "0 0 15px rgba(56, 189, 248, 0.35)",
                        transition: "all 0.2s ease"
                      }}
                    >
                      {regLoading ? "Initializing SOC Platform..." : "🚀 Initialize Company SOC & Enter ➔"}
                    </button>
                  </>
                )}
              </form>
            )}

            {/* TAB 3: 1-CLICK DEMO PERSONAS */}
            {authMode === "personas" && (
              <div>
                <p style={{ fontSize: "11.5px", color: "#94a3b8", margin: "0 0 12px 0", textAlign: "center" }}>
                  Select a pre-authorized role to immediately enter the SOC:
                </p>

                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {DEMO_PERSONAS.map((p) => (
                    <div
                      key={p.id}
                      onClick={() => handlePersonaClick(p)}
                      style={{
                        background: "rgba(15, 23, 42, 0.7)",
                        border: "1px solid rgba(56, 189, 248, 0.2)",
                        borderRadius: "8px",
                        padding: "10px 14px",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        transition: "all 0.15s ease"
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = "#38bdf8";
                        e.currentTarget.style.background = "rgba(56, 189, 248, 0.1)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = "rgba(56, 189, 248, 0.2)";
                        e.currentTarget.style.background = "rgba(15, 23, 42, 0.7)";
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div
                          style={{
                            width: "32px",
                            height: "32px",
                            borderRadius: "50%",
                            background: p.color,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontWeight: "700",
                            color: "#fff",
                            fontSize: "13px"
                          }}
                        >
                          {p.name[0]}
                        </div>
                        <div>
                          <div style={{ fontSize: "12.5px", fontWeight: "700", color: "#fff" }}>{p.name}</div>
                          <div style={{ fontSize: "10.5px", color: "#94a3b8" }}>
                            {p.role} • <span style={{ color: "#38bdf8" }}>{p.department}</span>
                          </div>
                        </div>
                      </div>

                      <div style={{ textAlign: "right" }}>
                        <span
                          style={{
                            background: "rgba(56, 189, 248, 0.12)",
                            color: "#38bdf8",
                            border: "1px solid rgba(56, 189, 248, 0.3)",
                            padding: "2px 6px",
                            borderRadius: "4px",
                            fontSize: "9.5px",
                            fontWeight: "700"
                          }}
                        >
                          {p.badge}
                        </span>
                        <div style={{ fontSize: "10px", color: "#64748b", marginTop: "3px" }}>Pass: {p.password}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}


        {/* SECURITY COMPLIANCE FOOTER */}
        <div
          style={{
            marginTop: "24px",
            paddingTop: "14px",
            borderTop: "1px solid rgba(255, 255, 255, 0.08)",
            textAlign: "center",
            fontSize: "11px",
            color: "#64748b"
          }}
        >
          <span>CyberAtlas Threat Defense Matrix</span> • <span>SOC 2 Type II Certified</span>
        </div>
      </div>
    </div>
  );
}
