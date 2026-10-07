import React, { useState, useEffect } from "react";

export default function UserManagement({ apiUrl }) {
  const [users, setUsers] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRoleFilter, setSelectedRoleFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("directory"); // "directory" | "rbac" | "audit" | "sessions"
  const [showAddModal, setShowAddModal] = useState(false);
  const [notification, setNotification] = useState("");
  const [apiKeyCopied, setApiKeyCopied] = useState(false);

  // Form State for Adding User
  const [newUser, setNewUser] = useState({
    full_name: "",
    email: "",
    role: "Senior Threat Analyst",
    department: "Threat Intelligence",
    status: "Active"
  });

  const showToast = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(""), 4000);
  };

  // Fetch initial data
  const fetchData = async () => {
    setLoading(true);
    try {
      const [usersRes, meRes, auditRes, sessRes] = await Promise.all([
        fetch(`${apiUrl}/users/`),
        fetch(`${apiUrl}/users/me`),
        fetch(`${apiUrl}/users/audit-logs`),
        fetch(`${apiUrl}/users/sessions`)
      ]);

      if (usersRes.ok) setUsers(await usersRes.json());
      if (meRes.ok) setCurrentUser(await meRes.json());
      if (auditRes.ok) setAuditLogs(await auditRes.json());
      if (sessRes.ok) setSessions(await sessRes.json());
    } catch (err) {
      console.error("Failed to load user management data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [apiUrl]);

  // Toggle 2FA
  const handleToggle2FA = async () => {
    try {
      const res = await fetch(`${apiUrl}/users/me/toggle-2fa`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser((prev) => ({ ...prev, mfa_enabled: data.mfa_enabled }));
        showToast(data.message);
        fetchData();
      }
    } catch (err) {
      showToast("❌ Failed to update 2FA status");
    }
  };

  // Generate fresh API Key
  const handleGenerateApiKey = async () => {
    try {
      const res = await fetch(`${apiUrl}/users/me/generate-api-key`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser((prev) => ({ ...prev, api_key_preview: data.preview }));
        navigator.clipboard.writeText(data.api_key);
        setApiKeyCopied(true);
        showToast("🔑 New API Token generated and copied to clipboard!");
        setTimeout(() => setApiKeyCopied(false), 3000);
        fetchData();
      }
    } catch (err) {
      showToast("❌ Failed to generate API token");
    }
  };

  // Add User Submit
  const handleAddUser = async (e) => {
    e.preventDefault();
    if (!newUser.full_name || !newUser.email) return;

    try {
      const res = await fetch(`${apiUrl}/users/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newUser)
      });

      if (res.ok) {
        const created = await res.json();
        setUsers((prev) => [...prev, created]);
        setShowAddModal(false);
        setNewUser({
          full_name: "",
          email: "",
          role: "Senior Threat Analyst",
          department: "Threat Intelligence",
          status: "Active"
        });
        showToast(`✅ Invited ${created.full_name} (${created.role}) successfully!`);
        fetchData();
      }
    } catch (err) {
      showToast("❌ Error adding user");
    }
  };

  // Change user role
  const handleRoleChange = async (userId, newRole) => {
    try {
      const res = await fetch(`${apiUrl}/users/${userId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        showToast("✅ Updated user role and permissions.");
        fetchData();
      }
    } catch (err) {
      showToast("❌ Failed to update role.");
    }
  };

  // Delete / Revoke User
  const handleDeleteUser = async (userId, userName) => {
    if (!window.confirm(`Are you sure you want to revoke and delete ${userName}'s account?`)) return;

    try {
      const res = await fetch(`${apiUrl}/users/${userId}`, { method: "DELETE" });
      if (res.ok) {
        setUsers((prev) => prev.filter((u) => u.id !== userId));
        showToast(`🗑️ Account for ${userName} has been revoked.`);
        fetchData();
      } else {
        const data = await res.json();
        showToast(`⚠️ ${data.detail || "Cannot delete user"}`);
      }
    } catch (err) {
      showToast("❌ Failed to delete user");
    }
  };

  // Revoke Remote Sessions
  const handleRevokeSessions = async () => {
    try {
      const res = await fetch(`${apiUrl}/users/sessions/revoke-others`, { method: "POST" });
      if (res.ok) {
        showToast("🔒 All other remote sessions terminated successfully.");
        fetchData();
      }
    } catch (err) {
      showToast("❌ Failed to revoke sessions");
    }
  };

  // Filtered users
  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      u.full_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.department.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = selectedRoleFilter === "all" || u.role === selectedRoleFilter;
    return matchesSearch && matchesRole;
  });

  return (
    <div style={{ padding: "16px 20px", width: "100%", color: "var(--text-main)" }}>
      {/* Toast Notification */}
      {notification && (
        <div
          style={{
            position: "fixed",
            bottom: "24px",
            right: "24px",
            background: "rgba(13, 21, 39, 0.95)",
            border: "1px solid var(--neon-cyan)",
            boxShadow: "0 0 15px rgba(56, 189, 248, 0.4)",
            padding: "12px 20px",
            borderRadius: "8px",
            zIndex: 9999,
            display: "flex",
            alignItems: "center",
            gap: "10px",
            fontSize: "13px",
            fontWeight: "500",
            animation: "fadeIn 0.3s ease-out"
          }}
        >
          {notification}
        </div>
      )}

      {/* HEADER BAR */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "20px",
          flexWrap: "wrap",
          gap: "12px"
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <h2 style={{ fontSize: "20px", fontWeight: "700", letterSpacing: "0.5px", margin: 0, color: "#ffffff" }}>
              👤 Identity & Access Control (RBAC)
            </h2>
            <span
              style={{
                background: "rgba(56, 189, 248, 0.15)",
                color: "var(--neon-cyan)",
                border: "1px solid rgba(56, 189, 248, 0.3)",
                padding: "3px 8px",
                borderRadius: "12px",
                fontSize: "11px",
                fontWeight: "600"
              }}
            >
              Enterprise Security
            </span>
          </div>
          <p style={{ color: "var(--text-muted)", fontSize: "12.5px", margin: "4px 0 0 0" }}>
            Manage SOC analysts, role permissions, active login telemetry, and zero-trust authentication policies.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          style={{
            background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
            color: "#fff",
            border: "1px solid #38bdf8",
            padding: "8px 16px",
            borderRadius: "6px",
            cursor: "pointer",
            fontWeight: "600",
            fontSize: "12.5px",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            boxShadow: "0 0 10px rgba(56, 189, 248, 0.25)"
          }}
        >
          <span>➕</span> Add / Invite Analyst
        </button>
      </div>

      {/* CURRENT LOGGED-IN OPERATOR PROFILE CARD */}
      {currentUser && (
        <div
          style={{
            background: "radial-gradient(ellipse at top left, #111e38 0%, #0a1122 100%)",
            border: "1px solid var(--border-highlight)",
            borderRadius: "10px",
            padding: "16px 20px",
            marginBottom: "24px",
            boxShadow: "var(--glow-card)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "16px"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "50%",
                background: `linear-gradient(135deg, ${currentUser.avatar_color} 0%, #0284c7 100%)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "20px",
                fontWeight: "700",
                color: "#fff",
                boxShadow: `0 0 12px ${currentUser.avatar_color}66`
              }}
            >
              {currentUser.full_name[0]}
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)" }}>
                  {currentUser.full_name}
                </span>
                <span
                  style={{
                    background: "rgba(16, 185, 129, 0.15)",
                    color: "var(--neon-green)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    padding: "2px 6px",
                    borderRadius: "4px",
                    fontSize: "10px",
                    fontWeight: "600"
                  }}
                >
                  ACTIVE SESSION
                </span>
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
                <span>{currentUser.email}</span> • <strong style={{ color: "var(--neon-cyan)" }}>{currentUser.role}</strong> • {currentUser.department}
              </div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "20px", flexWrap: "wrap" }}>
            {/* 2FA Status Indicator & Toggle */}
            <div style={{ display: "flex", alignItems: "center", gap: "10px", background: "rgba(0,0,0,0.25)", padding: "6px 12px", borderRadius: "6px", border: "1px solid var(--border-subtle)" }}>
              <div>
                <div style={{ fontSize: "10.5px", color: "var(--text-muted)", textTransform: "uppercase" }}>2FA Shield (MFA)</div>
                <div style={{ fontSize: "12px", fontWeight: "600", color: currentUser.mfa_enabled ? "var(--neon-green)" : "var(--neon-red)" }}>
                  {currentUser.mfa_enabled ? "🛡️ Enforced (FIDO2 / TOTP)" : "⚠️ Disabled"}
                </div>
              </div>
              <button
                onClick={handleToggle2FA}
                style={{
                  background: currentUser.mfa_enabled ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.2)",
                  color: currentUser.mfa_enabled ? "var(--neon-red)" : "var(--neon-green)",
                  border: `1px solid ${currentUser.mfa_enabled ? "var(--neon-red)" : "var(--neon-green)"}`,
                  padding: "4px 8px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  cursor: "pointer",
                  fontWeight: "600"
                }}
              >
                {currentUser.mfa_enabled ? "Turn Off" : "Enable 2FA"}
              </button>
            </div>

            {/* API Key Box */}
            <div style={{ display: "flex", alignItems: "center", gap: "10px", background: "rgba(0,0,0,0.25)", padding: "6px 12px", borderRadius: "6px", border: "1px solid var(--border-subtle)" }}>
              <div>
                <div style={{ fontSize: "10.5px", color: "var(--text-muted)", textTransform: "uppercase" }}>Personal API Token</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "11.5px", color: "var(--neon-cyan)" }}>
                  {currentUser.api_key_preview}
                </div>
              </div>
              <button
                onClick={handleGenerateApiKey}
                style={{
                  background: "rgba(56, 189, 248, 0.15)",
                  color: "var(--neon-cyan)",
                  border: "1px solid var(--neon-cyan)",
                  padding: "4px 8px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  cursor: "pointer",
                  fontWeight: "600"
                }}
              >
                {apiKeyCopied ? "✓ Copied" : "Rotate"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODULE NAVIGATION TABS */}
      <div
        style={{
          display: "flex",
          gap: "8px",
          borderBottom: "1px solid var(--border-subtle)",
          marginBottom: "16px",
          paddingBottom: "8px"
        }}
      >
        <button
          onClick={() => setActiveTab("directory")}
          style={{
            background: activeTab === "directory" ? "rgba(56, 189, 248, 0.15)" : "transparent",
            color: activeTab === "directory" ? "var(--neon-cyan)" : "var(--text-muted)",
            border: activeTab === "directory" ? "1px solid var(--neon-cyan)" : "1px solid transparent",
            padding: "6px 14px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: "600"
          }}
        >
          👥 Personnel Directory ({users.length})
        </button>

        <button
          onClick={() => setActiveTab("rbac")}
          style={{
            background: activeTab === "rbac" ? "rgba(56, 189, 248, 0.15)" : "transparent",
            color: activeTab === "rbac" ? "var(--neon-cyan)" : "var(--text-muted)",
            border: activeTab === "rbac" ? "1px solid var(--neon-cyan)" : "1px solid transparent",
            padding: "6px 14px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: "600"
          }}
        >
          🔒 Role Permissions Matrix (RBAC)
        </button>

        <button
          onClick={() => setActiveTab("audit")}
          style={{
            background: activeTab === "audit" ? "rgba(56, 189, 248, 0.15)" : "transparent",
            color: activeTab === "audit" ? "var(--neon-cyan)" : "var(--text-muted)",
            border: activeTab === "audit" ? "1px solid var(--neon-cyan)" : "1px solid transparent",
            padding: "6px 14px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: "600"
          }}
        >
          📜 Security Audit Trail ({auditLogs.length})
        </button>

        <button
          onClick={() => setActiveTab("sessions")}
          style={{
            background: activeTab === "sessions" ? "rgba(56, 189, 248, 0.15)" : "transparent",
            color: activeTab === "sessions" ? "var(--neon-cyan)" : "var(--text-muted)",
            border: activeTab === "sessions" ? "1px solid var(--neon-cyan)" : "1px solid transparent",
            padding: "6px 14px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: "600"
          }}
        >
          💻 Active Sessions ({sessions.length})
        </button>
      </div>

      {/* TAB 1: PERSONNEL DIRECTORY */}
      {activeTab === "directory" && (
        <div>
          {/* Filter Bar */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "14px",
              gap: "12px",
              flexWrap: "wrap"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", flex: 1, maxWidth: "400px" }}>
              <input
                type="text"
                placeholder="Search by analyst name, email, or department..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: "100%",
                  background: "var(--bg-card)",
                  border: "1px solid var(--border-subtle)",
                  color: "var(--text-main)",
                  padding: "7px 12px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  outline: "none"
                }}
              />
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>Filter by Role:</span>
              <select
                value={selectedRoleFilter}
                onChange={(e) => setSelectedRoleFilter(e.target.value)}
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--border-subtle)",
                  color: "var(--text-main)",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  fontSize: "12px"
                }}
              >
                <option value="all">All Roles ({users.length})</option>
                <option value="SOC Lead / Admin">SOC Lead / Admin</option>
                <option value="Senior Threat Analyst">Senior Threat Analyst</option>
                <option value="Tier-1 Incident Responder">Tier-1 Incident Responder</option>
                <option value="Compliance Auditor">Compliance Auditor</option>
                <option value="IT Department Head">IT Department Head</option>
              </select>
            </div>
          </div>

          {/* Directory Table */}
          <div
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "8px",
              overflow: "hidden"
            }}
          >
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "12px" }}>
              <thead>
                <tr style={{ background: "rgba(10, 16, 31, 0.8)", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-muted)" }}>
                  <th style={{ padding: "10px 14px" }}>ANALYST PERSONNEL</th>
                  <th style={{ padding: "10px 14px" }}>ASSIGNED ROLE</th>
                  <th style={{ padding: "10px 14px" }}>DEPARTMENT</th>
                  <th style={{ padding: "10px 14px" }}>2FA STATUS</th>
                  <th style={{ padding: "10px 14px" }}>ACCOUNT STATUS</th>
                  <th style={{ padding: "10px 14px" }}>LAST ACTIVE</th>
                  <th style={{ padding: "10px 14px", textAlign: "right" }}>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((user) => (
                  <tr
                    key={user.id}
                    style={{
                      borderBottom: "1px solid var(--border-subtle)",
                      background: user.id === 1 ? "rgba(56, 189, 248, 0.03)" : "transparent"
                    }}
                  >
                    <td style={{ padding: "12px 14px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div
                          style={{
                            width: "30px",
                            height: "30px",
                            borderRadius: "50%",
                            background: user.avatar_color,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontWeight: "700",
                            color: "#fff",
                            fontSize: "12px"
                          }}
                        >
                          {user.full_name[0]}
                        </div>
                        <div>
                          <div style={{ fontWeight: "600", color: "var(--text-main)" }}>{user.full_name}</div>
                          <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>{user.email}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: "12px 14px" }}>
                      <select
                        value={user.role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                        disabled={user.id === 1}
                        style={{
                          background: "var(--bg-card-alt)",
                          border: "1px solid var(--border-subtle)",
                          color: "var(--text-main)",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          fontSize: "11.5px",
                          cursor: user.id === 1 ? "not-allowed" : "pointer"
                        }}
                      >
                        <option value="SOC Lead / Admin">SOC Lead / Admin</option>
                        <option value="Senior Threat Analyst">Senior Threat Analyst</option>
                        <option value="Tier-1 Incident Responder">Tier-1 Incident Responder</option>
                        <option value="Compliance Auditor">Compliance Auditor</option>
                        <option value="IT Department Head">IT Department Head</option>
                      </select>
                    </td>
                    <td style={{ padding: "12px 14px", color: "var(--text-muted)" }}>{user.department}</td>
                    <td style={{ padding: "12px 14px" }}>
                      <span
                        style={{
                          background: user.mfa_enabled ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
                          color: user.mfa_enabled ? "var(--neon-green)" : "var(--neon-red)",
                          padding: "2px 8px",
                          borderRadius: "10px",
                          fontSize: "10.5px",
                          fontWeight: "600"
                        }}
                      >
                        {user.mfa_enabled ? "✓ Enabled" : "✗ Inactive"}
                      </span>
                    </td>
                    <td style={{ padding: "12px 14px" }}>
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "5px",
                          fontSize: "11px",
                          color: user.status === "Active" ? "var(--neon-green)" : "var(--text-dim)"
                        }}
                      >
                        <span
                          style={{
                            width: "6px",
                            height: "6px",
                            borderRadius: "50%",
                            background: user.status === "Active" ? "var(--neon-green)" : "var(--text-dim)"
                          }}
                        />
                        {user.status}
                      </span>
                    </td>
                    <td style={{ padding: "12px 14px", color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                      {user.last_login}
                    </td>
                    <td style={{ padding: "12px 14px", textAlign: "right" }}>
                      {user.id !== 1 ? (
                        <button
                          onClick={() => handleDeleteUser(user.id, user.full_name)}
                          style={{
                            background: "transparent",
                            border: "1px solid rgba(239, 68, 68, 0.4)",
                            color: "var(--neon-red)",
                            padding: "3px 8px",
                            borderRadius: "4px",
                            fontSize: "11px",
                            cursor: "pointer"
                          }}
                        >
                          Revoke
                        </button>
                      ) : (
                        <span style={{ fontSize: "10.5px", color: "var(--text-dim)" }}>Primary Admin</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: ROLE PERMISSIONS MATRIX (RBAC) */}
      {activeTab === "rbac" && (
        <div>
          <div
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "8px",
              padding: "16px",
              marginBottom: "16px"
            }}
          >
            <h3 style={{ fontSize: "14px", fontWeight: "700", marginBottom: "8px", color: "var(--neon-cyan)" }}>
              🛡️ Enterprise Privilege & Access Matrix
            </h3>
            <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "16px" }}>
              Enforces Zero-Trust role separation across infrastructure topology modification, active containment, vulnerability scanning, and compliance auditing.
            </p>

            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "center" }}>
              <thead>
                <tr style={{ background: "rgba(10, 16, 31, 0.8)", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-muted)" }}>
                  <th style={{ textAlign: "left", padding: "10px 14px" }}>SECURITY CAPABILITY</th>
                  <th style={{ padding: "10px 14px" }}>SOC LEAD (ADMIN)</th>
                  <th style={{ padding: "10px 14px" }}>SR. THREAT ANALYST</th>
                  <th style={{ padding: "10px 14px" }}>INCIDENT RESPONDER</th>
                  <th style={{ padding: "10px 14px" }}>COMPLIANCE AUDITOR</th>
                  <th style={{ padding: "10px 14px" }}>DEPT MANAGER</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { name: "Execute Deep Vulnerability Scans", admin: true, sr: true, ir: true, aud: false, mgr: false },
                  { name: "Live Attack & Penetration Simulation", admin: true, sr: true, ir: false, aud: false, mgr: false },
                  { name: "Firewall Policy Push & Port Blocking", admin: true, sr: true, ir: true, aud: false, mgr: false },
                  { name: "AI Copilot Exploit Script Downloads", admin: true, sr: true, ir: false, aud: false, mgr: false },
                  { name: "Digital Twin Topology Modifications", admin: true, sr: false, ir: false, aud: false, mgr: false },
                  { name: "Export ISO/SOC2 Regulatory Reports", admin: true, sr: true, ir: true, aud: true, mgr: true },
                  { name: "Manage Analyst Credentials & 2FA Enforcement", admin: true, sr: false, ir: false, aud: false, mgr: false }
                ].map((row, idx) => (
                  <tr key={idx} style={{ borderBottom: "1px solid var(--border-subtle)", background: idx % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent" }}>
                    <td style={{ textAlign: "left", padding: "10px 14px", fontWeight: "600", color: "var(--text-main)" }}>
                      {row.name}
                    </td>
                    <td style={{ padding: "10px 14px", color: row.admin ? "var(--neon-green)" : "var(--text-dim)", fontWeight: "700" }}>
                      {row.admin ? "✓ Full Access" : "✗"}
                    </td>
                    <td style={{ padding: "10px 14px", color: row.sr ? "var(--neon-green)" : "var(--text-dim)", fontWeight: "700" }}>
                      {row.sr ? "✓ Allowed" : "✗"}
                    </td>
                    <td style={{ padding: "10px 14px", color: row.ir ? "var(--neon-green)" : "var(--text-dim)", fontWeight: "700" }}>
                      {row.ir ? "✓ Allowed" : "✗"}
                    </td>
                    <td style={{ padding: "10px 14px", color: row.aud ? "var(--neon-cyan)" : "var(--text-dim)", fontWeight: "700" }}>
                      {row.aud ? "👁️ Read-Only" : "✗"}
                    </td>
                    <td style={{ padding: "10px 14px", color: row.mgr ? "var(--neon-cyan)" : "var(--text-dim)", fontWeight: "700" }}>
                      {row.mgr ? "👁️ Dept View" : "✗"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: AUDIT TRAIL */}
      {activeTab === "audit" && (
        <div
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "8px",
            overflow: "hidden"
          }}
        >
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "13px", fontWeight: "600" }}>Immutable Access & Modification Logs</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>SOC 2 Type II Compliant</span>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
            <thead>
              <tr style={{ background: "rgba(10, 16, 31, 0.8)", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-muted)" }}>
                <th style={{ padding: "10px 14px" }}>EVENT ID</th>
                <th style={{ padding: "10px 14px" }}>OPERATOR</th>
                <th style={{ padding: "10px 14px" }}>SECURITY ACTION</th>
                <th style={{ padding: "10px 14px" }}>ORIGIN IP</th>
                <th style={{ padding: "10px 14px" }}>TIMESTAMP</th>
                <th style={{ padding: "10px 14px" }}>SEVERITY</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={log.id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", color: "var(--neon-cyan)", fontSize: "11px" }}>
                    {log.id}
                  </td>
                  <td style={{ padding: "10px 14px", fontWeight: "600" }}>{log.user_name}</td>
                  <td style={{ padding: "10px 14px", color: "var(--text-main)" }}>{log.action}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", color: "var(--text-muted)", fontSize: "11px" }}>
                    {log.ip_address}
                  </td>
                  <td style={{ padding: "10px 14px", color: "var(--text-dim)", fontSize: "11px" }}>{log.timestamp}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <span
                      style={{
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "10px",
                        fontWeight: "700",
                        textTransform: "uppercase",
                        background:
                          log.severity === "critical" || log.severity === "high"
                            ? "rgba(239, 68, 68, 0.15)"
                            : log.severity === "medium"
                            ? "rgba(245, 158, 11, 0.15)"
                            : "rgba(56, 189, 248, 0.15)",
                        color:
                          log.severity === "critical" || log.severity === "high"
                            ? "var(--neon-red)"
                            : log.severity === "medium"
                            ? "var(--neon-orange)"
                            : "var(--neon-cyan)"
                      }}
                    >
                      {log.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 4: ACTIVE SESSIONS */}
      {activeTab === "sessions" && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
            <p style={{ margin: 0, fontSize: "12.5px", color: "var(--text-muted)" }}>
              Live authenticated client sessions accessing the CyberAtlas Security Engine.
            </p>

            <button
              onClick={handleRevokeSessions}
              style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid var(--neon-red)",
                color: "var(--neon-red)",
                padding: "6px 12px",
                borderRadius: "6px",
                fontSize: "11.5px",
                cursor: "pointer",
                fontWeight: "600"
              }}
            >
              🔒 Terminate All Other Sessions
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px" }}>
            {sessions.map((s) => (
              <div
                key={s.id}
                style={{
                  background: "var(--bg-card)",
                  border: s.is_current ? "1px solid var(--neon-cyan)" : "1px solid var(--border-subtle)",
                  borderRadius: "8px",
                  padding: "16px",
                  boxShadow: s.is_current ? "0 0 12px rgba(56, 189, 248, 0.2)" : "none"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontWeight: "700", fontSize: "13px" }}>{s.device_name}</span>
                  {s.is_current && (
                    <span
                      style={{
                        background: "rgba(56, 189, 248, 0.15)",
                        color: "var(--neon-cyan)",
                        border: "1px solid var(--neon-cyan)",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "10px",
                        fontWeight: "700"
                      }}
                    >
                      THIS DEVICE
                    </span>
                  )}
                </div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  <strong>Browser:</strong> {s.browser}
                </div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  <strong>IP / Network:</strong> <span style={{ fontFamily: "var(--font-mono)" }}>{s.ip_address}</span> ({s.location})
                </div>
                <div style={{ fontSize: "11.5px", color: "var(--text-dim)", marginTop: "8px" }}>
                  Status: <strong style={{ color: "var(--neon-green)" }}>{s.last_active}</strong>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MODAL: ADD / INVITE ANALYST */}
      {showAddModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(7, 11, 20, 0.85)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 10000
          }}
        >
          <div
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-highlight)",
              borderRadius: "10px",
              padding: "24px",
              width: "100%",
              maxWidth: "460px",
              boxShadow: "0 10px 30px rgba(0,0,0,0.6)"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h3 style={{ margin: 0, fontSize: "16px", fontWeight: "700", color: "var(--neon-cyan)" }}>
                ➕ Add New Security Analyst
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", fontSize: "16px", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddUser}>
              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "11.5px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Jordan Miller"
                  value={newUser.full_name}
                  onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })}
                  style={{
                    width: "100%",
                    background: "var(--bg-card-alt)",
                    border: "1px solid var(--border-subtle)",
                    color: "var(--text-main)",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    outline: "none"
                  }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "11.5px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. j.miller@cybertwin.soc"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  style={{
                    width: "100%",
                    background: "var(--bg-card-alt)",
                    border: "1px solid var(--border-subtle)",
                    color: "var(--text-main)",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    outline: "none"
                  }}
                />
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "11.5px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Assigned Security Role
                </label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  style={{
                    width: "100%",
                    background: "var(--bg-card-alt)",
                    border: "1px solid var(--border-subtle)",
                    color: "var(--text-main)",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px"
                  }}
                >
                  <option value="Senior Threat Analyst">Senior Threat Analyst</option>
                  <option value="Tier-1 Incident Responder">Tier-1 Incident Responder</option>
                  <option value="Compliance Auditor">Compliance Auditor</option>
                  <option value="IT Department Head">IT Department Head</option>
                  <option value="SOC Lead / Admin">SOC Lead / Admin</option>
                </select>
              </div>

              <div style={{ marginBottom: "18px" }}>
                <label style={{ display: "block", fontSize: "11.5px", color: "var(--text-muted)", marginBottom: "4px" }}>
                  Department
                </label>
                <select
                  value={newUser.department}
                  onChange={(e) => setNewUser({ ...newUser, department: e.target.value })}
                  style={{
                    width: "100%",
                    background: "var(--bg-card-alt)",
                    border: "1px solid var(--border-subtle)",
                    color: "var(--text-main)",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12px"
                  }}
                >
                  <option value="Threat Intelligence">Threat Intelligence</option>
                  <option value="SOC Operations">SOC Operations</option>
                  <option value="Compliance & GRC">Compliance & GRC</option>
                  <option value="Infrastructure">Infrastructure</option>
                  <option value="DevSecOps">DevSecOps</option>
                </select>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  style={{
                    background: "transparent",
                    border: "1px solid var(--border-subtle)",
                    color: "var(--text-muted)",
                    padding: "8px 14px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "12px"
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                    border: "1px solid #38bdf8",
                    color: "#fff",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "600",
                    fontSize: "12px",
                    boxShadow: "0 0 10px rgba(56, 189, 248, 0.3)"
                  }}
                >
                  Confirm & Provision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
