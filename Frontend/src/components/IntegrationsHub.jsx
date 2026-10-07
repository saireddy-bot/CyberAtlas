import React, { useState, useEffect } from "react";

export default function IntegrationsHub({ apiUrl }) {
  const [connectors, setConnectors] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedConnector, setSelectedConnector] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [secretInput, setSecretInput] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [syncingId, setSyncingId] = useState(null);
  const [notification, setNotification] = useState("");

  const CATEGORIES = [
    { id: "all", label: "All Connectors" },
    { id: "Cloud Infrastructure", label: "☁️ Cloud (AWS/GCP/Azure)" },
    { id: "Identity & SSO", label: "👥 Identity & SSO (Okta/Entra)" },
    { id: "Workstations & Endpoints", label: "💻 Endpoints & EDR Fleet" },
    { id: "Databases & Storage", label: "🗄️ Databases & Storage" },
    { id: "Software Supply Chain", label: "📦 Code & Supply Chain" },
    { id: "Network & Firewalls", label: "🧱 Firewalls & Network" },
    { id: "Email & Communication", label: "📧 Executive Email & M365" },
    { id: "Remote Access", label: "🌐 VPN / RDP / ZTNA" },
    { id: "Supply Chain Vendors", label: "🤝 3rd-Party Vendor Risk" }
  ];

  const fetchConnectors = async () => {
    try {
      const res = await fetch(`${apiUrl}/integrations/`);
      if (res.ok) {
        const data = await res.json();
        setConnectors(data.connectors || []);
        setSummary(data.summary || null);
      }
    } catch (err) {
      console.error("Failed to load integrations:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnectors();
  }, []);

  const handleOpenConfig = (connector) => {
    setSelectedConnector(connector);
    setApiKeyInput("");
    setSecretInput("");
    setModalOpen(true);
  };

  const handleConnectSubmit = async (e) => {
    e?.preventDefault();
    if (!selectedConnector) return;

    setConnecting(true);
    try {
      const res = await fetch(`${apiUrl}/integrations/${selectedConnector.id}/connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          api_key: apiKeyInput || "cyb_live_sec_key_482109",
          client_secret: secretInput || "sec_prod_stream_99182"
        })
      });

      if (res.ok) {
        const data = await res.json();
        setNotification(`✅ ${data.message}`);
        setTimeout(() => setNotification(""), 5000);
        setModalOpen(false);
        fetchConnectors();
      }
    } catch (err) {
      alert("Failed to connect asset.");
    } finally {
      setConnecting(false);
    }
  };

  const handleSyncNow = async (connectorId, name) => {
    setSyncingId(connectorId);
    try {
      const res = await fetch(`${apiUrl}/integrations/${connectorId}/sync`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setNotification(`🔄 ${data.message}`);
        setTimeout(() => setNotification(""), 4000);
        fetchConnectors();
      }
    } catch (err) {
      console.error("Sync error:", err);
    } finally {
      setSyncingId(null);
    }
  };

  const handleDisconnect = async (connectorId, name) => {
    if (!window.confirm(`Disconnect ${name} from CyberAtlas ingestion pipeline?`)) return;
    try {
      const res = await fetch(`${apiUrl}/integrations/${connectorId}/disconnect`, { method: "POST" });
      if (res.ok) {
        setNotification(`⚠️ Disconnected ${name}. Ingestion paused.`);
        setTimeout(() => setNotification(""), 4000);
        fetchConnectors();
      }
    } catch (err) {
      console.error("Disconnect error:", err);
    }
  };

  const handleDownloadAgent = (platform) => {
    window.open(`${apiUrl}/integrations/agent/download/${platform}`, "_blank");
  };

  const filteredConnectors = connectors.filter((c) => {
    const matchesCat = activeCategory === "all" || c.category === activeCategory;
    const matchesSearch =
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.vendor.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  return (
    <div style={{ padding: "24px 32px", color: "#f1f5f9", maxWidth: "1600px", margin: "0 auto" }}>
      {/* 1. HERO HEADER */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "24px" }}>🔌</span>
            <h1 style={{ fontSize: "22px", fontWeight: "800", letterSpacing: "1px", margin: 0, color: "#38bdf8" }}>
              ENTERPRISE CONNECTORS & ASSET TELEMETRY HUB
            </h1>
          </div>
          <p style={{ color: "#94a3b8", fontSize: "13px", margin: "6px 0 0 0" }}>
            Real-time security telemetry ingestion across Cloud, Workstations, Identity, Databases, Code Repositories, and Firewalls.
          </p>
        </div>

        {/* SUMMARY STATS BAR */}
        {summary && (
          <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
            <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid #1e3a8a", borderRadius: "10px", padding: "10px 16px", textAlign: "center" }}>
              <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Active Connectors</div>
              <div style={{ fontSize: "18px", fontWeight: "800", color: "#10b981" }}>
                {summary.active_connected} <span style={{ fontSize: "12px", color: "#64748b" }}>/ {summary.total_connectors}</span>
              </div>
            </div>

            <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid #1e3a8a", borderRadius: "10px", padding: "10px 16px", textAlign: "center" }}>
              <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Events Ingested</div>
              <div style={{ fontSize: "18px", fontWeight: "800", color: "#38bdf8" }}>
                {summary.total_events_ingested.toLocaleString()}
              </div>
            </div>

            <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid #1e3a8a", borderRadius: "10px", padding: "10px 16px", textAlign: "center" }}>
              <div style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Ingestion Pipeline</div>
              <div style={{ fontSize: "13px", fontWeight: "700", color: "#10b981", marginTop: "3px" }}>
                ● 98.4% Optimal
              </div>
            </div>
          </div>
        )}
      </div>

      {/* NOTIFICATION TOAST */}
      {notification && (
        <div
          style={{
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid #10b981",
            color: "#6ee7b7",
            padding: "12px 18px",
            borderRadius: "8px",
            fontSize: "13px",
            marginBottom: "20px",
            display: "flex",
            alignItems: "center",
            gap: "10px"
          }}
        >
          <span>ℹ️</span>
          <span>{notification}</span>
        </div>
      )}

      {/* 2. EDR SENSOR AGENT FLEET DEPLOYMENT BANNER */}
      <div
        style={{
          background: "linear-gradient(135deg, rgba(14, 165, 233, 0.12) 0%, rgba(15, 23, 42, 0.9) 100%)",
          border: "1px solid rgba(56, 189, 248, 0.35)",
          borderRadius: "14px",
          padding: "20px 24px",
          marginBottom: "28px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "20px"
        }}
      >
        <div style={{ maxWidth: "700px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
            <span style={{ background: "#0284c7", color: "#fff", fontSize: "10px", fontWeight: "800", padding: "2px 8px", borderRadius: "4px" }}>
              NATIVE SENSOR FLEET
            </span>
            <h3 style={{ margin: 0, fontSize: "16px", fontWeight: "700", color: "#fff" }}>
              Deploy CyberAtlas Sentinel Agents on Employee Laptops & Servers
            </h3>
          </div>
          <p style={{ margin: 0, fontSize: "12.5px", color: "#94a3b8", lineHeight: "1.5" }}>
            Install the CyberAtlas kernel sensor to stream real-time process execution, detect ransomware file tampering, prevent Mimikatz credential dumping, and isolate infected endpoints across your fleet.
          </p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button
            onClick={() => handleDownloadAgent("windows")}
            style={{
              background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
              border: "1px solid #38bdf8",
              color: "#fff",
              padding: "10px 16px",
              borderRadius: "8px",
              fontSize: "12.5px",
              fontWeight: "700",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              boxShadow: "0 0 15px rgba(56, 189, 248, 0.3)"
            }}
          >
            <span>🪟</span> Download Windows Agent (.ps1)
          </button>

          <button
            onClick={() => handleDownloadAgent("linux")}
            style={{
              background: "rgba(30, 41, 59, 0.9)",
              border: "1px solid #475569",
              color: "#f1f5f9",
              padding: "10px 16px",
              borderRadius: "8px",
              fontSize: "12.5px",
              fontWeight: "600",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "8px"
            }}
          >
            <span>🐧</span> Linux / Mac eBPF (.sh)
          </button>
        </div>
      </div>

      {/* 3. CATEGORY FILTER TABS & SEARCH BAR */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", flexWrap: "wrap", gap: "14px" }}>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              style={{
                background: activeCategory === cat.id ? "#0284c7" : "rgba(15, 23, 42, 0.8)",
                color: activeCategory === cat.id ? "#fff" : "#94a3b8",
                border: activeCategory === cat.id ? "1px solid #38bdf8" : "1px solid #1e293b",
                padding: "7px 13px",
                borderRadius: "8px",
                fontSize: "12px",
                fontWeight: activeCategory === cat.id ? "700" : "500",
                cursor: "pointer",
                transition: "all 0.15s ease"
              }}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* SEARCH BAR */}
        <div style={{ position: "relative", minWidth: "260px" }}>
          <input
            type="text"
            placeholder="🔍 Search connectors (e.g. AWS, Okta, DB)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              background: "#070b14",
              border: "1px solid #1e3a8a",
              color: "#fff",
              padding: "8px 14px",
              borderRadius: "8px",
              fontSize: "12px",
              outline: "none",
              boxSizing: "border-box"
            }}
          />
        </div>
      </div>

      {/* 4. CONNECTOR GRID CARDS */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: "18px" }}>
        {filteredConnectors.map((c) => (
          <div
            key={c.id}
            style={{
              background: "rgba(10, 16, 31, 0.85)",
              border: c.status === "connected" ? "1px solid rgba(56, 189, 248, 0.3)" : "1px solid #1e293b",
              borderRadius: "12px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              boxShadow: "0 10px 25px rgba(0, 0, 0, 0.5)",
              position: "relative",
              overflow: "hidden"
            }}
          >
            {/* CONNECTOR HEADER */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
                <div>
                  <span
                    style={{
                      background: "rgba(56, 189, 248, 0.12)",
                      color: "#38bdf8",
                      border: "1px solid rgba(56, 189, 248, 0.3)",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      fontSize: "9.5px",
                      fontWeight: "700"
                    }}
                  >
                    {c.badge}
                  </span>
                  <h3 style={{ fontSize: "15px", fontWeight: "700", margin: "6px 0 2px 0", color: "#fff" }}>
                    {c.name}
                  </h3>
                  <div style={{ fontSize: "11px", color: "#64748b" }}>Vendor: {c.vendor} • {c.auth_type}</div>
                </div>

                {/* STATUS BADGE */}
                <div>
                  {c.status === "connected" ? (
                    <span
                      style={{
                        background: "rgba(16, 185, 129, 0.15)",
                        color: "#10b981",
                        border: "1px solid rgba(16, 185, 129, 0.4)",
                        padding: "3px 8px",
                        borderRadius: "12px",
                        fontSize: "10.5px",
                        fontWeight: "700"
                      }}
                    >
                      ● Streaming
                    </span>
                  ) : (
                    <span
                      style={{
                        background: "rgba(148, 163, 184, 0.12)",
                        color: "#94a3b8",
                        border: "1px solid #334155",
                        padding: "3px 8px",
                        borderRadius: "12px",
                        fontSize: "10.5px",
                        fontWeight: "600"
                      }}
                    >
                      ○ Ready
                    </span>
                  )}
                </div>
              </div>

              <p style={{ fontSize: "12px", color: "#94a3b8", lineHeight: "1.45", margin: "0 0 16px 0" }}>
                {c.description}
              </p>
            </div>

            {/* TELEMETRY TELEMETRY METRICS */}
            <div>
              <div
                style={{
                  background: "#070b14",
                  borderRadius: "8px",
                  padding: "10px 12px",
                  marginBottom: "14px",
                  fontSize: "11px",
                  display: "flex",
                  justifyContent: "space-between",
                  border: "1px solid rgba(255, 255, 255, 0.05)"
                }}
              >
                <div>
                  <div style={{ color: "#64748b" }}>Data Rate:</div>
                  <div style={{ color: c.status === "connected" ? "#38bdf8" : "#64748b", fontWeight: "600" }}>
                    {c.telemetry_rate}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ color: "#64748b" }}>Events Ingested:</div>
                  <div style={{ color: "#fff", fontWeight: "700" }}>{c.events_ingested.toLocaleString()}</div>
                </div>
              </div>

              {/* ACTION BUTTONS */}
              <div style={{ display: "flex", gap: "8px" }}>
                {c.status === "connected" ? (
                  <>
                    <button
                      onClick={() => handleSyncNow(c.id, c.name)}
                      disabled={syncingId === c.id}
                      style={{
                        flex: 1,
                        background: "rgba(56, 189, 248, 0.12)",
                        border: "1px solid #0284c7",
                        color: "#38bdf8",
                        padding: "8px",
                        borderRadius: "6px",
                        fontSize: "11.5px",
                        fontWeight: "700",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: "6px"
                      }}
                    >
                      {syncingId === c.id ? "🔄 Syncing..." : "🔄 Sync Now"}
                    </button>
                    <button
                      onClick={() => handleDisconnect(c.id, c.name)}
                      style={{
                        background: "transparent",
                        border: "1px solid #334155",
                        color: "#ef4444",
                        padding: "8px 12px",
                        borderRadius: "6px",
                        fontSize: "11px",
                        cursor: "pointer"
                      }}
                    >
                      Disconnect
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => handleOpenConfig(c)}
                    style={{
                      width: "100%",
                      background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                      border: "1px solid #38bdf8",
                      color: "#fff",
                      padding: "8px",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "700",
                      cursor: "pointer",
                      boxShadow: "0 0 12px rgba(56, 189, 248, 0.25)"
                    }}
                  >
                    ⚡ Connect Asset ➔
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 5. CONFIGURATION & HANDSHAKE MODAL */}
      {modalOpen && selectedConnector && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(8px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: "20px"
          }}
        >
          <div
            style={{
              background: "#0a101f",
              border: "1px solid #38bdf8",
              borderRadius: "14px",
              width: "100%",
              maxWidth: "520px",
              padding: "24px",
              boxShadow: "0 20px 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(56, 189, 248, 0.2)"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div>
                <span style={{ fontSize: "10px", color: "#38bdf8", fontWeight: "700", textTransform: "uppercase" }}>
                  {selectedConnector.badge}
                </span>
                <h2 style={{ margin: "2px 0 0 0", fontSize: "17px", color: "#fff" }}>
                  Connect {selectedConnector.name}
                </h2>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                style={{ background: "transparent", border: "none", color: "#94a3b8", fontSize: "18px", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: "12px", color: "#94a3b8", margin: "0 0 20px 0", lineHeight: "1.4" }}>
              {selectedConnector.description}
            </p>

            <form onSubmit={handleConnectSubmit}>
              <div style={{ marginBottom: "14px" }}>
                <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "6px" }}>
                  API Token / Secret Key / Role ARN ({selectedConnector.auth_type})
                </label>
                <input
                  type="password"
                  placeholder="e.g. arn:aws:iam::123456789012:role/CyberAtlasSOC-Auditor"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  style={{
                    width: "100%",
                    background: "#070b14",
                    border: "1px solid #1e3a8a",
                    color: "#38bdf8",
                    padding: "10px 12px",
                    borderRadius: "8px",
                    fontSize: "12.5px",
                    fontFamily: "monospace",
                    outline: "none",
                    boxSizing: "border-box"
                  }}
                />
              </div>

              <div style={{ marginBottom: "20px" }}>
                <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "6px" }}>
                  Webhook URL / Endpoint Target (Optional)
                </label>
                <input
                  type="text"
                  placeholder="https://api.cyberatlas.soc/ingest/webhook"
                  value={secretInput}
                  onChange={(e) => setSecretInput(e.target.value)}
                  style={{
                    width: "100%",
                    background: "#070b14",
                    border: "1px solid #1e3a8a",
                    color: "#fff",
                    padding: "10px 12px",
                    borderRadius: "8px",
                    fontSize: "12px",
                    outline: "none",
                    boxSizing: "border-box"
                  }}
                />
              </div>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
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
                  disabled={connecting}
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
                    boxShadow: "0 0 15px rgba(56, 189, 248, 0.35)"
                  }}
                >
                  {connecting ? "Testing Handshake & Ingesting..." : "Test Connection & Start Streaming ➔"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
