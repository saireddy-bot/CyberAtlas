import React, { useState, useEffect } from "react";

const DEFAULT_SETTINGS = {
  // 1. General & Branding
  orgName: "CyberAtlas SOC Enterprise",
  logoUrl: "",
  themeAccent: "cyan", // cyan, emerald, crimson, violet, amber
  refreshInterval: "5",
  audioAlerts: true,
  defaultMapView: "kaspersky",
  compactTables: false,
  cisoContact: "ciso-desk@cyberatlas.soc",

  // 2. Scanner & Discovery
  targetSubnet: "192.168.1.0/24",
  scanDepth: "standard", // quick, standard, deep
  scanSchedule: "60", // 60, 300, 900, 3600
  autoDiscovery: true,

  // 3. Geo-Defense & Threat Blocking
  geoblockedCountries: ["RU", "CN", "KP", "IR"],
  blockTorExitNodes: true,
  blockAnonymousProxies: true,

  // 4. Sentinel AI Tuning
  aiModel: "gemini-1.5-pro",
  aiSensitivity: "aggressive",
  autoQuarantine: true,
  autoRemediate: false,

  // 5. Alerts & Webhooks
  alertEmail: "soc-leads@cyberatlas.soc",
  slackWebhook: "https://hooks.slack.com/services/T000/B000/XXXXX",
  alertThreshold: "critical_high",
  pagerDutyEnabled: false,

  // 6. Agent & Remote Gateway
  agentSecretKey: "ca_sec_live_9f83a810b42c7e09",
  autoApproveAgents: true,
  customDomain: "soc.cyberatlas.enterprise",
  cloudflareTunnelToken: "",
  restrictToLocalLan: false,

  // 7. Security & Access
  enforce2FA: true,
  sessionTimeout: "30",
  maxSessions: "3",

  // 8. Compliance & Storage
  retentionDays: "90",
  autoWeeklyReport: true,
  complianceFrameworks: ["pci_dss", "iso_27001", "soc2", "nist"]
};

const THEME_PRESETS = [
  { id: "cyan", name: "Cyber Cyan", color: "#38bdf8", glow: "rgba(56, 189, 248, 0.4)" },
  { id: "emerald", name: "Matrix Emerald", color: "#10b981", glow: "rgba(16, 185, 129, 0.4)" },
  { id: "crimson", name: "Threat Crimson", color: "#ef4444", glow: "rgba(239, 68, 68, 0.4)" },
  { id: "violet", name: "Deep Tech Violet", color: "#a855f7", glow: "rgba(168, 85, 247, 0.4)" },
  { id: "amber", name: "Command Gold", color: "#f59e0b", glow: "rgba(245, 158, 11, 0.4)" }
];

const GEO_COUNTRIES = [
  { code: "RU", name: "Russia", attacks: "142 hits/day" },
  { code: "CN", name: "China", attacks: "98 hits/day" },
  { code: "KP", name: "North Korea", attacks: "APT Activity" },
  { code: "IR", name: "Iran", attacks: "State Probes" },
  { code: "NL", name: "Netherlands", attacks: "64 hits/day" },
  { code: "BR", name: "Brazil", attacks: "Botnet Scans" },
  { code: "US", name: "United States", attacks: "Commercial Cloud" }
];

const COMPLIANCE_LIST = [
  { id: "pci_dss", name: "PCI-DSS v4.0", desc: "Payment Card Industry Data Security Standard" },
  { id: "iso_27001", name: "ISO / IEC 27001", desc: "Information Security Management System" },
  { id: "soc2", name: "SOC 2 Type II", desc: "Trust Services Criteria for Security & Availability" },
  { id: "nist", name: "NIST CSF 2.0", desc: "National Institute of Standards & Technology" },
  { id: "hipaa", name: "HIPAA Security", desc: "Health Insurance Portability and Accountability Act" }
];

export default function SettingsCenter({ apiUrl, onSaveToast }) {
  const [activeSubTab, setActiveSubTab] = useState("general");
  const [settings, setSettings] = useState(() => {
    try {
      const saved = localStorage.getItem("cyberatlas_system_settings");
      return saved ? { ...DEFAULT_SETTINGS, ...JSON.parse(saved) } : DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  });

  const [saving, setSaving] = useState(false);
  const [testWebhookStatus, setTestWebhookStatus] = useState("");
  const [copiedKey, setCopiedKey] = useState(false);

  const handleChange = (key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleToggleCountry = (code) => {
    setSettings((prev) => {
      const list = prev.geoblockedCountries || [];
      return {
        ...prev,
        geoblockedCountries: list.includes(code)
          ? list.filter((c) => c !== code)
          : [...list, code]
      };
    });
  };

  const handleToggleCompliance = (id) => {
    setSettings((prev) => {
      const list = prev.complianceFrameworks || [];
      return {
        ...prev,
        complianceFrameworks: list.includes(id)
          ? list.filter((f) => f !== id)
          : [...list, id]
      };
    });
  };

  const handleRegenerateKey = () => {
    if (window.confirm("Regenerate Endpoint Agent Secret Key? Existing agents will need the new key to sync.")) {
      const randomHex = Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
      const newKey = `ca_sec_live_${randomHex}`;
      handleChange("agentSecretKey", newKey);
      if (onSaveToast) onSaveToast("🔑 New Agent Enrollment Key generated!");
    }
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(settings.agentSecretKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleSave = () => {
    setSaving(true);
    try {
      localStorage.setItem("cyberatlas_system_settings", JSON.stringify(settings));
      
      // Dynamically apply chosen accent theme color to document root
      const chosenTheme = THEME_PRESETS.find((t) => t.id === settings.themeAccent) || THEME_PRESETS[0];
      document.documentElement.style.setProperty("--neon-cyan", chosenTheme.color);
      document.documentElement.style.setProperty("--glow-cyan", `0 0 10px ${chosenTheme.glow}`);

      setTimeout(() => {
        setSaving(false);
        if (onSaveToast) onSaveToast("✅ All SOC settings & security policies saved!");
      }, 400);
    } catch (e) {
      setSaving(false);
      alert("Failed to save settings: " + e.message);
    }
  };

  const handleReset = () => {
    if (window.confirm("Reset all settings to factory SOC defaults?")) {
      setSettings(DEFAULT_SETTINGS);
      localStorage.removeItem("cyberatlas_system_settings");
      document.documentElement.style.setProperty("--neon-cyan", "#38bdf8");
      if (onSaveToast) onSaveToast("🔄 Settings reset to factory defaults.");
    }
  };

  const handleTestWebhook = () => {
    setTestWebhookStatus("sending");
    setTimeout(() => {
      setTestWebhookStatus("sent");
      setTimeout(() => setTestWebhookStatus(""), 3500);
    }, 900);
  };

  return (
    <div className="soc-settings-container">
      {/* HEADER BANNER */}
      <div className="settings-header-banner">
        <div>
          <div className="settings-title-row">
            <span className="settings-header-icon">⚙️</span>
            <h2>Enterprise SOC Platform Configuration</h2>
          </div>
          <p className="settings-subtitle">
            Configure automated discovery subnets, active country geoblocking, client white-labeling, agent enrollment keys, Cloudflare gateway, and compliance frameworks.
          </p>
        </div>
        <div className="settings-top-badges">
          <span className="badge-pill green">● Engine v2.4 Online</span>
          <span className="badge-pill cyan">● Geoblock: {settings.geoblockedCountries?.length || 0} Regions</span>
        </div>
      </div>

      {/* MAIN BODY: 8-CATEGORY NAV + CONTENT PANEL */}
      <div className="settings-body-grid">
        {/* SETTINGS SUB-NAV */}
        <div className="settings-nav-panel">
          <button
            className={`settings-nav-item ${activeSubTab === "general" ? "active" : ""}`}
            onClick={() => setActiveSubTab("general")}
          >
            <span className="s-icon">🖥️</span>
            <div className="s-nav-text">
              <strong>General & Branding</strong>
              <span>Org Name, Theme, Logo</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "scanner" ? "active" : ""}`}
            onClick={() => setActiveSubTab("scanner")}
          >
            <span className="s-icon">🔍</span>
            <div className="s-nav-text">
              <strong>Scanner & Discovery</strong>
              <span>Subnet, Depth, Schedule</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "geoblock" ? "active" : ""}`}
            onClick={() => setActiveSubTab("geoblock")}
          >
            <span className="s-icon">🌍</span>
            <div className="s-nav-text">
              <strong>Geo-Defense & Filtering</strong>
              <span>Country IP Ban, Tor Exit</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "ai" ? "active" : ""}`}
            onClick={() => setActiveSubTab("ai")}
          >
            <span className="s-icon">🤖</span>
            <div className="s-nav-text">
              <strong>Sentinel AI Tuning</strong>
              <span>Gemini LLM, Quarantine</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "notifications" ? "active" : ""}`}
            onClick={() => setActiveSubTab("notifications")}
          >
            <span className="s-icon">🔔</span>
            <div className="s-nav-text">
              <strong>Alerts & Webhooks</strong>
              <span>Slack, Teams, PagerDuty</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "agents" ? "active" : ""}`}
            onClick={() => setActiveSubTab("agents")}
          >
            <span className="s-icon">🔑</span>
            <div className="s-nav-text">
              <strong>Agents & Gateway</strong>
              <span>Secret Keys, Cloudflare</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "security" ? "active" : ""}`}
            onClick={() => setActiveSubTab("security")}
          >
            <span className="s-icon">🔒</span>
            <div className="s-nav-text">
              <strong>Security & Access</strong>
              <span>2FA, Session Timeout</span>
            </div>
          </button>

          <button
            className={`settings-nav-item ${activeSubTab === "compliance" ? "active" : ""}`}
            onClick={() => setActiveSubTab("compliance")}
          >
            <span className="s-icon">📑</span>
            <div className="s-nav-text">
              <strong>Compliance & Audit</strong>
              <span>PCI-DSS, ISO, Backups</span>
            </div>
          </button>

          <div className="settings-system-info-box">
            <div className="sys-title">SYSTEM STATUS</div>
            <div className="sys-row"><span>Node Host:</span> <code>DESKTOP-CYBER</code></div>
            <div className="sys-row"><span>FastAPI Backend:</span> <code>0.115.6</code></div>
            <div className="sys-row"><span>Subnet Monitored:</span> <code>{settings.targetSubnet}</code></div>
            <div className="sys-row"><span>Active Decoys:</span> <span style={{ color: "#10b981", fontWeight: "700" }}>3 Armed</span></div>
          </div>
        </div>

        {/* SETTINGS CONTENT FORM */}
        <div className="settings-content-panel">
          {/* 1. GENERAL & BRANDING */}
          {activeSubTab === "general" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🖥️ General & Company Branding (White-Labeling)</h3>
                <p>Customize organization branding, theme color accents, and UI telemetry refresh intervals.</p>
              </div>

              <div className="settings-form-group">
                <label>Organization / Company Name</label>
                <input
                  type="text"
                  value={settings.orgName}
                  onChange={(e) => handleChange("orgName", e.target.value)}
                  placeholder="e.g. Acme Corp Cyber Command"
                />
                <span className="input-hint">Displayed on executive reports, audit logs, and command center headers.</span>
              </div>

              <div className="settings-form-group">
                <label>Theme Color Accent</label>
                <div className="theme-swatch-row">
                  {THEME_PRESETS.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      className={`theme-swatch-btn ${settings.themeAccent === t.id ? "active" : ""}`}
                      onClick={() => handleChange("themeAccent", t.id)}
                      style={{ borderColor: settings.themeAccent === t.id ? t.color : "rgba(255,255,255,0.1)" }}
                    >
                      <span className="swatch-circle" style={{ background: t.color, boxShadow: `0 0 8px ${t.glow}` }}></span>
                      <span>{t.name}</span>
                    </button>
                  ))}
                </div>
                <span className="input-hint">Adapts glowing borders, primary buttons, and live radar accents.</span>
              </div>

              <div className="settings-form-row">
                <div className="settings-form-group flex-1">
                  <label>Custom Company Logo URL (Optional)</label>
                  <input
                    type="text"
                    value={settings.logoUrl}
                    onChange={(e) => handleChange("logoUrl", e.target.value)}
                    placeholder="https://company.com/assets/logo.png"
                  />
                  <span className="input-hint">Replaces top-left shield with your client company's corporate insignia.</span>
                </div>

                <div className="settings-form-group flex-1">
                  <label>CISO / Internal Helpdesk Contact</label>
                  <input
                    type="text"
                    value={settings.cisoContact}
                    onChange={(e) => handleChange("cisoContact", e.target.value)}
                    placeholder="security-desk@company.com"
                  />
                  <span className="input-hint">Displayed to employees on how to reach their internal incident response team.</span>
                </div>
              </div>

              <div className="settings-form-row">
                <div className="settings-form-group flex-1">
                  <label>Telemetry Live Polling Frequency</label>
                  <select
                    value={settings.refreshInterval}
                    onChange={(e) => handleChange("refreshInterval", e.target.value)}
                  >
                    <option value="3">3 seconds (Real-time / High Bandwidth)</option>
                    <option value="5">5 seconds (Recommended Default)</option>
                    <option value="15">15 seconds (Balanced)</option>
                    <option value="30">30 seconds (Eco mode)</option>
                  </select>
                </div>

                <div className="settings-form-group flex-1">
                  <label>Default Threat Map Visualization</label>
                  <select
                    value={settings.defaultMapView}
                    onChange={(e) => handleChange("defaultMapView", e.target.value)}
                  >
                    <option value="kaspersky">Kaspersky 3D Cyberthreat Globe</option>
                    <option value="vector">CyberAtlas SVG Vector Map</option>
                  </select>
                </div>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Audible Threat Siren</strong>
                    <span>Emit a tactical audio chime whenever a CRITICAL threat is detected.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.audioAlerts}
                      onChange={(e) => handleChange("audioAlerts", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Compact Data Tables</strong>
                    <span>Reduce row padding across alert logs to fit 30% more entries on laptop screens.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.compactTables}
                      onChange={(e) => handleChange("compactTables", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* 2. SCANNER & DISCOVERY */}
          {activeSubTab === "scanner" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🔍 Network Scanner & Target Subnet Discovery Tuning</h3>
                <p>Define which IP ranges your EDR and automated network scanner investigate for open ports and vulnerabilities.</p>
              </div>

              <div className="settings-form-group">
                <label>Target Subnet / IP Range</label>
                <input
                  type="text"
                  value={settings.targetSubnet}
                  onChange={(e) => handleChange("targetSubnet", e.target.value)}
                  placeholder="e.g. 192.168.1.0/24, 10.0.0.0/16, 172.16.0.0/24"
                />
                <span className="input-hint">The CIDR block or comma-separated IP list that CyberAtlas automatically scans and inventories.</span>
              </div>

              <div className="settings-form-row">
                <div className="settings-form-group flex-1">
                  <label>Scan Depth & Technique</label>
                  <select
                    value={settings.scanDepth}
                    onChange={(e) => handleChange("scanDepth", e.target.value)}
                  >
                    <option value="quick">⚡ Quick Discovery (Top 100 Ports)</option>
                    <option value="standard">🛡️ Standard SOC (Top 1000 Ports + -sV)</option>
                    <option value="deep">🔬 Deep Audit (Nmap CVE Scripts)</option>
                  </select>
                  <span className="input-hint">Controls how aggressively Nmap and Python probe monitored hosts.</span>
                </div>

                <div className="settings-form-group flex-1">
                  <label>Automated Scan Interval</label>
                  <select
                    value={settings.scanSchedule}
                    onChange={(e) => handleChange("scanSchedule", e.target.value)}
                  >
                    <option value="60">Every 1 Minute (High Security)</option>
                    <option value="300">Every 5 Minutes (Enterprise)</option>
                    <option value="900">Every 15 Minutes (Balanced)</option>
                    <option value="3600">Hourly (Low Resource)</option>
                  </select>
                  <span className="input-hint">Frequency of the background auto-scanner audit cycle.</span>
                </div>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Auto-Discovery of New Unmanaged Devices</strong>
                    <span>Automatically create asset inventory cards when unknown MAC/IP addresses appear on the corporate network.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.autoDiscovery}
                      onChange={(e) => handleChange("autoDiscovery", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* 3. GEO-DEFENSE & FILTERING */}
          {activeSubTab === "geoblock" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🌍 Geo-Perimeter Defense & High-Risk Country IP Blocking</h3>
                <p>Instantly drop and quarantine incoming traffic originating from selected high-threat geographical zones.</p>
              </div>

              <div className="geoblock-grid">
                {GEO_COUNTRIES.map((c) => {
                  const isBlocked = settings.geoblockedCountries?.includes(c.code);
                  return (
                    <div
                      key={c.code}
                      className={`geoblock-card ${isBlocked ? "blocked" : ""}`}
                      onClick={() => handleToggleCountry(c.code)}
                    >
                      <div className="geoblock-header">
                        <span className="geo-code">{c.code}</span>
                        <strong>{c.name}</strong>
                      </div>
                      <div className="geoblock-sub">{c.attacks}</div>
                      <div className={`geo-badge ${isBlocked ? "drop" : "allow"}`}>
                        {isBlocked ? "🛡️ BLOCKED (DROP)" : "✓ Allowed"}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="settings-toggle-group" style={{ marginTop: "16px" }}>
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Block Known Tor Exit Nodes</strong>
                    <span>Automatically deny connections originating from the official Tor public directory to prevent anonymous probing.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.blockTorExitNodes}
                      onChange={(e) => handleChange("blockTorExitNodes", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Filter Commercial Datacenter Proxies</strong>
                    <span>Flag or drop non-residential proxy IP ranges often rented by automated credential-stuffing botnets.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.blockAnonymousProxies}
                      onChange={(e) => handleChange("blockAnonymousProxies", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* 4. SENTINEL AI TUNING */}
          {activeSubTab === "ai" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🤖 Sentinel AI Engine & Autonomous Mitigation</h3>
                <p>Fine-tune machine learning anomaly sensitivity and automatic quarantine actions.</p>
              </div>

              <div className="settings-form-row">
                <div className="settings-form-group flex-1">
                  <label>AI Copilot LLM Engine</label>
                  <select
                    value={settings.aiModel}
                    onChange={(e) => handleChange("aiModel", e.target.value)}
                  >
                    <option value="gemini-1.5-pro">Google Gemini 1.5 Pro (Deep Reasoning)</option>
                    <option value="gemini-1.5-flash">Google Gemini 1.5 Flash (Ultra-Fast)</option>
                    <option value="local-llama">Local Llama-3 8B (Air-Gapped Offline)</option>
                  </select>
                </div>

                <div className="settings-form-group flex-1">
                  <label>Detection Heuristic Sensitivity</label>
                  <select
                    value={settings.aiSensitivity}
                    onChange={(e) => handleChange("aiSensitivity", e.target.value)}
                  >
                    <option value="conservative">Conservative (Low False Positives)</option>
                    <option value="aggressive">Aggressive (Balanced Enterprise)</option>
                    <option value="paranoid">Paranoid (High Sensitivity)</option>
                  </select>
                </div>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Autonomous Edge Firewall Quarantine</strong>
                    <span>Automatically append temporary Windows/Linux firewall drop rules for IPs triggering 3+ critical alarms.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.autoQuarantine}
                      onChange={(e) => handleChange("autoQuarantine", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Auto-Execute Verified Remediation Playbooks</strong>
                    <span>Allow Sentinel AI to autonomously kill known rogue processes and isolate infected workstations.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.autoRemediate}
                      onChange={(e) => handleChange("autoRemediate", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* 5. ALERTS & WEBHOOKS */}
          {activeSubTab === "notifications" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🔔 Alert Dispatch & Incident Webhook Integration</h3>
                <p>Broadcast high-priority findings to chat channels, on-call pagers, and email distribution lists.</p>
              </div>

              <div className="settings-form-group">
                <label>SOC Emergency Email Dispatch</label>
                <input
                  type="email"
                  value={settings.alertEmail}
                  onChange={(e) => handleChange("alertEmail", e.target.value)}
                  placeholder="soc-leads@company.com"
                />
                <span className="input-hint">Instant incident bulletins will be dispatched here for Critical findings.</span>
              </div>

              <div className="settings-form-group">
                <label>Slack / MS Teams Ingress Webhook URL</label>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    type="text"
                    value={settings.slackWebhook}
                    onChange={(e) => handleChange("slackWebhook", e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    className="soc-btn cyan-btn"
                    onClick={handleTestWebhook}
                    disabled={testWebhookStatus === "sending"}
                  >
                    {testWebhookStatus === "sending" ? "⏳ Sending..." : testWebhookStatus === "sent" ? "✅ Sent!" : "⚡ Test Ping"}
                  </button>
                </div>
                <span className="input-hint">Sends formatted threat cards with attacker IP, severity, and 1-click quarantine links.</span>
              </div>

              <div className="settings-form-group">
                <label>Alert Forwarding Threshold</label>
                <select
                  value={settings.alertThreshold}
                  onChange={(e) => handleChange("alertThreshold", e.target.value)}
                >
                  <option value="critical_only">Critical Alerts Only (Minimal Noise)</option>
                  <option value="critical_high">Critical + High Severity (Standard SOC)</option>
                  <option value="all">All Severities (Including Medium & Low)</option>
                </select>
              </div>

              <div className="toggle-item" style={{ marginTop: "12px" }}>
                <div className="toggle-label">
                  <strong>PagerDuty On-Call Incident Wakeup</strong>
                  <span>Trigger emergency phone/pager alerts during off-hours for active network perimeter breaches.</span>
                </div>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={settings.pagerDutyEnabled}
                    onChange={(e) => handleChange("pagerDutyEnabled", e.target.checked)}
                  />
                  <span className="slider round"></span>
                </label>
              </div>
            </div>
          )}

          {/* 6. AGENTS & GATEWAY */}
          {activeSubTab === "agents" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🔑 Endpoint Agent Enrollment & Remote Gateway</h3>
                <p>Manage secret tokens used by downloadable sensor scripts and configure your company's custom domain tunnel.</p>
              </div>

              <div className="settings-form-group">
                <label>Endpoint Sensor Secret Key (Pre-Shared Token)</label>
                <div className="secret-key-box">
                  <code>{settings.agentSecretKey}</code>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <button type="button" className="soc-btn small-btn" onClick={handleCopyKey}>
                      {copiedKey ? "✅ Copied!" : "📋 Copy"}
                    </button>
                    <button type="button" className="soc-btn small-btn" onClick={handleRegenerateKey} style={{ color: "#f59e0b" }}>
                      🔄 Regenerate
                    </button>
                  </div>
                </div>
                <span className="input-hint">Required by CyberAtlas-Agent.ps1 and .sh scripts on employee laptops to securely upload telemetry.</span>
              </div>

              <div className="settings-form-row">
                <div className="settings-form-group flex-1">
                  <label>Custom Enterprise Domain</label>
                  <input
                    type="text"
                    value={settings.customDomain}
                    onChange={(e) => handleChange("customDomain", e.target.value)}
                    placeholder="soc.yourcompany.com"
                  />
                  <span className="input-hint">Your company's official web address for remote SOC operator access.</span>
                </div>

                <div className="settings-form-group flex-1">
                  <label>Cloudflare Zero Trust Tunnel Token (Optional)</label>
                  <input
                    type="password"
                    value={settings.cloudflareTunnelToken}
                    onChange={(e) => handleChange("cloudflareTunnelToken", e.target.value)}
                    placeholder="eyJhIjoi..."
                  />
                  <span className="input-hint">Links your local instance to your purchased domain without opening router ports.</span>
                </div>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Auto-Approve Newly Enrolled Endpoint Agents</strong>
                    <span>Automatically accept and monitor new employee laptops without requiring manual admin authorization.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.autoApproveAgents}
                      onChange={(e) => handleChange("autoApproveAgents", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Enforce Local Air-Gapped Mode (LAN Only)</strong>
                    <span>Block all WAN access and restrict the SOC dashboard strictly to internal office Wi-Fi and VPN subnets.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.restrictToLocalLan}
                      onChange={(e) => handleChange("restrictToLocalLan", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* 7. SECURITY & ACCESS */}
          {activeSubTab === "security" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>🔒 Security, MFA & Session Governance</h3>
                <p>Enforce zero-trust operator access, session timeouts, and authentication policies.</p>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Enforce Two-Factor Authentication (2FA / TOTP)</strong>
                    <span>Require a 6-digit authenticator code for all SOC Analysts and Administrators.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.enforce2FA}
                      onChange={(e) => handleChange("enforce2FA", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>

              <div className="settings-form-row" style={{ marginTop: "12px" }}>
                <div className="settings-form-group flex-1">
                  <label>Operator Inactivity Timeout</label>
                  <select
                    value={settings.sessionTimeout}
                    onChange={(e) => handleChange("sessionTimeout", e.target.value)}
                  >
                    <option value="15">15 minutes (High Security / Military)</option>
                    <option value="30">30 minutes (Standard SOC)</option>
                    <option value="60">60 minutes (Extended)</option>
                    <option value="0">Never (Kiosk / Wallboard Mode)</option>
                  </select>
                </div>

                <div className="settings-form-group flex-1">
                  <label>Maximum Concurrent Sessions per User</label>
                  <select
                    value={settings.maxSessions}
                    onChange={(e) => handleChange("maxSessions", e.target.value)}
                  >
                    <option value="1">1 Session (Strict Single Sign-On)</option>
                    <option value="3">3 Sessions (Workstation + Mobile)</option>
                    <option value="unlimited">Unlimited</option>
                  </select>
                </div>
              </div>

              <div className="settings-info-alert">
                <span>🛡️ <strong>Cryptographic Audit Trail:</strong> All rule additions, IP bans, and manual scans are hashed and permanently recorded to WORM-compliant audit logs for SOC2 compliance.</span>
              </div>
            </div>
          )}

          {/* 8. COMPLIANCE & AUDIT */}
          {activeSubTab === "compliance" && (
            <div className="settings-section">
              <div className="section-title-wrap">
                <h3>📑 Compliance Standards & Automated Executive Reporting</h3>
                <p>Configure automated security audit briefs and compliance benchmarks.</p>
              </div>

              <div className="settings-form-group">
                <label>Active Compliance Frameworks to Benchmark Against</label>
                <div className="compliance-checklist">
                  {COMPLIANCE_LIST.map((comp) => {
                    const isChecked = settings.complianceFrameworks?.includes(comp.id);
                    return (
                      <div
                        key={comp.id}
                        className={`compliance-row ${isChecked ? "active" : ""}`}
                        onClick={() => handleToggleCompliance(comp.id)}
                      >
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => {}}
                          style={{ marginRight: "10px", cursor: "pointer" }}
                        />
                        <div style={{ flex: 1 }}>
                          <strong>{comp.name}</strong>
                          <span style={{ display: "block", fontSize: "10px", color: "#94a3b8" }}>{comp.desc}</span>
                        </div>
                        <span className={`pill-badge ${isChecked ? "green" : "gray"}`}>
                          {isChecked ? "Enforcing" : "Disabled"}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="settings-toggle-group">
                <div className="toggle-item">
                  <div className="toggle-label">
                    <strong>Auto-Compile Weekly Executive Brief (Every Monday 08:00 AM)</strong>
                    <span>Generates a high-level PDF score for the board of directors summarizing prevented attacks and remediation SLA.</span>
                  </div>
                  <label className="switch">
                    <input
                      type="checkbox"
                      checked={settings.autoWeeklyReport}
                      onChange={(e) => handleChange("autoWeeklyReport", e.target.checked)}
                    />
                    <span className="slider round"></span>
                  </label>
                </div>
              </div>

              <div className="settings-form-group" style={{ marginTop: "14px" }}>
                <label>Telemetry & Raw Packet Log Retention</label>
                <select
                  value={settings.retentionDays}
                  onChange={(e) => handleChange("retentionDays", e.target.value)}
                >
                  <option value="30">30 Days (Standard Enterprise)</option>
                  <option value="90">90 Days (PCI-DSS & SOC2 Requirement)</option>
                  <option value="180">180 Days (Financial Enterprise)</option>
                  <option value="365">365 Days (Government & Defense)</option>
                </select>
              </div>

              <div className="maintenance-actions-grid">
                <div className="action-card">
                  <div className="action-card-header">
                    <strong>📥 Export Full System State</strong>
                    <span>Download complete encrypted JSON backup of rules, alerts, and assets.</span>
                  </div>
                  <button
                    className="soc-btn"
                    onClick={() => {
                      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(settings, null, 2));
                      const a = document.createElement("a");
                      a.href = dataStr;
                      a.download = `cyberatlas_backup_${new Date().toISOString().slice(0, 10)}.json`;
                      a.click();
                    }}
                  >
                    💾 Download Backup
                  </button>
                </div>

                <div className="action-card">
                  <div className="action-card-header">
                    <strong>🧹 Purge Resolved Alerts</strong>
                    <span>Permanently free database space by pruning alerts marked as Resolved.</span>
                  </div>
                  <button
                    className="soc-btn"
                    onClick={() => {
                      if (window.confirm("Purge all resolved alerts from local database?")) {
                        if (onSaveToast) onSaveToast("🧹 Resolved alerts purged from cache.");
                      }
                    }}
                  >
                    Prune Cache
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* BOTTOM SAVE / CANCEL BAR */}
          <div className="settings-footer-actions">
            <button
              type="button"
              className="soc-btn"
              onClick={handleReset}
              style={{ color: "#94a3b8" }}
            >
              🔄 Reset Defaults
            </button>

            <button
              type="button"
              className="soc-btn primary-cyan"
              onClick={handleSave}
              disabled={saving}
              style={{ minWidth: "160px" }}
            >
              {saving ? "⏳ Saving..." : "💾 Save All Configuration"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
