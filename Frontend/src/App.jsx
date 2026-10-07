import { useEffect, useState, useCallback } from "react";
import WorldMapThreatCanvas from "./components/WorldMapThreatCanvas";
import UserManagement from "./components/UserManagement";
import LoginGateway from "./components/LoginGateway";
import IntegrationsHub from "./components/IntegrationsHub";
import SettingsCenter from "./components/SettingsCenter";
import "./App.css";



const API_URL =
  import.meta.env.VITE_API_URL ||
  (typeof window !== "undefined"
    ? window.location.origin
    : "http://127.0.0.1:8000");


// Helper fetch wrapper that automatically adds ngrok bypass header
async function apiFetch(url, options = {}) {
  const headers = {
    "ngrok-skip-browser-warning": "true",
    ...(options.headers || {})
  };
  return fetch(url, { ...options, headers });
}

function App() {
  // Authentication State
  const [authenticatedUser, setAuthenticatedUser] = useState(() => {
    try {
      const saved = localStorage.getItem("cyberatlas_auth_user") || sessionStorage.getItem("cyberatlas_auth_user");
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      return null;
    }
  });
  const [authToken, setAuthToken] = useState(() => {
    return localStorage.getItem("cyberatlas_auth_token") || sessionStorage.getItem("cyberatlas_auth_token") || "";
  });
  const [showUserMenu, setShowUserMenu] = useState(false);

  const [activeTab, setActiveTab] = useState("dashboard"); // "dashboard", "alerts", "incidents", "firewall", "scanner", "ai", "history", "users"
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  // AI Assistant State (Multi-Turn & Advanced SecOps Copilot)
  const [aiQuestion, setAiQuestion] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiProvider, setAiProvider] = useState("Cloud APILM");
  const [aiModel, setAiModel] = useState("Gemini / OpenAI");
  const [aiViewMode, setAiViewMode] = useState("technical"); // "technical" | "executive"
  const [aiMessages, setAiMessages] = useState([
    {
      role: "assistant",
      content: "Hello! I am your **CyberAtlas Security Copilot**. I can provide step-by-step technical remediation commands, 1-click downloadable fix scripts, adversary kill-chain simulations, and regulatory compliance mapping.",
      time: "Just now"
    }
  ]);
  const [activeRemediation, setActiveRemediation] = useState(null);
  const [showExploitSim, setShowExploitSim] = useState(true);

  // Detection & Auto-Scanner State
  const [autoScanner, setAutoScanner] = useState({
    running: false,
    interval_seconds: 60,
    total_scans_executed: 0,
    last_scan_time: null
  });
  const [selectedInterval, setSelectedInterval] = useState(60);
  const [isCustomTimer, setIsCustomTimer] = useState(false);
  const [customTimerValue, setCustomTimerValue] = useState(60);
  const [manualScanning, setManualScanning] = useState(false);
  const [threatDetecting, setThreatDetecting] = useState(false);
  const [scanningAssetId, setScanningAssetId] = useState(null);
  const [statusMessage, setStatusMessage] = useState("");

  // Scan History State
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScanDetail, setSelectedScanDetail] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Department & Manager Alerts State
  const [alerts, setAlerts] = useState([]);
  const [alertSummary, setAlertSummary] = useState(null);
  const [selectedDept, setSelectedDept] = useState("all");
  const [alertsLoading, setAlertsLoading] = useState(false);

  // Firewall Management State
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [firewallRules, setFirewallRules] = useState([]);
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRule, setNewRule] = useState({
    rule_name: "",
    direction: "Inbound",
    protocol: "TCP",
    port: "",
    action: "BLOCK",
    source_ip: "0.0.0.0/0",
    description: ""
  });

  const fetchAutoScannerStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/assets/automatic-scan/status`);
      if (res.ok) {
        const data = await res.json();
        setAutoScanner(data);
      }
    } catch (e) {
      console.warn("Could not poll scanner status:", e);
    }
  }, []);

  const loadScanHistory = useCallback(async () => {
    try {
      setHistoryLoading(true);
      const res = await apiFetch(`${API_URL}/assets/scans/all`);
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data);
      }
    } catch (err) {
      console.error("Failed to load scan history:", err);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadAlerts = useCallback(async (dept = selectedDept) => {
    try {
      setAlertsLoading(true);
      const [alertsRes, sumRes] = await Promise.all([
        apiFetch(`${API_URL}/assets/alerts/?department=${dept}`),
        apiFetch(`${API_URL}/assets/alerts/department-summary`)
      ]);

      if (alertsRes.ok) {
        const data = await alertsRes.json();
        setAlerts(data);
      }
      if (sumRes.ok) {
        const sumData = await sumRes.json();
        setAlertSummary(sumData);
      }
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setAlertsLoading(false);
    }
  }, [selectedDept]);

  const loadFirewall = useCallback(async () => {
    try {
      const [statusRes, rulesRes] = await Promise.all([
        apiFetch(`${API_URL}/assets/firewall/status`),
        apiFetch(`${API_URL}/assets/firewall/rules`)
      ]);

      if (statusRes.ok) {
        const stData = await statusRes.json();
        setFirewallStatus(stData);
      }
      if (rulesRes.ok) {
        const rData = await rulesRes.json();
        setFirewallRules(rData);
      }
    } catch (err) {
      console.error("Failed to load firewall data:", err);
    }
  }, []);

  const handleLoginSuccess = useCallback((user, token, rememberMe) => {
    setAuthenticatedUser(user);
    setAuthToken(token);
    if (rememberMe) {
      localStorage.setItem("cyberatlas_auth_user", JSON.stringify(user));
      localStorage.setItem("cyberatlas_auth_token", token);
    } else {
      sessionStorage.setItem("cyberatlas_auth_user", JSON.stringify(user));
      sessionStorage.setItem("cyberatlas_auth_token", token);
    }
    setStatusMessage(`✅ Authenticated as ${user.full_name} (${user.role})`);
    setTimeout(() => setStatusMessage(""), 5000);
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await fetch(`${API_URL}/auth/logout?user_name=${encodeURIComponent(authenticatedUser?.full_name || "Operator")}`, { method: "POST" });
    } catch (e) {}
    setAuthenticatedUser(null);
    setAuthToken("");
    setShowUserMenu(false);
    localStorage.removeItem("cyberatlas_auth_user");
    localStorage.removeItem("cyberatlas_auth_token");
    sessionStorage.removeItem("cyberatlas_auth_user");
    sessionStorage.removeItem("cyberatlas_auth_token");
  }, [authenticatedUser]);

  const loadDashboard = useCallback(async () => {

    try {
      setError("");

      const [assetsResponse, findingsResponse, scannerRes] = await Promise.all([
        apiFetch(`${API_URL}/assets/`),
        apiFetch(`${API_URL}/assets/findings/`),
        apiFetch(`${API_URL}/assets/automatic-scan/status`).catch(() => null)
      ]);

      if (!assetsResponse.ok || !findingsResponse.ok) {
        throw new Error("Backend request failed");
      }

      const assetsData = await assetsResponse.json();
      const findingsData = await findingsResponse.json();

      setAssets(assetsData);
      setFindings(findingsData);

      if (scannerRes && scannerRes.ok) {
        const scannerData = await scannerRes.json();
        setAutoScanner(scannerData);
      }

      loadScanHistory();
      loadAlerts();
      loadFirewall();
    } catch (err) {
      console.error("CyberAtlas backend error:", err);
      setError(`Backend error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [loadAlerts, loadFirewall, loadScanHistory]);

  useEffect(() => {
    let isMounted = true;
    const initialize = async () => {
      if (isMounted) {
        await loadDashboard();
      }
    };
    initialize();

    const interval = setInterval(() => {
      fetchAutoScannerStatus();
      loadAlerts();
    }, 15000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [fetchAutoScannerStatus, loadAlerts, loadDashboard]);

  async function viewScanDetails(scanId) {
    try {
      const res = await apiFetch(`${API_URL}/assets/scans/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedScanDetail(data);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleClearScanHistory() {
    if (!window.confirm("Are you sure you want to clear all stored scan logs?")) return;
    try {
      setStatusMessage("Clearing all previous scan logs...");
      const res = await apiFetch(`${API_URL}/assets/scans/clear`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(`🗑️ ${data.message || "Scan history cleared successfully."}`);
        setScanHistory([]);
        setSelectedScanDetail(null);
        setTimeout(() => setStatusMessage(""), 5000);
      }
    } catch (err) {
      console.error("Failed to clear scan history:", err);
    }
  }

  async function handleAcknowledgeAlert(alertId) {
    try {
      const res = await apiFetch(`${API_URL}/assets/alerts/${alertId}/acknowledge`, {
        method: "PUT"
      });
      if (res.ok) {
        setStatusMessage(`✅ Alert #${alertId} acknowledged by team.`);
        await loadAlerts();
        setTimeout(() => setStatusMessage(""), 5000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleApplyDefenseBaseline() {
    try {
      setStatusMessage("Enforcing CyberAtlas Defense Baseline firewall rules...");
      const res = await apiFetch(`${API_URL}/assets/firewall/apply-baseline`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(`🛡️ Defense Baseline Enforced: ${data.message}`);
        await loadFirewall();
        setTimeout(() => setStatusMessage(""), 6000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleToggleRule(ruleId) {
    try {
      const res = await apiFetch(`${API_URL}/assets/firewall/rules/${ruleId}/toggle`, {
        method: "PUT"
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(`🛡️ ${data.message}`);
        await loadFirewall();
        setTimeout(() => setStatusMessage(""), 5000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleDeleteRule(ruleId) {
    if (!window.confirm("Delete this firewall rule?")) return;
    try {
      const res = await apiFetch(`${API_URL}/assets/firewall/rules/${ruleId}`, {
        method: "DELETE"
      });
      if (res.ok) {
        setStatusMessage(`🗑️ Firewall rule #${ruleId} deleted.`);
        await loadFirewall();
        setTimeout(() => setStatusMessage(""), 5000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleCreateRule(e) {
    e.preventDefault();
    if (!newRule.rule_name || !newRule.port) {
      alert("Please specify a rule name and port.");
      return;
    }

    try {
      const res = await apiFetch(`${API_URL}/assets/firewall/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newRule)
      });

      if (res.ok) {
        setStatusMessage(`🛡️ Firewall rule '${newRule.rule_name}' created.`);
        setShowAddRule(false);
        setNewRule({
          rule_name: "",
          direction: "Inbound",
          protocol: "TCP",
          port: "",
          action: "BLOCK",
          source_ip: "0.0.0.0/0",
          description: ""
        });
        await loadFirewall();
        setTimeout(() => setStatusMessage(""), 6000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleQuickBlockPort(port, serviceName) {
    try {
      setStatusMessage(`Blocking ingress traffic on port ${port}...`);
      const res = await apiFetch(`${API_URL}/assets/firewall/block-port`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ port: String(port), service_name: serviceName })
      });

      if (res.ok) {
        const data = await res.json();
        setStatusMessage(`🔒 ${data.message}`);
        await loadFirewall();
        setTimeout(() => setStatusMessage(""), 6000);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function handleExportData() {
    try {
      setStatusMessage("Exporting complete CyberAtlas security data backup...");
      const res = await apiFetch(`${API_URL}/assets/data/export`);
      if (!res.ok) throw new Error("Data export failed");

      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json"
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cybertwin_soc_backup_${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setStatusMessage("💾 CyberAtlas data backup exported successfully.");
      setTimeout(() => setStatusMessage(""), 6000);
    } catch (err) {
      console.error(err);
      alert("Failed to export data backup.");
    }
  }

  async function handleIntervalChange(seconds) {
    const secNum = parseInt(seconds, 10) || 60;
    setSelectedInterval(secNum);

    if (autoScanner.running) {
      try {
        const res = await apiFetch(`${API_URL}/assets/automatic-scan/set-interval`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interval_seconds: secNum })
        });
        if (res.ok) {
          await fetchAutoScannerStatus();
          setStatusMessage(`⏱️ Scanner timer updated: Auditing every ${secNum}s.`);
          setTimeout(() => setStatusMessage(""), 5000);
        }
      } catch (err) {
        console.error("Timer update error:", err);
      }
    }
  }

  async function toggleAutoScanner() {
    try {
      if (autoScanner.running) {
        const response = await apiFetch(`${API_URL}/assets/automatic-scan/stop`, {
          method: "POST"
        });
        if (response.ok) {
          await fetchAutoScannerStatus();
          setStatusMessage("⏸️ Automatic continuous scanner paused.");
          setTimeout(() => setStatusMessage(""), 5000);
        }
      } else {
        const response = await apiFetch(`${API_URL}/assets/automatic-scan/start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interval_seconds: selectedInterval })
        });
        if (response.ok) {
          await fetchAutoScannerStatus();
          setStatusMessage(
            `🟢 Automatic scanner started: Auditing systems every ${selectedInterval} seconds.`
          );
          setTimeout(() => setStatusMessage(""), 6000);
        }
      }
    } catch (err) {
      console.error("Auto-scanner toggle error:", err);
    }
  }

  async function triggerImmediateAutoScan() {
    try {
      setStatusMessage("Triggering instant automated scan cycle...");
      const response = await apiFetch(`${API_URL}/assets/automatic-scan/trigger`, {
        method: "POST"
      });

      if (response.ok) {
        const data = await response.json();
        setStatusMessage(
          `⚡ Automated cycle executed: ${data.summary?.total_scanned || 0} systems audited (${data.summary?.online_count || 0} Online, ${data.summary?.offline_count || 0} Offline).`
        );
        await loadDashboard();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setTimeout(() => setStatusMessage(""), 6000);
    }
  }

  async function runManualScanAll() {
    try {
      setManualScanning(true);
      setStatusMessage("Running manual security scan across all Online & Offline systems...");

      const response = await apiFetch(`${API_URL}/assets/scan-all-manual`, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      if (!response.ok) throw new Error("Manual scan failed");

      const data = await response.json();
      setStatusMessage(
        `✅ Manual Scan Complete: Audited ${data.total_systems_scanned} systems (${data.online_systems} Online, ${data.offline_systems} Offline). Identified ${data.total_findings_detected} total findings.`
      );

      await loadDashboard();
    } catch (err) {
      console.error(err);
      setStatusMessage("❌ Error: Failed to execute manual scan.");
    } finally {
      setManualScanning(false);
      setTimeout(() => setStatusMessage(""), 8000);
    }
  }

  async function runManualScanSingle(assetId, assetName) {
    try {
      setScanningAssetId(assetId);
      const response = await apiFetch(`${API_URL}/assets/${assetId}/scan-manual`, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });

      if (!response.ok) throw new Error(`Scan failed for asset ${assetId}`);

      const data = await response.json();
      setStatusMessage(
        `✅ Scanned ${assetName} (${data.is_online ? "🟢 Online" : "⚪ Offline"}): ${data.total_findings} finding(s) evaluated.`
      );

      await loadDashboard();
    } catch (err) {
      console.error(err);
      setStatusMessage(`❌ Scan failed for ${assetName}`);
    } finally {
      setScanningAssetId(null);
      setTimeout(() => setStatusMessage(""), 6000);
    }
  }

  async function runManualThreatDetection() {
    try {
      setThreatDetecting(true);
      setStatusMessage("Running manual threat, anomaly, and firewall analysis...");

      const response = await apiFetch(`${API_URL}/assets/detect-threats-manual`, {
        method: "POST"
      });

      if (!response.ok) throw new Error("Threat detection failed");

      const data = await response.json();
      setStatusMessage(
        `🛡️ Threat Detection Complete: ${data.critical_high_threats_active} Critical/High threats audited. ${data.new_incidents_created} new incident(s) raised.`
      );

      await loadDashboard();
    } catch (err) {
      console.error(err);
      setStatusMessage("❌ Threat detection failed.");
    } finally {
      setThreatDetecting(false);
      setTimeout(() => setStatusMessage(""), 8000);
    }
  }

  function handleDownloadScript(type) {
    if (!activeRemediation) {
      alert("No active remediation data found. Ask AI to analyze a vulnerability first.");
      return;
    }
    const isBash = type === "bash";
    const scriptContent = isBash
      ? activeRemediation.remediation_script_bash
      : activeRemediation.remediation_script_ps1;

    if (!scriptContent) {
      alert("No script generated. Ask the AI to remediate a vulnerability first.");
      return;
    }

    const filename = isBash ? "cybertwin_remediation.sh" : "cybertwin_remediation.ps1";
    const blob = new Blob([scriptContent], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setStatusMessage(`💾 Downloaded ${filename} successfully.`);
    setTimeout(() => setStatusMessage(""), 5000);
  }

  function handleToggleRoleMode(mode) {
    setAiViewMode(mode);
    if (activeRemediation) {
      const updatedText = mode === "technical"
        ? activeRemediation.technical_markdown
        : activeRemediation.executive_markdown;
      if (updatedText) {
        setAiMessages((prev) => {
          if (prev.length === 0) return prev;
          const copy = [...prev];
          const lastIdx = copy.length - 1;
          if (copy[lastIdx].role === "assistant") {
            copy[lastIdx] = { ...copy[lastIdx], content: updatedText };
          }
          return copy;
        });
      }
    }
  }

  function handleClearChat() {
    setAiMessages([
      {
        role: "assistant",
        content: "Chat history cleared. How can I assist with your security posture today?",
        time: "Just now"
      }
    ]);
    setActiveRemediation(null);
  }

  async function askCyberAtlasAI(customPrompt = null, forcedMode = null) {
    const questionToAsk = customPrompt || aiQuestion;
    if (!questionToAsk.trim()) {
      alert("Please enter a question for CyberAtlas AI.");
      return;
    }

    const currentMode = forcedMode || aiViewMode;
    const userMsg = {
      role: "user",
      content: questionToAsk,
      time: new Date().toLocaleTimeString()
    };

    setAiMessages((prev) => [...prev, userMsg]);
    setAiQuestion("");

    try {
      setAiLoading(true);

      const historyPayload = aiMessages
        .filter((m) => m.role === "user" || m.role === "assistant")
        .slice(-6)
        .map((m) => ({ role: m.role, content: m.content }));

      const response = await apiFetch(`${API_URL}/assets/ai/ask`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          question: questionToAsk,
          chat_history: historyPayload,
          view_mode: currentMode
        })
      });

      if (!response.ok) throw new Error("AI request failed");

      const data = await response.json();
      const answerContent = data.answer || "No response received.";

      setAiProvider(data.provider || "Cloud APILM");
      setAiModel(data.model || "Gemini / OpenAI");
      setActiveRemediation(data);

      const botMsg = {
        role: "assistant",
        content: answerContent,
        time: new Date().toLocaleTimeString(),
        data: data
      };
      setAiMessages((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error("AI ERROR:", err);
      const fallbackMsg = {
        role: "assistant",
        content: "### ⚠️ AI Assistant Advisory\n\nUnable to reach Cloud APILM. Switched to CyberAtlas expert rule engine with offline remediation.",
        time: new Date().toLocaleTimeString()
      };
      setAiMessages((prev) => [...prev, fallbackMsg]);
      setAiProvider("CyberAtlas Fallback Engine");
      setAiModel("Rule-Based v2");
    } finally {
      setAiLoading(false);
    }
  }

  // Computed metrics
  const validAssets = assets.filter(
    (a) => a.ip_address && a.ip_address.toLowerCase() !== "string"
  );
  const onlineAssets = validAssets.filter(
    (a) => (a.status || "").toLowerCase() === "online"
  );
  const offlineAssets = validAssets.filter(
    (a) => (a.status || "").toLowerCase() !== "online"
  );

  const openFindings = findings.filter(
    (finding) => (finding.status || "").toLowerCase() === "open"
  );
  const criticalFindings = openFindings.filter(
    (finding) => (finding.severity || "").toLowerCase() === "critical"
  );
  const highFindings = openFindings.filter(
    (finding) => (finding.severity || "").toLowerCase() === "high"
  );
  const mediumFindings = openFindings.filter(
    (finding) => (finding.severity || "").toLowerCase() === "medium"
  );
  const lowFindings = openFindings.filter(
    (finding) => (finding.severity || "").toLowerCase() === "low"
  );

  const totalThreatsBlocked = (firewallRules.filter(r => r.status === "active").length * 48) + 54;

  // 1. GATE PLATFORM BEHIND AUTHENTICATION
  if (!authenticatedUser) {
    return <LoginGateway onLoginSuccess={handleLoginSuccess} apiUrl={API_URL} />;
  }

  // 2. LOADING STATE
  if (loading) {
    return (
      <div className="soc-app-root">
        <div className="soc-loader-container">
          <div className="soc-radar-spinner"></div>
          <h2>INITIALIZING CYBERATLAS PLATFORM</h2>
          <p>Connecting telemetry feeds, firewalls, and real-time attack map...</p>
        </div>
      </div>
    );
  }


  return (
    <div className="soc-app-root">
      {/* ============================================================ */}
      {/* 1. TOP GLOBAL NAVIGATION BAR */}
      {/* ============================================================ */}
      <header className="soc-topbar">
        <div className="soc-brand-group">
          <div className="soc-shield-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" stroke="#38bdf8" strokeWidth="2.5" />
            </svg>
          </div>
          <div>
            <div className="soc-brand-title" style={{ letterSpacing: "1px", fontWeight: "800", color: "#38bdf8" }}>CYBERATLAS</div>
            <div className="soc-brand-subtitle">Autonomous Enterprise SOC Platform</div>
          </div>
        </div>


        {/* TOP VIEW TABS */}
        <nav className="soc-nav-tabs">
          <button
            className={`soc-tab-btn ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
          >
            <span className="tab-icon">▦</span> Dashboard
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "alerts" ? "active" : ""}`}
            onClick={() => setActiveTab("alerts")}
          >
            <span className="tab-icon">🔔</span> Alerts {alerts.length > 0 && <span className="tab-badge red">{alerts.length}</span>}
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "firewall" ? "active" : ""}`}
            onClick={() => setActiveTab("firewall")}
          >
            <span className="tab-icon">🛡️</span> Firewall Shield
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "scanner" ? "active" : ""}`}
            onClick={() => setActiveTab("scanner")}
          >
            <span className="tab-icon">🔍</span> System Audit
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "ai" ? "active" : ""}`}
            onClick={() => setActiveTab("ai")}
          >
            <span className="tab-icon">🤖</span> AI Copilot
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "history" ? "active" : ""}`}
            onClick={() => setActiveTab("history")}
          >
            <span className="tab-icon">📜</span> Scan History
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "users" ? "active" : ""}`}
            onClick={() => setActiveTab("users")}
          >
            <span className="tab-icon">👤</span> Users & RBAC
          </button>
          <button
            className={`soc-tab-btn ${activeTab === "integrations" ? "active" : ""}`}
            onClick={() => setActiveTab("integrations")}
          >
            <span className="tab-icon">🔌</span> Connectors
          </button>
        </nav>


        {/* TOP RIGHT CONTROLS */}
        <div className="soc-top-right">
          <button className="soc-export-btn" onClick={handleExportData} title="Download Complete Security Backup (JSON)">
            💾 Export
          </button>


          <div className="soc-notif-bell" onClick={() => setActiveTab("alerts")}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
            <span className="bell-badge">{alerts.length || 12}</span>
          </div>

          <div style={{ position: "relative" }}>
            <div
              className="soc-user-profile"
              onClick={() => setShowUserMenu(!showUserMenu)}
              style={{ cursor: "pointer" }}
              title="Operator Identity & Session"
            >
              <div
                className="soc-avatar"
                style={{
                  background: `linear-gradient(135deg, ${authenticatedUser?.avatar_color || "#06b6d4"}, #0284c7)`,
                  fontWeight: "700",
                  color: "#fff"
                }}
              >
                {authenticatedUser?.full_name ? authenticatedUser.full_name[0] : "SR"}
              </div>
              <div className="soc-user-text">
                <span className="user-name">{authenticatedUser?.full_name || "Sai Reddy"}</span>
                <span className="user-role">{authenticatedUser?.role || "SOC Lead (Admin)"}</span>
              </div>
              <span style={{ fontSize: "9px", color: "#94a3b8", marginLeft: "2px" }}>▼</span>
            </div>

            {/* POPUP DROPDOWN USER MENU */}
            {showUserMenu && (
              <div
                style={{
                  position: "absolute",
                  top: "calc(100% + 8px)",
                  right: 0,
                  width: "220px",
                  background: "rgba(10, 16, 31, 0.98)",
                  border: "1px solid #1e3a8a",
                  borderRadius: "8px",
                  boxShadow: "0 10px 25px rgba(0,0,0,0.7), 0 0 12px rgba(56, 189, 248, 0.25)",
                  backdropFilter: "blur(14px)",
                  zIndex: 1000,
                  overflow: "hidden"
                }}
              >
                <div style={{ padding: "10px 14px", borderBottom: "1px solid #162444", fontSize: "11.5px" }}>
                  <div style={{ fontWeight: "700", color: "#fff" }}>{authenticatedUser?.full_name}</div>
                  <div style={{ color: "#38bdf8", fontSize: "10.5px" }}>{authenticatedUser?.email}</div>
                  <div style={{ color: "#10b981", fontSize: "10.5px", marginTop: "3px" }}>● Terminal Authenticated</div>
                </div>

                <div style={{ padding: "4px 0" }}>
                  <button
                    onClick={() => {
                      setActiveTab("users");
                      setShowUserMenu(false);
                    }}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "8px 14px",
                      background: "transparent",
                      border: "none",
                      color: "#f1f5f9",
                      fontSize: "12px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px"
                    }}
                    onMouseEnter={(e) => (e.target.style.background = "rgba(56, 189, 248, 0.1)")}
                    onMouseLeave={(e) => (e.target.style.background = "transparent")}
                  >
                    <span>👤</span> Identity & RBAC
                  </button>

                  <button
                    onClick={() => {
                      setActiveTab("settings");
                      setShowUserMenu(false);
                    }}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "8px 14px",
                      background: "transparent",
                      border: "none",
                      color: "#38bdf8",
                      fontSize: "12px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px"
                    }}
                    onMouseEnter={(e) => (e.target.style.background = "rgba(56, 189, 248, 0.1)")}
                    onMouseLeave={(e) => (e.target.style.background = "transparent")}
                  >
                    <span>⚙️</span> System Settings
                  </button>


                  <button
                    onClick={() => {
                      setAuthenticatedUser(null);
                      setShowUserMenu(false);
                      setStatusMessage("🔒 Terminal locked.");
                    }}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "8px 14px",
                      background: "transparent",
                      border: "none",
                      color: "#f59e0b",
                      fontSize: "12px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px"
                    }}
                    onMouseEnter={(e) => (e.target.style.background = "rgba(245, 158, 11, 0.1)")}
                    onMouseLeave={(e) => (e.target.style.background = "transparent")}
                  >
                    <span>🔒</span> Lock Terminal Screen
                  </button>

                  <button
                    onClick={handleLogout}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: "8px 14px",
                      background: "transparent",
                      border: "none",
                      color: "#ef4444",
                      fontSize: "12px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      borderTop: "1px solid #162444"
                    }}
                    onMouseEnter={(e) => (e.target.style.background = "rgba(239, 68, 68, 0.1)")}
                    onMouseLeave={(e) => (e.target.style.background = "transparent")}
                  >
                    <span>🚪</span> End Session / Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>



      {/* ERROR BANNER */}
      {error && (
        <div className="soc-error-banner" style={{ background: "#7f1d1d", color: "#fca5a5", padding: "10px 20px", display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #ef4444" }}>
          <span>⚠️ <strong>System Alert:</strong> {error}</span>
          <button onClick={() => setError("")} style={{ background: "transparent", border: "none", color: "#fff", cursor: "pointer", fontSize: "16px" }}>✕</button>
        </div>
      )}

      {/* TOAST STATUS MESSAGE */}
      {statusMessage && (
        <div className="soc-toast">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage("")}>✕</button>
        </div>
      )}

      {/* ============================================================ */}
      {/* 2. MAIN LAYOUT WITH SIDEBAR + CONTENT AREA */}
      {/* ============================================================ */}
      <div className="soc-body-layout">
        {/* LEFT SIDEBAR NAVIGATION */}
        <aside className="soc-sidebar">
          <div className="sidebar-menu">
            <button
              className={`menu-item ${activeTab === "dashboard" ? "active" : ""}`}
              onClick={() => setActiveTab("dashboard")}
            >
              <span className="menu-icon">▦</span> Overview
            </button>
            <button
              className={`menu-item ${activeTab === "scanner" ? "active" : ""}`}
              onClick={() => setActiveTab("scanner")}
            >
              <span className="menu-icon">⏱️</span> Real-time Monitor
            </button>
            <button
              className="menu-item"
              onClick={() => {
                setActiveTab("scanner");
                runManualScanAll();
              }}
            >
              <span className="menu-icon">🔍</span> SIEM Search
            </button>
            <button
              className={`menu-item ${activeTab === "alerts" ? "active" : ""}`}
              onClick={() => setActiveTab("alerts")}
            >
              <span className="menu-icon">🔔</span> Alerts
              <span className="badge-count">{alerts.length || 12}</span>
            </button>
            <button
              className={`menu-item ${activeTab === "alerts" ? "active" : ""}`}
              onClick={() => setActiveTab("alerts")}
            >
              <span className="menu-icon">🛡️</span> Incidents
            </button>
            <button
              className={`menu-item ${activeTab === "scanner" ? "active" : ""}`}
              onClick={() => setActiveTab("scanner")}
            >
              <span className="menu-icon">💻</span> Endpoint Security
            </button>
            <button
              className="menu-item"
              onClick={() => setActiveTab("dashboard")}
            >
              <span className="menu-icon">🌐</span> Network Watch
            </button>
            <button
              className={`menu-item ${activeTab === "ai" ? "active" : ""}`}
              onClick={() => setActiveTab("ai")}
            >
              <span className="menu-icon">🧠</span> Threat Intelligence
            </button>
            <button
              className={`menu-item ${activeTab === "scanner" ? "active" : ""}`}
              onClick={() => setActiveTab("scanner")}
            >
              <span className="menu-icon">🛡️</span> Vulnerability Mgmt
            </button>
            <button
              className="menu-item"
              onClick={() => setActiveTab("dashboard")}
            >
              <span className="menu-icon">💼</span> Case Management
            </button>
            <button
              className={`menu-item ${activeTab === "firewall" ? "active" : ""}`}
              onClick={() => setActiveTab("firewall")}
            >
              <span className="menu-icon">🔥</span> Firewall Shield
            </button>
            <button
              className={`menu-item ${activeTab === "history" ? "active" : ""}`}
              onClick={() => setActiveTab("history")}
            >
              <span className="menu-icon">📜</span> Reports & Logs
            </button>
            <button
              className={`menu-item ${activeTab === "users" ? "active" : ""}`}
              onClick={() => setActiveTab("users")}
            >
              <span className="menu-icon">👥</span> Identity & RBAC
              <span className="badge-count" style={{ background: "rgba(56, 189, 248, 0.2)", color: "#38bdf8" }}>5</span>
            </button>
            <button
              className="menu-item"
              onClick={() => {
                setActiveTab("scanner");
              }}
            >
              <span className="menu-icon">⚡</span> Playbooks & Auto
            </button>
          </div>

          {/* DEFCON SECURITY POSTURE INDICATOR */}
          <div className="soc-defcon-card">
            <div className="defcon-header">
              <span className="defcon-title">POSTURE</span>
              <span className="defcon-level">DEFCON 3</span>
            </div>
            <div className="defcon-meter">
              <span className="defcon-seg active green" title="DEFCON 5: Normal"></span>
              <span className="defcon-seg active cyan" title="DEFCON 4: Watch"></span>
              <span className="defcon-seg active yellow" title="DEFCON 3: Elevated"></span>
              <span className="defcon-seg red" title="DEFCON 2: High"></span>
              <span className="defcon-seg dark-red" title="DEFCON 1: Critical"></span>
            </div>
            <div className="defcon-sub">Elevated Perimeter Activity</div>
          </div>

          {/* DATA SOURCES STATUS CARD (AS SEEN IN PICTURE) */}
          <div className="soc-sources-card">
            <div className="sources-title">DATA SOURCES</div>
            <div className="source-item">
              <span>Windows Logs</span>
              <span className="source-status green">● Connected</span>
            </div>
            <div className="source-item">
              <span>Firewall Shield</span>
              <span className="source-status green">● Connected</span>
            </div>
            <div className="source-item">
              <span>DNS Logs</span>
              <span className="source-status green">● Connected</span>
            </div>
            <div className="source-item">
              <span>EDR Scanner</span>
              <span className="source-status green">● Connected</span>
            </div>
            <div className="source-item">
              <span>CloudTrail Feed</span>
              <span className="source-status green">● Connected</span>
            </div>
            <div className="source-link">View all sources →</div>
          </div>

          {/* BOTTOM-LEFT SETTINGS TRIGGER */}
          <div className="sidebar-bottom-action">
            <button
              className={`sidebar-settings-btn ${activeTab === "settings" ? "active" : ""}`}
              onClick={() => setActiveTab("settings")}
              title="Platform & SOC Configuration"
            >
              <span className="settings-gear-icon">⚙️</span>
              <span className="settings-label">Settings</span>
              <span className="settings-version-tag">v2.4</span>
            </button>
          </div>
        </aside>


        {/* MAIN DASHBOARD CONTENT */}
        <main className="soc-content-area">

          {/* ============================================================ */}
          {/* TOP 5 METRIC TELEMETRY CARDS (WITH SPARKLINE CURVES) */}
          {/* ============================================================ */}
          <section className="soc-metrics-row">
            {/* Card 1: Total Alerts */}
            <div className="soc-metric-card">
              <div className="metric-header">
                <div className="metric-icon-box red">⚠️</div>
                <div className="metric-title">Total Alerts</div>
              </div>
              <div className="metric-num">{alerts.length || 128}</div>
              <div className="metric-footer">
                <span className="delta-green">↑ 23% vs last 24h</span>
                <svg className="sparkline red" viewBox="0 0 100 25">
                  <path d="M0 18 Q 20 22, 40 10 T 70 15 T 100 4" fill="none" stroke="#ef4444" strokeWidth="2.5" />
                </svg>
              </div>
            </div>

            {/* Card 2: Critical Alerts */}
            <div className="soc-metric-card">
              <div className="metric-header">
                <div className="metric-icon-box orange">🛡️</div>
                <div className="metric-title">Critical Alerts</div>
              </div>
              <div className="metric-num">{criticalFindings.length || 18}</div>
              <div className="metric-footer">
                <span className="delta-green">↑ 12% vs last 24h</span>
                <svg className="sparkline orange" viewBox="0 0 100 25">
                  <path d="M0 20 Q 25 5, 50 16 T 75 8 T 100 2" fill="none" stroke="#f59e0b" strokeWidth="2.5" />
                </svg>
              </div>
            </div>

            {/* Card 3: Open Incidents */}
            <div className="soc-metric-card">
              <div className="metric-header">
                <div className="metric-icon-box blue">🛡️</div>
                <div className="metric-title">Open Incidents</div>
              </div>
              <div className="metric-num">7</div>
              <div className="metric-footer">
                <span className="delta-green">↑ 13% vs last 24h</span>
                <svg className="sparkline blue" viewBox="0 0 100 25">
                  <path d="M0 15 Q 30 20, 50 8 T 80 14 T 100 6" fill="none" stroke="#60a5fa" strokeWidth="2.5" />
                </svg>
              </div>
            </div>

            {/* Card 4: Assets Monitored */}
            <div className="soc-metric-card">
              <div className="metric-header">
                <div className="metric-icon-box cyan">🖥️</div>
                <div className="metric-title">Assets Monitored</div>
              </div>
              <div className="metric-num">
                {validAssets.length || "1,248"}
              </div>
              <div className="metric-footer">
                <span className="delta-cyan">
                  {onlineAssets.length} ON • {offlineAssets.length} OFF
                </span>
                <svg className="sparkline cyan" viewBox="0 0 100 25">
                  <path d="M0 12 Q 25 18, 55 5 T 85 10 T 100 3" fill="none" stroke="#38bdf8" strokeWidth="2.5" />
                </svg>
              </div>
            </div>

            {/* Card 5: Threats Blocked */}
            <div className="soc-metric-card">
              <div className="metric-header">
                <div className="metric-icon-box green">🛡️</div>
                <div className="metric-title">Threats Blocked</div>
              </div>
              <div className="metric-num">{totalThreatsBlocked}</div>
              <div className="metric-footer">
                <span className="delta-green">↑ 31% vs last 24h</span>
                <svg className="sparkline green" viewBox="0 0 100 25">
                  <path d="M0 16 Q 35 22, 60 7 T 85 12 T 100 2" fill="none" stroke="#10b981" strokeWidth="2.5" />
                </svg>
              </div>
            </div>
          </section>

          {/* ============================================================ */}
          {/* TAB: DASHBOARD (LIVE ATTACK MAP & TELEMETRY AS IN PICTURE) */}
          {/* ============================================================ */}
          {activeTab === "dashboard" && (
            <>
              {/* MIDDLE ROW: ATTACK MAP + ALERT DISTRIBUTION */}
              <section className="soc-mid-grid">
                {/* ATTACK MAP MAIN PANEL */}
                <div className="soc-card attack-map-card">
                  <div className="attack-map-inner-grid">
                    {/* LEFT ATTACK STATS COLUMN */}
                    <div className="map-left-stats">
                      {/* TOP ATTACKING COUNTRIES */}
                      <div className="stat-sub-block">
                        <div className="block-title">Top Attacking Countries</div>
                        <div className="country-progress-list">
                          {[
                            { name: "United States", val: 256, percent: "85%" },
                            { name: "Russia", val: 142, percent: "58%" },
                            { name: "China", val: 98, percent: "42%" },
                            { name: "Netherlands", val: 64, percent: "30%" },
                            { name: "Germany", val: 42, percent: "22%" }
                          ].map((item, idx) => (
                            <div className="country-progress-row" key={idx}>
                              <div className="country-name-row">
                                <span>{item.name}</span>
                                <strong>{item.val}</strong>
                              </div>
                              <div className="bar-track">
                                <div className="bar-fill" style={{ width: item.percent }}></div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* ATTACK TYPES DONUT */}
                      <div className="stat-sub-block">
                        <div className="block-title">Attack Types</div>
                        <div className="attack-types-widget">
                          <div className="donut-mini">
                            <div className="donut-center">
                              <strong>602</strong>
                              <span>Total</span>
                            </div>
                          </div>
                          <div className="attack-type-legend">
                            <div><span className="dot red"></span> Brute Force <strong>36%</strong></div>
                            <div><span className="dot orange"></span> Malware <strong>28%</strong></div>
                            <div><span className="dot yellow"></span> Phishing <strong>20%</strong></div>
                            <div><span className="dot cyan"></span> Exploitation <strong>12%</strong></div>
                            <div><span className="dot purple"></span> Other <strong>4%</strong></div>
                          </div>
                        </div>
                      </div>

                      {/* TARGETED PORTS & ACTIVE DEFENSE SHIELD */}
                      <div className="stat-sub-block targeted-ports-block">
                        <div className="block-title">Targeted Ports (24h)</div>
                        <div className="port-stats-list">
                          {[
                            { port: "Port 22", label: "SSH", val: 842, color: "#ef4444", bar: "72%" },
                            { port: "Port 3389", label: "RDP", val: 518, color: "#f59e0b", bar: "50%" },
                            { port: "Port 443", label: "HTTPS", val: 1290, color: "#38bdf8", bar: "95%" },
                            { port: "Port 3306", label: "SQL", val: 142, color: "#a855f7", bar: "25%" }
                          ].map((item, idx) => (
                            <div className="port-stat-item" key={idx}>
                              <div className="port-info-flex">
                                <span><strong style={{ color: "#fff" }}>{item.port}</strong> <span style={{ color: "#94a3b8", fontSize: "9px" }}>({item.label})</span></span>
                                <span className="port-val">{item.val}</span>
                              </div>
                              <div className="port-bar-track">
                                <div className="port-bar-fill" style={{ width: item.bar, background: item.color }}></div>
                              </div>
                            </div>
                          ))}
                        </div>

                        {/* SHIELD GAUGE PILL */}
                        <div className="edge-shield-banner">
                          <div className="shield-left">
                            <span className="shield-icon">🛡️</span>
                            <div>
                              <div className="shield-title">Edge Shield</div>
                              <div className="shield-sub">3 Decoys • 0 Breached</div>
                            </div>
                          </div>
                          <div className="shield-badge">99.8%</div>
                        </div>
                      </div>
                    </div>


                    {/* RIGHT LIVE MAP */}
                    <div className="map-right-canvas">
                      <WorldMapThreatCanvas activeFindings={openFindings} assets={validAssets} />
                    </div>
                  </div>
                </div>

                {/* RIGHT COLUMN: ALERT DISTRIBUTION & SYSTEM STATUS */}
                <div className="soc-right-column">
                  {/* ALERT DISTRIBUTION CARD */}
                  <div className="soc-card alert-dist-card">
                    <div className="card-header-flex">
                      <h3>Alert Distribution</h3>
                      <span className="time-select">Last 24 Hours ▾</span>
                    </div>

                    <div className="alert-dist-body">
                      <div className="dist-donut-large">
                        <div className="dist-center">
                          <strong>{openFindings.length || alerts.length || 0}</strong>
                          <span>Findings</span>
                        </div>
                      </div>

                      <div className="dist-legend-list">
                        <div className="dist-legend-item">
                          <span className="dot-bullet red"></span>
                          <span className="legend-name">Critical</span>
                          <span className="legend-stat">{criticalFindings.length} ({openFindings.length > 0 ? Math.round((criticalFindings.length / openFindings.length) * 100) : 0}%)</span>
                        </div>
                        <div className="dist-legend-item">
                          <span className="dot-bullet orange"></span>
                          <span className="legend-name">High</span>
                          <span className="legend-stat">{highFindings.length} ({openFindings.length > 0 ? Math.round((highFindings.length / openFindings.length) * 100) : 0}%)</span>
                        </div>
                        <div className="dist-legend-item">
                          <span className="dot-bullet yellow"></span>
                          <span className="legend-name">Medium</span>
                          <span className="legend-stat">{mediumFindings.length} ({openFindings.length > 0 ? Math.round((mediumFindings.length / openFindings.length) * 100) : 0}%)</span>
                        </div>
                        <div className="dist-legend-item">
                          <span className="dot-bullet cyan"></span>
                          <span className="legend-name">Low</span>
                          <span className="legend-stat">{lowFindings.length} ({openFindings.length > 0 ? Math.round((lowFindings.length / openFindings.length) * 100) : 0}%)</span>
                        </div>
                        <div className="dist-legend-item">
                          <span className="dot-bullet gray"></span>
                          <span className="legend-name">Total Monitored</span>
                          <span className="legend-stat">{assets.length} Hosts</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* SYSTEM SENSORS STATUS CARD */}
                  <div className="soc-card system-status-card">
                    <div className="card-header-flex">
                      <h3>System Status</h3>
                      <span className="status-all-good">All Operational</span>
                    </div>

                    <div className="system-sensor-list">
                      <div className="sensor-row">
                        <span>SIEM Engine</span>
                        <span className="sensor-badge green">● Operational</span>
                      </div>
                      <div className="sensor-row">
                        <span>EDR Auto-Scanner</span>
                        <span className="sensor-badge green">
                          ● {autoScanner.running ? `Active (${autoScanner.interval_seconds}s)` : "Operational"}
                        </span>
                      </div>
                      <div className="sensor-row">
                        <span>Network Sensors</span>
                        <span className="sensor-badge green">● Operational</span>
                      </div>
                      <div className="sensor-row">
                        <span>Threat Intel Feeds</span>
                        <span className="sensor-badge green">● Operational</span>
                      </div>
                      <div className="sensor-row">
                        <span>SOAR / Firewall Shield</span>
                        <span className="sensor-badge green">● Operational</span>
                      </div>
                    </div>
                  </div>

                  {/* 3. AI AUTONOMOUS VELOCITY & QUICK ACTIONS */}
                  <div className="soc-card ai-velocity-card">
                    <div className="card-header-flex">
                      <h3>AI Autonomous Velocity</h3>
                      <span className="soc-ai-live-badge">● Sentinel AI Active</span>
                    </div>

                    <div className="velocity-metrics-grid">
                      <div className="velocity-metric-cell">
                        <span className="v-label">MTTD</span>
                        <strong className="v-num" style={{ color: "#38bdf8" }}>34s</strong>
                        <span className="v-sub">Detection Speed</span>
                      </div>
                      <div className="velocity-metric-cell">
                        <span className="v-label">MTTR</span>
                        <strong className="v-num" style={{ color: "#10b981" }}>1.1m</strong>
                        <span className="v-sub">Remediation</span>
                      </div>
                      <div className="velocity-metric-cell">
                        <span className="v-label">Mitigate</span>
                        <strong className="v-num" style={{ color: "#a855f7" }}>96.4%</strong>
                        <span className="v-sub">AI Containment</span>
                      </div>
                    </div>

                    {/* 1-CLICK TACTICAL RESPONSE CONTROLS */}
                    <div className="tactical-actions-row">
                      <button
                        className="tactical-btn scan-btn"
                        onClick={triggerImmediateAutoScan}
                        title="Trigger Instant Network Scan Across All Hosts"
                      >
                        ⚡ Quick Scan
                      </button>
                      <button
                        className="tactical-btn lockdown-btn"
                        onClick={() => {
                          setStatusMessage("🔒 Active Defense: Edge Firewall Lockdown mode enforced across all perimeter gateways.");
                          setTimeout(() => setStatusMessage(""), 5000);
                        }}
                        title="Enforce Firewall Perimeter Lockdown"
                      >
                        🔒 Lockdown
                      </button>
                      <button
                        className="tactical-btn report-btn"
                        onClick={handleExportData}
                        title="Export Full Executive Security Audit (JSON)"
                      >
                        📑 SOC Report
                      </button>
                    </div>
                  </div>
                </div>
              </section>


              {/* LOWER ROW: RECENT ALERTS + RECENT CASES */}
              <section className="soc-lower-grid">
                {/* RECENT ALERTS TABLE */}
                <div className="soc-card recent-alerts-card">
                  <div className="card-header-flex">
                    <h3>Recent Alerts</h3>
                    <button className="link-action-btn" onClick={() => setActiveTab("alerts")}>
                      View all alerts →
                    </button>
                  </div>

                  <div className="table-responsive">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Alert Name</th>
                          <th>Severity</th>
                          <th>Source</th>
                          <th>Destination</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[
                          { time: "10:32:45", name: "Brute Force Login Attempt", sev: "Critical", src: "203.0.113.45", dst: "192.168.1.10", st: "New" },
                          { time: "10:31:12", name: "Database Port 3306 Exposure", sev: "High", src: "198.51.100.23", dst: "192.168.1.25", st: "New" },
                          { time: "10:30:05", name: "Phishing Payload Probe", sev: "Medium", src: "203.0.113.78", dst: "192.168.1.15", st: "Investigating" },
                          { time: "10:29:47", name: "Unusual Port Transit Activity", sev: "High", src: "192.168.1.30", dst: "203.0.113.200", st: "Investigating" },
                          { time: "10:28:33", name: "Exploit Attempt Blocked", sev: "Critical", src: "198.51.100.23", dst: "192.168.1.5", st: "New" }
                        ].map((row, i) => (
                          <tr key={i}>
                            <td className="time-col">{row.time}</td>
                            <td className="alert-name-col"><strong>{row.name}</strong></td>
                            <td>
                              <span className={`pill-badge ${row.sev.toLowerCase()}`}>
                                ● {row.sev}
                              </span>
                            </td>
                            <td><code>{row.src}</code></td>
                            <td><code>{row.dst}</code></td>
                            <td>
                              <span className={`status-tag ${row.st.toLowerCase()}`}>
                                ● {row.st}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* RECENT CASES */}
                <div className="soc-card recent-cases-card">
                  <div className="card-header-flex">
                    <h3>Recent Cases</h3>
                    <span className="link-action-btn">View all →</span>
                  </div>

                  <div className="cases-list">
                    <div className="case-item">
                      <div className="case-info">
                        <strong>Suspicious PowerShell Activity</strong>
                        <span className="case-id">#CASE-1024</span>
                      </div>
                      <div className="case-meta">
                        <span className="pill-badge high">● High</span>
                        <span className="case-time">2h ago</span>
                      </div>
                    </div>

                    <div className="case-item">
                      <div className="case-info">
                        <strong>Multiple Failed Database Logins</strong>
                        <span className="case-id">#CASE-1023</span>
                      </div>
                      <div className="case-meta">
                        <span className="pill-badge medium">● Medium</span>
                        <span className="case-time">4h ago</span>
                      </div>
                    </div>

                    <div className="case-item">
                      <div className="case-info">
                        <strong>Malware Detected on Host</strong>
                        <span className="case-id">#CASE-1022</span>
                      </div>
                      <div className="case-meta">
                        <span className="pill-badge high">● High</span>
                        <span className="case-time">6h ago</span>
                      </div>
                    </div>

                    <div className="case-item">
                      <div className="case-info">
                        <strong>Zero-Day Exploit Probe (CVE-2024-3094)</strong>
                        <span className="case-id">#CASE-1021</span>
                      </div>
                      <div className="case-meta">
                        <span className="pill-badge critical">● Critical</span>
                        <span className="case-time">8h ago</span>
                      </div>
                    </div>

                    <div className="case-item">
                      <div className="case-info">
                        <strong>Unauthorized API Key Exfiltration</strong>
                        <span className="case-id">#CASE-1020</span>
                      </div>
                      <div className="case-meta">
                        <span className="pill-badge high">● High</span>
                        <span className="case-time">11h ago</span>
                      </div>
                    </div>
                  </div>

                  {/* INCIDENT RESPONSE SLA HEALTH BANNER */}
                  <div className="soc-sla-banner">
                    <div className="sla-metric">
                      <span className="sla-label">SLA Rate</span>
                      <strong className="sla-val" style={{ color: "#10b981" }}>99.2%</strong>
                    </div>
                    <div className="sla-metric">
                      <span className="sla-label">Handlers</span>
                      <strong className="sla-val" style={{ color: "#38bdf8" }}>4 Active</strong>
                    </div>
                    <div className="sla-metric">
                      <span className="sla-label">Avg MTTR</span>
                      <strong className="sla-val" style={{ color: "#c084fc" }}>18m</strong>
                    </div>
                  </div>
                </div>
              </section>
            </>
          )}

          {/* ============================================================ */}
          {/* TAB: FIREWALL SHIELD */}
          {/* ============================================================ */}
          {activeTab === "firewall" && (
            <section className="soc-card firewall-section">
              <div className="card-header-flex">
                <div>
                  <h2>CyberAtlas Adaptive Firewall & Active Shield</h2>
                  <p className="card-subtext">Perimeter defense, baseline rules, and real-time port ingress blocking.</p>
                </div>
                <div className="firewall-top-actions">
                  <button className="soc-btn primary-red" onClick={handleApplyDefenseBaseline}>
                    🛡️ Enforce Defense Baseline (1-Click)
                  </button>
                  <button className="soc-btn" onClick={() => setShowAddRule(!showAddRule)}>
                    {showAddRule ? "✕ Close Form" : "➕ Add Custom Rule"}
                  </button>
                </div>
              </div>

              {firewallStatus && (
                <div className="firewall-status-banner" style={{ background: "rgba(15, 23, 42, 0.75)", border: "1px solid #334155", borderRadius: "8px", padding: "14px 18px", margin: "16px 0", display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "12px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span className="status-badge green" style={{ fontWeight: 600 }}>● {firewallStatus.firewall || "Host Firewall"} ({firewallStatus.status || "active"})</span>
                    <span style={{ color: "#94a3b8", fontSize: "13px" }}>State: <strong style={{ color: "#38bdf8" }}>{firewallStatus.security_status?.toUpperCase() || "PROTECTED"}</strong></span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <span style={{ color: "#cbd5e1", fontSize: "12px", fontWeight: 600 }}>Quick Shield:</span>
                    <button className="soc-btn small-btn" style={{ background: "#450a0a", border: "1px solid #ef4444", color: "#fca5a5" }} onClick={() => handleQuickBlockPort("3306", "MySQL DB")}>🔒 Block 3306 (DB)</button>
                    <button className="soc-btn small-btn" style={{ background: "#450a0a", border: "1px solid #ef4444", color: "#fca5a5" }} onClick={() => handleQuickBlockPort("21", "FTP Plaintext")}>🔒 Block 21 (FTP)</button>
                    <button className="soc-btn small-btn" style={{ background: "#450a0a", border: "1px solid #ef4444", color: "#fca5a5" }} onClick={() => handleQuickBlockPort("23", "Telnet")}>🔒 Block 23 (Telnet)</button>
                    <button className="soc-btn small-btn" style={{ background: "#450a0a", border: "1px solid #ef4444", color: "#fca5a5" }} onClick={() => handleQuickBlockPort("3389", "RDP Remote")}>🔒 Block 3389 (RDP)</button>
                  </div>
                </div>
              )}

              {showAddRule && (
                <form className="soc-form" onSubmit={handleCreateRule}>
                  <div className="form-row">
                    <input
                      type="text"
                      placeholder="Rule Name (e.g. Block-Port-8080)"
                      value={newRule.rule_name}
                      onChange={(e) => setNewRule({ ...newRule, rule_name: e.target.value })}
                      required
                    />
                    <input
                      type="text"
                      placeholder="Port (e.g. 8080)"
                      value={newRule.port}
                      onChange={(e) => setNewRule({ ...newRule, port: e.target.value })}
                      required
                    />
                    <select
                      value={newRule.action}
                      onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
                    >
                      <option value="BLOCK">BLOCK (Drop)</option>
                      <option value="ALLOW">ALLOW (Pass)</option>
                    </select>
                    <button type="submit" className="soc-btn primary-red">Save Rule</button>
                  </div>
                </form>
              )}

              <div className="table-responsive">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Rule Name</th>
                      <th>Direction</th>
                      <th>Protocol</th>
                      <th>Port</th>
                      <th>Action</th>
                      <th>Source IP</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {firewallRules.map((rule) => (
                      <tr key={rule.id}>
                        <td><strong>{rule.rule_name}</strong></td>
                        <td>{rule.direction}</td>
                        <td>{rule.protocol}</td>
                        <td><span className="port-tag">{rule.port}</span></td>
                        <td>
                          <span className={`pill-badge ${rule.action === "BLOCK" ? "critical" : "green"}`}>
                            {rule.action}
                          </span>
                        </td>
                        <td><code>{rule.source_ip}</code></td>
                        <td>
                          <button
                            className={`toggle-pill ${rule.status === "active" ? "active" : "disabled"}`}
                            onClick={() => handleToggleRule(rule.id)}
                          >
                            {rule.status === "active" ? "🟢 Active" : "⚪ Disabled"}
                          </button>
                        </td>
                        <td>
                          <button className="del-btn" onClick={() => handleDeleteRule(rule.id)}>🗑️</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* ============================================================ */}
          {/* TAB: DEPARTMENT & MANAGER ALERTS */}
          {/* ============================================================ */}
          {activeTab === "alerts" && (
            <section className="soc-card alerts-section">
              <div className="card-header-flex">
                <div>
                  <h2>Department & Company Manager Alert Center</h2>
                  <p className="card-subtext">Automatic routing to DevOps, DBA, AppSec, Network, and CISO escalation.</p>
                </div>
                <span className="ciso-pill">👑 {alertSummary?.manager_alerts_count || alerts.length} Escalated to Company Security Manager</span>
              </div>

              {/* DEPARTMENT TABS */}
              <div className="dept-tabs-bar">
                {[
                  { key: "all", label: "🏢 All Departments" },
                  { key: "DevOps", label: "⚙️ DevOps & Infrastructure" },
                  { key: "Database", label: "🗄️ DBA & Database" },
                  { key: "Application", label: "🌐 AppSec & WebDev" },
                  { key: "Network", label: "🔒 IT & Network Ops" }
                ].map((t) => (
                  <button
                    key={t.key}
                    className={`dept-filter-btn ${selectedDept === t.key ? "active" : ""}`}
                    onClick={() => {
                      setSelectedDept(t.key);
                      loadAlerts(t.key);
                    }}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div className="alerts-stream-cards">
                {alertsLoading && (
                  <div style={{ textAlign: "center", padding: "20px", color: "#38bdf8" }}>
                    🔄 Updating department telemetry and alert feed...
                  </div>
                )}
                {!alertsLoading && alerts.length === 0 && (
                  <div style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                    ✅ No active alerts for the selected department. All systems nominal.
                  </div>
                )}
                {alerts.map((a) => (
                  <div className={`alert-stream-item ${a.severity}`} key={a.alert_id}>
                    <div className="stream-header">
                      <div className="stream-badges">
                        <span className={`pill-badge ${a.severity}`}>{a.severity.toUpperCase()}</span>
                        <span className="dept-tag">{a.department}</span>
                        {a.manager_notified && <span className="manager-tag">👑 Alerted: {a.manager_role}</span>}
                      </div>
                      <span className="time-text">{a.created_at ? new Date(a.created_at).toLocaleString() : "Just now"}</span>
                    </div>

                    <h4>{a.title}</h4>
                    <p>{a.message}</p>

                    <div className="stream-actions">
                      <span className="channel-text">Channel: {a.notification_channel}</span>
                      <div className="btn-group">
                        {a.status === "unread" ? (
                          <button className="soc-btn green-btn" onClick={() => handleAcknowledgeAlert(a.alert_id)}>
                            ✅ Acknowledge
                          </button>
                        ) : (
                          <span className="ack-text">✓ Acknowledged</span>
                        )}
                        <button
                          className="soc-btn ai-btn"
                          onClick={() => {
                            setActiveTab("ai");
                            const q = `Provide step-by-step fix for alert: ${a.title} on department ${a.department} (Host: ${a.host}, Port: ${a.port})`;
                            setAiQuestion(q);
                            askCyberAtlasAI(q);
                          }}
                        >
                          💬 Ask AI to Fix
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* ============================================================ */}
          {/* TAB: SYSTEM AUDIT & SCANNER CONTROLS */}
          {/* ============================================================ */}
          {activeTab === "scanner" && (
            <section className="soc-card scanner-section">
              <div className="card-header-flex">
                <div>
                  <h2>System Audit Engine (Online & Offline Hosts)</h2>
                  <p className="card-subtext">Active discovery on Online (ON) systems & downtime/dormant vulnerability audit on Offline (OFF) servers.</p>
                </div>
              </div>

              {/* TIMER SELECTOR BAR */}
              <div className="scanner-control-bar">
                <div className="timer-select-group">
                  <label>⏱️ Configurable Scan Timer:</label>
                  <select
                    className="timer-dropdown"
                    value={isCustomTimer ? "custom" : selectedInterval}
                    onChange={(e) => {
                      if (e.target.value === "custom") {
                        setIsCustomTimer(true);
                      } else {
                        setIsCustomTimer(false);
                        handleIntervalChange(e.target.value);
                      }
                    }}
                  >
                    <option value={15}>⚡ 15 Seconds (Rapid Demo)</option>
                    <option value={30}>⏱️ 30 Seconds</option>
                    <option value={60}>⏱️ 60 Seconds (1 Minute)</option>
                    <option value={120}>⏱️ 2 Minutes (120s)</option>
                    <option value={300}>⏱️ 5 Minutes (300s)</option>
                    <option value={900}>⏱️ 15 Minutes (900s)</option>
                    <option value={3600}>⏱️ 1 Hour (3600s)</option>
                    <option value="custom">✏️ Custom Timer...</option>
                  </select>

                  {isCustomTimer && (
                    <div className="custom-input-wrap">
                      <input
                        type="number"
                        min="5"
                        placeholder="Seconds"
                        value={customTimerValue}
                        onChange={(e) => setCustomTimerValue(e.target.value)}
                      />
                      <button className="soc-btn" onClick={() => handleIntervalChange(customTimerValue)}>
                        Set
                      </button>
                    </div>
                  )}
                </div>

                <div className="scan-actions-group">
                  <button className="soc-btn cyan-btn" onClick={runManualScanAll} disabled={manualScanning}>
                    {manualScanning ? "🔍 Scanning..." : "🔍 Scan All Systems (Manual)"}
                  </button>

                  <button className="soc-btn purple-btn" onClick={runManualThreatDetection} disabled={threatDetecting}>
                    {threatDetecting ? "⚡ Detecting..." : "⚡ Run Threat Detection"}
                  </button>

                  <button className="soc-btn orange-btn" style={{ background: "#7c2d12", border: "1px solid #f97316", color: "#fdba74" }} onClick={triggerImmediateAutoScan}>
                    ⚡ Instant Auto-Cycle
                  </button>

                  <button
                    className={`soc-btn ${autoScanner.running ? "pause-btn" : "start-btn"}`}
                    onClick={toggleAutoScanner}
                  >
                    {autoScanner.running ? "⏸️ Pause Auto-Scanner" : `▶️ Start Auto-Scanner (${selectedInterval}s)`}
                  </button>
                </div>
              </div>

              {/* ASSET SYSTEM LIST */}
              <div className="assets-table-wrap">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>System / Server</th>
                      <th>Power Status</th>
                      <th>IP / Host</th>
                      <th>Type</th>
                      <th>Criticality</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {validAssets.map((asset) => {
                      const isOnline = (asset.status || "").toLowerCase() === "online";
                      return (
                        <tr key={asset.id}>
                          <td><strong>{asset.name}</strong></td>
                          <td>
                            <span className={`pill-badge ${isOnline ? "green" : "gray"}`}>
                              {isOnline ? "🟢 ONLINE (ON)" : "⚪ OFFLINE (OFF)"}
                            </span>
                          </td>
                          <td><code>{asset.ip_address}</code></td>
                          <td>{asset.asset_type}</td>
                          <td>{asset.criticality || 5}/5</td>
                          <td>
                            <button
                              className="soc-btn small-btn"
                              onClick={() => runManualScanSingle(asset.id, asset.name)}
                              disabled={scanningAssetId === asset.id}
                            >
                              {scanningAssetId === asset.id ? "Scanning..." : "🔍 Scan"}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* ============================================================ */}
          {/* TAB: AI CYBERSECURITY COPILOT (MULTI-TURN SECOPS WORKSPACE) */}
          {/* ============================================================ */}
          {activeTab === "ai" && (
            <section className="soc-card ai-section">
              <div className="card-header-flex ai-header-flex">
                <div>
                  <h2>CyberAtlas AI SecOps Copilot</h2>
                  <p className="card-subtext">
                    Engine: <strong style={{ color: "#38bdf8" }}>{aiProvider}</strong> • Model: <code>{aiModel}</code>
                  </p>
                </div>

                <div className="ai-top-controls">
                  {/* ROLE-BASED OUTPUT TOGGLE */}
                  <div className="role-mode-toggle">
                    <button
                      className={`role-toggle-btn ${aiViewMode === "technical" ? "active" : ""}`}
                      onClick={() => handleToggleRoleMode("technical")}
                      title="Deep technical remediation, CLI commands, scripts, configs"
                    >
                      🔧 SecOps Technical
                    </button>
                    <button
                      className={`role-toggle-btn ${aiViewMode === "executive" ? "active" : ""}`}
                      onClick={() => handleToggleRoleMode("executive")}
                      title="CISO & Executive summary, business impact, compliance, breach liability"
                    >
                      👔 CISO Executive
                    </button>
                  </div>

                  <button className="soc-btn small-btn" onClick={handleClearChat} title="Clear conversation history">
                    🗑️ Clear Chat
                  </button>
                </div>
              </div>

              {/* ACTIVE REMEDIATION & COMPLIANCE TOOLBAR */}
              {activeRemediation && (
                <div className="remediation-toolbox-card">
                  <div className="toolbox-header">
                    <div className="target-pill">
                      <span>🎯 Target: <strong>{activeRemediation.target_vulnerability || "Detected Finding"}</strong></span>
                    </div>

                    {/* 1-CLICK DOWNLOADABLE SCRIPTS */}
                    <div className="script-download-group">
                      <button
                        className="soc-btn small-btn bash-dl-btn"
                        onClick={() => handleDownloadScript("bash")}
                        title="Download automated bash script (.sh) for Linux/macOS"
                      >
                        💾 Download fix.sh (Linux)
                      </button>
                      <button
                        className="soc-btn small-btn ps1-dl-btn"
                        onClick={() => handleDownloadScript("ps1")}
                        title="Download automated PowerShell script (.ps1) for Windows"
                      >
                        💾 Download fix.ps1 (PowerShell)
                      </button>
                    </div>
                  </div>

                  {/* COMPLIANCE MAPPING RIBBON */}
                  {activeRemediation.compliance && (
                    <div className="compliance-ribbon">
                      <span className="compliance-title">🏛️ Regulatory & Standards Mapping:</span>
                      <div className="compliance-badges-wrap">
                        {activeRemediation.compliance.pci_dss && (
                          <span className="comp-badge pci" title={activeRemediation.compliance.pci_dss}>
                            💳 PCI-DSS 4.0
                          </span>
                        )}
                        {activeRemediation.compliance.nist && (
                          <span className="comp-badge nist" title={activeRemediation.compliance.nist}>
                            🛡️ NIST CSF 2.0
                          </span>
                        )}
                        {activeRemediation.compliance.cis && (
                          <span className="comp-badge cis" title={activeRemediation.compliance.cis}>
                            📋 CIS Controls
                          </span>
                        )}
                        {activeRemediation.compliance.iso27001 && (
                          <span className="comp-badge iso" title={activeRemediation.compliance.iso27001}>
                            🔒 ISO/IEC 27001
                          </span>
                        )}
                        {activeRemediation.compliance.hipaa && (
                          <span className="comp-badge hipaa" title={activeRemediation.compliance.hipaa}>
                            🏥 HIPAA Security
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* 🎯 EXPLOIT & KILL-CHAIN SIMULATION */}
                  {activeRemediation.exploit_simulation && (
                    <div className="exploit-sim-box">
                      <div className="exploit-sim-header" onClick={() => setShowExploitSim(!showExploitSim)}>
                        <strong>🎯 Adversary Kill-Chain Simulation (Attacker Perspective)</strong>
                        <span>{showExploitSim ? "▾ Hide" : "▸ Show"}</span>
                      </div>
                      {showExploitSim && (
                        <div className="killchain-steps">
                          <div className="killchain-step">
                            <span className="kc-num">1</span>
                            <div className="kc-text">
                              <strong>Reconnaissance:</strong> {activeRemediation.exploit_simulation.stage_1_recon}
                            </div>
                          </div>
                          <div className="killchain-step">
                            <span className="kc-num">2</span>
                            <div className="kc-text">
                              <strong>Initial Access:</strong> {activeRemediation.exploit_simulation.stage_2_exploit}
                            </div>
                          </div>
                          <div className="killchain-step">
                            <span className="kc-num">3</span>
                            <div className="kc-text">
                              <strong>Lateral Impact:</strong> {activeRemediation.exploit_simulation.stage_3_impact}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* MULTI-TURN CHAT THREAD */}
              <div className="ai-chat-thread">
                {aiMessages.map((msg, idx) => (
                  <div className={`chat-message-row ${msg.role}`} key={idx}>
                    <div className="chat-avatar">{msg.role === "assistant" ? "🛡️" : "👤"}</div>
                    <div className="chat-bubble">
                      <div className="chat-bubble-header">
                        <span className="sender-name">
                          {msg.role === "assistant" ? `CyberAtlas AI [${aiProvider}]` : "SecOps Analyst"}
                        </span>
                        <span className="msg-time">{msg.time || "Just now"}</span>
                      </div>
                      <div className="chat-bubble-content">
                        {msg.content.split("\n").map((line, lIdx) => (
                          <p key={lIdx}>{line || "\u00A0"}</p>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}

                {aiLoading && (
                  <div className="chat-message-row assistant">
                    <div className="chat-avatar">🛡️</div>
                    <div className="chat-bubble loading-bubble">
                      <div className="soc-typing-indicator">
                        <span></span>
                        <span></span>
                        <span></span>
                      </div>
                      <span className="typing-text">CyberAtlas AI is generating {aiViewMode} remediation playbook & scripts...</span>
                    </div>
                  </div>
                )}
              </div>

              {/* PROMPT CHIPS */}
              <div className="prompt-chips-row">
                <button
                  className="soc-chip"
                  onClick={() => askCyberAtlasAI("How do I remediate the critical vulnerabilities discovered in our systems?")}
                >
                  🛡️ Remediate Critical Vulnerabilities
                </button>
                <button
                  className="soc-chip"
                  onClick={() => askCyberAtlasAI("What are the security risks associated with our offline servers and dormant vulnerabilities?")}
                >
                  ⚡ Audit Offline Server Risks
                </button>
                <button
                  className="soc-chip"
                  onClick={() => askCyberAtlasAI("How can I whitelist only a specific trusted subnet IP 10.0.0.5 instead of completely closing the service?")}
                >
                  🔒 Whitelist Specific IP (10.0.0.5)
                </button>
                <button
                  className="soc-chip"
                  onClick={() => askCyberAtlasAI("Provide an executive security posture report and recommended patch priority.")}
                >
                  🏢 Executive Posture Report
                </button>
              </div>

              {/* CHAT INPUT AREA */}
              <div className="ai-chat-input-area">
                <textarea
                  placeholder={`Ask CyberAtlas AI in ${aiViewMode === "technical" ? "Technical" : "Executive"} mode (e.g. 'How do I remediate MySQL port 3306 on Payment Server?' or ask follow-ups)...`}
                  value={aiQuestion}
                  onChange={(e) => setAiQuestion(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      askCyberAtlasAI();
                    }
                  }}
                  rows="2"
                />
                <button className="soc-btn primary-cyan send-btn" onClick={() => askCyberAtlasAI()} disabled={aiLoading}>
                  {aiLoading ? "Thinking..." : "Send ↵"}
                </button>
              </div>
            </section>
          )}

          {/* ============================================================ */}
          {/* TAB: SCAN HISTORY */}
          {/* ============================================================ */}
          {activeTab === "history" && (
            <section className="soc-card history-section">
              <div className="card-header-flex">
                <div>
                  <h2>Persistent Security Scan History & Audit Logs</h2>
                  <p className="card-subtext">Historical record of all manual & automated scans.</p>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span className="ciso-pill">{scanHistory.length} Scans Stored</span>
                  {scanHistory.length > 0 && (
                    <button className="soc-btn pause-btn" onClick={handleClearScanHistory}>
                      🗑️ Clear History
                    </button>
                  )}
                </div>
              </div>

              <div className="table-responsive">
                {historyLoading && (
                  <div style={{ textAlign: "center", padding: "20px", color: "#38bdf8" }}>
                    🔄 Loading stored audit logs from persistent database...
                  </div>
                )}
                {!historyLoading && scanHistory.length === 0 && (
                  <div style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                    📭 No audit scan logs stored yet. Run a manual scan or start the auto-scanner.
                  </div>
                )}
                {scanHistory.length > 0 && (
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Scan ID</th>
                        <th>Timestamp</th>
                        <th>System / Asset</th>
                        <th>Scan Type</th>
                        <th>Power State</th>
                        <th>Findings</th>
                        <th>Risk Score</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanHistory.map((s) => (
                        <tr key={s.scan_id}>
                          <td><code>#{s.scan_id}</code></td>
                          <td>{s.created_at ? new Date(s.created_at).toLocaleString() : "N/A"}</td>
                          <td><strong>{s.asset_name || s.target}</strong></td>
                          <td>
                            <span className={`pill-badge ${s.scan_type === "automatic" ? "cyan" : "purple"}`}>
                              {s.scan_type === "automatic" ? "⚡ Automatic" : "🔍 Manual"}
                            </span>
                          </td>
                          <td>
                            <span className={`pill-badge ${s.is_online ? "green" : "gray"}`}>
                              {s.is_online ? "🟢 ON" : "⚪ OFF"}
                            </span>
                          </td>
                          <td><strong>{s.total_findings}</strong></td>
                          <td><span className="risk-num">{s.risk_score || 0}</span></td>
                          <td>
                            <button className="soc-btn small-btn" onClick={() => viewScanDetails(s.scan_id)}>
                              👁️ Snapshot
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* SNAPSHOT MODAL */}
              {selectedScanDetail && (
                <div className="soc-modal-backdrop" onClick={() => setSelectedScanDetail(null)}>
                  <div className="soc-modal-box" onClick={(e) => e.stopPropagation()}>
                    <div className="modal-top">
                      <h3>Scan Snapshot #{selectedScanDetail.scan_id} - {selectedScanDetail.asset_name}</h3>
                      <button className="close-btn" onClick={() => setSelectedScanDetail(null)}>✕</button>
                    </div>
                    <div className="modal-content">
                      <div className="snapshot-grid">
                        <div><strong>Target:</strong> {selectedScanDetail.target}</div>
                        <div><strong>Type:</strong> {selectedScanDetail.scan_type}</div>
                        <div><strong>Power:</strong> {selectedScanDetail.is_online ? "Online (ON)" : "Offline (OFF)"}</div>
                        <div><strong>Findings:</strong> {selectedScanDetail.total_findings}</div>
                      </div>

                      <h4>Discovered Vulnerabilities:</h4>
                      {Array.isArray(selectedScanDetail.scan_summary) ? (
                        <div className="snapshot-findings">
                          {selectedScanDetail.scan_summary.map((f, i) => (
                            <div className="snapshot-item" key={i}>
                              <span className={`pill-badge ${f.severity?.toLowerCase()}`}>{f.severity}</span>
                              <strong>{f.title}</strong>
                              {f.port && <span>(Port: {f.port})</span>}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <pre className="raw-code">{JSON.stringify(selectedScanDetail.scan_summary, null, 2)}</pre>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </section>
          )}

          {/* TAB 8: IDENTITY & ACCESS CONTROL (RBAC) */}
          {activeTab === "users" && (
            <section className="soc-main-view" style={{ padding: "0" }}>
              <UserManagement apiUrl={API_URL} />
            </section>
          )}

          {/* TAB 9: ENTERPRISE CONNECTORS & ASSET INTEGRATIONS */}
          {activeTab === "integrations" && (
            <section className="soc-main-view" style={{ padding: "0" }}>
              <IntegrationsHub apiUrl={API_URL} />
            </section>
          )}

          {/* TAB 10: ENTERPRISE SOC SYSTEM SETTINGS */}
          {activeTab === "settings" && (
            <section className="soc-main-view" style={{ padding: "0" }}>
              <SettingsCenter apiUrl={API_URL} onSaveToast={(msg) => setStatusMessage(msg)} />
            </section>
          )}


        </main>
      </div>



      {/* ============================================================ */}
      {/* 3. BOTTOM LIVE THREAT INTELLIGENCE FEED TICKER (AS IN PICTURE) */}
      {/* ============================================================ */}
      <footer className="soc-threat-ticker">
        <div className="ticker-label">
          <span className="ticker-badge">Threat Intelligence Feed [3]</span>
        </div>
        <div className="ticker-marquee">
          <div className="marquee-track">
            <span>🔴 New IOC: Malicious IP 185.220.101.45 observed in brute-force attacks</span>
            <span className="ticker-divider">|</span>
            <span>⚠️ Malware Campaign: "Luminous Manticore" targeting financial infrastructure</span>
            <span className="ticker-divider">|</span>
            <span>🛡️ Critical Vulnerability CVE-2024-3094 detected in network perimeter</span>
            <span className="ticker-divider">|</span>
            <span>🔒 CyberAtlas Active Shield enforcing 6 perimeter defense rules</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;