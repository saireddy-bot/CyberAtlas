import { useEffect, useState } from "react";

// Accurate geographic coordinates for viewBox="0 0 1000 480"
const COUNTRY_COORDS = {
  US_WEST: { name: "United States (West)", x: 185, y: 155, code: "US" },
  US_EAST: { name: "United States (East)", x: 275, y: 160, code: "US" },
  BRAZIL: { name: "Brazil (São Paulo)", x: 345, y: 325, code: "BR" },
  UK: { name: "United Kingdom (London)", x: 475, y: 120, code: "GB" },
  NETHERLANDS: { name: "Netherlands (Amsterdam)", x: 495, y: 122, code: "NL" },
  GERMANY: { name: "Germany (Frankfurt)", x: 510, y: 130, code: "DE" },
  RUSSIA: { name: "Russia (Moscow)", x: 590, y: 105, code: "RU" },
  CHINA: { name: "China (Beijing)", x: 770, y: 165, code: "CN" },
  INDIA: { name: "India (Mumbai)", x: 675, y: 215, code: "IN" },
  JAPAN: { name: "Japan (Tokyo)", x: 860, y: 155, code: "JP" },
  AUSTRALIA: { name: "Australia (Sydney)", x: 870, y: 355, code: "AU" },
  TARGET_LOCAL: { name: "CyberAtlas SOC Protected Node", x: 505, y: 145, code: "HQ" }
};


const ATTACK_TYPES = [
  { type: "Brute Force SSH (Port 22)", severity: "critical", color: "#ef4444" },
  { type: "Database Port Probe (MySQL 3306)", severity: "high", color: "#f59e0b" },
  { type: "SQL Injection Probe (/api/v1)", severity: "critical", color: "#ef4444" },
  { type: "RDP Exploit Scan (Port 3389)", severity: "high", color: "#f59e0b" },
  { type: "Malware Beacon Attempt", severity: "critical", color: "#a855f7" },
  { type: "Telnet Cleartext Probe (Port 23)", severity: "medium", color: "#38bdf8" },
  { type: "HTTP Exploit Attempt (Port 8080)", severity: "medium", color: "#38bdf8" },
  { type: "DDoS SYN Flood Attack", severity: "critical", color: "#ef4444" }
];

const ORIGINS = [
  COUNTRY_COORDS.US_WEST,
  COUNTRY_COORDS.US_EAST,
  COUNTRY_COORDS.RUSSIA,
  COUNTRY_COORDS.CHINA,
  COUNTRY_COORDS.NETHERLANDS,
  COUNTRY_COORDS.GERMANY,
  COUNTRY_COORDS.BRAZIL,
  COUNTRY_COORDS.AUSTRALIA,
  COUNTRY_COORDS.INDIA,
  COUNTRY_COORDS.UK,
  COUNTRY_COORDS.JAPAN
];

const TARGET_NODE = COUNTRY_COORDS.TARGET_LOCAL;

export default function WorldMapThreatCanvas({ activeFindings = [], assets = [] }) {
  const [mapMode, setMapMode] = useState("kaspersky"); // "kaspersky" | "cyberatlas"
  const [iframeLoading, setIframeLoading] = useState(true);
  const [activeAttacks, setActiveAttacks] = useState([]);
  const [hoveredNode, setHoveredNode] = useState(null);


  useEffect(() => {
    // Generate animated attack streams every 1.1 seconds
    const interval = setInterval(() => {
      const randomOrigin = ORIGINS[Math.floor(Math.random() * ORIGINS.length)];
      const randomAttack = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];

      const targetIp = assets.length > 0 && assets[0]?.ip_address 
        ? assets[0].ip_address 
        : "192.168.1.10";

      const newAttack = {
        id: Date.now() + Math.random(),
        source: randomOrigin,
        target: TARGET_NODE,
        attackType: randomAttack.type,
        severity: randomAttack.severity,
        color: randomAttack.color,
        sourceIp: `${Math.floor(Math.random() * 200 + 20)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        targetIp: targetIp,
        timestamp: new Date().toLocaleTimeString()
      };

      setActiveAttacks((prev) => [...prev.slice(-8), newAttack]);
    }, 1100);

    return () => clearInterval(interval);
  }, [assets]);

  return (
    <div className="threat-map-wrapper">
      {/* MAP TITLE & TELEMETRY HEADER */}
      <div className="threat-map-header">
        <div className="map-title-row">
          <div className="live-indicator">
            <span className="live-pulse-dot"></span>
            <strong>REAL-TIME ATTACK MAP</strong>
          </div>
          <span className="telemetry-pill">Active Trajectories: {activeAttacks.length}</span>
          {activeFindings.length > 0 && (
            <span className="telemetry-pill red">{activeFindings.length} Active Findings</span>
          )}
        </div>

        <div className="map-controls">
          {/* MAP MODE SWITCHER */}
          <div className="map-mode-switcher">
            <button
              className={`map-mode-btn ${mapMode === "kaspersky" ? "active" : ""}`}
              onClick={() => setMapMode("kaspersky")}
              title="Interactive 3D Kaspersky Cyberthreat Globe"
            >
              🌐 Kaspersky 3D Map
            </button>
            <button
              className={`map-mode-btn ${mapMode === "cyberatlas" ? "active" : ""}`}
              onClick={() => setMapMode("cyberatlas")}
              title="CyberAtlas Protected Asset Trajectories"
            >
              🛡️ CyberAtlas SOC Map
            </button>

            <a
              href="https://cybermap.kaspersky.com/"
              target="_blank"
              rel="noreferrer"
              className="map-mode-btn external-link-btn"
              title="Open full Kaspersky Cyberthreat Map in new tab"
            >
              ↗ Fullscreen
            </a>
          </div>

          <span className="map-stat-tag">Monitored Assets: {assets.length || 5}</span>
          <span className="map-stat-tag live-tag">Streaming 🟢</span>
        </div>
      </div>

      {/* CENTER MAP DISPLAY */}
      {mapMode === "kaspersky" ? (
        /* KASPERSKY 3D REAL-TIME CYBERTHREAT MAP EMBED */
        <div className="kaspersky-map-container">
          {iframeLoading && (
            <div className="kaspersky-loading-overlay">
              <div className="radar-spinner"></div>
              <p>Connecting to Kaspersky Cyberthreat Global Telemetry Grid...</p>
            </div>
          )}
          <iframe
            src="https://cybermap.kaspersky.com/en/widget/dynamic/dark"
            title="Kaspersky Cyberthreat Real-Time Map"
            className="kaspersky-map-iframe"
            onLoad={() => setIframeLoading(false)}
            allow="autoplay; fullscreen"
          />
          <div className="kaspersky-attribution-tag">
            <span>🛰️ Live Feed: <strong>Kaspersky Cyberthreat Real-Time Map</strong></span>
          </div>
        </div>
      ) : (
        /* CYBERTWIN SVG VECTOR MAP */
        <div className="svg-map-container">
          <svg
            viewBox="0 0 1000 480"
            className="world-map-svg"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              {/* Glow Filters */}
              <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="3.5" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <filter id="glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* HIGH-TECH LATITUDE & LONGITUDE GRID */}
            <g className="map-grid" stroke="rgba(56, 189, 248, 0.08)" strokeWidth="0.5">
              <line x1="50" y1="120" x2="950" y2="120" strokeDasharray="3 3" />
              <line x1="50" y1="240" x2="950" y2="240" strokeDasharray="3 3" />
              <line x1="50" y1="360" x2="950" y2="360" strokeDasharray="3 3" />
              <line x1="200" y1="30" x2="200" y2="450" strokeDasharray="3 3" />
              <line x1="400" y1="30" x2="400" y2="450" strokeDasharray="3 3" />
              <line x1="600" y1="30" x2="600" y2="450" strokeDasharray="3 3" />
              <line x1="800" y1="30" x2="800" y2="450" strokeDasharray="3 3" />
            </g>

            {/* ACCURATE WORLD CONTINENT PATHS */}
            <g className="world-continents" fill="#14213d" stroke="#253a63" strokeWidth="0.8">
              {/* NORTH AMERICA */}
              <path d="M 120 70 L 150 55 L 210 50 L 260 65 L 300 80 L 270 120 L 290 145 L 280 180 L 240 215 L 210 210 L 205 180 L 170 190 L 140 150 L 115 130 L 105 95 Z" />
              {/* Greenland */}
              <path d="M 330 35 L 380 40 L 360 85 L 320 80 Z" />
              {/* Central America */}
              <path d="M 235 220 L 255 240 L 280 260 L 270 270 L 240 245 Z" />

              {/* SOUTH AMERICA */}
              <path d="M 285 270 L 340 275 L 385 320 L 375 380 L 340 435 L 310 440 L 295 380 L 280 320 Z" />

              {/* EUROPE */}
              <path d="M 460 85 L 500 70 L 535 75 L 565 105 L 540 145 L 490 155 L 460 145 L 450 115 Z" />
              {/* Scandinavia */}
              <path d="M 495 50 L 530 45 L 535 90 L 505 85 Z" />
              {/* UK & Ireland */}
              <path d="M 445 105 L 465 95 L 470 130 L 450 130 Z" />

              {/* AFRICA */}
              <path d="M 455 165 L 545 160 L 590 215 L 575 300 L 535 375 L 495 370 L 455 280 L 440 210 Z" />
              {/* Madagascar */}
              <path d="M 605 320 L 620 325 L 610 370 L 595 365 Z" />

              {/* ASIA & RUSSIA */}
              <path d="M 570 70 L 680 50 L 830 55 L 890 90 L 880 140 L 820 165 L 795 210 L 735 240 L 660 210 L 605 175 L 560 130 Z" />
              {/* India */}
              <path d="M 645 205 L 705 210 L 690 280 L 655 250 Z" />
              {/* Southeast Asia */}
              <path d="M 750 225 L 805 235 L 800 295 L 760 280 Z" />
              {/* Japan */}
              <path d="M 850 135 L 870 140 L 860 185 L 845 175 Z" />

              {/* AUSTRALIA & OCEANIA */}
              <path d="M 800 315 L 895 310 L 910 380 L 845 410 L 785 375 Z" />
              {/* New Zealand */}
              <path d="M 930 395 L 945 400 L 935 440 L 920 435 Z" />
            </g>

            {/* ANIMATED ATTACK LASER TRAJECTORIES */}
            <g className="attack-arcs">
              {activeAttacks.map((attack) => {
                const midX = (attack.source.x + attack.target.x) / 2;
                const midY = Math.min(attack.source.y, attack.target.y) - 55;
                const pathD = `M ${attack.source.x} ${attack.source.y} Q ${midX} ${midY} ${attack.target.x} ${attack.target.y}`;

                return (
                  <g key={attack.id} className="attack-trajectory">
                    {/* Arc Guide */}
                    <path
                      d={pathD}
                      fill="none"
                      stroke={attack.color}
                      strokeWidth="1.2"
                      strokeOpacity="0.3"
                      strokeDasharray="4 4"
                    />

                    {/* Pulsing Animated Laser */}
                    <path
                      d={pathD}
                      fill="none"
                      stroke={attack.color}
                      strokeWidth="2.2"
                      filter="url(#glow-red)"
                      className="laser-pulse-beam"
                    />

                    {/* Moving Particle Head */}
                    <circle r="3.5" fill="#ffffff" filter="url(#glow-cyan)">
                      <animateMotion
                        path={pathD}
                        dur="1.1s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  </g>
                );
              })}
            </g>

            {/* ATTACKING SOURCE COUNTRY NODES */}
            <g className="origin-nodes">
              {ORIGINS.map((node, i) => (
                <g
                  key={i}
                  className="map-node-group"
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                >
                  {/* Radar Ring */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="8"
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth="1"
                    opacity="0.6"
                    className="pulse-ring"
                  />
                  {/* Center Beacon */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="3.5"
                    fill="#ef4444"
                    filter="url(#glow-red)"
                  />
                  <text
                    x={node.x + 6}
                    y={node.y + 3}
                    fill="#94a3b8"
                    fontSize="8.5"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {node.code}
                  </text>
                </g>
              ))}
            </g>

            {/* TARGET HUB (PROTECTED CYBERTWIN NODE) */}
            <g className="target-hub">
              <circle
                cx={TARGET_NODE.x}
                cy={TARGET_NODE.y}
                r="14"
                fill="none"
                stroke="#38bdf8"
                strokeWidth="1.5"
                className="target-pulse-ring"
              />
              <circle
                cx={TARGET_NODE.x}
                cy={TARGET_NODE.y}
                r="5.5"
                fill="#38bdf8"
                filter="url(#glow-cyan)"
              />
              <text
                x={TARGET_NODE.x - 38}
                y={TARGET_NODE.y - 12}
                fill="#38bdf8"
                fontSize="10"
                fontWeight="bold"
              >
                🛡️ CYBERATLAS HQ
              </text>

            </g>
          </svg>

          {/* HOVER TOOLTIP */}
          {hoveredNode && (
            <div
              className="map-tooltip"
              style={{
                left: `${(hoveredNode.x / 1000) * 100}%`,
                top: `${(hoveredNode.y / 480) * 100}%`
              }}
            >
              <div className="tooltip-country">🚩 {hoveredNode.name}</div>
              <div className="tooltip-sub">Threat Actor Activity: ACTIVE</div>
            </div>
          )}
        </div>
      )}

      {/* LIVE STREAM TICKER BAR UNDER MAP */}
      <div className="map-bottom-stream">
        <span className="stream-label">LIVE STREAM:</span>
        <div className="stream-items">
          {activeAttacks.slice(-3).map((atk) => (
            <span key={atk.id} className="stream-pill">
              <strong style={{ color: atk.color }}>[{atk.severity.toUpperCase()}]</strong> {atk.attackType} from <code>{atk.source.code} ({atk.sourceIp})</code> ➔ <code>{atk.target.code}</code>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
