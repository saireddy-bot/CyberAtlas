import socket
import urllib.request
from typing import Dict, List, Optional, Any


# ============================================================
# COMMON AUDIT PORTS & SERVICES
# ============================================================

COMMON_PORT_CATALOG = {
    21: "FTP (Plaintext)",
    22: "SSH",
    23: "Telnet (Insecure)",
    25: "SMTP",
    53: "DNS",
    80: "HTTP (Unencrypted)",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS (Encrypted)",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    5432: "PostgreSQL Database",
    6379: "Redis Cache",
    8000: "HTTP-Dev (Alt)",
    8002: "CyberTwin API",
    8080: "HTTP-Proxy",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

ALLOWED_DEFAULT_PORTS = {443}


# ============================================================
# 1. HOST REACHABILITY CHECK (POWER STATE: ON / OFF)
# ============================================================

def check_host_reachability(ip_address: str, timeout_seconds: float = 0.5) -> Dict[str, Any]:
    """
    Checks network reachability of a host by testing common TCP service ports.
    Determines whether a system or server is currently ON (online) or OFF (offline).
    """
    if not ip_address:
        return {
            "check": "host_reachability",
            "status": "offline",
            "reachable": False,
            "ip_address": None,
            "detected_port": None,
            "message": "No IP address provided."
        }

    # Special handling for localhost/loopback
    if ip_address in ["127.0.0.1", "localhost"]:
        # Test common local ports
        for port in [8000, 8002, 80, 443, 5173, 3000, 22]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            try:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    sock.close()
                    return {
                        "check": "host_reachability",
                        "status": "online",
                        "reachable": True,
                        "ip_address": ip_address,
                        "detected_port": port,
                        "message": f"Local system is active and accepting connections on TCP port {port}."
                    }
            except socket.error:
                pass
            finally:
                sock.close()

    # Fast multi-port sweep for remote or local hosts
    probe_ports = [80, 443, 22, 8000, 8002, 8080, 3306, 5432, 3389, 21]
    for port in probe_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)
        try:
            res = sock.connect_ex((ip_address, port))
            if res == 0:
                sock.close()
                return {
                    "check": "host_reachability",
                    "status": "online",
                    "reachable": True,
                    "ip_address": ip_address,
                    "detected_port": port,
                    "message": f"Host is reachable and responding on TCP port {port}."
                }
        except socket.error:
            pass
        finally:
            sock.close()

    # If no TCP port connected, try basic socket resolution check
    return {
        "check": "host_reachability",
        "status": "offline",
        "reachable": False,
        "ip_address": ip_address,
        "detected_port": None,
        "message": "No tested TCP ports responded. System/server is currently powered off, in maintenance, or firewall-isolated."
    }


# ============================================================
# 2. COMMON SERVICE DISCOVERY (FOR ONLINE SYSTEMS)
# ============================================================

def check_common_services(ip_address: str, timeout_seconds: float = 0.4) -> Dict[str, Any]:
    """
    Discovers all open TCP services and banners on an online host.
    """
    discovered_services = []

    for port, service_name in COMMON_PORT_CATALOG.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)
        try:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                discovered_services.append({
                    "host": ip_address,
                    "port": port,
                    "service": service_name,
                    "status": "open"
                })
        except socket.error:
            pass
        finally:
            sock.close()

    return {
        "check": "common_service_discovery",
        "status": "completed",
        "services": discovered_services
    }


# ============================================================
# 3. HTTP ENDPOINT DISCOVERY
# ============================================================

def discover_http_endpoints(ip_address: str, port: int) -> List[str]:
    """Discovers accessible HTTP/HTTPS endpoints on exposed web services."""
    endpoints = []
    protocol = "https" if port == 443 else "http"
    base_url = f"{protocol}://{ip_address}:{port}"
    common_endpoints = ["/", "/health", "/docs", "/openapi.json", "/api", "/status"]

    for endpoint in common_endpoints:
        url = base_url + endpoint
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "CyberTwin-Security-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status < 400:
                    endpoints.append(endpoint)
        except Exception:
            pass

    return endpoints


# ============================================================
# 4. SERVICE FINDINGS GENERATION (ONLINE SYSTEMS)
# ============================================================

def generate_service_findings(services: List[Dict[str, Any]], host: str, asset_name: str = "") -> List[Dict[str, Any]]:
    """Generates vulnerability and exposure findings for open services on active systems."""
    findings = []

    for service in services:
        port = service["port"]
        service_name = service["service"]
        service_host = service.get("host", host)
        endpoints = service.get("endpoints", [])
        endpoint_val = endpoints[0] if endpoints else None

        if port not in ALLOWED_DEFAULT_PORTS:
            # Determine severity based on exposed service sensitivity
            if port in [21, 23]:
                severity = "Critical"
                cvss_score = "9.1"
                vuln_type = "Insecure Cleartext Protocol"
                desc = f"Legacy plaintext protocol {service_name} is active on port {port}. Credentials and data travel in cleartext over the network."
                remed = f"Immediately disable {service_name} and replace with encrypted SSH (port 22) or SFTP."
            elif port in [3306, 5432, 6379, 27017]:
                severity = "High"
                cvss_score = "8.2"
                vuln_type = "Database Port Public Exposure"
                desc = f"{service_name} is listening on open port {port}. Direct database exposure increases the risk of unauthorized brute-force and remote extraction."
                remed = f"Bind {service_name} strictly to localhost (127.0.0.1) or internal VPC subnet. Enforce strong database authentication and TLS encryption."
            elif port in [80, 8000, 8080]:
                severity = "Medium"
                cvss_score = "6.0"
                vuln_type = "Unencrypted Web Service"
                desc = f"Web service {service_name} on port {port} is accessible without mandatory HTTPS encryption. Traffic is vulnerable to interception."
                remed = "Redirect HTTP traffic to HTTPS (port 443) and provision an active TLS/SSL certificate."
            elif port == 3389:
                severity = "High"
                cvss_score = "7.8"
                vuln_type = "Remote Desktop Protocol Exposure"
                desc = "RDP port 3389 is exposed to the network. Susceptible to credential stuffing, BlueKeep vulnerabilities, and unauthorized access."
                remed = "Place RDP behind an authenticated VPN / Bastion gateway and enforce Network Level Authentication (NLA) with MFA."
            else:
                severity = "Medium"
                cvss_score = "5.0"
                vuln_type = "Service Exposure"
                desc = f"Service {service_name} is accessible on port {port} without being registered in the allowed service whitelist."
                remed = f"Review whether port {port} is required for business operations. If unnecessary, block access using host firewall rules."

            findings.append({
                "title": f"Unexpected Exposed Service: {service_name}",
                "description": desc,
                "severity": severity,
                "cvss_score": cvss_score,
                "vulnerability_type": vuln_type,
                "affected_component": f"{service_name} on port {port}",
                "host": service_host,
                "port": str(port),
                "endpoint": endpoint_val,
                "database_name": None,
                "file_path": None,
                "status": "open",
                "remediation": remed
            })

    return findings


# ============================================================
# 5. OFFLINE SECURITY & AVAILABILITY AUDIT (FOR OFFLINE ASSETS)
# ============================================================

def run_offline_security_audit(
    ip_address: str,
    asset_type: str,
    asset_name: str = "Target Server",
    criticality: int = 5,
    existing_findings_count: int = 0
) -> Dict[str, Any]:
    """
    Performs a security and posture audit when a system/server is OFFLINE (OFF).
    Evaluates availability disruptions, dormant unpatched risks, shadow asset risks,
    and disaster recovery posture.
    """
    offline_findings = []

    # 1. Critical Asset Availability Disruption
    if criticality >= 4:
        severity = "High" if criticality == 4 else "Critical"
        cvss = "7.5" if criticality == 4 else "8.8"
        offline_findings.append({
            "title": f"Critical Server Outage / Unreachable Asset: {asset_name}",
            "description": (
                f"Asset '{asset_name}' (Criticality: {criticality}/5) is currently offline and unresponsive on all network interfaces. "
                "For high-criticality assets, unexpected downtime creates severe operational dependencies and potential service failure."
            ),
            "severity": severity,
            "cvss_score": cvss,
            "vulnerability_type": "Availability & Denial of Service",
            "affected_component": f"System Host ({ip_address or 'Offline Node'})",
            "host": ip_address,
            "port": None,
            "endpoint": None,
            "database_name": None,
            "file_path": None,
            "status": "open",
            "remediation": (
                "Verify server power status, physical hardware/hypervisor health, and network routing. "
                "Ensure failover clusters or automated disaster recovery instances assume traffic."
            )
        })

    # 2. Dormant Unpatched Security Posture Check
    if existing_findings_count > 0:
        offline_findings.append({
            "title": f"Dormant Unpatched Vulnerabilities on Offline Asset: {asset_name}",
            "description": (
                f"Asset '{asset_name}' contains {existing_findings_count} unresolved vulnerability finding(s). "
                "While offline, the system remains vulnerable to immediate exploitation upon reboot if patches are not applied prior to rejoining the network."
            ),
            "severity": "Medium",
            "cvss_score": "5.5",
            "vulnerability_type": "Dormant Patch Gap",
            "affected_component": "System Firmware & Installed Packages",
            "host": ip_address,
            "port": None,
            "endpoint": None,
            "database_name": None,
            "file_path": None,
            "status": "open",
            "remediation": (
                "Boot the machine in an isolated maintenance VLAN and apply all outstanding security patches and firmware updates before reconnecting to the production subnet."
            )
        })

    # 3. Dormant / Shadow Asset Policy Non-Compliance
    offline_findings.append({
        "title": f"Offline Asset Lifecycle & Dormancy Review: {asset_name}",
        "description": (
            f"Asset '{asset_name}' is currently in an OFF/offline state. Unmonitored offline assets increase shadow IT risk, "
            "miss scheduled automated compliance scans, and may harbor expired TLS certificates or deprecated software stacks."
        ),
        "severity": "Low",
        "cvss_score": "3.5",
        "vulnerability_type": "Asset Management & Compliance",
        "affected_component": "Asset Catalog Lifecycle",
        "host": ip_address,
        "port": None,
        "endpoint": None,
        "database_name": None,
        "file_path": None,
        "status": "open",
        "remediation": (
            "Verify whether this asset is actively maintained, temporarily paused, or slated for decommissioning. "
            "If decommissioned, archive and securely purge sensitive data."
        )
    })

    return {
        "status": "completed_offline",
        "target": ip_address,
        "asset_type": asset_type,
        "is_online": False,
        "checks": [
            {
                "check": "host_reachability",
                "status": "offline",
                "reachable": False,
                "ip_address": ip_address,
                "message": "Host is offline / powered off. Executed offline security, availability, and dormancy audit."
            },
            {
                "check": "offline_posture_audit",
                "status": "completed",
                "criticality_level": criticality,
                "dormant_findings_evaluated": existing_findings_count
            }
        ],
        "findings": offline_findings,
        "total_findings": len(offline_findings),
        "message": f"Offline security audit completed for {asset_name}. Evaluated downtime risk, dormant vulnerabilities, and compliance."
    }


# ============================================================
# 6. MASTER SECURITY SCAN (SCANS BOTH ONLINE & OFFLINE ASSETS)
# ============================================================

def run_security_scan(
    ip_address: str,
    asset_type: str,
    asset_name: str = "",
    criticality: int = 5,
    existing_findings_count: int = 0
) -> Dict[str, Any]:
    """
    Main scanner function.
    Automatically audits both Online (ON) systems (active network/service scan)
    and Offline (OFF) systems (dormant posture, availability, and compliance audit).
    """
    if not ip_address:
        return {
            "status": "failed",
            "target": None,
            "asset_type": asset_type,
            "is_online": False,
            "checks": [],
            "findings": [],
            "total_findings": 0,
            "message": "Asset does not have an IP address configured."
        }

    # 1. Test Host Reachability / Power Status
    reachability_result = check_host_reachability(ip_address)

    # 2. IF SYSTEM IS OFFLINE (OFF): Execute Offline Security Audit
    if not reachability_result["reachable"]:
        return run_offline_security_audit(
            ip_address=ip_address,
            asset_type=asset_type,
            asset_name=asset_name or ip_address,
            criticality=criticality,
            existing_findings_count=existing_findings_count
        )

    # 3. IF SYSTEM IS ONLINE (ON): Execute Active Live Security Scan
    service_result = check_common_services(ip_address)

    for service in service_result["services"]:
        port = service["port"]
        if port in {80, 443, 8000, 8002, 8080}:
            endpoints = discover_http_endpoints(ip_address, port)
            service["endpoints"] = endpoints

    findings = generate_service_findings(
        services=service_result["services"],
        host=ip_address,
        asset_name=asset_name
    )

    checks = [
        reachability_result,
        service_result
    ]

    return {
        "status": "completed_online",
        "target": ip_address,
        "asset_type": asset_type,
        "is_online": True,
        "checks": checks,
        "findings": findings,
        "total_findings": len(findings),
        "message": f"Active security scan completed successfully for online host {ip_address}."
    }