from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import get_db

from .models import (
    Asset,
    SecurityFinding,
    AvailabilityEvent,
    SecurityIncident,
    SecurityAlert,
    FirewallRule
)

from .schemas import (
    AssetCreate,
    AssetResponse,
    SecurityFindingResponse
)

from .risk_engine import calculate_risk
from .business_impact import calculate_business_impact
from .risk_priority import calculate_priority
from .remediation import generate_remediation
from .security_posture import calculate_security_posture
from .exposure_analysis import calculate_exposure
from .remediation_verification import verify_remediation
from .risk_reduction import calculate_risk_reduction

from .incidents import (
    create_incident,
    get_incident,
    list_incidents,
    update_incident_status
)

from .alerts import (
    check_finding_for_alert,
    get_all_alerts,
    get_alert,
    acknowledge_alert,
    get_department_alert_summary
)

from .scan_history import (
    create_scan_record,
    get_scan_history,
    get_all_scan_history,
    get_scan,
    clear_all_scan_history
)

from .asset_discovery import discover_asset
from .security_assessment import assess_asset_security
from .scanner import run_security_scan
from .ai_assistant import ask_cybertwin_ai
from .availability_monitor import check_host_reachability
from .firewall import (
    get_firewall_status,
    get_firewall_rules,
    create_firewall_rule,
    toggle_firewall_rule,
    delete_firewall_rule,
    apply_defense_baseline,
    block_port_with_firewall
)

from .auto_scanner import (
    start_automatic_scanner,
    stop_automatic_scanner,
    get_automatic_scanner_status,
    run_automatic_scan,
    save_scan_finding,
    set_scan_interval
)


router = APIRouter(
    prefix="/assets",
    tags=["Assets"]
)


# ============================================================
# CREATE ASSET
# ============================================================

@router.post("/", response_model=AssetResponse)
def create_asset(
    asset: AssetCreate,
    db: Session = Depends(get_db)
):
    new_asset = Asset(**asset.model_dump())

    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    return new_asset


# ============================================================
# GET ALL ASSETS
# ============================================================

@router.get("/")
def get_assets(
    db: Session = Depends(get_db)
):
    assets = (
        db.query(Asset)
        .order_by(Asset.id.asc())
        .all()
    )

    print("DEBUG ASSETS:")
    print("TOTAL ASSETS:", len(assets))

    for asset in assets:
        print(
            "ASSET:",
            asset.id,
            asset.name,
            asset.risk_level,
            asset.data_sensitivity,
            asset.operational_dependency,
            asset.customer_impact,
            asset.financial_impact
        )

    return [
        {
            "id": asset.id,
            "name": asset.name,
            "asset_type": asset.asset_type,
            "ip_address": asset.ip_address,
            "status": asset.status,
            "risk_level": asset.risk_level,
            "criticality": asset.criticality,
            "data_sensitivity": asset.data_sensitivity,
            "operational_dependency": asset.operational_dependency,
            "customer_impact": asset.customer_impact,
            "financial_impact": asset.financial_impact,
            "description": asset.description
        }
        for asset in assets
    ]

# ============================================================
# UPDATE ASSET
# ============================================================

@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset: AssetCreate,
    db: Session = Depends(get_db)
):
    existing_asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not existing_asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    for field, value in asset.model_dump().items():
        setattr(existing_asset, field, value)

    db.commit()
    db.refresh(existing_asset)

    return existing_asset


# ============================================================
# GET ALL SECURITY FINDINGS
# ============================================================

@router.get(
    "/findings/",
    response_model=list[SecurityFindingResponse]
)
def get_findings(
    db: Session = Depends(get_db)
):
    findings = (
        db.query(SecurityFinding)
        .order_by(SecurityFinding.id.desc())
        .all()
    )

    results = []

    for finding in findings:

        asset = (
            db.query(Asset)
            .filter(Asset.id == finding.asset_id)
            .first()
        )

        asset_criticality = (
            asset.criticality
            if asset
            else 5
        )

        risk_result = calculate_risk(
            cvss_score=float(finding.cvss_score or 0),
            asset_criticality=asset_criticality,
            exposure=8,
            exploitability=9,
            business_impact=9
        )

        results.append({
            "id": finding.id,
            "asset_id": finding.asset_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "vulnerability_type": finding.vulnerability_type,
            "affected_component": finding.affected_component,

            "host": finding.host,
            "port": finding.port,
            "endpoint": finding.endpoint,
            "database_name": finding.database_name,
            "file_path": finding.file_path,

            "status": finding.status,
            "remediation": finding.remediation,

            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"]
        })

    return results


# ============================================================
# ANALYZE FINDING RISK
# ============================================================

@router.get("/findings/{finding_id}/risk")
def analyze_finding_risk(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found"
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == finding.asset_id)
        .first()
    )

    asset_criticality = (
        asset.criticality
        if asset
        else 5
    )

    risk_result = calculate_risk(
        cvss_score=float(finding.cvss_score or 0),
        asset_criticality=asset_criticality,
        exposure=8,
        exploitability=9,
        business_impact=9
    )

    if asset:
        impact_result = calculate_business_impact(
            asset_criticality=asset.criticality,
            data_sensitivity=asset.data_sensitivity,
            operational_dependency=asset.operational_dependency,
            customer_impact=asset.customer_impact,
            financial_impact=asset.financial_impact
        )
    else:
        impact_result = calculate_business_impact(
            asset_criticality=5,
            data_sensitivity=5,
            operational_dependency=5,
            customer_impact=5,
            financial_impact=5
        )

    priority_result = calculate_priority(
        risk_score=risk_result["risk_score"],
        business_impact_score=impact_result["business_impact_score"]
    )

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,
        "severity": finding.severity,
        "cvss_score": float(finding.cvss_score or 0),

        "host": finding.host,
        "port": finding.port,
        "endpoint": finding.endpoint,
        "database_name": finding.database_name,
        "file_path": finding.file_path,

        "asset_criticality": asset_criticality,

        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],

        "business_impact_score": impact_result[
            "business_impact_score"
        ],
        "business_impact_level": impact_result[
            "business_impact_level"
        ],

        "priority_score": priority_result[
            "priority_score"
        ],
        "priority": priority_result[
            "priority"
        ]
    }


# ============================================================
# BUSINESS IMPACT
# ============================================================

@router.get("/findings/{finding_id}/business-impact")
def analyze_business_impact(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found"
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == finding.asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Associated asset not found"
        )

    impact_result = calculate_business_impact(
        asset_criticality=asset.criticality,
        data_sensitivity=asset.data_sensitivity,
        operational_dependency=asset.operational_dependency,
        customer_impact=asset.customer_impact,
        financial_impact=asset.financial_impact
    )

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,

        "asset_criticality": asset.criticality,

        "business_impact_score": impact_result[
            "business_impact_score"
        ],

        "business_impact_level": impact_result[
            "business_impact_level"
        ],

        "potential_consequences": [
            "Payment processing disruption",
            "Potential exposure of sensitive customer data",
            "Customer service disruption",
            "Potential financial loss"
        ]
    }


# ============================================================
# PRIORITY ANALYSIS
# ============================================================

@router.get("/findings/{finding_id}/priority")
def analyze_priority(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found"
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == finding.asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Associated asset not found"
        )

    risk_result = calculate_risk(
        cvss_score=float(finding.cvss_score or 0),
        asset_criticality=asset.criticality,
        exposure=8,
        exploitability=9,
        business_impact=9
    )

    impact_result = calculate_business_impact(
        asset_criticality=asset.criticality,
        data_sensitivity=asset.data_sensitivity,
        operational_dependency=asset.operational_dependency,
        customer_impact=asset.customer_impact,
        financial_impact=asset.financial_impact
    )

    priority_result = calculate_priority(
        risk_score=risk_result["risk_score"],
        business_impact_score=impact_result[
            "business_impact_score"
        ]
    )

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,

        "risk_score": risk_result["risk_score"],

        "business_impact_score": impact_result[
            "business_impact_score"
        ],

        "priority_score": priority_result[
            "priority_score"
        ],

        "priority": priority_result[
            "priority"
        ]
    }


# ============================================================
# REMEDIATION
# ============================================================

@router.get("/findings/{finding_id}/remediation")
def get_finding_remediation(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found"
        )

    remediation_result = generate_remediation(
        finding_title=finding.title,
        severity=finding.severity
    )

    return {
        "finding_id": finding.id,
        "finding": finding.title,
        "severity": finding.severity,

        "host": finding.host,
        "port": finding.port,
        "endpoint": finding.endpoint,
        "database_name": finding.database_name,
        "file_path": finding.file_path,

        "remediation": remediation_result[
            "remediation"
        ],

        "recommended_actions": remediation_result[
            "recommended_actions"
        ]
    }


# ============================================================
# SECURITY POSTURE
# ============================================================

@router.get("/security-posture")
def get_security_posture(
    db: Session = Depends(get_db)
):
    return calculate_security_posture(db)


# ============================================================
# ASSET RISK
# ============================================================

@router.get("/{asset_id}/risk")
def analyze_asset_risk(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.asset_id == asset_id)
        .all()
    )

    if not findings:
        return {
            "asset_id": asset.id,
            "asset": asset.name,
            "criticality": asset.criticality,
            "risk_score": 0,
            "risk_level": "Low",
            "business_impact_score": 0,
            "priority": "Low",
            "critical_findings": 0,
            "open_findings": 0,
            "top_threats": []
        }

    risk_results = []

    for finding in findings:

        risk_result = calculate_risk(
            cvss_score=float(finding.cvss_score or 0),
            asset_criticality=asset.criticality,
            exposure=8,
            exploitability=9,
            business_impact=9
        )

        impact_result = calculate_business_impact(
            asset_criticality=asset.criticality,
            data_sensitivity=asset.data_sensitivity,
            operational_dependency=asset.operational_dependency,
            customer_impact=asset.customer_impact,
            financial_impact=asset.financial_impact
        )

        priority_result = calculate_priority(
            risk_score=risk_result["risk_score"],
            business_impact_score=impact_result[
                "business_impact_score"
            ]
        )

        risk_results.append({
            "finding_id": finding.id,
            "finding": finding.title,
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "business_impact_score": impact_result[
                "business_impact_score"
            ],
            "priority": priority_result["priority"]
        })

    overall_risk = round(
        sum(
            item["risk_score"]
            for item in risk_results
        ) / len(risk_results),
        2
    )

    if overall_risk >= 80:
        risk_level = "Critical"
    elif overall_risk >= 60:
        risk_level = "High"
    elif overall_risk >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    business_impact_score = round(
        sum(
            item["business_impact_score"]
            for item in risk_results
        ) / len(risk_results),
        2
    )

    priority_order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    highest_priority = max(
        risk_results,
        key=lambda item: priority_order.get(
            item["priority"],
            0
        )
    )

    critical_findings = sum(
        1
        for finding in findings
        if (finding.severity or "").lower() == "critical"
    )

    open_findings = sum(
        1
        for finding in findings
        if (finding.status or "").lower() == "open"
    )

    top_threats = [
        item["finding"]
        for item in sorted(
            risk_results,
            key=lambda item: item["risk_score"],
            reverse=True
        )[:5]
    ]

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "criticality": asset.criticality,
        "risk_score": overall_risk,
        "risk_level": risk_level,
        "business_impact_score": business_impact_score,
        "priority": highest_priority["priority"],
        "critical_findings": critical_findings,
        "open_findings": open_findings,
        "top_threats": top_threats
    }


# ============================================================
# ASSET EXPOSURE ANALYSIS
# ============================================================

@router.get("/{asset_id}/exposure")
def analyze_asset_exposure(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    return calculate_exposure(
        db=db,
        asset_id=asset_id
    )


# ============================================================
# UPDATE FINDING STATUS
# ============================================================

@router.put("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    status: str,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Security finding not found"
        )

    allowed_statuses = [
        "open",
        "in_progress",
        "resolved"
    ]

    normalized_status = status.strip().lower()

    if normalized_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid status",
                "allowed_statuses": allowed_statuses
            }
        )

    finding.status = normalized_status

    db.commit()
    db.refresh(finding)

    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "finding": finding.title,
        "status": finding.status,
        "message": "Finding status updated successfully"
    }


# ============================================================
# VERIFY REMEDIATION
# ============================================================

@router.get("/findings/{finding_id}/verify-remediation")
def verify_finding_remediation(
    finding_id: int,
    db: Session = Depends(get_db)
):
    return verify_remediation(
        db=db,
        finding_id=finding_id
    )


# ============================================================
# RISK REDUCTION
# ============================================================

@router.get("/findings/{finding_id}/risk-reduction")
def get_risk_reduction(
    finding_id: int,
    db: Session = Depends(get_db)
):
    return calculate_risk_reduction(
        db=db,
        finding_id=finding_id
    )


# ============================================================
# ASSET DISCOVERY
# ============================================================

@router.get("/{asset_id}/discover")
def discover_asset_details(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    discovery_result = discover_asset(
        asset.ip_address
    )

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "discovery": discovery_result
    }


# ============================================================
# SECURITY ASSESSMENT
# ============================================================

@router.get("/{asset_id}/security-assessment")
def security_assessment(
    asset_id: int,
    db: Session = Depends(get_db)
):
    return assess_asset_security(
        db=db,
        asset_id=asset_id
    )


# ============================================================
# SECURITY SCAN (MANUAL SCAN SINGLE ASSET - ON OR OFF)
# ============================================================

@router.get("/{asset_id}/scan")
@router.post("/{asset_id}/scan")
@router.post("/{asset_id}/scan-manual")
def scan_asset(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    if not asset.ip_address:
        raise HTTPException(
            status_code=400,
            detail="Asset does not have an IP address"
        )

    # 1. Update live reachability / power status (ON or OFF)
    reachability = check_host_reachability(asset.ip_address)
    is_online = reachability.get("reachable", False)
    asset.status = "online" if is_online else "offline"
    db.commit()

    # 2. Count existing open findings
    open_findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.asset_id == asset.id,
            SecurityFinding.status == "open"
        )
        .all()
    )

    # 3. Execute Dual-mode Security Scan (Online active scan or Offline dormant audit)
    scan_result = run_security_scan(
        ip_address=asset.ip_address,
        asset_type=asset.asset_type,
        asset_name=asset.name,
        criticality=getattr(asset, "criticality", 5) or 5,
        existing_findings_count=len(open_findings)
    )

    saved_findings = []

    for scan_finding in scan_result.get("findings", []):
        finding, is_new, was_resolved = save_scan_finding(
            db=db,
            asset=asset,
            scan_finding=scan_finding
        )

        if is_new or was_resolved:
            check_finding_for_alert(
                db=db,
                finding=finding,
                is_new=is_new
            )

        saved_findings.append({
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "action": "created" if is_new else "updated"
        })

    scan_record = create_scan_record(
        db=db,
        asset_id=asset.id,
        target=asset.ip_address,
        asset_type=asset.asset_type,
        total_findings=len(scan_result.get("findings", [])),
        risk_score=float(len(scan_result.get("findings", [])) * 2.5),
        status=scan_result.get("status", "completed"),
        scan_type="manual",
        is_online=is_online,
        scan_summary=[
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cvss_score": f.get("cvss_score"),
                "port": f.get("port")
            }
            for f in scan_result.get("findings", [])
        ]
    )

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "asset_type": asset.asset_type,
        "target": asset.ip_address,
        "is_online": is_online,
        "system_status": asset.status,
        "scan": scan_result,
        "saved_findings": saved_findings,
        "total_findings": len(saved_findings)
    }


# ============================================================
# MANUAL SCAN ALL SYSTEMS (BOTH ONLINE & OFFLINE)
# ============================================================

@router.post("/scan-all-manual")
@router.get("/scan-all-manual")
def scan_all_assets_manual(
    db: Session = Depends(get_db)
):
    """
    Manually triggers a complete security audit across ALL systems and servers.
    Audits active exposures for Online (ON) machines and downtime/dormant risks for Offline (OFF) machines.
    """
    assets = db.query(Asset).all()
    results = []
    online_count = 0
    offline_count = 0
    total_findings_count = 0

    for asset in assets:
        if not asset.ip_address or asset.ip_address.lower() == "string":
            continue

        try:
            # 1. Probe reachability
            reachability = check_host_reachability(asset.ip_address)
            is_online = reachability.get("reachable", False)
            asset.status = "online" if is_online else "offline"
            db.commit()

            if is_online:
                online_count += 1
            else:
                offline_count += 1

            # 2. Existing open findings
            open_findings = (
                db.query(SecurityFinding)
                .filter(
                    SecurityFinding.asset_id == asset.id,
                    SecurityFinding.status == "open"
                )
                .all()
            )

            # 3. Dual Scan
            scan_result = run_security_scan(
                ip_address=asset.ip_address,
                asset_type=asset.asset_type,
                asset_name=asset.name,
                criticality=getattr(asset, "criticality", 5) or 5,
                existing_findings_count=len(open_findings)
            )

            findings = scan_result.get("findings", [])
            total_findings_count += len(findings)

            for scan_finding in findings:
                finding, is_new, was_resolved = save_scan_finding(
                    db=db,
                    asset=asset,
                    scan_finding=scan_finding
                )
                if is_new or was_resolved:
                    check_finding_for_alert(
                        db=db,
                        finding=finding,
                        is_new=is_new
                    )

            create_scan_record(
                db=db,
                asset_id=asset.id,
                target=asset.ip_address,
                asset_type=asset.asset_type,
                total_findings=len(findings),
                risk_score=float(len(findings) * 2.5),
                status=scan_result.get("status", "completed"),
                scan_type="manual",
                is_online=is_online,
                scan_summary=[
                    {
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "cvss_score": f.get("cvss_score"),
                        "port": f.get("port")
                    }
                    for f in findings
                ]
            )

            results.append({
                "asset_id": asset.id,
                "name": asset.name,
                "ip_address": asset.ip_address,
                "asset_type": asset.asset_type,
                "status": asset.status,
                "is_online": is_online,
                "findings_count": len(findings),
                "scan_status": scan_result.get("status")
            })
        except Exception as e:
            print(f"[MANUAL SCAN ERROR] {asset.name}: {e}")

    return {
        "status": "completed",
        "message": f"Manual scan finished across {len(results)} system(s). Found {online_count} Online (ON) and {offline_count} Offline (OFF).",
        "total_systems_scanned": len(results),
        "online_systems": online_count,
        "offline_systems": offline_count,
        "total_findings_detected": total_findings_count,
        "assets": results
    }


# ============================================================
# MANUAL THREAT & ANOMALY DETECTION
# ============================================================

@router.post("/detect-threats-manual")
def detect_threats_manual(
    db: Session = Depends(get_db)
):
    """
    Executes a manual threat, anomaly, and firewall exposure analysis.
    Identifies high-risk openings, unencrypted channels, unexpected server downtime,
    and converts severe threats into actionable Security Incidents.
    """
    # 1. Run full system scan
    scan_summary = run_automatic_scan()

    # 2. Check for Critical/High findings and ensure incidents are logged
    open_critical_high = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.status == "open",
            SecurityFinding.severity.in_(["Critical", "High", "critical", "high"])
        )
        .all()
    )

    new_incidents = 0
    for finding in open_critical_high:
        existing_incident = (
            db.query(SecurityIncident)
            .filter(SecurityIncident.finding_id == finding.id)
            .first()
        )
        if not existing_incident:
            inc = SecurityIncident(
                finding_id=finding.id,
                asset_id=finding.asset_id,
                title=f"Automated Threat Incident: {finding.title}",
                severity=finding.severity,
                status="Open",
                description=f"Threat detector identified {finding.severity} risk: {finding.description}"
            )
            db.add(inc)
            new_incidents += 1

    db.commit()

    return {
        "status": "completed",
        "message": "Manual threat and anomaly detection completed.",
        "scan_summary": scan_summary,
        "critical_high_threats_active": len(open_critical_high),
        "new_incidents_created": new_incidents
    }


# ============================================================
# SYSTEM SUMMARY (DASHBOARD METRICS & POSTURE OVERVIEW)
# ============================================================

@router.get("/system-summary")
def get_system_summary(
    db: Session = Depends(get_db)
):
    assets = db.query(Asset).all()
    findings = db.query(SecurityFinding).filter(SecurityFinding.status == "open").all()
    auto_status = get_automatic_scanner_status()

    valid_assets = [a for a in assets if a.ip_address and a.ip_address.lower() != "string"]
    online_count = sum(1 for a in valid_assets if (a.status or "").lower() == "online")
    offline_count = sum(1 for a in valid_assets if (a.status or "").lower() != "online")

    critical_count = sum(1 for f in findings if (f.severity or "").lower() == "critical")
    high_count = sum(1 for f in findings if (f.severity or "").lower() == "high")
    medium_count = sum(1 for f in findings if (f.severity or "").lower() == "medium")
    low_count = sum(1 for f in findings if (f.severity or "").lower() == "low")

    return {
        "total_systems": len(valid_assets),
        "online_systems": online_count,
        "offline_systems": offline_count,
        "open_findings": len(findings),
        "severity_breakdown": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        },
        "auto_scanner": auto_status
    }


# ============================================================
# TRIGGER IMMEDIATE AUTOMATIC SCAN
# ============================================================

@router.post("/automatic-scan/trigger")
def trigger_auto_scan():
    summary = run_automatic_scan()
    return {
        "status": "triggered",
        "message": "Automated scan cycle executed immediately across all ON/OFF systems.",
        "summary": summary
    }


# ============================================================
# AI ASSISTANT (POWERED BY CLOUD APILM / GEMINI / OPENAI)
# ============================================================
# AI CYBERTWIN COPILOT (MULTI-TURN & ADVANCED REMEDIATION)
# ============================================================

class AIQuestion(BaseModel):
    question: str
    chat_history: Optional[List[Dict[str, str]]] = []
    view_mode: Optional[str] = "technical"
    target_asset_id: Optional[int] = None


@router.post("/ai/ask")
def ask_ai(
    data: AIQuestion,
    db: Session = Depends(get_db)
):
    findings_query = db.query(SecurityFinding).filter(SecurityFinding.status == "open")
    if data.target_asset_id:
        findings_query = findings_query.filter(SecurityFinding.asset_id == data.target_asset_id)
    findings = findings_query.all()

    context = []
    for finding in findings:
        asset = (
            db.query(Asset)
            .filter(Asset.id == finding.asset_id)
            .first()
        )

        context.append({
            "finding_id": finding.id,
            "asset": asset.name if asset else "Unknown Asset",
            "asset_type": asset.asset_type if asset else "Unknown",
            "asset_status": asset.status if asset else "offline",
            "ip_address": asset.ip_address if asset else None,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "vulnerability_type": finding.vulnerability_type,
            "affected_component": finding.affected_component,
            "host": finding.host,
            "port": finding.port,
            "endpoint": finding.endpoint,
            "database_name": finding.database_name,
            "file_path": finding.file_path,
            "status": finding.status,
            "remediation": finding.remediation
        })

    ai_response = ask_cybertwin_ai(
        question=data.question,
        context=context,
        chat_history=data.chat_history,
        view_mode=data.view_mode or "technical"
    )

    return {
        "question": data.question,
        "answer": ai_response.get("answer", ""),
        "provider": ai_response.get("provider", "APILM"),
        "model": ai_response.get("model", "APILM"),
        "status": ai_response.get("status", "success"),
        "view_mode": ai_response.get("view_mode", data.view_mode or "technical"),
        "compliance": ai_response.get("compliance", {}),
        "exploit_simulation": ai_response.get("exploit_simulation", {}),
        "remediation_script_bash": ai_response.get("remediation_script_bash", ""),
        "remediation_script_ps1": ai_response.get("remediation_script_ps1", ""),
        "target_vulnerability": ai_response.get("target_vulnerability", "Exposed Service"),
        "technical_markdown": ai_response.get("technical_markdown", ""),
        "executive_markdown": ai_response.get("executive_markdown", ""),
        "findings_considered": len(context)
    }


# ============================================================
# ASSET AVAILABILITY
# ============================================================

@router.get("/{asset_id}/availability")
def check_asset_availability(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    if not asset.ip_address:
        raise HTTPException(
            status_code=400,
            detail="Asset does not have an IP address"
        )

    result = check_host_reachability(
        asset.ip_address
    )

    asset.status = result["status"]

    event = AvailabilityEvent(
        asset_id=asset.id,
        status=result["status"],
        checked_at=datetime.utcnow(),
        response_time_ms=None,
        is_available=(
            result["status"].lower() == "online"
        ),
        message=result.get("message")
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "availability": result,
        "event_id": event.id
    }


# ============================================================
# AVAILABILITY HISTORY
# ============================================================

@router.get("/{asset_id}/availability/history")
def get_availability_history(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    events = (
        db.query(AvailabilityEvent)
        .filter(
            AvailabilityEvent.asset_id == asset_id
        )
        .order_by(
            AvailabilityEvent.checked_at.desc()
        )
        .all()
    )

    total_checks = len(events)

    online_checks = sum(
        1
        for event in events
        if (event.status or "").lower()
        in ["online", "passed"]
    )

    offline_checks = sum(
        1
        for event in events
        if (event.status or "").lower()
        in ["offline", "failed"]
    )

    if total_checks > 0:
        uptime_percentage = round(
            (online_checks / total_checks) * 100,
            2
        )
    else:
        uptime_percentage = 0

    if total_checks == 0:
        current_status = "unknown"
    elif offline_checks == 0:
        current_status = "online"
    elif online_checks == 0:
        current_status = "offline"
    else:
        current_status = "degraded"

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "current_status": current_status,
        "total_checks": total_checks,
        "online_checks": online_checks,
        "offline_checks": offline_checks,
        "uptime_percentage": uptime_percentage,

        "history": [
            {
                "event_id": event.id,

                "status": (
                    "online"
                    if (event.status or "").lower()
                    == "passed"
                    else "offline"
                    if (event.status or "").lower()
                    == "failed"
                    else event.status
                ),

                "checked_at": event.checked_at,

                "response_time_ms":
                    event.response_time_ms,

                "message": event.message
            }

            for event in events
        ]
    }


# ============================================================
# CREATE SECURITY INCIDENT
# ============================================================

@router.post("/findings/{finding_id}/incident")
def create_security_incident(
    finding_id: int,
    db: Session = Depends(get_db)
):
    result = create_incident(
        db=db,
        finding_id=finding_id
    )

    if "error" in result:
        raise HTTPException(
            status_code=404,
            detail=result["error"]
        )

    return result


# ============================================================
# GET ALL SECURITY INCIDENTS
# ============================================================

@router.get("/incidents/")
def get_security_incidents(
    db: Session = Depends(get_db)
):
    return list_incidents(db)


# ============================================================
# GET SINGLE SECURITY INCIDENT
# ============================================================

@router.get("/incidents/{incident_id}")
def get_security_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    result = get_incident(
        db=db,
        incident_id=incident_id
    )

    if "error" in result:
        raise HTTPException(
            status_code=404,
            detail=result["error"]
        )

    return result


# ============================================================
# UPDATE SECURITY INCIDENT STATUS
# ============================================================

@router.put("/incidents/{incident_id}/status")
def update_security_incident_status(
    incident_id: int,
    status: str,
    db: Session = Depends(get_db)
):
    result = update_incident_status(
        db=db,
        incident_id=incident_id,
        status=status
    )

    if "error" in result:
        raise HTTPException(
            status_code=400,
            detail=result["error"]
        )

    return result


# ============================================================
# SECURITY ALERTS (WITH DEPARTMENT & MANAGER ROUTING)
# ============================================================

@router.get("/alerts/")
def get_security_alerts(
    department: str = "all",
    status: str = "all",
    db: Session = Depends(get_db)
):
    return get_all_alerts(
        db=db,
        department=department,
        status=status
    )


# ============================================================
# ACTIVE / UNREAD SECURITY ALERTS
# ============================================================

@router.get("/alerts/active")
def get_active_security_alerts(
    db: Session = Depends(get_db)
):
    return get_all_alerts(
        db=db,
        status="unread"
    )


# ============================================================
# DEPARTMENT ALERT SUMMARY
# ============================================================

@router.get("/alerts/department-summary")
@router.get("/alerts/summary")
def get_security_alert_summary(
    db: Session = Depends(get_db)
):
    return get_department_alert_summary(db)


# ============================================================
# GET SINGLE SECURITY ALERT
# ============================================================

@router.get("/alerts/{alert_id}")
def get_security_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = get_alert(db=db, alert_id=alert_id)
    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )
    return alert


# ============================================================
# ACKNOWLEDGE SECURITY ALERT
# ============================================================

@router.put("/alerts/{alert_id}/acknowledge")
def acknowledge_security_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    result = acknowledge_alert(db=db, alert_id=alert_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )
    return result


# ============================================================
# SCAN HISTORY (ORGANIZATION-WIDE & PER-ASSET)
# ============================================================

@router.get("/scans/all")
def get_all_previous_scans(
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Retrieves all previous security scans stored across all systems."""
    return get_all_scan_history(db=db, limit=limit)


@router.delete("/scans/clear")
@router.post("/scans/clear")
def clear_historical_scans(
    db: Session = Depends(get_db)
):
    """Clears all historical scan logs from the database."""
    return clear_all_scan_history(db=db)


@router.get("/{asset_id}/scan-history")
def get_asset_scan_history(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    history = get_scan_history(
        db=db,
        asset_id=asset_id
    )

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "total_scans": len(history),
        "scans": history
    }


# ============================================================
# GET SINGLE SCAN
# ============================================================

@router.get("/scans/{scan_id}")
def get_single_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    scan = get_scan(
        db=db,
        scan_id=scan_id
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return scan


# ============================================================
# COMPLETE DATA PERSISTENCE & BACKUP EXPORT
# ============================================================

@router.get("/data/export")
def export_all_cybertwin_data(
    db: Session = Depends(get_db)
):
    """
    Exports all CyberTwin stored data (Assets, Findings, Scan History,
    Incidents, Alerts, Availability Events, and Firewall Rules) as a downloadable JSON backup.
    """
    assets = db.query(Asset).all()
    findings = db.query(SecurityFinding).all()
    scans = get_all_scan_history(db, limit=200)
    incidents = db.query(SecurityIncident).all()
    alerts = get_all_alerts(db)
    firewall_rules = get_firewall_rules(db)

    return {
        "export_metadata": {
            "platform": "CyberTwin Security Intelligence Platform",
            "version": "2.0.0",
            "exported_at": datetime.utcnow().isoformat(),
            "total_assets": len(assets),
            "total_findings": len(findings),
            "total_scans": len(scans),
            "total_alerts": len(alerts),
            "total_firewall_rules": len(firewall_rules)
        },
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "ip_address": a.ip_address,
                "status": a.status,
                "criticality": a.criticality,
                "risk_level": a.risk_level
            }
            for a in assets
        ],
        "findings": [
            {
                "id": f.id,
                "asset_id": f.asset_id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "vulnerability_type": f.vulnerability_type,
                "affected_component": f.affected_component,
                "host": f.host,
                "port": f.port,
                "status": f.status,
                "remediation": f.remediation
            }
            for f in findings
        ],
        "scans": scans,
        "incidents": [
            {
                "id": inc.id,
                "finding_id": inc.finding_id,
                "asset_id": inc.asset_id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "description": inc.description,
                "created_at": inc.created_at.isoformat() if inc.created_at else None
            }
            for inc in incidents
        ],
        "alerts": alerts,
        "firewall_rules": firewall_rules
    }


# ============================================================
# FIREWALL MANAGEMENT & ACTIVE SHIELD
# ============================================================

@router.get("/firewall/status")
def firewall_status():
    return get_firewall_status()


@router.get("/firewall/rules")
def list_firewall_rules(
    db: Session = Depends(get_db)
):
    return get_firewall_rules(db=db)


class FirewallRuleCreate(BaseModel):
    rule_name: str
    direction: str = "Inbound"
    protocol: str = "TCP"
    port: str
    action: str = "BLOCK"
    source_ip: str = "0.0.0.0/0"
    description: Optional[str] = None
    target_asset_id: Optional[int] = None


@router.post("/firewall/rules")
def add_firewall_rule(
    data: FirewallRuleCreate,
    db: Session = Depends(get_db)
):
    return create_firewall_rule(db=db, rule_data=data.model_dump())


@router.put("/firewall/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: int,
    db: Session = Depends(get_db)
):
    res = toggle_firewall_rule(db=db, rule_id=rule_id)
    if not res:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return res


@router.delete("/firewall/rules/{rule_id}")
def remove_rule(
    rule_id: int,
    db: Session = Depends(get_db)
):
    success = delete_firewall_rule(db=db, rule_id=rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return {"status": "deleted", "message": f"Firewall rule #{rule_id} removed."}


@router.post("/firewall/apply-baseline")
def enforce_defense_baseline(
    db: Session = Depends(get_db)
):
    return apply_defense_baseline(db=db)


class BlockPortRequest(BaseModel):
    port: str
    service_name: Optional[str] = "Exposed Service"


@router.post("/firewall/block-port")
def quick_block_port(
    data: BlockPortRequest,
    db: Session = Depends(get_db)
):
    return block_port_with_firewall(
        db=db,
        port=data.port,
        service_name=data.service_name or "Exposed Service"
    )


# ============================================================
# AUTOMATIC SCANNER
# ============================================================

class AutoScanStartRequest(BaseModel):
    interval_seconds: Optional[int] = 60


@router.post("/automatic-scan/start")
def start_auto_scan(
    payload: Optional[AutoScanStartRequest] = None,
    interval_seconds: Optional[int] = 60
):
    seconds = 60
    if payload and payload.interval_seconds:
        seconds = payload.interval_seconds
    elif interval_seconds:
        seconds = interval_seconds
    return start_automatic_scanner(interval_seconds=seconds)


@router.post("/automatic-scan/set-interval")
def update_auto_scan_interval(
    payload: AutoScanStartRequest
):
    return set_scan_interval(interval_seconds=payload.interval_seconds or 60)


# ============================================================
# STOP AUTOMATIC SCANNER
# ============================================================

@router.post("/automatic-scan/stop")
def stop_auto_scan():
    return stop_automatic_scanner()


# ============================================================
# AUTOMATIC SCANNER STATUS
# ============================================================

@router.get("/automatic-scan/status")
def automatic_scan_status():
    return get_automatic_scanner_status()