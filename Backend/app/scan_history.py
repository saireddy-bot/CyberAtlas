import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from .models import SecurityScan, Asset


def create_scan_record(
    db: Session,
    asset_id: int,
    target: str,
    asset_type: str,
    total_findings: int,
    risk_score: float = 0,
    status: str = "completed",
    scan_type: str = "manual",
    is_online: bool = True,
    scan_summary: Optional[Any] = None
) -> SecurityScan:
    """Creates and persists a comprehensive security scan record."""
    summary_text = None
    if scan_summary is not None:
        if isinstance(scan_summary, (dict, list)):
            summary_text = json.dumps(scan_summary, default=str)
        else:
            summary_text = str(scan_summary)

    scan = SecurityScan(
        asset_id=asset_id,
        target=target,
        asset_type=asset_type,
        total_findings=total_findings,
        risk_score=risk_score,
        status=status,
        scan_type=scan_type,
        is_online=is_online,
        scan_summary=summary_text
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan_history(
    db: Session,
    asset_id: int
) -> List[Dict[str, Any]]:
    """Returns previous scans for a specific asset."""
    scans = (
        db.query(SecurityScan)
        .filter(SecurityScan.asset_id == asset_id)
        .order_by(SecurityScan.id.desc())
        .all()
    )

    return [
        {
            "scan_id": scan.id,
            "asset_id": scan.asset_id,
            "target": scan.target,
            "asset_type": scan.asset_type,
            "scan_type": scan.scan_type or "manual",
            "is_online": scan.is_online if scan.is_online is not None else True,
            "status": scan.status,
            "total_findings": scan.total_findings,
            "risk_score": scan.risk_score,
            "created_at": scan.created_at.isoformat() if scan.created_at else None
        }
        for scan in scans
    ]


def get_all_scan_history(
    db: Session,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Returns all previous scans across all systems in the organization."""
    scans = (
        db.query(SecurityScan)
        .order_by(SecurityScan.id.desc())
        .limit(limit)
        .all()
    )

    results = []
    for scan in scans:
        asset = db.query(Asset).filter(Asset.id == scan.asset_id).first()
        results.append({
            "scan_id": scan.id,
            "asset_id": scan.asset_id,
            "asset_name": asset.name if asset else "Target Server",
            "target": scan.target,
            "asset_type": scan.asset_type,
            "scan_type": scan.scan_type or "manual",
            "is_online": scan.is_online if scan.is_online is not None else True,
            "status": scan.status,
            "total_findings": scan.total_findings,
            "risk_score": scan.risk_score,
            "created_at": scan.created_at.isoformat() if scan.created_at else None
        })

    return results


def get_scan(
    db: Session,
    scan_id: int
) -> Optional[Dict[str, Any]]:
    """Returns details and findings snapshot for a single historical scan."""
    scan = (
        db.query(SecurityScan)
        .filter(SecurityScan.id == scan_id)
        .first()
    )

    if not scan:
        return None

    asset = db.query(Asset).filter(Asset.id == scan.asset_id).first()

    summary_obj = None
    if scan.scan_summary:
        try:
            summary_obj = json.loads(scan.scan_summary)
        except Exception:
            summary_obj = scan.scan_summary

    return {
        "scan_id": scan.id,
        "asset_id": scan.asset_id,
        "asset_name": asset.name if asset else "Target Server",
        "target": scan.target,
        "asset_type": scan.asset_type,
        "scan_type": scan.scan_type or "manual",
        "is_online": scan.is_online if scan.is_online is not None else True,
        "status": scan.status,
        "total_findings": scan.total_findings,
        "risk_score": scan.risk_score,
        "scan_summary": summary_obj,
        "created_at": scan.created_at.isoformat() if scan.created_at else None
    }


def clear_all_scan_history(
    db: Session
) -> Dict[str, Any]:
    """Clears all historical scan records from the database."""
    count = db.query(SecurityScan).delete()
    db.commit()
    return {
        "status": "cleared",
        "deleted_count": count,
        "message": f"Successfully cleared {count} scan history record(s)."
    }