import time
from datetime import datetime

from .database import SessionLocal
from .models import (
    Asset,
    AvailabilityEvent,
    MonitoringState
)
from .scanner import check_host_reachability


def monitor_assets():
    """
    Background worker that iterates through all assets, probes reachability,
    logs availability events, and updates monitoring state.
    """
    db = SessionLocal()

    try:
        assets = db.query(Asset).filter(
            Asset.ip_address.isnot(None)
        ).all()

        for asset in assets:
            if not asset.ip_address or asset.ip_address.lower() == "string":
                continue

            try:
                # 1. Probe reachability
                reachability_result = check_host_reachability(asset.ip_address)
                is_online = reachability_result.get("reachable", False)
                current_status = "online" if is_online else "offline"
                now = datetime.utcnow()

                # 2. Log availability event
                event = AvailabilityEvent(
                    asset_id=asset.id,
                    status=current_status,
                    checked_at=now,
                    response_time_ms=None,
                    is_available=is_online,
                    message=reachability_result.get("message")
                )
                db.add(event)

                # 3. Update or create monitoring state
                state = db.query(MonitoringState).filter(
                    MonitoringState.asset_id == asset.id
                ).first()

                if not state:
                    state = MonitoringState(
                        asset_id=asset.id,
                        is_monitoring=True,
                        status=current_status,
                        started_at=now,
                        stopped_at=None if is_online else now,
                        last_checked_at=now
                    )
                    db.add(state)
                else:
                    state.is_monitoring = True
                    state.status = current_status
                    state.last_checked_at = now
                    if is_online and state.stopped_at is not None:
                        state.stopped_at = None
                    elif not is_online and state.stopped_at is None:
                        state.stopped_at = now

                # 4. Update asset status
                asset.status = current_status
                db.commit()

            except Exception as e:
                db.rollback()
                print(f"[CYBERTWIN MONITOR ERROR] Failed monitoring asset {asset.name}: {e}")

    finally:
        db.close()


def start_monitoring(interval_seconds=60):
    """
    Daemon loop for continuous background monitoring.
    """
    while True:
        try:
            monitor_assets()
        except Exception as e:
            print(f"[CYBERTWIN MONITOR DAEMON ERROR] {e}")
        time.sleep(interval_seconds)