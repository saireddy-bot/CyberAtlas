from datetime import datetime

from sqlalchemy.orm import Session

from .models import (
    Asset,
    MonitoringState,
    AvailabilityEvent
)

from .availability_monitor import check_host_reachability


# ============================================================
# MONITOR ASSET
# ============================================================

def monitor_asset(
    db: Session,
    asset_id: int
):
    """
    Check the current availability of an asset,
    compare it with the previous monitoring state,
    update monitoring state,
    and store an availability event.
    """

    # --------------------------------------------------------
    # Find asset
    # --------------------------------------------------------

    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "error": "Asset not found"
        }

    if not asset.ip_address:
        return {
            "error": "Asset does not have an IP address"
        }

    # --------------------------------------------------------
    # Check current host availability
    # --------------------------------------------------------

    availability_result = check_host_reachability(
        asset.ip_address
    )

    current_status = (
        availability_result.get(
            "status",
            "unknown"
        )
        .lower()
    )

    # Normalize possible status values
    if current_status in ["online", "passed", "up"]:
        current_status = "online"

    elif current_status in ["offline", "failed", "down"]:
        current_status = "offline"

    else:
        current_status = "unknown"

    checked_at = datetime.utcnow()

    # --------------------------------------------------------
    # Get existing monitoring state
    # --------------------------------------------------------

    monitoring_state = db.query(
        MonitoringState
    ).filter(
        MonitoringState.asset_id == asset.id
    ).first()

    # --------------------------------------------------------
    # Create monitoring state if it does not exist
    # --------------------------------------------------------

    if not monitoring_state:

        monitoring_state = MonitoringState(
            asset_id=asset.id,
            is_monitoring=True,
            status=current_status,
            started_at=checked_at,
            stopped_at=None,
            last_checked_at=checked_at
        )

        db.add(monitoring_state)

        previous_status = None

        state_changed = False

    else:

        previous_status = (
            monitoring_state.status
            if monitoring_state.status
            else None
        )

        state_changed = (
            previous_status != current_status
            and previous_status is not None
        )

        # ----------------------------------------------------
        # Update monitoring state
        # ----------------------------------------------------

        monitoring_state.is_monitoring = True
        monitoring_state.status = current_status
        monitoring_state.last_checked_at = checked_at

        if current_status == "offline":
            monitoring_state.stopped_at = checked_at

        elif (
            current_status == "online"
            and previous_status == "offline"
        ):
            monitoring_state.started_at = checked_at
            monitoring_state.stopped_at = None

    # --------------------------------------------------------
    # Update asset status
    # --------------------------------------------------------

    if current_status == "online":
        asset.status = "online"

    elif current_status == "offline":
        asset.status = "offline"

    else:
        asset.status = "unknown"

    # --------------------------------------------------------
    # Store availability event
    # --------------------------------------------------------

    availability_event = AvailabilityEvent(
        asset_id=asset.id,
        status=current_status,
        response_time_ms=None,
        is_available=(
            current_status == "online"
        ),
        message=availability_result.get(
            "message"
        ),
        checked_at=checked_at
    )

    db.add(availability_event)

    # --------------------------------------------------------
    # Save everything
    # --------------------------------------------------------

    db.commit()

    db.refresh(monitoring_state)
    db.refresh(availability_event)

    # --------------------------------------------------------
    # Determine event type
    # --------------------------------------------------------

    event_type = None

    if previous_status is None:
        event_type = "INITIAL_STATUS"

    elif (
        previous_status == "online"
        and current_status == "offline"
    ):
        event_type = "SYSTEM_DOWN"

    elif (
        previous_status == "offline"
        and current_status == "online"
    ):
        event_type = "SYSTEM_RECOVERED"

    elif state_changed:
        event_type = "STATUS_CHANGED"

    # --------------------------------------------------------
    # Return monitoring result
    # --------------------------------------------------------

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,

        "current_status": current_status,
        "previous_status": previous_status,

        "state_changed": state_changed,
        "event_type": event_type,

        "monitoring": {
            "is_monitoring": monitoring_state.is_monitoring,
            "started_at": monitoring_state.started_at,
            "stopped_at": monitoring_state.stopped_at,
            "last_checked_at": monitoring_state.last_checked_at
        },

        "availability_event": {
            "event_id": availability_event.id,
            "status": availability_event.status,
            "is_available": availability_event.is_available,
            "checked_at": availability_event.checked_at,
            "message": availability_event.message
        },

        "message": (
            "Asset monitoring check completed successfully."
        )
    }


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring(
    db: Session,
    asset_id: int
):
    """
    Start monitoring an asset.
    """

    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "error": "Asset not found"
        }

    monitoring_state = db.query(
        MonitoringState
    ).filter(
        MonitoringState.asset_id == asset_id
    ).first()

    now = datetime.utcnow()

    if not monitoring_state:

        monitoring_state = MonitoringState(
            asset_id=asset_id,
            is_monitoring=True,
            status="unknown",
            started_at=now,
            stopped_at=None,
            last_checked_at=None
        )

        db.add(monitoring_state)

    else:

        monitoring_state.is_monitoring = True
        monitoring_state.started_at = now
        monitoring_state.stopped_at = None

    db.commit()
    db.refresh(monitoring_state)

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "is_monitoring": monitoring_state.is_monitoring,
        "status": monitoring_state.status,
        "started_at": monitoring_state.started_at,
        "message": "Asset monitoring started successfully."
    }


# ============================================================
# STOP MONITORING
# ============================================================

def stop_monitoring(
    db: Session,
    asset_id: int
):
    """
    Stop monitoring an asset.
    """

    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "error": "Asset not found"
        }

    monitoring_state = db.query(
        MonitoringState
    ).filter(
        MonitoringState.asset_id == asset_id
    ).first()

    if not monitoring_state:
        return {
            "error": "Monitoring has not been configured for this asset."
        }

    now = datetime.utcnow()

    monitoring_state.is_monitoring = False
    monitoring_state.status = "stopped"
    monitoring_state.stopped_at = now

    db.commit()
    db.refresh(monitoring_state)

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "is_monitoring": monitoring_state.is_monitoring,
        "status": monitoring_state.status,
        "stopped_at": monitoring_state.stopped_at,
        "message": "Asset monitoring stopped successfully."
    }


# ============================================================
# GET MONITORING STATUS
# ============================================================

def get_monitoring_status(
    db: Session,
    asset_id: int
):
    """
    Return the current monitoring state of an asset.
    """

    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "error": "Asset not found"
        }

    monitoring_state = db.query(
        MonitoringState
    ).filter(
        MonitoringState.asset_id == asset_id
    ).first()

    if not monitoring_state:
        return {
            "asset_id": asset.id,
            "asset": asset.name,
            "is_monitoring": False,
            "status": "not_configured",
            "message": "Monitoring has not been configured for this asset."
        }

    return {
        "asset_id": asset.id,
        "asset": asset.name,
        "ip_address": asset.ip_address,
        "is_monitoring": monitoring_state.is_monitoring,
        "status": monitoring_state.status,
        "started_at": monitoring_state.started_at,
        "stopped_at": monitoring_state.stopped_at,
        "last_checked_at": monitoring_state.last_checked_at
    }