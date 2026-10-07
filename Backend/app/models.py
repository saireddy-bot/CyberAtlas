from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    Boolean,
    DateTime
)

from sqlalchemy.sql import func

from .database import Base


# ============================================================
# ASSET
# ============================================================

class Asset(Base):
    __tablename__ = "assets"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    asset_type = Column(
        String,
        nullable=False
    )

    ip_address = Column(
        String,
        nullable=True
    )

    criticality = Column(
        Integer,
        nullable=False,
        default=5
    )

    data_sensitivity = Column(
        Integer,
        nullable=False,
        default=5
    )

    operational_dependency = Column(
        Integer,
        nullable=False,
        default=5
    )

    customer_impact = Column(
        Integer,
        nullable=False,
        default=5
    )

    financial_impact = Column(
        Integer,
        nullable=False,
        default=5
    )

    description = Column(
        Text,
        nullable=True
    )

    status = Column(
        String,
        nullable=True,
        default="active"
    )

    risk_level = Column(
        String,
        nullable=True,
        default="Low"
    )


# ============================================================
# SECURITY FINDING
# ============================================================

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    severity = Column(
        String,
        nullable=False
    )

    cvss_score = Column(
        String,
        nullable=True
    )

    vulnerability_type = Column(
        String,
        nullable=True
    )

    affected_component = Column(
        String,
        nullable=True
    )

    # --------------------------------------------------------
    # Location-aware finding information
    # --------------------------------------------------------

    host = Column(
        String,
        nullable=True
    )

    port = Column(
        String,
        nullable=True
    )

    endpoint = Column(
        String,
        nullable=True
    )

    database_name = Column(
        String,
        nullable=True
    )

    file_path = Column(
        String,
        nullable=True
    )

    status = Column(
        String,
        default="open"
    )

    remediation = Column(
        Text,
        nullable=True
    )


# ============================================================
# ASSET RESOURCE
# ============================================================

class AssetResource(Base):
    __tablename__ = "asset_resources"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    resource_type = Column(
        String,
        nullable=True
    )

    name = Column(
        String,
        nullable=True
    )

    location = Column(
        String,
        nullable=True
    )

    status = Column(
        String,
        nullable=True,
        default="active"
    )


# ============================================================
# SECURITY SCAN
# ============================================================

class SecurityScan(Base):
    __tablename__ = "security_scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    status = Column(
        String,
        nullable=False,
        default="completed"
    )

    scan_type = Column(
        String,
        nullable=True,
        default="manual"
    )

    is_online = Column(
        Boolean,
        default=True
    )

    target = Column(
        String,
        nullable=True
    )

    asset_type = Column(
        String,
        nullable=True
    )

    total_findings = Column(
        Integer,
        nullable=True,
        default=0
    )

    risk_score = Column(
        Float,
        nullable=True
    )

    scan_summary = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )


# ============================================================
# AVAILABILITY EVENT
# ============================================================

class AvailabilityEvent(Base):
    __tablename__ = "availability_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    status = Column(
        String,
        nullable=False
    )

    response_time_ms = Column(
        Float,
        nullable=True
    )

    is_available = Column(
        Boolean,
        default=True
    )

    message = Column(
        Text,
        nullable=True
    )

    checked_at = Column(
        DateTime,
        server_default=func.now()
    )


# ============================================================
# MONITORING STATE
# ============================================================

class MonitoringState(Base):
    __tablename__ = "monitoring_state"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    is_monitoring = Column(
        Boolean,
        default=False
    )

    status = Column(
        String,
        nullable=True,
        default="stopped"
    )

    started_at = Column(
        DateTime,
        nullable=True
    )

    stopped_at = Column(
        DateTime,
        nullable=True
    )

    last_checked_at = Column(
        DateTime,
        nullable=True
    )


# ============================================================
# SECURITY INCIDENT
# ============================================================

class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    finding_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="Open"
    )

    description = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

# ============================================================
# SECURITY ALERT (WITH DEPARTMENT & MANAGER ROUTING)
# ============================================================

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    finding_id = Column(
        Integer,
        nullable=True,
        index=True
    )

    asset_id = Column(
        Integer,
        nullable=True,
        index=True
    )

    alert_type = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False
    )

    department = Column(
        String,
        nullable=True,
        default="Information Security"
    )

    manager_notified = Column(
        Boolean,
        default=True
    )

    manager_role = Column(
        String,
        nullable=True,
        default="Company Security Manager / CISO"
    )

    notification_channel = Column(
        String,
        nullable=True,
        default="Dashboard & Alert Feed"
    )

    title = Column(
        String,
        nullable=False
    )

    message = Column(
        Text,
        nullable=True
    )

    host = Column(
        String,
        nullable=True
    )

    port = Column(
        String,
        nullable=True
    )

    endpoint = Column(
        String,
        nullable=True
    )

    database_name = Column(
        String,
        nullable=True
    )

    file_path = Column(
        String,
        nullable=True
    )

    status = Column(
        String,
        nullable=False,
        default="unread"
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    acknowledged_at = Column(
        DateTime,
        nullable=True
    )


# ============================================================
# FIREWALL RULE (CYBERTWIN ACTIVE DEFENSE SHIELD)
# ============================================================

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    rule_name = Column(
        String,
        nullable=False
    )

    direction = Column(
        String,
        nullable=False,
        default="Inbound"
    )

    protocol = Column(
        String,
        nullable=False,
        default="TCP"
    )

    port = Column(
        String,
        nullable=False
    )

    action = Column(
        String,
        nullable=False,
        default="BLOCK"
    )

    target_asset_id = Column(
        Integer,
        nullable=True
    )

    source_ip = Column(
        String,
        nullable=False,
        default="0.0.0.0/0"
    )

    status = Column(
        String,
        nullable=False,
        default="active"
    )

    description = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )