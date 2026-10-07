from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timezone
import uuid

router = APIRouter(prefix="/users", tags=["User & Access Management"])

# ============================================================
# PYDANTIC SCHEMAS
# ============================================================

class UserCreate(BaseModel):
    full_name: str
    email: str
    role: str
    department: str
    status: Optional[str] = "Active"

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    status: Optional[str] = None
    mfa_enabled: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    role: str
    department: str
    status: str
    mfa_enabled: bool
    avatar_color: str
    api_key_preview: str
    last_login: str
    created_at: str

class AuditLogItem(BaseModel):
    id: str
    user_name: str
    action: str
    ip_address: str
    timestamp: str
    severity: str

class SessionItem(BaseModel):
    id: str
    device_name: str
    browser: str
    ip_address: str
    location: str
    is_current: bool
    last_active: str


# ============================================================
# IN-MEMORY SOC USERS & AUDIT REPOSITORY
# ============================================================

USERS_DB = [
    {
        "id": 1,
        "full_name": "Sai Reddy (You)",
        "email": "sai.reddy@cyberatlas.soc",
        "role": "SOC Lead / Admin",
        "department": "SOC Operations",
        "status": "Active",
        "mfa_enabled": True,
        "avatar_color": "#06b6d4",
        "api_key_preview": "ct_sec_live_98a7...f41e",
        "last_login": "Just now",
        "created_at": "2026-01-15"
    },
    {
        "id": 2,
        "full_name": "Sarah Connor",
        "email": "sarah.c@cyberatlas.soc",
        "role": "Senior Threat Analyst",
        "department": "Threat Intelligence",
        "status": "Active",
        "mfa_enabled": True,
        "avatar_color": "#8b5cf6",
        "api_key_preview": "ct_sec_live_33b1...81aa",
        "last_login": "12 mins ago",
        "created_at": "2026-02-01"
    },
    {
        "id": 3,
        "full_name": "David Chen",
        "email": "d.chen@cyberatlas.soc",
        "role": "Tier-1 Incident Responder",
        "department": "SOC Operations",
        "status": "Active",
        "mfa_enabled": True,
        "avatar_color": "#10b981",
        "api_key_preview": "ct_sec_live_77c2...52bd",
        "last_login": "1 hour ago",
        "created_at": "2026-02-10"
    },
    {
        "id": 4,
        "full_name": "Elena Rostova",
        "email": "elena.r@cyberatlas.soc",
        "role": "Compliance Auditor",
        "department": "Compliance & GRC",
        "status": "Active",
        "mfa_enabled": True,
        "avatar_color": "#f59e0b",
        "api_key_preview": "ct_sec_live_12de...99ff",
        "last_login": "Yesterday",
        "created_at": "2026-02-18"
    },
    {
        "id": 5,
        "full_name": "Marcus Brody",
        "email": "marcus.b@cyberatlas.soc",
        "role": "IT Department Head",
        "department": "Infrastructure",
        "status": "Inactive",
        "mfa_enabled": False,
        "avatar_color": "#64748b",
        "api_key_preview": "ct_sec_live_44ee...11aa",
        "last_login": "3 days ago",
        "created_at": "2026-03-01"
    }
]

AUDIT_LOGS_DB = [
    {
        "id": "AUD-9821",
        "user_name": "Alex Vance",
        "action": "Updated Firewall Policy: Blocked Inbound Port 445 (SMB)",
        "ip_address": "10.104.57.193",
        "timestamp": "2 mins ago",
        "severity": "high"
    },
    {
        "id": "AUD-9820",
        "user_name": "Sai Reddy",
        "action": "Initiated Automated Vulnerability Scan across Payment Subnet",
        "ip_address": "10.104.57.193",
        "timestamp": "14 mins ago",
        "severity": "medium"
    },
    {
        "id": "AUD-9819",
        "user_name": "Sarah Connor",
        "action": "Triaged Threat Detection: Critical CVE-2026-2104 on DB Cluster",
        "ip_address": "192.168.1.104",
        "timestamp": "45 mins ago",
        "severity": "critical"
    },
    {
        "id": "AUD-9818",
        "user_name": "Elena Rostova",
        "action": "Exported ISO 27001 SOC Compliance Audit Report (PDF)",
        "ip_address": "10.104.57.210",
        "timestamp": "3 hours ago",
        "severity": "low"
    },
    {
        "id": "AUD-9817",
        "user_name": "Sai Reddy",
        "action": "Authenticated with Hardware FIDO2 Security Key",
        "ip_address": "10.104.57.193",
        "timestamp": "5 hours ago",
        "severity": "low"
    }
]

SESSIONS_DB = [
    {
        "id": "sess_1",
        "device_name": "SOC Management Workstation (Windows 11)",
        "browser": "Chrome 134.0 (Enterprise SOC Profile)",
        "ip_address": "10.104.57.193",
        "location": "Local Security Center",
        "is_current": True,
        "last_active": "Active Now"
    },
    {
        "id": "sess_2",
        "device_name": "SOC Mobile Security Monitor (iOS 19)",
        "browser": "Safari Mobile",
        "ip_address": "2409:40f4:af:510a",
        "location": "Verified Cellular VPN",
        "is_current": False,
        "last_active": "1 hour ago"
    }
]


# ============================================================
# API ENDPOINTS
# ============================================================

@router.get("/", response_model=List[UserResponse])
def get_all_users():
    """Retrieve all users in the SOC organization."""
    return USERS_DB

@router.get("/me", response_model=UserResponse)
def get_current_user():
    """Retrieve the current logged-in analyst profile."""
    return USERS_DB[0]

@router.post("/", response_model=UserResponse, status_code=201)
def create_user(user_in: UserCreate):
    """Create / invite a new SOC team member."""
    new_id = max([u["id"] for u in USERS_DB], default=0) + 1
    
    # Random stylish avatar accent colors
    colors = ["#06b6d4", "#8b5cf6", "#10b981", "#ec4899", "#f59e0b", "#3b82f6"]
    avatar_color = colors[new_id % len(colors)]
    
    random_hex = uuid.uuid4().hex[:8]
    api_key = f"ct_sec_live_{random_hex[:4]}...{random_hex[4:]}"
    
    new_user = {
        "id": new_id,
        "full_name": user_in.full_name,
        "email": user_in.email,
        "role": user_in.role,
        "department": user_in.department,
        "status": user_in.status or "Active",
        "mfa_enabled": False,
        "avatar_color": avatar_color,
        "api_key_preview": api_key,
        "last_login": "Never",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d")
    }
    
    USERS_DB.append(new_user)
    
    # Add audit log
    AUDIT_LOGS_DB.insert(0, {
        "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
        "user_name": "Sai Reddy",
        "action": f"Created new user account: {new_user['full_name']} ({new_user['role']})",
        "ip_address": "10.104.57.193",
        "timestamp": "Just now",
        "severity": "medium"
    })
    
    return new_user

@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_in: UserUpdate):
    """Update user role, department, or active status."""
    for user in USERS_DB:
        if user["id"] == user_id:
            if user_in.full_name is not None:
                user["full_name"] = user_in.full_name
            if user_in.role is not None:
                user["role"] = user_in.role
            if user_in.department is not None:
                user["department"] = user_in.department
            if user_in.status is not None:
                user["status"] = user_in.status
            if user_in.mfa_enabled is not None:
                user["mfa_enabled"] = user_in.mfa_enabled
                
            AUDIT_LOGS_DB.insert(0, {
                "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
                "user_name": "Sai Reddy",
                "action": f"Updated profile/permissions for {user['full_name']}",
                "ip_address": "10.104.57.193",
                "timestamp": "Just now",
                "severity": "low"
            })
            return user
            
    raise HTTPException(status_code=404, detail="User not found")

@router.delete("/{user_id}")
def delete_user(user_id: int):
    """Deactivate or remove a team member."""
    if user_id == 1:
        raise HTTPException(status_code=400, detail="Cannot delete the primary Lead SOC Administrator account.")
        
    for index, user in enumerate(USERS_DB):
        if user["id"] == user_id:
            removed = USERS_DB.pop(index)
            AUDIT_LOGS_DB.insert(0, {
                "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
                "user_name": "Alex Vance",
                "action": f"Revoked and deleted user account: {removed['full_name']}",
                "ip_address": "10.104.57.193",
                "timestamp": "Just now",
                "severity": "high"
            })
            return {"status": "success", "message": f"User {removed['full_name']} removed."}
            
    raise HTTPException(status_code=404, detail="User not found")

@router.post("/me/toggle-2fa")
def toggle_2fa():
    """Toggle 2FA state for current analyst."""
    current_user = USERS_DB[0]
    current_user["mfa_enabled"] = not current_user["mfa_enabled"]
    state_str = "ENABLED" if current_user["mfa_enabled"] else "DISABLED"
    
    AUDIT_LOGS_DB.insert(0, {
        "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
        "user_name": current_user["full_name"],
        "action": f"Security Policy Change: 2FA MFA {state_str}",
        "ip_address": "10.104.57.193",
        "timestamp": "Just now",
        "severity": "high" if not current_user["mfa_enabled"] else "low"
    })
    
    return {
        "status": "success",
        "mfa_enabled": current_user["mfa_enabled"],
        "message": f"Two-Factor Authentication is now {state_str}."
    }

@router.post("/me/generate-api-key")
def generate_api_key():
    """Generate a fresh personal SOC API Token."""
    new_token = f"ct_sec_live_{uuid.uuid4().hex[:12]}"
    USERS_DB[0]["api_key_preview"] = f"{new_token[:11]}...{new_token[-4:]}"
    
    AUDIT_LOGS_DB.insert(0, {
        "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
        "user_name": USERS_DB[0]["full_name"],
        "action": "Generated fresh Personal Access API Token",
        "ip_address": "10.104.57.193",
        "timestamp": "Just now",
        "severity": "medium"
    })
    
    return {
        "status": "success",
        "api_key": new_token,
        "preview": USERS_DB[0]["api_key_preview"]
    }

@router.get("/audit-logs", response_model=List[AuditLogItem])
def get_audit_logs():
    """Retrieve security audit trails."""
    return AUDIT_LOGS_DB

@router.get("/sessions", response_model=List[SessionItem])
def get_active_sessions():
    """Retrieve active login sessions."""
    return SESSIONS_DB

@router.post("/sessions/revoke-others")
def revoke_other_sessions():
    """Revoke all active sessions except the current one."""
    global SESSIONS_DB
    SESSIONS_DB = [s for s in SESSIONS_DB if s["is_current"]]
    
    AUDIT_LOGS_DB.insert(0, {
        "id": f"AUD-{uuid.uuid4().hex[:4].upper()}",
        "user_name": USERS_DB[0]["full_name"],
        "action": "Terminated all remote active login sessions",
        "ip_address": "10.104.57.193",
        "timestamp": "Just now",
        "severity": "medium"
    })
    
    return {"status": "success", "message": "All other sessions revoked."}
