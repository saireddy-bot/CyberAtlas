from pydantic import BaseModel, ConfigDict


class AssetCreate(BaseModel):
    name: str
    asset_type: str
    ip_address: str | None = None
    status: str = "unknown"
    risk_level: str = "unknown"
    criticality: int = 5

    data_sensitivity: int = 5
    operational_dependency: int = 5
    customer_impact: int = 5
    financial_impact: int = 5

    description: str | None = None


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    ip_address: str | None = None
    status: str
    risk_level: str
    criticality: int

    data_sensitivity: int
    operational_dependency: int
    customer_impact: int
    financial_impact: int

    description: str | None = None

    model_config = ConfigDict(from_attributes=True)


class SecurityFindingCreate(BaseModel):
    asset_id: int
    title: str
    description: str | None = None
    severity: str
    cvss_score: str | None = None
    vulnerability_type: str | None = None
    affected_component: str | None = None

    host: str | None = None
    port: str | None = None
    endpoint: str | None = None
    database_name: str | None = None
    file_path: str | None = None
    
    status: str = "open"
    remediation: str | None = None

class SecurityFindingResponse(SecurityFindingCreate):
    id: int
    risk_score: float | None = None
    risk_level: str | None = None

    model_config = ConfigDict(from_attributes=True)