from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_name: str
    device_type: str
    operating_system: str
    department: str
    status: str
    failed_login_attempts: int
    open_ports: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    patch_age_days: int
    network_anomaly_score: float
    malware_alerts: int
    privilege_escalation_attempts: int
    previous_security_incidents: int
    created_at: Any

class PredictionRequest(BaseModel):
    device_id: Optional[int] = None
    device_name: Optional[str] = None
    device_type: str
    operating_system: str
    failed_login_attempts: int = Field(ge=0)
    open_ports: int = Field(ge=0)
    total_vulnerabilities: int = Field(ge=0)
    critical_vulnerabilities: int = Field(ge=0)
    patch_age_days: int = Field(ge=0)
    network_anomaly_score: float = Field(ge=0, le=100)
    malware_alerts: int = Field(ge=0)
    privilege_escalation_attempts: int = Field(ge=0)
    previous_security_incidents: int = Field(ge=0)

class PredictionOut(BaseModel):
    id: Optional[int] = None
    device_id: Optional[int] = None
    device_name: str
    risk_score: float
    risk_level: str
    prediction_time: Any
    contributing_factors: List[Dict[str, Any]]
    recommendations: List[str]
    class_probabilities: Optional[Dict[str, float]] = None
