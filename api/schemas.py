from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- Common ---
class ScanStatus(str):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

# --- Project Schemas ---
class ProjectBase(BaseModel):
    name: str
    base_url: str
    openapi_url: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# --- Profile Schemas ---
class ScanProfileBase(BaseModel):
    name: str
    role: str
    token: str

class ScanProfileCreate(ScanProfileBase):
    pass

class ScanProfileResponse(ScanProfileBase):
    id: int
    created_at: datetime
    # Mask token in response
    token: str = Field(..., description="Masked token") 

    class Config:
        from_attributes = True

# --- Scan Schemas ---
class ScanOptions(BaseModel):
    max_endpoints: int = 200
    timeout_seconds: int = 10
    concurrency: int = 5
    include_paths: Optional[List[str]] = None
    exclude_paths: Optional[List[str]] = None

class ScanCreate(BaseModel):
    profiles: List[ScanProfileCreate]
    scan_options: Optional[ScanOptions] = Field(default_factory=ScanOptions)

class VulnerabilityResponse(BaseModel):
    id: int
    vuln_type: str
    endpoint: str
    description: str
    severity: str
    evidence: str
    created_at: datetime

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    project_id: int
    status: str
    scan_type: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    error_stage: Optional[str] = None
    summary_counts: Optional[Dict[str, int]] = None
    vulnerabilities: List[VulnerabilityResponse] = []
    
    class Config:
        from_attributes = True

class ReportResponse(BaseModel):
    generated_at: datetime
    project: ProjectResponse
    scan: ScanResponse