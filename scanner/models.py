from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Enum, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from .db import Base

class VulnerabilityType(str, enum.Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"

class Project(Base):
    """
    Project model representing a target API.
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    base_url = Column(String)
    openapi_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="project")

class Scan(Base):
    """
    Scan task model representing a single execution.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    status = Column(String, default="queued")  # queued, running, completed, failed, canceled
    scan_type = Column(String, default="authz")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    error_message = Column(Text, nullable=True)
    error_stage = Column(String, nullable=True)
    
    # Store summary counts as JSON or individual columns? 
    # JSON is flexible for MVP.
    summary_counts = Column(JSON, default={}) 

    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    profiles = relationship("ScanProfile", back_populates="scan")

class ScanProfile(Base):
    """
    Profiles used for a specific scan (User roles, tokens).
    """
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    name = Column(String) # e.g. "alice"
    role = Column(String) # e.g. "user", "admin"
    token = Column(String) # Masked/Encrypted in real app, generic storage for MVP
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="profiles")

class Vulnerability(Base):
    """
    Vulnerability model recording specific findings.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vuln_type = Column(String, index=True)
    endpoint = Column(String)
    description = Column(Text)
    severity = Column(String, default="High")
    evidence = Column(Text)  # JSON or text
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
