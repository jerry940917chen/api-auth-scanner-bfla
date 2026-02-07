from sqlalchemy.orm import Session
from typing import List, Optional
from scanner.models import Scan, ScanProfile, Vulnerability
from .base import BaseRepository
from datetime import datetime

class ScanRepository(BaseRepository[Scan]):
    def __init__(self, db: Session):
        super().__init__(db, Scan)

    def create_scan(self, project_id: int, profiles_data: List[dict]) -> Scan:
        """Atomic creation of scan and its profiles."""
        scan = Scan(project_id=project_id, status="queued")
        self.db.add(scan)
        self.db.commit() # Commit first to get ID
        self.db.refresh(scan)

        for p_data in profiles_data:
            profile = ScanProfile(
                scan_id=scan.id,
                name=p_data["name"],
                role=p_data["role"],
                token=p_data["token"]
            )
            self.db.add(profile)
        
        self.db.commit()
        return scan

    def update_status(self, scan_id: int, status: str, error: Optional[str] = None):
        scan = self.get(scan_id)
        if scan:
            scan.status = status
            if status == "running":
                scan.started_at = datetime.utcnow()
            elif status in ["completed", "failed", "canceled"]:
                scan.completed_at = datetime.utcnow()
            
            if error:
                scan.error_message = error
            
            self.db.commit()
            self.db.refresh(scan)
        return scan

    def add_vulnerability(self, scan_id: int, vuln_data: dict):
        vuln = Vulnerability(scan_id=scan_id, **vuln_data)
        self.db.add(vuln)
        self.db.commit()
        return vuln
    
    def get_profiles(self, scan_id: int) -> List[ScanProfile]:
        return self.db.query(ScanProfile).filter(ScanProfile.scan_id == scan_id).all()
