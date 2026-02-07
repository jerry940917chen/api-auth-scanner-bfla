from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from sqlalchemy.orm import Session
from typing import List
import asyncio
import logging

from scanner.db import get_db
from scanner.repositories import ScanRepository, ProjectRepository
from scanner.services.engine import ScannerEngine
# from report.service import ReportService
from api.schemas import ScanCreate, ScanResponse, ScanOptions, ReportResponse

router = APIRouter(tags=["scans"]) 
logger = logging.getLogger("api.scans")

@router.post("/projects/{project_id}/scans", response_model=dict, status_code=202)
async def start_scan(
    project_id: int, 
    scan_in: ScanCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a new scan for a project.
    """
    proj_repo = ProjectRepository(db)
    if not proj_repo.get(project_id):
        raise HTTPException(status_code=404, detail="Project not found")

    scan_repo = ScanRepository(db)
    
    if not scan_in.profiles:
        raise HTTPException(status_code=400, detail="At least one profile is required")

    # Convert Pydantic profiles to list of dicts for repo
    profiles_data = [p.dict() for p in scan_in.profiles]
    
    # Convert options
    options_data = scan_in.scan_options.dict() if scan_in.scan_options else {}

    scan = scan_repo.create_scan(project_id, profiles_data, options_data)
    logger.info(f"Created scan {scan.id} for project {project_id}")
    
    # We define a wrapper to run the async task
    async def task_wrapper(sid: int):
        from scanner.db import SessionLocal
        logger.info(f"Background task started for scan {sid}")
        db_session = SessionLocal()
        try:
            svc = ScannerEngine(db_session)
            await svc.run_scan(sid)
        except Exception as e:
            logger.error(f"Background task failed for scan {sid}: {e}")
        finally:
            db_session.close()

    # Use asyncio.create_task directly to avoid BackgroundTasks crash issues
    asyncio.create_task(task_wrapper(scan.id))
    logger.info(f"Background task scheduled for scan {scan.id}")

    return {"scan_id": scan.id, "status": "queued"}

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Best-effort cancel (update status)
    if scan.status in ["completed", "failed"]:
        raise HTTPException(status_code=409, detail="Scan already completed or failed")
    
    if scan.status != "canceled":
        repo.update_status(scan_id, "canceled")
        
    return {"status": "canceled"}

@router.get("/scans/{scan_id}/report.json", response_model=ReportResponse)
def get_report_json(scan_id: int, db: Session = Depends(get_db)):
    # Inline implementation to avoid ReportService/WeasyPrint crash
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    from datetime import datetime
    return {
        "generated_at": datetime.utcnow(),
        "project": scan.project,
        "scan": scan
    }

@router.get("/scans/{scan_id}/report.pdf")
def get_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    # PDF generation disabled due to environment issues with WeasyPrint
    return Response(content=b"PDF reporting disabled in MVP", media_type="text/plain")
