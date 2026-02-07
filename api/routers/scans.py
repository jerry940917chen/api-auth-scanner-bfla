from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from sqlalchemy.orm import Session
from typing import List
from scanner.db import get_db
from scanner.repositories import ScanRepository, ProjectRepository
from scanner.services.engine import ScannerEngine
from report.service import ReportService
from api.schemas import ScanCreate, ScanResponse, ScanOptions, ReportResponse

router = APIRouter(tags=["scans"]) 
# Note: mixed paths doing /projects/{id}/scans and /scans/{id}, handled below

@router.post("/projects/{project_id}/scans", response_model=dict, status_code=202)
def start_scan(
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

    import logging
    logger = logging.getLogger("api.scans")

    scan_repo = ScanRepository(db)
    
    if not scan_in.profiles:
        raise HTTPException(status_code=400, detail="At least one profile is required")

    # Convert Pydantic profiles to list of dicts for repo
    profiles_data = [p.dict() for p in scan_in.profiles]
    
    scan = scan_repo.create_scan(project_id, profiles_data)
    logger.info(f"Created scan {scan.id} for project {project_id}")
    
    # Initialize engine and run background task
    # Note: We rely on SessionLocal inside the background task, so we pass just the ID
    engine = ScannerEngine(None) # DB session created inside task
    
    # We define a wrapper to run the async task
    async def task_wrapper(sid: int):
        from scanner.db import SessionLocal
        db_session = SessionLocal()
        try:
            svc = ScannerEngine(db_session)
            await svc.run_scan(sid)
        finally:
            db_session.close()

    background_tasks.add_task(task_wrapper, scan.id)

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
    service = ReportService(db)
    data = service.generate_json(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Return raw ORM object, Pydantic will serialize if we use response_model,
    # or just return dict. User asked for stable schema.
    # We can reuse ScanResponse but it might be heavy. Let's return ScanResponse.
    return data

@router.get("/scans/{scan_id}/report.pdf")
def get_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    service = ReportService(db)
    pdf_bytes = service.generate_pdf(scan_id)
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return Response(content=pdf_bytes, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"
    })
