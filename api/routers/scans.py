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

@router.get("/health")
def health_check():
    return {"status": "ok"}

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

@router.get("/scans/{scan_id}/auth-matrix")
def get_auth_matrix(scan_id: int, db: Session = Depends(get_db)):
    """
    Returns an Auth Matrix: for each endpoint, whether access was allowed/denied/unknown.
    This shows which roles can access which endpoints — the core differentiator vs Burp/AppScan.
    """
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = scan.vulnerabilities or []
    
    # Gather all unique endpoints from scan
    all_endpoints = list({v.endpoint for v in vulns})
    
    # Gather roles from profiles
    profiles = scan.profiles or []
    roles = list({p.role for p in profiles}) if profiles else ["user"]
    
    # Build matrix: endpoint -> role -> result
    # BFLA vuln = endpoint accessible by role that shouldn't have access
    matrix = {}
    for ep in all_endpoints:
        ep_vulns = [v for v in vulns if v.endpoint == ep]
        matrix[ep] = {}
        for role in roles:
            bfla_vuln = next((v for v in ep_vulns if v.vuln_type in ["BFLA", "Broken Authentication"]), None)
            if bfla_vuln:
                matrix[ep][role] = {"status": "vulnerable", "severity": bfla_vuln.severity, "vuln_type": bfla_vuln.vuln_type}
            elif any(v for v in ep_vulns if v.vuln_type == "BOLA"):
                matrix[ep][role] = {"status": "vulnerable", "severity": "High", "vuln_type": "BOLA"}
            else:
                # Check if endpoint has any non-auth related findings
                other_vulns = [v for v in ep_vulns if v.vuln_type not in ["BFLA", "BOLA", "Broken Authentication"]]
                if other_vulns:
                    matrix[ep][role] = {"status": "allowed", "severity": other_vulns[0].severity, "vuln_type": other_vulns[0].vuln_type}
                else:
                    matrix[ep][role] = {"status": "secure", "severity": None, "vuln_type": None}

    return {
        "scan_id": scan_id,
        "roles": roles,
        "endpoints": all_endpoints,
        "matrix": matrix
    }


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
async def get_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    repo = ScanRepository(db)
    scan = repo.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    from scanner.services.reporting_service import ReportingService
    from datetime import datetime
    
    report_data = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "project": scan.project,
        "scan": scan
    }
    
    try:
        report_service = ReportingService()
        pdf_bytes = await report_service.generate_pdf_report(report_data)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=audit_report_{scan_id}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")
