from scanner.repositories import ScanRepository
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
import os

class ReportService:
    def __init__(self, db_session):
        self.repo = ScanRepository(db_session)
        self.template_dir = os.path.join(os.getcwd(), "report")
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate_json(self, scan_id: int):
        scan = self.repo.get(scan_id)
        from datetime import datetime
        if not scan:
            return None
        return {
            "generated_at": datetime.utcnow(),
            "project": scan.project,
            "scan": scan
        }

    def generate_pdf(self, scan_id: int):
        scan = self.repo.get(scan_id)
        if not scan:
            return None
            
        template = self.env.get_template("template.html")
        
        # Prepare context
        vulns_by_severity = {"High": [], "Medium": [], "Low": []}
        for v in scan.vulnerabilities:
            if v.severity in vulns_by_severity:
                vulns_by_severity[v.severity].append(v)
            else:
                vulns_by_severity["High"].append(v) # Default
                
        context = {
            "project_name": scan.project.name,
            "scan_id": scan.id,
            "date": scan.created_at.strftime("%Y-%m-%d"),
            "status": scan.status,
            "high_count": len(vulns_by_severity["High"]),
            "medium_count": len(vulns_by_severity["Medium"]),
            "low_count": len(vulns_by_severity["Low"]),
            "vulnerabilities": scan.vulnerabilities
        }
        
        html_content = template.render(context)
        pdf = HTML(string=html_content, base_url=self.template_dir).write_pdf()
        return pdf
