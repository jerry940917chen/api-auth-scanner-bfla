import os
import asyncio
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from scanner.services.remediation_service import RemediationService
from scanner.services.llm_service import LLMService

class ReportingService:
    def __init__(self):
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))
        self.remediation_service = RemediationService()
        self.llm_service = LLMService()

    async def generate_pdf_report(self, report_data: dict) -> bytes:
        """
        Generates a professional PDF audit report from scan data, enriched with AI.
        """
        scan = report_data.get("scan")
        project = report_data.get("project")
        
        # Support both dict and object access for vulnerabilities
        vulnerabilities = scan.vulnerabilities if hasattr(scan, "vulnerabilities") else scan.get("vulnerabilities", [])
        
        async def process_vuln(vuln):
            vuln_type = vuln.vuln_type if hasattr(vuln, "vuln_type") else vuln.get("vuln_type")
            endpoint = vuln.endpoint if hasattr(vuln, "endpoint") else vuln.get("endpoint")
            evidence = vuln.evidence if hasattr(vuln, "evidence") else vuln.get("evidence")
            severity = vuln.severity if hasattr(vuln, "severity") else vuln.get("severity")
            description = vuln.description if hasattr(vuln, "description") else vuln.get("description")

            # Call LLM for professional audit text
            llm_content = None
            if self.llm_service.enabled:
                llm_content = await self.llm_service.generate_audit_content(vuln_type, endpoint, evidence)

            # Get final remediation (AI + Static fallback)
            remediation = self.remediation_service.get_remediation(vuln_type, endpoint, llm_content)
            
            return {
                "vuln_type": vuln_type,
                "endpoint": endpoint,
                "description": description,
                "severity": severity,
                "evidence": evidence,
                "remediation": remediation
            }

        # Concurrently process all AI vulnerability generations
        tasks = [process_vuln(v) for v in vulnerabilities]
        enriched_vulns = await asyncio.gather(*tasks)

        template = self.jinja_env.get_template("report_template.html")
        
        # Prepare template variables
        html_content = template.render(
            project_name=project.name if hasattr(project, "name") else project.get("name", "Unknown"),
            generated_at=report_data.get("generated_at", ""),
            base_url=project.base_url if hasattr(project, "base_url") else project.get("base_url", ""),
            scan_id=scan.id if hasattr(scan, "id") else scan.get("id", ""),
            summary=scan.summary_counts if hasattr(scan, "summary_counts") else scan.get("summary_counts", {}),
            vulnerabilities=enriched_vulns
        )

        # Convert HTML to PDF (Note: WeasyPrint write_pdf is blocking, but we run in thread)
        loop = asyncio.get_event_loop()
        pdf_bytes = await loop.run_in_executor(None, lambda: HTML(string=html_content).write_pdf())
        
        return pdf_bytes
