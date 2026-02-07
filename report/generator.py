import os
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML, CSS
from sqlalchemy.orm import Session
from scanner.models import Scan, Vulnerability
import matplotlib.pyplot as plt
from datetime import datetime

def generate_report_pdf(db: Session, scan_id: int) -> str:
    """
    為指定掃描生成 PDF 報告。
    
    Args:
        db (Session): 資料庫 Session。
        scan_id (int): 掃描 ID。
    
    Returns:
        str: 生成的 PDF 檔案路徑。
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError("Scan not found")
    
    project = scan.project
    
    # 準備資料
    vulns = scan.vulnerabilities
    bola_count = sum(1 for v in vulns if v.vuln_type == "BOLA")
    bfla_count = sum(1 for v in vulns if v.vuln_type == "BFLA")
    total_vulns = len(vulns)
    
    # 生成圖表
    chart_path = generate_chart(bola_count, bfla_count, scan_id)
    
    # 設定 Report 路徑
    report_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(os.path.dirname(report_dir), "sample_reports")
    os.makedirs(output_dir, exist_ok=True)
    pdf_filename = f"report_{project.id}_{scan.id}.pdf"
    pdf_path = os.path.join(output_dir, pdf_filename)
    
    # 設定 Template
    env = Environment(loader=FileSystemLoader(report_dir))
    template = env.get_template("template.html")
    
    css_path = os.path.join(report_dir, "style.css")
    
    # 渲染 HTML
    # 注意：Windows 下 file:// 路徑需要正確處理，這裡簡單轉換
    chart_url = f"file:///{chart_path.replace(os.sep, '/')}"
    css_url = f"file:///{css_path.replace(os.sep, '/')}"

    html_content = template.render(
        project_name=project.name,
        scan_id=scan.id,
        scan_date=scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        total_vulns=total_vulns,
        bola_count=bola_count,
        bfla_count=bfla_count,
        vulnerabilities=vulns,
        chart_url=chart_url,
        css_url=css_url
    )
    
    # 轉換為 PDF
    HTML(string=html_content, base_url=report_dir).write_pdf(
        pdf_path, 
        stylesheets=[CSS(css_path)]
    )
    
    return pdf_path

def generate_chart(bola_count: int, bfla_count: int, scan_id: int) -> str:
    """
    生成漏洞類型分佈圖表。
    """
    assets_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    os.makedirs(assets_dir, exist_ok=True)
    
    categories = ['BOLA', 'BFLA']
    counts = [bola_count, bfla_count]
    colors = ['#e74c3c', '#e67e22']
    
    plt.figure(figsize=(6, 4))
    plt.bar(categories, counts, color=colors)
    plt.title('Vulnerabilities by Type')
    plt.ylabel('Count')
    
    chart_filename = f"chart_{scan_id}.png"
    chart_path = os.path.join(assets_dir, chart_filename)
    
    plt.savefig(chart_path)
    plt.close()
    
    return chart_path
