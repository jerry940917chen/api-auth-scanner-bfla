import requests
import time
import sys
import argparse
import json

def run_ci_scan(scanner_url, project_id, token, target_url=None):
    print(f"[*] Triggering CI Scan for Project {project_id} at {scanner_url}")
    
    # Optional: Update project base_url if provided (for dynamic environments like PR previews)
    if target_url:
        print(f"[*] Updating project base_url to {target_url}")
        resp = requests.patch(f"{scanner_url}/projects/{project_id}", json={"base_url": target_url})
        resp.raise_for_status()

    # Start Scan
    payload = {
        "profiles": [
            {"name": "CI_Tester", "role": "user", "token": token}
        ],
        "scan_options": {
            "max_endpoints": 50,
            "timeout_seconds": 15
        }
    }
    
    resp = requests.post(f"{scanner_url}/projects/{project_id}/scans", json=payload)
    if resp.status_code != 202:
        print(f"[!] Failed to start scan: {resp.text}")
        sys.exit(1)
    
    scan_id = resp.json()["scan_id"]
    print(f"[*] Scan {scan_id} started. Polling status...")

    # Polling
    while True:
        resp = requests.get(f"{scanner_url}/scans/{scan_id}")
        resp.raise_for_status()
        data = resp.json()
        status = data["status"]
        
        if status == "completed":
            print("[+] Scan completed successfully!")
            summary = data.get("summary_counts", {})
            print(f"[*] Summary: {json.dumps(summary)}")
            
            vulns = data.get("vulnerabilities", [])
            
            # Download the PDF Report
            print("[*] Downloading AI Audit Report (PDF)...")
            try:
                pdf_resp = requests.get(f"{scanner_url}/scans/{scan_id}/report")
                if pdf_resp.status_code == 200:
                    with open("api_audit_report.pdf", "wb") as f:
                        f.write(pdf_resp.content)
                    print("[+] Report saved as 'api_audit_report.pdf'")
                else:
                    print(f"[-] Failed to download report: HTTP {pdf_resp.status_code}")
            except Exception as e:
                print(f"[-] Error downloading report: {e}")

            if vulns:
                print(f"\n[!] Found {len(vulns)} vulnerabilities!")
                for v in vulns:
                    print(f"  - [{v['severity']}] {v['vuln_type']} at {v['endpoint']}")
                
                # Exit with error if high/critical severity found
                if summary.get("High", 0) > 0 or summary.get("Critical", 0) > 0:
                    print("\n[!] HIGH/CRITICAL vulnerabilities found! Failing the build to prevent deployment.")
                    sys.exit(1)
            else:
                print("\n[+] No vulnerabilities found. Build passed.")
            break
        elif status == "failed":
            print(f"[!] Scan failed: {data.get('error_message')}")
            sys.exit(1)
        elif status == "canceled":
            print("[!] Scan was canceled.")
            sys.exit(1)
        
        time.sleep(5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Auth Scanner CI Utility")
    parser.add_argument("--scanner-url", default="http://localhost:8000", help="Scanner API Base URL")
    parser.add_argument("--project-id", type=int, required=True, help="Project ID to scan")
    parser.add_argument("--auth-token", required=True, help="User auth token for scanning")
    parser.add_argument("--target-url", help="Override project base_url (optional)")
    
    args = parser.parse_args()
    run_ci_scan(args.scanner_url, args.project_id, args.auth_token, args.target_url)
