import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import datetime
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Payloads
SQLI_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert(1)</script>"

# Security headers to check
REQUIRED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy"
]

def check_security_headers(url):
    logging.info("Checking security headers...")
    try:
        res = requests.get(url, timeout=10)
        issues = [header for header in REQUIRED_HEADERS if header not in res.headers]
        return [f"[Headers] {header} is missing." for header in issues]
    except Exception as e:
        return [f"[Headers] Error checking headers: {e}"]

def get_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        logging.warning(f"Error retrieving forms: {e}")
        return []

def scan_sqli(url):
    logging.info("Scanning for SQL Injection...")
    found = []
    for form in get_forms(url):
        data = {inp.get("name"): SQLI_PAYLOAD for inp in form.find_all("input") if inp.get("name")}
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "get").lower()

        try:
            res = requests.post(action, data=data) if method == "post" else requests.get(action, params=data)
            if "sql" in res.text.lower() or "syntax" in res.text.lower():
                found.append(f"[SQLi] Possible SQL Injection at {action}")
        except Exception as e:
            logging.warning(f"Error during SQLi scan on {action}: {e}")
    return found

def scan_xss(url):
    logging.info("Scanning for XSS...")
    found = []
    for form in get_forms(url):
        data = {inp.get("name"): XSS_PAYLOAD for inp in form.find_all("input") if inp.get("name")}
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "get").lower()

        try:
            res = requests.post(action, data=data) if method == "post" else requests.get(action, params=data)
            if XSS_PAYLOAD in res.text:
                found.append(f"[XSS] Possible XSS at {action}")
        except Exception as e:
            logging.warning(f"Error during XSS scan on {action}: {e}")
    return found

def check_directories(url):
    logging.info("Checking for common exposed directories...")
    directories = ["admin", "backup", "old", "test", ".git"]
    found = []
    for d in directories:
        full_url = urljoin(url + "/", d)
        try:
            res = requests.get(full_url, timeout=5)
            if res.status_code == 200:
                found.append(f"[Dir] Exposed directory found: {full_url}")
        except Exception as e:
            logging.warning(f"Error checking directory {full_url}: {e}")
    return found

def generate_html_report(vulnerabilities, url):
    logging.info("Generating HTML report...")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = "report.html"

    header_issues = [v for v in vulnerabilities if "Headers" in v]
    sqli_issues = [v for v in vulnerabilities if "SQLi" in v]
    xss_issues = [v for v in vulnerabilities if "XSS" in v]
    dir_issues = [v for v in vulnerabilities if "Dir" in v]

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 30px; }}
        .issue {{ background: #ffecec; border-left: 4px solid #e00; padding: 10px; margin-bottom: 10px; }}
        .summary {{ background: #eef; padding: 10px; border-left: 4px solid #00f; }}
        canvas {{ max-width: 400px; }}
    </style>
</head>
<body>
    <h1>Web Vulnerability Report</h1>
    <p><strong>Scanned URL:</strong> {url}</p>
    <p><strong>Date:</strong> {timestamp}</p>

    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Security Header Issues: {len(header_issues)}</li>
            <li>SQL Injection Issues: {len(sqli_issues)}</li>
            <li>XSS Issues: {len(xss_issues)}</li>
            <li>Directory Exposures: {len(dir_issues)}</li>
        </ul>
        <canvas id="chart" width="400" height="300"></canvas>
    </div>

    <div class="section">
        <h2>Vulnerabilities Found</h2>
        {''.join(f'<div class="issue">{v}</div>' for v in vulnerabilities)}
        {'<p>No issues found.</p>' if not vulnerabilities else ''}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const ctx = document.getElementById('chart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: ['Headers', 'SQLi', 'XSS', 'Dirs'],
                datasets: [{{
                    label: 'Issues Found',
                    data: [{len(header_issues)}, {len(sqli_issues)}, {len(xss_issues)}, {len(dir_issues)}],
                    backgroundColor: ['#f88', '#fa0', '#fd0', '#aaf']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
    </script>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    logging.info(f"Report saved as {filename}")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="URL of the web application to scan")
    args = parser.parse_args()
    url = args.url or input("Enter the URL to scan: ").strip()

    print(f"\n[*] Starting scan on: {url}\n")

    vulnerabilities = []
    vulnerabilities += check_security_headers(url)
    vulnerabilities += scan_sqli(url)
    vulnerabilities += scan_xss(url)
    vulnerabilities += check_directories(url)

    generate_html_report(vulnerabilities, url)

if __name__ == "__main__":
    main()
