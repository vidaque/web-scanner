# 🛡️ Web Application Vulnerability Scanner

A lightweight yet powerful Python-based tool for scanning web applications for common security vulnerabilities, including SQL Injection (SQLi), Cross-Site Scripting (XSS), missing security headers, and exposed directories. Generates a detailed and styled HTML report with charts.

---

## 📌 Features

- 🔎 **SQL Injection Detection**  
  Identifies potential SQL injection vulnerabilities by submitting crafted payloads to form fields.

- 🧪 **XSS Detection**  
  Tests for reflected Cross-Site Scripting vulnerabilities using script payloads.

- 🔐 **Security Headers Check**  
  Validates presence of key security headers like `Content-Security-Policy`, `X-Frame-Options`, etc.

- 📁 **Exposed Directories Scanner**  
  Attempts to access common sensitive directories like `/admin`, `/backup`, etc.

- 📊 **HTML Report Generation**  
  Generates a responsive and styled HTML report with summary and vulnerability charts.

---

## 📂 Project Structure 

web-vuln-scanner/
├── scanner.py # Main scanner script
├── utils.py # Helper functions (optional modularization)
├── requirements.txt # Python dependencies
├── report.html # Generated HTML report
└── README.md # Project documentation
    project report.pdf #final project report 


