import requests

def test_sql_injection(url, form):
    payload = "' OR '1'='1"
    data = {}
    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if name:
            data[name] = payload
    action = form.get("action") or url
    method = form.get("method", "get").lower()

    try:
        if method == "post":
            res = requests.post(action, data=data)
        else:
            res = requests.get(action, params=data)
        if "sql" in res.text.lower() or "syntax" in res.text.lower():
            return f"[SQL Injection] Possible vulnerability at {action}"
    except:
        pass
    return None

def test_xss(url, form):
    payload = "<script>alert(1)</script>"
    data = {}
    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if name:
            data[name] = payload
    action = form.get("action") or url
    method = form.get("method", "get").lower()

    try:
        if method == "post":
            res = requests.post(action, data=data)
        else:
            res = requests.get(action, params=data)
        if payload in res.text:
            return f"[XSS] Possible vulnerability at {action}"
    except:
        pass
    return None

def check_security_headers(url):
    issues = []
    try:
        res = requests.get(url)
        headers = res.headers
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy"
        ]
        for header in required_headers:
            if header not in headers:
                issues.append(f"[Headers] Missing security header: {header}")
    except:
        pass
    return issues

def generate_report(vulnerabilities):
    with open("report.txt", "w") as f:
        if vulnerabilities:
            for v in vulnerabilities:
                f.write(v + "\n")
        else:
            f.write("No vulnerabilities found.\n")
