import requests, ssl, socket, json, re, sys, subprocess, argparse, datetime, time
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# === ASCII Banner ===
def display_banner():
    KNIGHT_COLOR = "\033[1;34m"
    TEXT_COLOR   = "\033[1;37m"
    RESET_COLOR  = "\033[0m"
    banner = rf"""{KNIGHT_COLOR}
          ,   A           {{}}
         / \, | ,        .--.
        |    =|= >      /.--.\
         \ /` | `       |====|
          `   |         |`::`|
              |     .-;`\..../`;_.-^-._
             /\\/  /  |...::..|`   :   `|
             |:'\ |   /'''::''|   .:.   |
              \ /\;-,/\   ::  |..:::::..|
              |\ <` >  >._::_.| ':::::' |
              | `""`  /   ^^  |   ':'   |
              |       |       \    :    /
              |       |        \   :   /
              |       |___/\___|`-.:.-`
              |        \_ || _/    `
              |        <_ >< _>
              |        |  ||  |
              |        |  ||  |
              |       _\.:||:./_
              |      /____/\____\{RESET_COLOR}
{TEXT_COLOR}        [SENTINEL] Passive Recon Scanner by Jake Boren{RESET_COLOR}
"""
    print(banner)

#CLI
def parse_args():
    parser = argparse.ArgumentParser(description="Sentinel Passive Recon Scanner")
    parser.add_argument("url", help="Target URL (e.g., https://site.com)")
    parser.add_argument("--login", default="/login", help="Login endpoint path")
    parser.add_argument("--api", default="/api", help="API endpoint path")
    parser.add_argument("--custom", default=None, help="Custom endpoint path")
    parser.add_argument("--out", default="sentinel_report.json", help="Output report file")
    return parser.parse_args()

#Global Report
report_data = {
    "missing_headers": [],
    "tls": {},
    "auth_enum": [],
    "rate_limit": [],
    "sensitive_data": [],
    "outdated_components": [],
    "injection_tests": [],
    "backend_fingerprint": []
}

HEADERS_TO_CHECK = [
    'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
    'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy',
    'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
    'Cross-Origin-Opener-Policy'
]

SENSITIVE_PATTERNS = [
    r'api_key\s*=\s*\w+', r'bearer\s+[A-Za-z0-9\-_\.=]+',
    r'(?:password|secret|access_token|auth_token)\s*[:=]\s*["\'][^"\']+["\']',
    r'[A-Za-z0-9]{32,}'
]

INJECTION_PAYLOADS = [
    "' OR '1'='1", "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
    "'; DROP TABLE users;--", "<svg/onload=confirm(1)>"
]

#Scanners (It's over 9000!)
def check_missing_headers(response):
    print("\n[+] Missing Security Headers:")
    for header in HEADERS_TO_CHECK:
        if header not in response.headers:
            print(f"  - {header} is missing")
            report_data["missing_headers"].append(header)

def check_tls_config(domain):
    print("\n[+] TLS Configuration & Cipher Suites:")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            subj = cert.get('subject')[0][0][1]
            print(f"  - Cert CN: {subj}")
            report_data["tls"]["cert_subject"] = subj
    except Exception as e:
        print(f"  - TLS Error: {e}")
        report_data["tls"]["error"] = str(e)

    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain], stderr=subprocess.DEVNULL)
        tls_lines = []
        for line in result.decode().split('\n'):
            if "TLS" in line or "weak" in line.lower():
                print("   ", line.strip())
                tls_lines.append(line.strip())
        report_data["tls"]["nmap_results"] = tls_lines
    except Exception:
        print("  - nmap not available or failed.")
        report_data["tls"]["nmap_results"] = ["nmap not available"]

def check_auth_enumeration(url):
    print("\n[+] Auth Enumeration Response Differences:")
    usernames = ['admin', 'test', 'user1', 'guest']
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Pre-check to verify POST is allowed. This will be skipped if no logins or auth portals are found.
    try:
        pre_check = requests.post(url, headers=headers, data={"username": "check", "password": "test"})
        if pre_check.status_code == 405:
            print(f"  - Endpoint {url} does not accept POST requests (405 Method Not Allowed). Skipping enumeration test.")
            return
    except Exception as e:
        print(f"  - Error reaching endpoint for enumeration check: {e}")
        return

    responses = {}

    for user in usernames:
        data = {'username': user, 'password': 'invalid'}
        try:
            r = requests.post(url, headers=headers, data=data)
            key = f"{r.status_code}:{len(r.text)}"
            if key not in responses:
                responses[key] = []
            responses[key].append(user)

            snippet = r.text[:80].replace("\n", " ")
            print(f"  - Username: {user} | Status: {r.status_code} | Len: {len(r.text)} | Snippet: {snippet}")
            report_data["auth_enum"].append({"user": user, "status": r.status_code, "length": len(r.text), "snippet": snippet})
        except Exception as e:
            print(f"  - Error with username '{user}': {e}")

    if len(responses) == 1:
        print("  - All usernames returned identical responses. Likely protected.")


def check_rate_limiting(url):
    print("\n[+] Rate Limiting Check (POST to Login):")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Pre-check to verify POST is allowed. This will be skipped if no login or auth portals are found. 
    test_response = requests.post(url, headers=headers, data={"username": "check", "password": "test"})
    if test_response.status_code == 405:
        print(f"  - Endpoint {url} does not accept POST requests (405 Method Not Allowed). Skipping rate limit test.")
        return

    delays = []
    throttled = False

    for i in range(10):
        data = {"username": "admin", "password": f"wrongpass{i}"}
        try:
            start = time.time()
            r = requests.post(url, headers=headers, data=data)
            elapsed = round(time.time() - start, 4)
            delays.append(elapsed)

            if r.status_code == 429:
                print(f"  - Req {i+1}: Status 429 (Too Many Requests), Time: {elapsed}s")
                throttled = True
            else:
                print(f"  - Req {i+1}: Status {r.status_code}, Time: {elapsed}s")

            report_data["rate_limit"].append({
                "request": i+1,
                "status": r.status_code,
                "time": elapsed
            })
        except Exception as e:
            print(f"  - Error during request {i+1}: {e}")

    if not throttled and len(set(delays)) <= 2:
        print("  - No signs of rate limiting or throttling observed.")


def check_sensitive_data(url):
    print("\n[+] Sensitive Data Detection:")
    try:
        r = requests.get(url)
        fulltext = r.text
        found_any = False
        for pattern in SENSITIVE_PATTERNS:
            matches = re.finditer(pattern, fulltext, re.IGNORECASE)
            for match in matches:
                found_any = True
                value = match.group(0)
                start = max(0, match.start() - 100)
                end = match.end() + 100
                context = fulltext[start:end].replace("\n", " ")
                print(f"  - Pattern: {pattern} | Found: {value}\n    → Context Snippet:\n    {'-'*32}\n    {context}\n    {'-'*32}\n    → Found at: {url}")
                report_data["sensitive_data"].append({
                    "pattern": pattern,
                    "value": value,
                    "context": context,
                    "url": url
                })
        if not found_any:
            print("  - No sensitive data patterns found.")
    except Exception as e:
        print(f"  - Error in sensitive data detection: {e}")



def check_outdated_components(url):
    print("\n[+] Outdated Components Detection:")
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    found = []

    for meta in soup.find_all('meta'):
        if meta.get('name') == 'generator':
            gen = meta.get('content')
            print(f"  - Generator: {gen}")
            found.append(gen)

    for script in soup.find_all('script', src=True):
        src = script['src']
        if re.search(r'v?(\d+\.\d+(\.\d+)?)+', src):
            print(f"  - Versioned JS: {src}")
            found.append(src)

    report_data["outdated_components"] = found

#Did you drink enough water today?

def label_reflection_context(snippet):
    if "<script" in snippet.lower() or "javascript" in snippet.lower():
        return "JavaScript Context"
    elif "<" in snippet and ">" in snippet:
        return "HTML Context"
    else:
        return "Plaintext Context"

def basic_injection_test(url):
    print("\n[+] Output Handling / Injection Test:")
    for payload in INJECTION_PAYLOADS:
        try:
            test_url = f"{url}?test={payload}"
            r = requests.get(test_url)
            reflected = payload in r.text
            result = {
                "payload": payload,
                "reflected": reflected,
                "url": test_url
            }

            if reflected:
                print(f"  - Reflected: {payload}")
                try:
                    index = r.text.index(payload)
                    snippet = r.text[max(0, index - 100):index + len(payload) + 100]
                    context_type = label_reflection_context(snippet)
                    print(f"    → Context Type: {context_type}")
                    print("    → Reflection Snippet:")
                    print("    --------------------------------")
                    print("    " + snippet.replace("\n", " ").strip())
                    print("    --------------------------------")
                    print(f"    → Found at: {test_url}")
                    result["context_type"] = context_type
                    result["context_snippet"] = snippet.strip()
                except Exception as e:
                    result["context_type"] = "Unknown"
                    result["context_snippet"] = "Could not extract context"
            else:
                print(f"  - No reflection: {payload}")

            report_data["injection_tests"].append(result)

        except Exception as e:
            print(f"  - Error testing {payload}: {e}")


def fingerprint_backend(response):
    print("\n[+] Backend Fingerprint Detection:")
    tech = []
    server = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")
    cookie = response.headers.get("Set-Cookie", "")

    if server: tech.append(f"Server: {server}")
    if powered: tech.append(f"X-Powered-By: {powered}")
    if "PHP" in powered or ".php" in response.text: tech.append("Likely PHP backend")
    if "wp-content" in response.text: tech.append("WordPress CMS detected")
    if "laravel" in cookie.lower(): tech.append("Laravel framework detected")

    if tech:
        for t in tech: print(f"  - {t}")
    else:
        print("  - No obvious backend signatures found.")

    report_data["backend_fingerprint"] = tech

def save_report(filename):
    report_data["scan_time"] = datetime.datetime.now().isoformat()
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[✓] Report saved to {filename}")

#Main
if __name__ == "__main__":
    display_banner()
    args = parse_args()
    TARGET = args.url
    parsed_url = urlparse(TARGET)
    domain = parsed_url.hostname or parsed_url.netloc

    try:
        r = requests.get(TARGET)
    except Exception as e:
        print("[-] Target unreachable:", e)
        sys.exit(1)

    check_missing_headers(r)
    check_tls_config(domain)
    fingerprint_backend(r)
    check_auth_enumeration(TARGET + args.login)
    check_rate_limiting(TARGET + args.login)
    check_sensitive_data(TARGET)
    check_outdated_components(TARGET)
    basic_injection_test(TARGET)
    if args.custom:
        print(f"\n[+] Scanning custom path: {args.custom}")
        try:
            custom_url = TARGET.rstrip('/') + args.custom
            basic_injection_test(custom_url)
            check_sensitive_data(custom_url)
        except:
            pass
    save_report(args.out)
