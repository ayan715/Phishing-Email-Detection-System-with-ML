import argparse
import csv
import os
import re
import sys
from urllib.parse import urlsplit
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import joblib
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException
import time

def selenium_sandbox(url, timeout=10):
    """
    Open a URL in a headless browser and collect basic info safely.
    Returns:
        dict: final_url, status_code (approx), page_title, screenshot_path, error
    """
    chrome_options = Options()
    chrome_options.headless = True   # No GUI
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3")
    
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(2)  # Let page load JS

        # Take screenshot (optional)
        screenshot_path = f"screenshots/{url.split('//')[-1].replace('/', '_')}.png"
        os.makedirs("screenshots", exist_ok=True)
        driver.save_screenshot(screenshot_path)

        final_url = driver.current_url
        page_title = driver.title

        driver.quit()

        return {
            "final_url": final_url,
            "page_title": page_title,
            "screenshot_path": screenshot_path,
            "error": None
        }

    except (WebDriverException, TimeoutException) as e:
        try:
            driver.quit()
        except:
            pass
        return {
            "final_url": None,
            "page_title": None,
            "screenshot_path": None,
            "error": str(e)
        }


def sandbox_url(url, timeout=5):
    """
    Fetch URL safely and return basic info.
    Returns:
        dict with keys: final_url, status_code, redirect_chain
    """
    try:
        # Allow redirects to follow
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        redirect_chain = [r.url for r in resp.history]  # List of redirects
        return {
            "final_url": resp.url,
            "status_code": resp.status_code,
            "redirect_chain": redirect_chain
        }
    except requests.exceptions.RequestException as e:
        return {
            "final_url": None,
            "status_code": None,
            "redirect_chain": [],
            "error": str(e)
        }

# Load your trained ML model and TF-IDF vectorizer
ML_MODEL_PATH = "phishing_model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

ml_model = joblib.load(ML_MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

def ml_predict(email_text):
    """Predict phishing using trained ML model."""
    X_vec = vectorizer.transform([email_text])
    pred = ml_model.predict(X_vec)[0]
    return "Phishing" if pred == 1 else "Safe"


SUSPICIOUS_TLDS = {
    "zip","mov","click","xyz","top","work","loan","info","gq","tk","cn","ru","rest","fit","biz"
}

KEYWORDS = [
    "verify","urgent","limited time","password","invoice","suspend","suspended",
    "update account","unusual activity","confirm","reset","win","prize","gift","free"
]

KNOWN_BRANDS = ["paypal","microsoft","apple","google","amazon","bank","facebook","instagram","netflix"]

def read_eml(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)

def extract_bodies(msg):
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    text_body += part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html_body += part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            text_body = msg.get_content()
        elif ctype == "text/html":
            html_body = msg.get_content()
    return text_body or "", html_body or ""

URL_REGEX = re.compile(r"https?://[^\s\"')>]+", re.IGNORECASE)

def extract_urls(text, html):
    urls = set()
    # From plain text
    for m in URL_REGEX.finditer(text or ""):
        urls.add(m.group(0))
    # From HTML anchors
    if html:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            urls.add(a["href"])
    return list(urls)

def hostname_from_url(u):
    try:
        parsed = urlsplit(u)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:
        return ""

def is_ipv4(s):
    # Simple IPv4 check
    parts = s.split(".")
    if len(parts) != 4: return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def tld_of(host):
    if "." not in host:
        return ""
    return host.rsplit(".", 1)[-1].lower()

def subdomain_count(host):
    return len(host.split("."))

def has_userinfo(u):
    # URL with username:password@host pattern
    return "@" in urlsplit(u).netloc

def anchor_brand_mismatch(html, url):
    # If anchor text mentions a known brand but the href domain does not, flag it.
    try:
        if not html:
            return False
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            if a["href"] == url:
                text = (a.get_text() or "").lower()
                for brand in KNOWN_BRANDS:
                    if brand in text and brand not in (hostname_from_url(url) or ""):
                        return True
        return False
    except Exception:
        return False

def brand_claim_without_domain(headers_text, body_text, host):
    everything = (headers_text + " " + body_text).lower()
    for brand in KNOWN_BRANDS:
        if brand in everything and brand not in (host or ""):
            return True
    return False

def score_url(u, html):
    reasons = []
    score = 0
    host = hostname_from_url(u)
    if not host:
        return 0, []

    # Punycode
    if "xn--" in host:
        score += 1; reasons.append("Punycode hostname")

    # IP literal
    if is_ipv4(host) or ":" in host:
        score += 1; reasons.append("IP-based host")

    # Suspicious TLD
    tld = tld_of(host)
    if tld in SUSPICIOUS_TLDS:
        score += 1; reasons.append(f"Suspicious TLD .{tld}")

    # Excessive subdomains
    if subdomain_count(host) >= 4 and not is_ipv4(host):
        score += 1; reasons.append("Excessive subdomains")

    # Very long URL
    if len(u) > 120:
        score += 1; reasons.append("Very long URL")

    # Userinfo in URL
    if has_userinfo(u):
        score += 1; reasons.append("Userinfo in URL")

    # Anchor/brand mismatch
    if anchor_brand_mismatch(html, u):
        score += 1; reasons.append("Anchor text brand mismatch")

    return score, reasons

def domains_mismatch(from_addr, reply_to_addr):
    def dom(a):
        if not a: return ""
        m = re.search(r"@([A-Za-z0-9\.\-\_]+)", a)
        return (m.group(1).lower() if m else "")
    fd, rd = dom(from_addr), dom(reply_to_addr)
    return fd, rd, (fd and rd and fd != rd)

def keyword_hits(text):
    text_l = (text or "").lower()
    hits = [k for k in KEYWORDS if k in text_l]
    return hits

def risk_level(total_score):
    if total_score >= 4:
        return "HIGH"
    if total_score >= 2:
        return "MEDIUM"
    return "LOW"

# Analyze attachments
def analyze_attachments(msg):
    attachment_info = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content_type = part.get_content_type()
        suspicious = False
        if filename and filename.lower().endswith((
            '.exe', '.js', '.vbs', '.scr', '.bat', '.jar', '.docm', '.xlsm'
        )):
            suspicious = True
        attachment_info.append({
            "filename": filename,
            "type": content_type,
            "suspicious": suspicious
        })
    return attachment_info

# Analyze scripts in HTML


def analyze_scripts(html_body):
    if not html_body:
        return []
    soup = BeautifulSoup(html_body, "lxml")
    scripts = soup.find_all("script")
    events = [tag for tag in soup.find_all(True) if any(attr.startswith('on') for attr in tag.attrs)]
    warnings = []
    if scripts:
        warnings.append(f"Found {len(scripts)} <script> tag(s)")
    if events:
        warnings.append(f"Found {len(events)} inline event handler(s)")
    return warnings

def analyze_email(path):
    msg = read_eml(path)
    headers_text = ""
    for k, v in msg.items():
        headers_text += f"{k}: {v}\n"

    text_body, html_body = extract_bodies(msg)

    attachments_report = analyze_attachments(msg)
    script_warnings = analyze_scripts(html_body)

    urls = extract_urls(text_body, html_body)
    # ML prediction
    ml_result = ml_predict(text_body + " " + html_body)

    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")

    fd, rd, mismatch = domains_mismatch(from_addr, reply_to)
    kw = set(keyword_hits(subject) + keyword_hits(text_body) + keyword_hits(html_body))

    total = 0
    reasons = []

    if mismatch:
        total += 2
        reasons.append(f"From vs Reply-To mismatch ({fd} ≠ {rd})")

    if kw:
        total += 1
        reasons.append("Suspicious keywords: " + ", ".join(sorted(kw)))

    # Brand claim without domain match
    primary_host = hostname_from_url(urls[0]) if urls else ""
    if brand_claim_without_domain(headers_text, text_body + " " + html_body, primary_host):
        total += 1
        reasons.append("Brand claim without matching domain")

    url_details = []
    for u in urls:
        s, r = score_url(u, html_body)
        total += s
        sandbox_result = selenium_sandbox(u)  # <- run Selenium sandbox
        if r:
            url_details.append({
                "url": u,
                "reasons": r,
                "sandbox": sandbox_result  # <- save Selenium info
            })


    return {
        "file": os.path.basename(path),
        "subject": subject,
        "from": from_addr,
        "reply_to": reply_to,
        "date": date,
        "num_urls": len(urls),
        "urls": urls,
        "score": total,
        "risk": risk_level(total),
        "email_reasons": reasons,
        "url_reasons": url_details,
        "ml_prediction": ml_result,  # <- added ML result
        "attachments": attachments_report,   # <- new
        "script_warnings": script_warnings   # <- new    
    }

def write_summary(rows, out_csv):
    fieldnames = [
        "file", "subject", "from", "reply_to", "date",
        "num_urls", "risk", "score", "ml_prediction",
        "top_reasons", "urls", "attachments", "script_warnings"
    ]
    
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        
        for r in rows:
            # Combine email-level and top URL reasons
            top_reasons = r["email_reasons"][:]
            for ur in r["url_reasons"]:
                top_reasons.extend(ur["reasons"][:2])  # take top 2 reasons per URL
            
            # Build a readable string for each URL including Selenium sandbox info
            url_infos = []
            for ud in r["url_reasons"]:
                sandbox = ud.get("sandbox", {})
                info = f"{ud['url']}"
                if sandbox:
                    parts = []
                    if sandbox.get("final_url"):
                        parts.append(f"final:{sandbox['final_url']}")
                    if sandbox.get("page_title"):
                        parts.append(f"title:{sandbox['page_title']}")
                    if sandbox.get("screenshot_path"):
                        parts.append(f"screenshot:{sandbox['screenshot_path']}")
                    if sandbox.get("error"):
                        parts.append(f"error:{sandbox['error']}")
                    if parts:
                        info += " (" + " | ".join(parts) + ")"
                url_infos.append(info)

            attachment_summary = []
            for att in r["attachments"]:
                fname = att.get("filename", "Unknown")
                suspicious = att.get("suspicious", False)
                if suspicious:
                    attachment_summary.append(f"{fname} (Suspicious)")
                else:
                    attachment_summary.append(fname)

            script_summary = "; ".join(r.get("script_warnings", [])) or "None"
            
            w.writerow({
                "file": r["file"],
                "subject": r["subject"],
                "from": r["from"],
                "reply_to": r["reply_to"],
                "date": r["date"],
                "num_urls": r["num_urls"],
                "risk": r["risk"],
                "score": r["score"],
                "ml_prediction": r["ml_prediction"],
                "top_reasons": "; ".join(top_reasons),
                "urls": " ; ".join(url_infos),
                "attachments": " ; ".join(attachment_summary),
                "script_warnings": script_summary
            })


def write_markdown_report(result, out_dir):
    base = os.path.splitext(result["file"])[0]
    path = os.path.join(out_dir, f"{base}_report.md")
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Email Report: {result['file']}\n\n")
        f.write(f"**Subject:** {result['subject']}\n\n")
        f.write(f"**From:** {result['from']}  \n")
        f.write(f"**Reply-To:** {result['reply_to']}  \n")
        f.write(f"**Date:** {result['date']}\n\n")
        f.write(f"**Risk Level:** {result['risk']}  \n")
        f.write(f"**Score:** {result['score']}\n\n")
        f.write(f"**ML Prediction:** {result['ml_prediction']}  \n\n")

        # Email-level reasons
        f.write("## Reasons (Email-level)\n\n")
        if result["email_reasons"]:
            for r in result["email_reasons"]:
                f.write(f"- {r}\n")
        else:
            f.write("- None\n")

        # URL Analysis
        f.write("\n## URL Analysis\n\n")
        if result["urls"]:
            for u in result["urls"]:
                f.write(f"- {u}\n")
        else:
            f.write("- No URLs found\n")

        f.write("\n### URL Flags and Sandbox Info\n\n")
        for ur in result["url_reasons"]:
            f.write(f"- **{ur['url']}**\n")
            # URL-specific reasons
            for rr in ur["reasons"]:
                f.write(f"  - {rr}\n")
            # Selenium sandbox info
            sandbox = ur.get("sandbox", {})
            if sandbox:
                if sandbox.get("final_url"):
                    f.write(f"  - Sandbox Final URL: {sandbox['final_url']}\n")
                if sandbox.get("page_title"):
                    f.write(f"  - Page Title: {sandbox['page_title']}\n")
                if sandbox.get("screenshot_path"):
                    f.write(f"  - Screenshot: {sandbox['screenshot_path']}\n")
                if sandbox.get("error"):
                    f.write(f"  - Error: {sandbox['error']}\n")

        else:
            f.write("- No URLs found\\n")

        # Attachment Analysis
        f.write("\n## Attachments Analysis\n\n")
        if result["attachments"]:
            for att in result["attachments"]:
                fname = att.get("filename", "Unknown")
                ctype = att.get("type", "Unknown")
                suspicious = att.get("suspicious", False)
                f.write(f"- **{fname}** ({ctype})")
                if suspicious:
                    f.write(" ⚠️ Suspicious file type")
                f.write("\n")
        else:
            f.write("- No attachments found\n")
        
            # Script Analysis
        f.write("\n## Script Analysis\n\n")
        if result.get("script_warnings"):
                for wng in result["script_warnings"]:
                    f.write(f"- ⚠️ {wng}\n")
        else:
            f.write("- No suspicious scripts or inline events found\n")



def main():
    p = argparse.ArgumentParser(description="Phishing Email Analysis Tool (Lite)")
    p.add_argument("--input", required=True, help="Folder with .eml files")
    p.add_argument("--output", required=True, help="Folder to write reports")
    args = p.parse_args()

    in_dir = args.input
    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)

    results = []
    for name in sorted(os.listdir(in_dir)):
        if name.lower().endswith(".eml"):
            try:
                res = analyze_email(os.path.join(in_dir, name))
                results.append(res)
                write_markdown_report(res, out_dir)
                print(f"[OK] {name}: risk={res['risk']} score={res['score']} urls={res['num_urls']}")
            except Exception as e:
                print(f"[ERR] {name}: {e}", file=sys.stderr)

    if results:
        write_summary(results, os.path.join(out_dir, "summary.csv"))
        print(f"\\nWrote {len(results)} report(s). See: {os.path.join(out_dir, 'summary.csv')}\\n")
    else:
        print("No .eml files found.")

if __name__ == "__main__":
    main()





















