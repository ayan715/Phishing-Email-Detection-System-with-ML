# app.py
import os
import tempfile
import csv
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
import phishing_analyzer  # your provided module
import datetime
import re
from flask import Response

# --- Safety / config ---
# By default we disable the heavy Selenium sandboxing when running in the web app.
# Set DISABLE_SELENIUM=0 in env to allow Selenium (NOT recommended on shared hosts).
if os.getenv("DISABLE_SELENIUM", "1") in ("1", "true", "True"):
    # replace selenium sandbox with the lightweight HTTP fetch sandbox
    phishing_analyzer.selenium_sandbox = phishing_analyzer.sandbox_url

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "change-me-in-prod")


def analyze_raw_email(subject, from_addr, reply_to, text_body, html_body):
    """
    Build a result dict similar to analyze_email() but for pasted text/html.
    Re-uses the helper functions in phishing_analyzer where possible.
    """
    headers_text = f"Subject: {subject}\nFrom: {from_addr}\nReply-To: {reply_to}\n"
    body_combined = (text_body or "") + " " + (html_body or "")

    # ML prediction
    ml_result = phishing_analyzer.ml_predict(body_combined)

    # Keyword hits and domain mismatch
    fd, rd, mismatch = phishing_analyzer.domains_mismatch(from_addr, reply_to)
    kw = set(phishing_analyzer.keyword_hits(subject) + phishing_analyzer.keyword_hits(text_body) + phishing_analyzer.keyword_hits(html_body))

    total = 0
    reasons = []
    if mismatch:
        total += 2
        reasons.append(f"From vs Reply-To mismatch ({fd} ≠ {rd})")
    if kw:
        total += 1
        reasons.append("Suspicious keywords: " + ", ".join(sorted(kw)))

    # URLs
    urls = phishing_analyzer.extract_urls(text_body, html_body)
    url_details = []
    primary_host = phishing_analyzer.hostname_from_url(urls[0]) if urls else ""
    if phishing_analyzer.brand_claim_without_domain(headers_text, body_combined, primary_host):
        total += 1
        reasons.append("Brand claim without matching domain")

    for u in urls:
        s, r = phishing_analyzer.score_url(u, html_body)
        total += s
        # run sandbox (either selenium-based or lightweight sandbox depending on env)
        sandbox_result = phishing_analyzer.selenium_sandbox(u)
        url_details.append({
            "url": u,
            "reasons": r,
            "sandbox": sandbox_result
        })

    # attachments and script warnings are empty for raw text
    attachments_report = []
    script_warnings = phishing_analyzer.analyze_scripts(html_body)

    result = {
        "file": None,
        "subject": subject,
        "from": from_addr,
        "reply_to": reply_to,
        "date": "",
        "num_urls": len(urls),
        "urls": urls,
        "score": total,
        "risk": phishing_analyzer.risk_level(total),
        "email_reasons": reasons,
        "url_reasons": url_details,
        "ml_prediction": ml_result,
        "attachments": attachments_report,
        "script_warnings": script_warnings
    }
    return result


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze_upload", methods=["POST"])
def analyze_upload():
    """
    Accept file uploads (one or more .eml files) and analyze them using analyze_email().
    """
    files = request.files.getlist("eml_files")
    results = []
    if not files or files == [None]:
        flash("No files uploaded", "warning")
        return redirect(url_for("index"))

    for f in files:
        if not f:
            continue
        fname = f.filename or "upload.eml"
        safe_path = os.path.join(UPLOAD_DIR, fname)
        # Save uploaded file
        f.save(safe_path)
        try:
            res = phishing_analyzer.analyze_email(safe_path)
            # also write per-email markdown report
            phishing_analyzer.write_markdown_report(res, REPORT_DIR)
            results.append(res)
        except Exception as e:
            # return its error in the UI
            results.append({
                "file": fname,
                "error": str(e)
            })

    # Save a summary CSV
    if results:
        csv_path = os.path.join(REPORT_DIR, "summary.csv")
        phishing_analyzer.write_summary([r for r in results if "error" not in r], csv_path)
    return render_template("result.html", results=results)


# Helper: create a safe filename base from the email subject
def safe_name_from_subject(subject: str) -> str:
    """
    Return a filesystem-safe short name derived from subject.
    If subject is empty, returns 'pasted_email'.
    """
    if not subject:
        subject = "pasted_email"
    # replace disallowed chars with underscores and trim length
    name = re.sub(r'[^A-Za-z0-9._-]+', '_', subject).strip('_')[:60]
    if not name:
        name = "pasted_email"
    return name


@app.route("/analyze_text", methods=["POST"])
def analyze_text_route():
    """
    Analyze pasted email text / HTML. Accepts form fields:
    subject, from_addr, reply_to, text_body, html_body
    """
    try:
        subject = request.form.get("subject", "")
        from_addr = request.form.get("from_addr", "")
        reply_to = request.form.get("reply_to", "")
        text_body = request.form.get("text_body", "")
        html_body = request.form.get("html_body", "")

        result = analyze_raw_email(subject, from_addr, reply_to, text_body, html_body)

        # Ensure result["file"] is always a string (write_markdown_report expects it).
        if not result.get("file"):
            safe_base = safe_name_from_subject(subject)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pseudo_filename = f"{safe_base}_{timestamp}.eml"
            result["file"] = pseudo_filename  # used only for naming the report

        # Ensure reports dir exists
        os.makedirs(REPORT_DIR, exist_ok=True)

        # Try writing the markdown report; if it fails, log but don't abort the response
        try:
            phishing_analyzer.write_markdown_report(result, REPORT_DIR)
        except Exception as e:
            import traceback
            traceback.print_exc()
            result.setdefault("notes", []).append(f"report_write_failed: {e!s}")

        return render_template("result.html", results=[result])

    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response(f"Exception during analysis: {e}\n\nSee server console for full traceback", status=500, mimetype="text/plain")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    JSON API: POST {"subject":"...", "from":"...", "reply_to":"...", "text":"...", "html":"..."}
    returns JSON analysis.
    """
    data = request.get_json(force=True)
    subject = data.get("subject", "")
    from_addr = data.get("from", "")
    reply_to = data.get("reply_to", "")
    text_body = data.get("text", "")
    html_body = data.get("html", "")

    result = analyze_raw_email(subject, from_addr, reply_to, text_body, html_body)
    return jsonify(result)


@app.route("/download/summary")
def download_summary():
    p = os.path.join(REPORT_DIR, "summary.csv")
    if not os.path.exists(p):
        flash("No summary found", "warning")
        return redirect(url_for("index"))
    return send_file(p, as_attachment=True, download_name="summary.csv")


if __name__ == "__main__":
    # For local dev only. Use gunicorn / uvicorn + proper WSGI in production.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=(os.getenv("FLASK_DEBUG", "0") == "1"))
