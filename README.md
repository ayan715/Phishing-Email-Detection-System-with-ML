📧 Phishing Email Detection System with ML

A web-based application that analyzes email files and raw content to detect potential phishing attempts using Machine Learning (Random Forest) and rule-based heuristics.

This system allows users to upload .eml files or paste raw email text/HTML into a simple web interface. It then applies a trained Random Forest model (with a TF-IDF vectorizer) along with additional security checks to classify and explain whether the email is legitimate or phishing.

🚀 Features

Machine Learning Detection
Uses a trained Random Forest model to classify email bodies.

Heuristic Analysis

Suspicious keyword detection

From vs. Reply-To domain mismatch

URL analysis & risk scoring

Script warnings in HTML content

Attachment inspection

Web Interface (Flask)

Upload .eml files for automated analysis

Paste raw email subject/text/HTML directly into the browser

View a detailed breakdown of risk factors

Report Generation

Markdown reports per email

Downloadable CSV summary for multiple uploads

🛠️ Tech Stack

Python 3

Flask (for the web interface)

scikit-learn (for ML model training & inference)

BeautifulSoup4 + lxml (for HTML parsing)

Joblib (for loading trained models)
