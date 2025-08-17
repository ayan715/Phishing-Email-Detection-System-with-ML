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

Project Structure
phishing_email_analysis_lite/
│
├── app.py                  # Flask web application(Backend)
├── phishing_analyzer.py    # Core phishing analysis logic
├── train_ml_model.py       # ML model Random Forest Script
├── phishing_model.pkl      # Trained Random Forest model
├── vectorizer.pkl          # TF-IDF vectorizer
├── templates/              # HTML templates (index + results)(Frontend)
├── uploads/                # Uploaded emails (runtime)
└── reports/                # Generated reports

-How to run(Can vary for everyone)

1) git clone https://github.com/yourusername/Phishing-Email-Detection-System-with-ML.git
cd Phishing-Email-Detection-System-with-ML

2) python -m venv venv

Activate it:
PowerShell: .\venv\Scripts\Activate.ps1
CMD: venv\Scripts\activate.bat

3) pip install -r requirements.txt

4) Run Application
python app.py
Then open: http://127.0.0.1:5000/

-Manual Deployment Steps

1) Copy Phishing_analyzer.py, train_ml_model.py, index.html(in template folder), result.html(in template folder), app.py
2) Download all prerequisites and libraries
3) Download csv file as dataset
4) Give path in train_ml_model.py to train model
5) After model is trained on your system just run app.py as shown above then open http://127.0.0.1:5000

🎯 Future Improvements

Expand ML model with larger phishing datasets

Add support for additional file formats (e.g., .msg)

Integrate email header authenticity checks (SPF/DKIM/DMARC)

Dockerize for easier deployment

✨ This project was built as a demonstration of Machine Learning in cybersecurity — showing how ML and heuristics can work together to protect against phishing.









