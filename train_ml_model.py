import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load dataset
df = pd.read_csv("Phishing_Email1.csv")

# Drop the unnecessary "Unnamed: 0" column if it exists
if "Unnamed: 0" in df.columns:
    df = df.drop(columns=["Unnamed: 0"])

# Remove rows where Email Text or Email Type is missing
df = df.dropna(subset=["Email Text", "Email Type"])

# Create label: 1 = phishing, 0 = safe
df["label"] = df["Email Type"].astype(str).apply(
    lambda x: 1 if "phish" in x.lower() else 0
)

# Features and target
X = df["Email Text"].astype(str)  # Ensure all are strings
y = df["label"]

# Convert text to numerical features
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# Train model
model = LogisticRegression()
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Save model and vectorizer
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
