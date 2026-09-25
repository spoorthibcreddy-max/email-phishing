from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import csv
import sqlite3
import json
from datetime import datetime
import joblib


# --------------------------------------------------
# FLASK APPLICATION
# --------------------------------------------------

app = Flask(__name__)

# Security:
# Use an environment variable for the Flask secret key.
# The fallback keeps the project working locally.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "AI_Phishing_Email_Detection_Local_2026"
)


# --------------------------------------------------
# ADMIN LOGIN CONFIGURATION
# --------------------------------------------------

# Admin credentials can be changed through environment variables.
# Default values are kept so the existing login continues to work.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_FILE = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "phishing.db"
)

HISTORY_FILE = os.path.join(
    BASE_DIR,
    "history.csv"
)


# --------------------------------------------------
# LOAD MACHINE LEARNING MODEL
# --------------------------------------------------

model = None

try:

    if os.path.exists(MODEL_FILE):

        model = joblib.load(MODEL_FILE)

        print("✓ Machine Learning model loaded:")
        print(MODEL_FILE)

    else:

        print("⚠ Machine Learning model NOT found:")
        print(MODEL_FILE)


except Exception as e:

    print("⚠ Error loading Machine Learning model:")
    print(e)


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_database():

    conn = sqlite3.connect(DATABASE_FILE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# CSV HISTORY INITIALIZATION
# --------------------------------------------------

def init_history():

    if not os.path.exists(HISTORY_FILE):

        with open(
            HISTORY_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "ID",
                "Email",
                "Prediction",
                "Confidence",
                "Date"
            ])


# --------------------------------------------------
# SAVE PREDICTION
# --------------------------------------------------

def save_prediction(email, prediction, confidence):

    date_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Save to SQLite
    try:

        conn = sqlite3.connect(DATABASE_FILE)

        conn.execute("""
            INSERT INTO predictions
            (email, prediction, confidence, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            email,
            prediction,
            confidence,
            date_time
        ))

        conn.commit()
        conn.close()

    except Exception as e:

        print("Database error:")
        print(e)


    # Save to CSV
    try:

        with open(
            HISTORY_FILE,
            "a",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "",
                email,
                prediction,
                confidence,
                date_time
            ])

    except Exception as e:

        print("History error:")
        print(e)


# --------------------------------------------------
# EMAIL PREDICTION
# --------------------------------------------------

def predict_email(email_text):

    if model is None:

        return "Model Not Found", 0.0

    try:

        prediction = model.predict(
            [email_text]
        )[0]

        confidence = 0.0

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(
                [email_text]
            )[0]

            confidence = max(probabilities) * 100

        else:

            confidence = 100.0


        prediction_text = str(
            prediction
        ).lower().strip()


        if prediction_text in [
            "1",
            "phishing",
            "spam",
            "malicious",
            "fraud",
            "scam"
        ]:

            result = "Phishing"

        else:

            result = "Legitimate"


        return result, round(
            float(confidence),
            2
        )


    except Exception as e:

        print("Prediction error:")
        print(e)

        return "Error", 0.0


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# --------------------------------------------------
# PREDICT EMAIL
# --------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    email_text = request.form.get(
        "email",
        ""
    ).strip()


    if not email_text:

        flash(
            "Please enter an email message.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    prediction, confidence = predict_email(
        email_text
    )


    if prediction == "Model Not Found":

        flash(
            "Machine Learning model was not found.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    if prediction == "Error":

        flash(
            "An error occurred while analyzing the email.",
            "error"
        )

        return redirect(
            url_for("home")
        )


    save_prediction(
        email_text,
        prediction,
        confidence
    )


    return render_template(
        "result.html",
        email=email_text,
        prediction=prediction,
        confidence=confidence
    )


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()


        if (
            username == ADMIN_USERNAME
            and password == ADMIN_PASSWORD
        ):

            session[
                "admin_logged_in"
            ] = True

            return redirect(
                url_for("dashboard")
            )


        flash(
            "Invalid username or password.",
            "error"
        )


    return render_template(
        "login.html"
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.pop(
        "admin_logged_in",
        None
    )

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    conn = sqlite3.connect(
        DATABASE_FILE
    )

    conn.row_factory = sqlite3.Row


    # Get all records
    records = conn.execute("""
        SELECT *
        FROM predictions
        ORDER BY id DESC
    """).fetchall()


    # Total scanned
    total = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
    """).fetchone()[0]


    # Phishing count
    phishing = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Phishing'
    """).fetchone()[0]


    # Safe count
    safe = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Legitimate'
    """).fetchone()[0]


    # High risk count
    # Phishing emails with confidence >= 80%
    high_risk = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Phishing'
        AND confidence >= 80
    """).fetchone()[0]


    conn.close()


    # --------------------------------------------------
    # CALCULATE DASHBOARD PERCENTAGES
    # --------------------------------------------------

    if total > 0:

        phishing_percent = round(
            (phishing / total) * 100,
            1
        )

        safe_percent = round(
            (safe / total) * 100,
            1
        )

        high_risk_percent = round(
            (high_risk / total) * 100,
            1
        )

    else:

        phishing_percent = 0
        safe_percent = 0
        high_risk_percent = 0


    return render_template(
        "dashboard.html",

        records=records,

        total=total,

        phishing=phishing,

        safe=safe,

        high_risk=high_risk,

        phishing_percent=phishing_percent,

        safe_percent=safe_percent,

        high_risk_percent=high_risk_percent
    )


# --------------------------------------------------
# HISTORY
# --------------------------------------------------

@app.route("/history")
def history():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    conn = sqlite3.connect(
        DATABASE_FILE
    )

    conn.row_factory = sqlite3.Row


    records = conn.execute("""
        SELECT id, email, prediction, confidence, created_at
        FROM predictions
        ORDER BY id DESC
    """).fetchall()


    conn.close()


    return render_template(
        "history.html",
        records=records
    )


# --------------------------------------------------
# MODEL PERFORMANCE
# --------------------------------------------------

@app.route("/model-performance")
def model_performance():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    metrics_file = os.path.join(
        BASE_DIR,
        "data",
        "model_metrics.json"
    )


    try:

        with open(
            metrics_file,
            "r",
            encoding="utf-8"
        ) as file:

            metrics = json.load(file)

    except Exception as e:

        print("Model metrics error:")
        print(e)

        metrics = {}


    return render_template(
        "model_performance.html",
        metrics=metrics
    )


# --------------------------------------------------
# DELETE ONE RECORD
# --------------------------------------------------

@app.route(
    "/delete/<int:record_id>",
    methods=["POST"]
)
def delete_record(record_id):

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    conn = sqlite3.connect(
        DATABASE_FILE
    )


    conn.execute(
        "DELETE FROM predictions WHERE id = ?",
        (record_id,)
    )


    conn.commit()
    conn.close()


    flash(
        "Record deleted successfully.",
        "success"
    )


    return redirect(
        url_for("history")
    )


# --------------------------------------------------
# DELETE ALL RECORDS
# --------------------------------------------------

@app.route(
    "/delete_all",
    methods=["POST"]
)
def delete_all():

    if not session.get(
        "admin_logged_in"
    ):

        return redirect(
            url_for("login")
        )


    conn = sqlite3.connect(
        DATABASE_FILE
    )


    conn.execute(
        "DELETE FROM predictions"
    )


    conn.commit()
    conn.close()


    # Reset CSV
    try:

        with open(
            HISTORY_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "ID",
                "Email",
                "Prediction",
                "Confidence",
                "Date"
            ])


    except Exception as e:

        print("History reset error:")
        print(e)


    flash(
        "All records deleted successfully.",
        "success"
    )


    return redirect(
        url_for("history")
    )


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():

    return {
        "application":
            "AI Phishing Email Detection System",

        "model_loaded":
            model is not None,

        "database_exists":
            os.path.exists(DATABASE_FILE)
    }


# --------------------------------------------------
# 404 ERROR
# --------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    """, 404


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    init_database()
    init_history()


    print("=" * 60)

    print(
        "AI-BASED PHISHING EMAIL DETECTION SYSTEM"
    )

    print("=" * 60)


    if model is not None:

        print(
            "✓ Machine Learning model loaded"
        )

    else:

        print(
            "⚠ Machine Learning model NOT found"
        )


    print(
        "✓ Database initialized"
    )

    print(
        "✓ History initialized"
    )

    print("=" * 60)


    print(
        "Starting Flask server..."
    )

    print(
        "Open on this laptop: http://127.0.0.1:5000"
    )

    print(
        "Phone access: http://<YOUR-LAPTOP-IP>:5000"
    )

    print("=" * 60)


    # 0.0.0.0 allows other devices on the same
    # local network to access the Flask application.
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )