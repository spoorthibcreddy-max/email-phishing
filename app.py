from flask import Flask, render_template, request, redirect, url_for, session, flash

import os
import csv
import sqlite3
import json
import re
from datetime import datetime
import joblib


# ==================================================
# FLASK APPLICATION
# ==================================================

app = Flask(__name__)


# ==================================================
# SECURITY / SECRET KEY
# ==================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "AI_Phishing_Email_Detection_Local_2026"
)


# ==================================================
# ADMIN LOGIN CONFIGURATION
# ==================================================

ADMIN_USERNAME = os.environ.get(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "admin123"
)


# ==================================================
# PROJECT PATHS
# ==================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

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


# ==================================================
# LOAD MACHINE LEARNING MODEL
# ==================================================

model = None

try:

    if os.path.exists(MODEL_FILE):

        model = joblib.load(
            MODEL_FILE
        )

        print("✓ Machine Learning model loaded:")
        print(MODEL_FILE)

    else:

        print("⚠ Machine Learning model NOT found:")
        print(MODEL_FILE)

except Exception as e:

    print("⚠ Error loading Machine Learning model:")
    print(e)


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def init_database():

    conn = sqlite3.connect(
        DATABASE_FILE
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT DEFAULT '',
            email TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------
    # CHECK EXISTING DATABASE COLUMNS
    # --------------------------------------------------

    columns = conn.execute("""
        PRAGMA table_info(predictions)
    """).fetchall()

    column_names = [
        column[1]
        for column in columns
    ]

    # --------------------------------------------------
    # ADD SENDER EMAIL COLUMN IF MISSING
    # --------------------------------------------------

    if "sender_email" not in column_names:

        conn.execute("""
            ALTER TABLE predictions
            ADD COLUMN sender_email TEXT DEFAULT ''
        """)

    conn.commit()
    conn.close()


# ==================================================
# CSV HISTORY INITIALIZATION
# ==================================================

def init_history():

    new_header = [
        "ID",
        "Sender Email",
        "Email",
        "Prediction",
        "Confidence",
        "Date"
    ]

    # --------------------------------------------------
    # CREATE CSV IF IT DOES NOT EXIST
    # --------------------------------------------------

    if not os.path.exists(HISTORY_FILE):

        with open(
            HISTORY_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                new_header
            )

        return

    # --------------------------------------------------
    # CHECK EXISTING CSV HEADER
    # --------------------------------------------------

    try:

        with open(
            HISTORY_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            rows = list(
                csv.reader(file)
            )

        if not rows:
            return

        current_header = rows[0]

        # Already updated
        if current_header == new_header:
            return

        # --------------------------------------------------
        # MIGRATE OLD 5-COLUMN CSV
        # --------------------------------------------------

        migrated_rows = []

        for row in rows[1:]:

            if not row:
                continue

            # Old format:
            # ID, Email, Prediction, Confidence, Date

            if len(row) >= 5:

                migrated_rows.append([
                    row[0],
                    "",
                    row[1],
                    row[2],
                    row[3],
                    row[4]
                ])

        with open(
            HISTORY_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                new_header
            )

            writer.writerows(
                migrated_rows
            )

    except Exception as e:

        print("History initialization error:")
        print(e)


# ==================================================
# SAVE PREDICTION
# ==================================================

def save_prediction(

    sender_email,
    email,
    prediction,
    confidence
):

    date_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------
    # SAVE TO SQLITE DATABASE
    # --------------------------------------------------

    conn = sqlite3.connect(
        DATABASE_FILE
    )

    conn.execute("""
        INSERT INTO predictions
        (
            sender_email,
            email,
            prediction,
            confidence,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        sender_email,
        email,
        prediction,
        confidence,
        date_time
    ))

    conn.commit()
    conn.close()

    # --------------------------------------------------
    # SAVE TO CSV HISTORY
    # --------------------------------------------------

    with open(
        HISTORY_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "",
            sender_email,
            email,
            prediction,
            confidence,
            date_time
        ])


# ==================================================
# EMAIL PREDICTION
# ==================================================

def predict_email(
    email_text
):

    if model is None:

        return (
            "Model Not Found",
            0.0,
            []
        )

    try:

        # ==================================================
        # MACHINE LEARNING PREDICTION
        # ==================================================

        prediction = model.predict(
            [email_text]
        )[0]

        confidence = 0.0

        if hasattr(
            model,
            "predict_proba"
        ):

            probabilities = model.predict_proba(
                [email_text]
            )[0]

            confidence = (
                max(probabilities) * 100
            )

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

        # ==================================================
        # ADDITIONAL PHISHING INDICATORS
        # ==================================================

        text = email_text.lower()

        reasons = []

        # --------------------------------------------------
        # URGENCY / THREAT
        # --------------------------------------------------

        urgency_words = [
            "urgent",
            "immediately",
            "right now",
            "act now",
            "within 24 hours",
            "within 48 hours",
            "last warning",
            "final warning",
            "account will be closed",
            "account will be suspended",
            "account has been suspended",
            "your account is locked",
            "legal action",
            "action required"
        ]

        if any(
            word in text
            for word in urgency_words
        ):

            reasons.append(
                "🚨 Urgent or threatening language detected"
            )

        # --------------------------------------------------
        # SENSITIVE INFORMATION
        # --------------------------------------------------

        sensitive_words = [
            "password",
            "passcode",
            "otp",
            "one time password",
            "one-time password",
            "pin",
            "cvv",
            "card number",
            "bank details",
            "account number",
            "login credentials",
            "security code",
            "verification code"
        ]

        if any(
            word in text
            for word in sensitive_words
        ):

            reasons.append(
                "🔐 Request for sensitive information detected"
            )

        # --------------------------------------------------
        # FINANCIAL REQUEST
        # --------------------------------------------------

        financial_words = [
            "transfer money",
            "send money",
            "payment",
            "pay immediately",
            "bank account",
            "credit card",
            "debit card",
            "refund",
            "prize",
            "lottery",
            "winning amount",
            "claim your money"
        ]

        if any(
            word in text
            for word in financial_words
        ):

            reasons.append(
                "💰 Financial or payment-related content detected"
            )

        # --------------------------------------------------
        # IMPERSONATION
        # --------------------------------------------------

        impersonation_words = [
            "your bank",
            "bank security team",
            "customer support",
            "account security team",
            "microsoft support",
            "google support",
            "apple support",
            "paypal support",
            "official support",
            "government department"
        ]

        impersonation_detected = any(
            word in text
            for word in impersonation_words
        )

        impersonation_action_words = [
            "verify",
            "confirm",
            "update",
            "login",
            "click",
            "open",
            "download",
            "provide",
            "send",
            "enter",
            "submit",
            "password",
            "otp",
            "pin",
            "cvv",
            "verification code",
            "security code"
        ]

        impersonation_action_detected = any(
            word in text
            for word in impersonation_action_words
        )

        if (
            impersonation_detected
            and impersonation_action_detected
        ):

            reasons.append(
                "🎭 Possible impersonation or authority claim detected"
            )

        # --------------------------------------------------
        # LINK DETECTION
        # --------------------------------------------------

        url_pattern = (
            r"https?://"
            r"|www\."
            r"|bit\.ly"
            r"|tinyurl"
            r"|t\.co/"
        )

        if re.search(
            url_pattern,
            text
        ):

            reasons.append(
                "🔗 Link or URL detected in the email"
            )

        # --------------------------------------------------
        # ATTACHMENT REQUEST
        # --------------------------------------------------

        attachment_words = [
            "open the attachment",
            "download the attachment",
            "attached file",
            "open attached",
            "download this file",
            "attachment"
        ]

        if any(
            word in text
            for word in attachment_words
        ):

            reasons.append(
                "📎 Attachment-related instruction detected"
            )

        # --------------------------------------------------
        # SUSPICIOUS ACTION REQUEST
        # --------------------------------------------------

        action_words = [
            "verify your account",
            "verify your identity",
            "confirm your account",
            "confirm your identity",
            "login immediately",
            "click here",
            "click the link",
            "update your account",
            "reactivate your account"
        ]

        if any(
            word in text
            for word in action_words
        ):

            reasons.append(
                "⚠️ Suspicious account or verification action detected"
            )

        # ==================================================
        # COMBINE ML + INDICATORS
        # ==================================================

        indicator_count = len(
            reasons
        )

        # --------------------------------------------------
        # THREE OR MORE INDICATORS
        # --------------------------------------------------

        if indicator_count >= 3:

            result = "Phishing"

            confidence = max(
                confidence,
                min(
                    60 + (indicator_count * 8),
                    95
                )
            )

        # --------------------------------------------------
        # TWO INDICATORS
        # --------------------------------------------------

        elif indicator_count == 2:

            if result == "Phishing":

                confidence = max(
                    confidence,
                    75
                )

            else:

                result = "Phishing"

                confidence = max(
                    confidence,
                    70
                )

        # --------------------------------------------------
        # ONE INDICATOR
        # --------------------------------------------------

        elif indicator_count == 1:

            if result == "Phishing":

                confidence = max(
                    confidence,
                    65
                )

        # --------------------------------------------------
        # NO INDICATORS
        # --------------------------------------------------

        if indicator_count == 0:

            reasons.append(
                "✅ No major rule-based phishing indicators detected"
            )

        # ==================================================
        # RETURN RESULT
        # ==================================================

        return (
            result,
            round(
                float(confidence),
                2
            ),
            reasons
        )

    except Exception as e:

        print("Prediction error:")
        print(e)

        return (
            "Error",
            0.0,
            []
        )


# ==================================================
# PUBLIC PAGES
# ==================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


@app.route("/how-it-works")
def how_it_works():

    return render_template(
        "how_it_works.html"
    )


@app.route("/analyzer")
def analyzer():

    return render_template(
        "analyzer.html"
    )


@app.route("/security-tips")
def security_tips():

    return render_template(
        "security_tips.html"
    )


@app.route("/faq")
def faq():

    return render_template(
        "faq.html"
    )


# ==================================================
# EMAIL ANALYSIS
# ==================================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    # --------------------------------------------------
    # GET USER EMAIL
    # --------------------------------------------------

    sender_email = request.form.get("sender_email", "").strip()
    email_text = request.form.get("email",
    "").strip()

    # --------------------------------------------------
    # GET SENDER EMAIL
    # --------------------------------------------------

    sender_email = request.form.get(
        "sender_email",
        ""
    ).strip()

    # --------------------------------------------------
    # GET EMAIL CONTENT
    # --------------------------------------------------

    email_text = request.form.get(
        "email",
        ""
    ).strip()

    # --------------------------------------------------
    # CHECK EMAIL CONTENT
    # --------------------------------------------------

    if not email_text:

        flash(
            "Please enter an email message.",
            "error"
        )

        return redirect(
            url_for("analyzer")
        )

    # ==================================================
    # PREDICT EMAIL
    # ==================================================

    prediction, confidence, reasons = predict_email(
        email_text
    )

    # ==================================================
    # ERROR CHECKING
    # ==================================================

    if prediction == "Model Not Found":

        flash(
            "Machine Learning model was not found.",
            "error"
        )

        return redirect(
            url_for("analyzer")
        )

    if prediction == "Error":

        flash(
            "An error occurred while analyzing the email.",
            "error"
        )

        return redirect(
            url_for("analyzer")
        )

    # ==================================================
    # SAVE COMPLETE RESULT
    # ==================================================

    save_prediction(
        sender_email,
        email_text,
        prediction,
        confidence
    )

    # ==================================================
    # SHOW RESULT PAGE
    # ==================================================

    return render_template(
        "result.html",
        sender_email=sender_email,
        email=email_text,
        prediction=prediction,
        confidence=confidence,
        reasons=reasons
    )


# ==================================================
# ADMIN LOGIN
# ==================================================

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


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.pop(
        "admin_logged_in",
        None
    )

    return redirect(
        url_for("login")
    )


# ==================================================
# ADMIN DASHBOARD
# ==================================================

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

    # --------------------------------------------------
    # LATEST 10 RECORDS
    # --------------------------------------------------

    records = conn.execute("""
        SELECT
            id,
            sender_email,
            email,
            prediction,
            confidence,
            created_at
        FROM predictions
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    # --------------------------------------------------
    # TOTAL SCANNED
    # --------------------------------------------------

    total = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
    """).fetchone()[0]

    # --------------------------------------------------
    # PHISHING COUNT
    # --------------------------------------------------

    phishing = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Phishing'
    """).fetchone()[0]

    # --------------------------------------------------
    # SAFE COUNT
    # --------------------------------------------------

    safe = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Legitimate'
    """).fetchone()[0]

    # --------------------------------------------------
    # HIGH RISK COUNT
    # --------------------------------------------------

    high_risk = conn.execute("""
        SELECT COUNT(*)
        FROM predictions
        WHERE prediction = 'Phishing'
        AND confidence >= 80
    """).fetchone()[0]

    conn.close()

    # --------------------------------------------------
    # DASHBOARD PERCENTAGES
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


# ==================================================
# DETECTION HISTORY
# ==================================================

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
        SELECT
            id,
            sender_email,
            email,
            prediction,
            confidence,
            created_at
        FROM predictions
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "history.html",
        records=records
    )


# ==================================================
# MODEL PERFORMANCE
# ==================================================

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

            metrics = json.load(
                file
            )

    except Exception as e:

        print(
            "Model metrics error:"
        )

        print(e)

        metrics = {}

    return render_template(
        "model_performance.html",
        metrics=metrics
    )


# ==================================================
# DELETE ONE RECORD
# ==================================================

@app.route(
    "/delete/<int:record_id>",
    methods=["POST"]
)
def delete_record(
    record_id
):

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


# ==================================================
# DELETE ALL RECORDS
# ==================================================

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

    # --------------------------------------------------
    # RESET CSV HISTORY
    # --------------------------------------------------

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
                "User Email",
                "Sender Email",
                "Email",
                "Prediction",
                "Confidence",
                "Date"
            ])

    except Exception as e:

        print(
            "History reset error:"
        )

        print(e)

    flash(
        "All records deleted successfully.",
        "success"
    )

    return redirect(
        url_for("history")
    )


# ==================================================
# HEALTH CHECK
# ==================================================

@app.route("/health")
def health():

    return {
        "application":
            "AI Phishing Email Detection System",

        "model_loaded":
            model is not None,

        "database_exists":
            os.path.exists(
                DATABASE_FILE
            )
    }


# ==================================================
# ERROR HANDLING
# ==================================================

@app.errorhandler(404)
def page_not_found(error):

    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    """, 404


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    # --------------------------------------------------
    # INITIALIZE DATABASE
    # --------------------------------------------------

    init_database()

    # --------------------------------------------------
    # INITIALIZE HISTORY
    # --------------------------------------------------

    init_history()

    # --------------------------------------------------
    # STARTUP INFORMATION
    # --------------------------------------------------

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

    # --------------------------------------------------
    # START FLASK
    # --------------------------------------------------

    app.run(
    debug=False,
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 5000))
    )