import pandas as pd
import joblib
import json

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# LOAD DATASET
# ==========================================

data = pd.read_csv("data/emails.csv")

print("Dataset loaded successfully!")
print("Total emails:", len(data))


# ==========================================
# EMAIL TEXT AND LABELS
# ==========================================

X = data["email"]
y = data["label"]


# ==========================================
# SPLIT DATASET
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# MACHINE LEARNING PIPELINE
# ==========================================

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])


# ==========================================
# TRAIN MODEL
# ==========================================

print("\nTraining model...")

model.fit(X_train, y_train)


# ==========================================
# PREDICTIONS
# ==========================================

predictions = model.predict(X_test)


# ==========================================
# MODEL EVALUATION
# ==========================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    predictions
)


print("\n================================")
print("       MODEL EVALUATION")
print("================================")

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1-Score  : {f1 * 100:.2f}%")


# ==========================================
# CLASSIFICATION REPORT
# ==========================================

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions
    )
)


# ==========================================
# CONFUSION MATRIX
# ==========================================

print("Confusion Matrix:")
print(cm)


# ==========================================
# SAVE EVALUATION RESULTS
# ==========================================

metrics = {
    "accuracy": round(float(accuracy) * 100, 2),
    "precision": round(float(precision) * 100, 2),
    "recall": round(float(recall) * 100, 2),
    "f1_score": round(float(f1) * 100, 2),
    "confusion_matrix": cm.tolist()
}


with open(
    "data/model_metrics.json",
    "w"
) as file:

    json.dump(
        metrics,
        file,
        indent=4
    )


print("\n================================")
print("MODEL METRICS SAVED")
print("================================")

print(
    "data/model_metrics.json"
)


# ==========================================
# SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "models/phishing_model.pkl"
)


print("\n================================")
print("MODEL SAVED SUCCESSFULLY")
print("================================")

print(
    "models/phishing_model.pkl"
)