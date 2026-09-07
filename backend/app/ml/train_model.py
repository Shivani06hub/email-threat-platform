"""
Trains a phishing email classifier.

Dataset: phishing_email.csv (from Kaggle, compiled from Enron, Nazario,
SpamAssassin, CEAS, Ling, and Nigerian Fraud sources).
Columns used: text_combined (email text), label (0 = safe, 1 = phishing).

Approach: TF-IDF text vectorization + Logistic Regression. This is
explainable (we can inspect which words push toward phishing) and
fast enough to train on a laptop without a GPU.

Run this script directly:
    python -m app.ml.train_model
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)
import joblib


DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "datasets", "phishing_dataset.csv"
)
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
SAMPLE_SIZE = 30000  # keep training fast; the full dataset has 100k+ rows


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    df = df.dropna(subset=["text_combined", "label"])

    if len(df) > SAMPLE_SIZE:
        per_class = SAMPLE_SIZE // 2
        df_0 = df[df["label"] == 0].sample(
            n=min(per_class, (df["label"] == 0).sum()), random_state=42
        )
        df_1 = df[df["label"] == 1].sample(
            n=min(per_class, (df["label"] == 1).sum()), random_state=42
        )
        df = pd.concat([df_0, df_1]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Training on {len(df)} rows.")
    print("Label distribution:")
    print(df["label"].value_counts())

    X = df["text_combined"].astype(str)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Vectorizing text (TF-IDF)...")
    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        stop_words="english",
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Training Logistic Regression model...")
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vec, y_train)

    print("Evaluating...")
    y_pred = model.predict(X_test_vec)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n--- Evaluation Results ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("Confusion Matrix:")
    print(cm)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "phishing_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))

    with open(os.path.join(MODEL_DIR, "metrics.txt"), "w") as f:
        f.write(f"Training rows: {len(X_train)}\n")
        f.write(f"Test rows: {len(X_test)}\n")
        f.write(f"Accuracy: {accuracy:.4f}\n")
        f.write(f"Precision: {precision:.4f}\n")
        f.write(f"Recall: {recall:.4f}\n")
        f.write(f"F1 Score: {f1:.4f}\n")
        f.write(f"Confusion Matrix:\n{cm}\n")

    print(f"\nModel saved to {MODEL_DIR}\\phishing_model.pkl")
    print(f"Vectorizer saved to {MODEL_DIR}\\tfidf_vectorizer.pkl")
    print(f"Metrics saved to {MODEL_DIR}\\metrics.txt")


if __name__ == "__main__":
    main()