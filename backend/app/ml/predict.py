"""
ML Predictor.

Loads the trained TF-IDF vectorizer + Logistic Regression model
(from Phase 8) and exposes a simple predict() function the API
can call on new email text.
"""

import os
import joblib
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")

_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            raise FileNotFoundError(
                "Trained model not found. Run 'python -m app.ml.train_model' first."
            )
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
    return _model, _vectorizer


def get_top_contributing_words(text, vectorizer, model, top_n=5):
    vec = vectorizer.transform([text])
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefficients = model.coef_[0]

    nonzero_indices = vec.nonzero()[1]
    if len(nonzero_indices) == 0:
        return []

    contributions = vec[0, nonzero_indices].toarray().flatten() * coefficients[nonzero_indices]
    words = feature_names[nonzero_indices]

    sorted_indices = np.argsort(contributions)[::-1]
    top_words = [words[i] for i in sorted_indices[:top_n] if contributions[i] > 0]
    return top_words


def predict(text: str) -> dict:
    model, vectorizer = _load()

    vec = vectorizer.transform([text])
    prediction = model.predict(vec)[0]
    probabilities = model.predict_proba(vec)[0]

    phishing_probability = probabilities[1]
    confidence = max(probabilities)

    classification = "PHISHING" if prediction == 1 else "BENIGN"
    top_words = get_top_contributing_words(text, vectorizer, model)

    return {
        "classification": classification,
        "confidence": round(float(confidence) * 100, 2),
        "phishing_probability": round(float(phishing_probability) * 100, 2),
        "top_contributing_words": top_words,
    }