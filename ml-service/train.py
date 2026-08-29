"""
TrustShield baseline ML model.

Trains a Logistic Regression classifier that estimates the phishing likelihood
of a URL from its structural features. The dataset is generated programmatically
from realistic feature distributions (benign vs. phishing) with a probabilistic
label so the model learns genuine weights rather than a trivial rule.

Run:  python train.py
Outputs: model.pkl, metrics.json
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
import joblib

FEATURES = ["urlLength", "hostnameLength", "pathLength", "subdomainCount",
            "hasIpHost", "hasPunycode", "hasAtSymbol", "digitCount",
            "hasHttps", "suspiciousKeyword"]
MODEL_VERSION = "baseline-1"
HERE = os.path.dirname(os.path.abspath(__file__))
RNG = np.random.default_rng(42)


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def generate_dataset(n=4000):
    rows = []
    for _ in range(n):
        benign = RNG.random() < 0.5
        if benign:
            url_len = RNG.integers(15, 70)
            host_len = RNG.integers(8, 25)
            path_len = RNG.integers(0, 25)
            subdomains = RNG.integers(0, 2)
            has_ip = int(RNG.random() < 0.02)
            has_puny = int(RNG.random() < 0.01)
            has_at = int(RNG.random() < 0.01)
            digits = RNG.integers(0, 2)
            https = int(RNG.random() < 0.92)
            susp_kw = int(RNG.random() < 0.10)
        else:
            url_len = RNG.integers(60, 180)
            host_len = RNG.integers(15, 55)
            path_len = RNG.integers(15, 90)
            subdomains = RNG.integers(1, 6)
            has_ip = int(RNG.random() < 0.30)
            has_puny = int(RNG.random() < 0.20)
            has_at = int(RNG.random() < 0.18)
            digits = RNG.integers(0, 12)
            https = int(RNG.random() < 0.45)
            susp_kw = int(RNG.random() < 0.70)

        # Latent risk -> probabilistic label (adds realistic overlap / noise).
        latent = (
            0.015 * url_len + 0.02 * host_len + 0.01 * path_len
            + 0.45 * subdomains + 2.2 * has_ip + 2.0 * has_puny + 1.6 * has_at
            + 0.12 * digits - 1.1 * https + 1.4 * susp_kw - 3.6
        )
        label = int(RNG.random() < _sigmoid(latent))
        rows.append([url_len, host_len, path_len, subdomains, has_ip, has_puny,
                     has_at, digits, https, susp_kw, label])
    return pd.DataFrame(rows, columns=FEATURES + ["label"])


def main():
    df = generate_dataset()
    X, y = df[FEATURES], df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000)),
    ])
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    metrics = {
        "modelVersion": MODEL_VERSION,
        "model": "LogisticRegression",
        "features": FEATURES,
        "trainSize": int(len(X_train)),
        "testSize": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1": round(float(f1_score(y_test, y_pred)), 4),
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "falsePositives": int(fp),
        "falseNegatives": int(fn),
    }

    joblib.dump({"model": model, "features": FEATURES, "modelVersion": MODEL_VERSION},
                os.path.join(HERE, "model.pkl"))
    with open(os.path.join(HERE, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("Saved model.pkl")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
