"""
TrustShield ML service (FastAPI).

Exposes POST /predict returning a real model probability. This service is called
ONLY by the Node.js backend, never directly by the browser.

Run:  uvicorn app:app --host 0.0.0.0 --port 5001
"""
import json
import os

import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="TrustShield ML Service", version="baseline-1")

_bundle = None
_metrics = None


def _load():
    global _bundle, _metrics
    if _bundle is None:
        _bundle = joblib.load(os.path.join(HERE, "model.pkl"))
    if _metrics is None and os.path.exists(os.path.join(HERE, "metrics.json")):
        with open(os.path.join(HERE, "metrics.json")) as f:
            _metrics = json.load(f)
    return _bundle


class PredictRequest(BaseModel):
    features: dict


@app.get("/health")
def health():
    ok = os.path.exists(os.path.join(HERE, "model.pkl"))
    return {"status": "ok" if ok else "model_missing"}


@app.get("/metrics")
def metrics():
    _load()
    return _metrics or {"error": "metrics unavailable"}


@app.post("/predict")
def predict(req: PredictRequest):
    bundle = _load()
    model, feat_names, version = bundle["model"], bundle["features"], bundle["modelVersion"]
    vector = [float(req.features.get(name, 0) or 0) for name in feat_names]
    proba = float(model.predict_proba(np.array([vector]))[0][1])
    return {"probability": round(proba, 4), "modelVersion": version}
