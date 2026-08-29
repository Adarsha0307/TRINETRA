"""TrustShield backend + ML integration tests"""
import os
import requests
import pytest

BASE = "https://9fff2426-305b-47a8-9e65-809d8d5dbc17.preview.emergentagent.com"
API = f"{BASE}/api"
ML = "http://localhost:5001"


# ---------- URL scanner ----------
class TestUrlScan:
    def test_safe_url(self):
        r = requests.post(f"{API}/scan/url", json={"url": "https://www.google.com"})
        assert r.status_code == 201, r.text
        d = r.json()
        assert d["classification"] == "SAFE"
        assert d["riskScore"] <= 29
        assert d["threatCategory"] == "NONE"

    def test_phishing_url_ml(self):
        r = requests.post(f"{API}/scan/url", json={"url": "http://paypa1.com/login/verify-account"})
        assert r.status_code == 201, r.text
        d = r.json()
        assert d["classification"] in ("SUSPICIOUS", "HIGH_RISK")
        codes = [s["code"] for s in d["signals"]]
        assert "BRAND_IMPERSONATION" in codes
        assert "ml" in d and d["ml"] is not None
        assert isinstance(d["ml"]["probability"], (int, float))
        assert d["ml"]["modelVersion"] == "baseline-1"

    def test_malformed_url(self):
        r = requests.post(f"{API}/scan/url", json={"url": "not a url"})
        assert r.status_code == 400

    def test_empty_url(self):
        r = requests.post(f"{API}/scan/url", json={"url": ""})
        assert r.status_code == 400

    def test_missing_url(self):
        r = requests.post(f"{API}/scan/url", json={})
        assert r.status_code == 400


# ---------- Email scanner ----------
class TestEmailScan:
    def test_phishing_email(self):
        r = requests.post(f"{API}/scan/email", json={
            "sender": "security@paypa1.com",
            "subject": "URGENT: Verify your account now",
            "content": "Your PayPal account will be suspended. Please verify your password immediately at http://paypa1.com/login"
        })
        assert r.status_code == 201, r.text
        d = r.json()
        assert d["classification"] in ("SUSPICIOUS", "HIGH_RISK")
        assert len(d["signals"]) >= 2
        assert d["explanation"]

    def test_empty_email(self):
        r = requests.post(f"{API}/scan/email", json={"sender": "a@b.com", "subject": "", "content": ""})
        assert r.status_code == 400


# ---------- Message scanner ----------
class TestMessageScan:
    def test_otp_scam(self):
        r = requests.post(f"{API}/scan/message", json={
            "content": "URGENT: Your account will be suspended today. Verify immediately and share the OTP sent to your phone at http://icici-verify.paypa1.com/login"
        })
        assert r.status_code == 201, r.text
        d = r.json()
        assert d["classification"] in ("SUSPICIOUS", "HIGH_RISK")
        codes = [s["code"] for s in d["signals"]]
        assert "OTP_REQUEST" in codes

    def test_empty_message(self):
        r = requests.post(f"{API}/scan/message", json={"content": ""})
        assert r.status_code == 400


# ---------- QR scanner ----------
class TestQrScan:
    def test_qr_content(self):
        r = requests.post(f"{API}/scan/qr", json={"content": "http://paypa1.com/login"})
        assert r.status_code == 201, r.text
        d = r.json()
        assert "decodedDestination" in d
        codes = [s["code"] for s in d["signals"]]
        assert "BRAND_IMPERSONATION" in codes

    def test_qr_missing(self):
        r = requests.post(f"{API}/scan/qr", json={})
        assert r.status_code == 400


# ---------- Scans list / detail / delete ----------
class TestScansCrud:
    def test_list_and_detail_and_delete(self):
        # create a scan first
        c = requests.post(f"{API}/scan/url", json={"url": "http://phishy-test-xyz.example.com/login"})
        assert c.status_code == 201
        sid = c.json()["id"]

        lst = requests.get(f"{API}/scans")
        assert lst.status_code == 200
        assert isinstance(lst.json(), list)

        det = requests.get(f"{API}/scans/{sid}")
        assert det.status_code == 200
        assert isinstance(det.json()["signals"], list)

        dele = requests.delete(f"{API}/scans/{sid}")
        assert dele.status_code == 204

        after = requests.get(f"{API}/scans/{sid}")
        assert after.status_code == 404

    def test_invalid_id(self):
        r = requests.get(f"{API}/scans/abc")
        assert r.status_code == 400

    def test_nonexistent_id(self):
        r = requests.get(f"{API}/scans/999999")
        assert r.status_code == 404


# ---------- Dashboard ----------
class TestDashboard:
    def test_dashboard(self):
        r = requests.get(f"{API}/dashboard")
        assert r.status_code == 200
        d = r.json()
        for k in ("totalScans", "safeScans", "suspiciousScans", "highRiskScans"):
            assert isinstance(d[k], int)
        assert isinstance(d["threatCategories"], list)
        assert isinstance(d["scansByType"], list)
        assert isinstance(d["recentScans"], list)


# ---------- ML service ----------
class TestMLService:
    def test_health(self):
        r = requests.get(f"{ML}/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_predict(self):
        features = {
            "urlLength": 45, "hostnameLength": 20, "pathLength": 15,
            "subdomainCount": 2, "hasIpHost": 0, "hasPunycode": 0,
            "hasAtSymbol": 0, "digitCount": 3, "hasHttps": 0, "suspiciousKeyword": 1
        }
        r = requests.post(f"{ML}/predict", json={"features": features})
        assert r.status_code == 200
        d = r.json()
        assert 0 <= d["probability"] <= 1
        assert d["modelVersion"]

    def test_metrics(self):
        r = requests.get(f"{ML}/metrics")
        assert r.status_code == 200
        d = r.json()
        for k in ("accuracy", "precision", "recall", "f1"):
            assert k in d
