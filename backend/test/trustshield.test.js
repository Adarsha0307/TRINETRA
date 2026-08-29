import { describe, it, expect } from 'vitest';
import { scanUrl, scanEmail, scanMessage, scanQrContent } from '../src/services/trustshield/index.js';

const codes = (r) => r.signals.map(s => s.code);

describe('URL scanner', () => {
  it('rates a legitimate URL as SAFE', () => {
    const { result } = scanUrl('https://www.google.com/search?q=hello');
    expect(result.classification).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(29);
    expect(result.threatCategory).toBe('NONE');
  });

  it('flags a raw IP host with an IP_HOSTNAME signal', () => {
    const { result } = scanUrl('http://192.168.10.5/login');
    expect(codes(result)).toContain('IP_HOSTNAME');
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
  });

  it('detects brand impersonation / typosquatting', () => {
    const { result } = scanUrl('http://paypa1.com/login');
    expect(codes(result)).toContain('BRAND_IMPERSONATION');
    expect(['SUSPICIOUS', 'HIGH_RISK']).toContain(result.classification);
  });

  it('flags credential keywords', () => {
    const { result } = scanUrl('http://secure-verify-account.xyz/update-password');
    expect(codes(result)).toContain('CREDENTIAL_KEYWORDS');
  });

  it('rejects malformed input', () => {
    expect(() => scanUrl('not a url')).toThrow();
  });

  it('clamps the score to 0-100', () => {
    const { result } = scanUrl('http://paypal.com.secure-login.verify-account.amaz0n.xyz/login/update-password?x=%20%20%20%20');
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
  });
});

describe('Message scanner', () => {
  it('treats a normal message as SAFE', () => {
    const { result } = scanMessage({ content: 'Hi, are we still on for lunch tomorrow at noon?' });
    expect(result.classification).toBe('SAFE');
  });

  it('detects an OTP scam', () => {
    const { result } = scanMessage({ content: 'Your account is blocked. Share the OTP immediately to verify your identity or it will be suspended.' });
    expect(codes(result)).toContain('OTP_REQUEST');
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
  });

  it('detects a banking/KYC scam', () => {
    const { result } = scanMessage({ content: 'Dear customer, your KYC is pending. Update your bank account details and CVV now to avoid account suspension.' });
    expect(codes(result)).toContain('FINANCIAL_REQUEST');
  });

  it('detects an investment scam', () => {
    const { result } = scanMessage({ content: 'Guaranteed returns! Double your money in 7 days with this risk-free investment opportunity.' });
    expect(codes(result)).toContain('INVESTMENT_SCAM');
  });

  it('detects a fake reward scam', () => {
    const { result } = scanMessage({ content: 'Congratulations! You have won a $1000 gift card. Claim your prize now.' });
    expect(codes(result)).toContain('FAKE_REWARD');
  });
});

describe('Email scanner', () => {
  it('flags phishing email and only cites detected signals', () => {
    const { result } = scanEmail({
      sender: 'security@gmail.com',
      subject: 'Urgent: verify your account',
      content: 'Your Paypal account will be suspended. Confirm your identity immediately at http://paypa1.com/login'
    });
    expect(['SUSPICIOUS', 'HIGH_RISK']).toContain(result.classification);
    expect(result.explanation.length).toBeGreaterThan(10);
    // explanation must not reference a signal that was not produced
    expect(result.signals.length).toBeGreaterThan(0);
  });
});

describe('QR scanner', () => {
  it('analyzes a URL destination', () => {
    const { result, decoded } = scanQrContent('http://paypa1.com/login');
    expect(codes(result)).toContain('BRAND_IMPERSONATION');
    expect(decoded).toBe('http://paypa1.com/login');
  });

  it('treats non-URL payloads as low risk', () => {
    const { result } = scanQrContent('WIFI:S:MyNetwork;;');
    expect(result.classification).toBe('SAFE');
  });
});

describe('Risk contract', () => {
  it('always returns the standard fields', () => {
    const { result } = scanUrl('https://example.com');
    for (const k of ['riskScore', 'classification', 'threatCategory', 'signals', 'explanation', 'recommendedAction']) {
      expect(result).toHaveProperty(k);
    }
  });
});
