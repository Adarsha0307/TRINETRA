// TrustShield rule-based detection constants.
// Thresholds are intentionally simple and easy to change later.

export const THRESHOLDS = {
  SAFE_MAX: 29,      // 0-29   => SAFE
  SUSPICIOUS_MAX: 69 // 30-69  => SUSPICIOUS, 70-100 => HIGH_RISK
};

export const CLASSIFICATIONS = ['SAFE', 'SUSPICIOUS', 'HIGH_RISK'];

export const THREAT_CATEGORIES = [
  'PHISHING', 'IMPERSONATION', 'OTP_SCAM', 'BANKING_SCAM', 'PAYMENT_SCAM',
  'JOB_SCAM', 'INVESTMENT_SCAM', 'LOAN_SCAM', 'REWARD_SCAM',
  'MALICIOUS_URL', 'SUSPICIOUS_CONTENT', 'NONE'
];

// Well-known legitimate domains (and their subdomains) that should never be
// flagged. Prevents false positives on common trusted sites. Configurable.
export const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'gmail.com', 'googleusercontent.com',
  'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'bing.com', 'windows.com', 'azure.com',
  'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com', 'amazonaws.com',
  'paypal.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
  'linkedin.com', 'twitter.com', 'x.com', 'netflix.com', 'wikipedia.org', 'wikimedia.org',
  'reddit.com', 'stackoverflow.com', 'stackexchange.com', 'github.com', 'githubusercontent.com', 'gitlab.com',
  'yahoo.com', 'dropbox.com', 'adobe.com', 'spotify.com', 'zoom.us', 'slack.com',
  'cloudflare.com', 'mozilla.org', 'wordpress.com', 'medium.com', 'quora.com',
  'pinterest.com', 'tumblr.com', 'twitch.tv', 'ebay.com', 'salesforce.com', 'oracle.com',
  'ibm.com', 'intel.com', 'nvidia.com', 'samsung.com', 'nike.com', 'cnn.com', 'bbc.com',
  'nytimes.com', 'forbes.com', 'bloomberg.com', 'flipkart.com', 'paytm.com', 'phonepe.com',
  'sbi.co.in', 'icicibank.com', 'hdfcbank.com', 'axisbank.com', 'chase.com', 'bankofamerica.com',
  'wellsfargo.com', 'visa.com', 'mastercard.com', 'stripe.com', 'razorpay.com',
]);

// Configurable brand list for impersonation / typosquatting detection.
export const BRANDS = [
  { name: 'google', domain: 'google.com' },
  { name: 'microsoft', domain: 'microsoft.com' },
  { name: 'paypal', domain: 'paypal.com' },
  { name: 'amazon', domain: 'amazon.com' },
  { name: 'apple', domain: 'apple.com' },
  { name: 'facebook', domain: 'facebook.com' },
  { name: 'instagram', domain: 'instagram.com' },
  { name: 'netflix', domain: 'netflix.com' },
  { name: 'whatsapp', domain: 'whatsapp.com' },
  { name: 'linkedin', domain: 'linkedin.com' }
];

export const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'gq', 'ml', 'cf', 'ga',
  'work', 'click', 'link', 'country', 'kim', 'loan', 'rest'
]);

// Central signal catalog. Every emitted signal MUST come from here so that
// scores, severities, categories and explanations stay consistent.
// reason = short human phrase used to build the explanation sentence.
export const SIGNAL_DEFS = {
  // --- URL signals ---
  IP_HOSTNAME: { name: 'IP address host', description: 'The link points directly to a numeric IP address instead of a domain name, a common technique to hide a malicious destination.', reason: 'points to a raw IP address instead of a domain', scoreContribution: 25, severity: 'HIGH', category: 'MALICIOUS_URL' },
  NO_HTTPS: { name: 'No HTTPS encryption', description: 'The link uses an unencrypted (HTTP) connection. This is a weak signal on its own but reduces trust.', reason: 'uses an unencrypted HTTP connection', scoreContribution: 5, severity: 'LOW', category: 'SUSPICIOUS_CONTENT' },
  PUNYCODE_DOMAIN: { name: 'Punycode / homograph domain', description: 'The domain uses punycode (xn--) encoding which can disguise look-alike characters to imitate a trusted brand.', reason: 'uses a punycode look-alike domain', scoreContribution: 20, severity: 'HIGH', category: 'IMPERSONATION' },
  AT_SYMBOL_OBFUSCATION: { name: 'Embedded credentials in URL', description: 'The URL contains an "@" userinfo component which can be used to make the real destination host look legitimate.', reason: 'hides its real destination using an "@" trick', scoreContribution: 15, severity: 'HIGH', category: 'MALICIOUS_URL' },
  SUSPICIOUS_ENCODING: { name: 'Suspicious characters / encoding', description: 'The URL contains heavy percent-encoding or unusual characters often used to obfuscate a malicious payload.', reason: 'contains obfuscated / heavily encoded characters', scoreContribution: 10, severity: 'MEDIUM', category: 'SUSPICIOUS_CONTENT' },
  LONG_URL: { name: 'Unusually long URL', description: 'The URL is unusually long. On its own this is only a weak signal, not proof of malice.', reason: 'is unusually long', scoreContribution: 5, severity: 'LOW', category: 'SUSPICIOUS_CONTENT' },
  EXCESSIVE_SUBDOMAINS: { name: 'Excessive subdomains', description: 'The hostname contains many subdomains, a pattern often used to bury a suspicious registrable domain.', reason: 'stacks an unusual number of subdomains', scoreContribution: 10, severity: 'MEDIUM', category: 'SUSPICIOUS_CONTENT' },
  CREDENTIAL_KEYWORDS: { name: 'Credential/login keywords in URL', description: 'The URL contains login or account-verification keywords frequently used in phishing pages.', reason: 'contains login/verification keywords in the link', scoreContribution: 15, severity: 'MEDIUM', category: 'PHISHING' },
  PAYMENT_KEYWORDS: { name: 'Payment keywords in URL', description: 'The URL references payment, billing or banking terms commonly abused in payment scams.', reason: 'references payment/billing terms in the link', scoreContribution: 10, severity: 'MEDIUM', category: 'PAYMENT_SCAM' },
  SUSPICIOUS_TLD: { name: 'Suspicious top-level domain', description: 'The domain uses a top-level domain frequently associated with abuse. This is a weak supporting signal only.', reason: 'uses a top-level domain often linked to abuse', scoreContribution: 5, severity: 'LOW', category: 'SUSPICIOUS_CONTENT' },
  BRAND_IMPERSONATION: { name: 'Brand impersonation', description: 'The domain imitates a well-known brand but is not its official domain, a classic impersonation tactic.', reason: 'imitates a well-known brand domain', scoreContribution: 20, severity: 'HIGH', category: 'IMPERSONATION' },

  // --- Email / message content signals ---
  URGENCY: { name: 'Urgency pressure', description: 'The content uses time pressure or urgency to push you into acting without thinking.', reason: 'creates a false sense of urgency', scoreContribution: 10, severity: 'MEDIUM', category: 'SUSPICIOUS_CONTENT' },
  ACCOUNT_SUSPENSION: { name: 'Account suspension threat', description: 'The content threatens that an account will be suspended, locked or closed to force a reaction.', reason: 'threatens account suspension or closure', scoreContribution: 10, severity: 'MEDIUM', category: 'PHISHING' },
  THREAT_LANGUAGE: { name: 'Threatening language', description: 'The content uses threats of legal action, fines or penalties to intimidate you.', reason: 'uses threats of legal or financial penalties', scoreContribution: 10, severity: 'MEDIUM', category: 'SUSPICIOUS_CONTENT' },
  CREDENTIAL_REQUEST: { name: 'Credential request', description: 'The content asks you to provide, confirm or re-enter login credentials.', reason: 'requests your login credentials', scoreContribution: 15, severity: 'HIGH', category: 'PHISHING' },
  OTP_REQUEST: { name: 'OTP request', description: 'The content asks for a one-time passcode (OTP) or verification code, which legitimate organizations never request.', reason: 'asks for a one-time passcode (OTP)', scoreContribution: 20, severity: 'HIGH', category: 'OTP_SCAM' },
  FINANCIAL_REQUEST: { name: 'Financial detail request', description: 'The content requests sensitive banking or card details (account number, CVV, KYC, UPI, etc.).', reason: 'requests sensitive banking or card details', scoreContribution: 15, severity: 'HIGH', category: 'BANKING_SCAM' },
  PAYMENT_REQUEST: { name: 'Payment / money request', description: 'The content pressures you to make a payment, transfer money or pay a fee.', reason: 'pressures you to send money or pay a fee', scoreContribution: 10, severity: 'MEDIUM', category: 'PAYMENT_SCAM' },
  FAKE_REWARD: { name: 'Fake reward / prize', description: 'The content claims you have won a prize, lottery or reward, a classic lure to harvest data or money.', reason: 'claims you have won a prize or reward', scoreContribution: 15, severity: 'MEDIUM', category: 'REWARD_SCAM' },
  JOB_SCAM: { name: 'Suspicious job offer', description: 'The content offers unrealistic easy-money or work-from-home earnings typical of job scams.', reason: 'offers an unrealistic job / easy-money opportunity', scoreContribution: 10, severity: 'MEDIUM', category: 'JOB_SCAM' },
  INVESTMENT_SCAM: { name: 'Guaranteed-return investment', description: 'The content promises guaranteed, risk-free or unusually high investment returns.', reason: 'promises guaranteed or unrealistic investment returns', scoreContribution: 15, severity: 'MEDIUM', category: 'INVESTMENT_SCAM' },
  LOAN_SCAM: { name: 'Suspicious loan offer', description: 'The content pushes an instant, pre-approved or no-collateral loan offer typical of loan scams.', reason: 'pushes a suspicious instant-loan offer', scoreContribution: 10, severity: 'MEDIUM', category: 'LOAN_SCAM' },
  GENERIC_GREETING: { name: 'Generic greeting', description: 'The content uses a generic greeting ("Dear Customer") instead of your name, common in mass phishing.', reason: 'uses a generic, impersonal greeting', scoreContribution: 5, severity: 'LOW', category: 'SUSPICIOUS_CONTENT' },
  BRAND_IMPERSONATION_CONTENT: { name: 'Brand impersonation', description: 'The content impersonates a well-known brand while asking you to take an account action.', reason: 'impersonates a well-known brand', scoreContribution: 15, severity: 'HIGH', category: 'IMPERSONATION' },
  SUSPICIOUS_LINK: { name: 'Suspicious embedded link', description: 'The content contains a link that shows suspicious characteristics when analyzed.', reason: 'contains a suspicious link', scoreContribution: 15, severity: 'HIGH', category: 'PHISHING' },

  // --- ML model ---
  ML_MODEL_RISK: { name: 'ML phishing likelihood', description: 'A machine-learning model trained on URL features estimated an elevated phishing likelihood.', reason: 'was flagged as likely phishing by the ML model', scoreContribution: 10, severity: 'MEDIUM', category: 'MALICIOUS_URL' },

  // --- QR ---
  QR_UNDECODABLE: { name: 'Unreadable QR code', description: 'No QR code could be decoded from the uploaded image.', reason: 'could not be decoded', scoreContribution: 0, severity: 'LOW', category: 'SUSPICIOUS_CONTENT' }
};

export const RECOMMENDED_ACTIONS = {
  HIGH_RISK: 'Do not interact with this content. Do not click any links, download attachments, or share personal, financial, or login information. Verify directly with the organization through an official channel you trust, then report and delete it.',
  SUSPICIOUS: 'Treat this with caution. Do not share sensitive information or click links until you independently verify the source through a trusted, official channel.',
  SAFE: 'No significant threat indicators were found. Continue to stay alert and never share OTPs, passwords, or financial details on unexpected requests.'
};
