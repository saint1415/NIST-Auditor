NIST 800-63-4 Auditor

A Python-based auditing tool for assessing compliance with NIST SP 800-63-4 Digital Identity Guidelines.
The auditor evaluates IAL, AAL, FAL controls, including password/authenticator requirements, multi-factor authentication, session management, credential storage, transport security, privacy, and account recovery.

📖 Overview

This tool enables consistent evaluation of identity and authentication controls against the NIST SP 800-63-4 framework.
It supports both manual configuration and automated collection (via Microsoft Entra ID and system probes).
The output is designed for audit evidence, gap analysis, and compliance reporting.

✨ Key Capabilities

Automated data collection from Microsoft Entra ID (Azure AD) via Microsoft Graph

Local system checks: crypto capabilities, TLS probing, endpoint hygiene

Manual configuration intake (via YAML if API access unavailable)

Checks aligned with NIST SP 800-63-4 (IAL, AAL, FAL)

Report generation in JSON, TXT, and HTML formats

Each control scored as: PASS / WARN / FAIL with rationale and remediation

📂 Supported Data Sources

Manual Input: Supply config in YAML or via interactive prompts

Entra ID Collector: Automatically extract password/MFA/conditional access policies via Microsoft Graph

Auto Collector: Gather local host crypto/TLS/system settings automatically

HTTPS Probe: Evaluate TLS configuration of external endpoints

📦 System Requirements

Python 3.9+ (3.11 recommended)

OS: Linux, macOS, or Windows

Internet access for Entra ID (Graph) and HTTPS probes

Permissions:

Azure App Registration with read-only Graph API scopes for Entra ID

No elevated privilege for other collectors

⚙️ Installation
1) Clone and set up environment
git clone <your-repo-url>
cd auditor
python -m venv .venv
source .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt


If requirements.txt is missing:

pip install requests msal cryptography pyopenssl pyyaml rich

2) Optional: Docker

Dockerfile:

FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install -U pip && pip install -r requirements.txt
ENV PYTHONUNBUFFERED=1
CMD ["python", "auditor.py", "--help"]


Build and run:

docker build -t nist-auditor:latest .
docker run --rm -it nist-auditor:latest --help

🔑 Configuration
A) Entra ID (Microsoft Graph) Setup

Create an Azure App Registration and capture:

Tenant ID

Client ID

Client Secret (store securely)

Grant read-only Microsoft Graph application permissions using least privilege. Common read-only permissions for policy reads include:

Policy.Read.All

Directory.Read.All

AuditLog.Read.All

IdentityUserFlow.Read.All

AuthenticationMethodPolicy.Read.All

ConditionalAccess.Read.All

Notes:

Admin consent is required for application permissions.

Use least privilege and remove scopes you don't need.

Set environment variables (preferred) or pass via CLI:

export ENTRA_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export ENTRA_CLIENT_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
export ENTRA_CLIENT_SECRET="your-super-secret"

B) Manual Config (YAML)

You can define system settings in a YAML file if you can't or don't want to use automation:

system:
  name: "Payment-Portal"
  owner: "IAM Team"
  environment: "production"

authentication:
  password_policy:
    min_length: 12
    requires_uppercase: true
    requires_lowercase: true
    requires_number: true
    requires_symbol: true
    reuse_prevention: 24
    max_age_days: 365
    lockout_threshold: 10
    lockout_duration_minutes: 15
  mfa:
    enabled: true
    allowed_factors: ["TOTP", "FIDO2", "Push"]
    required_for_admins: true
    required_for_all_users: true
  recovery:
    email_reset_allowed: false
    sms_reset_allowed: false
    kbq_allowed: false

session:
  idle_timeout_minutes: 15
  absolute_timeout_hours: 8
  reauth_for_sensitive_actions: true

transport:
  https_required: true
  hsts_enabled: true
  min_tls_version: "1.2"
  allowed_ciphersuites: ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"]

privacy:
  pii_minimization: true
  pii_retention_days: 365
  pii_encrypted_at_rest: true

▶️ Running the Auditor

View help:

python auditor.py --help

Common modes:

Manual config file:

python auditor.py --input config.yaml --format json --out ./reports


Interactive prompts (no file):

python auditor.py --interactive --format txt


Entra ID automated collection:

# Uses environment variables for credentials
python auditor.py --entra --format html --out ./reports


HTTPS probe of endpoints:

python auditor.py --probe https://login.example.com --probe https://app.example.com --format json


Combine Entra ID with HTTPS probe:

python auditor.py --entra --probe https://login.microsoftonline.com --format html --out ./reports

Output formats:

json: machine-readable findings

txt: console-friendly summary

html: shareable report (if supported by your version)

📊 Understanding Results

Each control is evaluated with a status and rationale:

PASS: Meets NIST SP 800-63-4 expectation for stated assurance level

WARN: Partially meets or ambiguous; review and consider remediation

FAIL: Does not meet expectation; remediation recommended

Findings typically include:

Control ID or category (e.g., AAL password verifiers, MFA, session)

Evidence excerpt (policy/readout)

Expected criteria

Gap analysis

Suggested remediation

If AAL/IAL/FAL targets are configurable, ensure you set the intended target in the config or command-line so checks align to your goals.

🔐 Security and Privacy Guidance

Store secrets (client secrets, tokens) only in secure vaults; avoid committing to source control.

Run read-only permissions; avoid unnecessary Graph or directory scopes.

Limit output distribution; reports may include sensitive policy details.

Use network allowlists for probes; avoid scanning endpoints without authorization.

Sanitize reports before sharing externally.

🛠 Troubleshooting

AuthenticationError or 401/403:

Verify ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET

Confirm admin consent is granted for required Graph scopes

Ensure the app registration is in the correct tenant

Missing data (e.g., conditional access not found):

Check that the account has ConditionalAccess.Read.All (or appropriate read-only scope)

Policy types vary by tenant feature enablement; ensure features are enabled

Rate limiting (HTTP 429):

Re-run later or reduce frequency

Consider adding backoff if running in pipelines

SSL/TLS probe errors:

Endpoint may block scanning or require SNI; try with full hostnames

Corporate proxy may interfere; set HTTPS_PROXY/HTTP_PROXY as needed

HTML report not generated:

Ensure your version supports --format html and that dependencies (e.g., jinja2 if used) are installed
📑 Operational Best Practices

Pin tool versions in requirements.txt and update quarterly.

Rotate client secrets regularly; use managed identities where possible.

Log to a central location with redaction for sensitive values.

Maintain a changelog for control logic updates (e.g., 800-63-4 revisions).

Validate Graph schema changes periodically; Microsoft may update policy endpoints.

🧪 Example Commands

Baseline Entra ID assessment, HTML report:

python auditor.py --entra --format html --out ./reports


Production web app probe with manual config:

python auditor.py --input prod-app.yaml --probe https://app.example.com --format json --out ./reports


Quick interactive check (no automation):

python auditor.py --interactive --format txt

📝 Sample Output (JSON excerpt)
{
  "system": "Payment-Portal",
  "target_levels": {"IAL": 2, "AAL": 2, "FAL": 2},
  "findings": [
    {
      "control": "PasswordPolicy.MinLength",
      "status": "PASS",
      "observed": 12,
      "expected": ">= 8 (higher recommended for AAL2+)",
      "rationale": "Meets minimum; aligns with strong password guidance."
    },
    {
      "control": "MFA.RequiredForAllUsers",
      "status": "FAIL",
      "observed": false,
      "expected": true,
      "remediation": "Enforce MFA for all users or all interactive sign-ins via Conditional Access."
    }
  ],
  "summary": {
    "pass": 25,
    "warn": 6,
    "fail": 3,
    "risk_rating": "Medium"
  }
}

❓ FAQ

What Graph permissions do I need?
It depends on which policies you query. Start with read-only scopes and add only what's necessary (examples: Policy.Read.All, Directory.Read.All, ConditionalAccess.Read.All, AuthenticationMethodPolicy.Read.All). Use least privilege and obtain admin consent.

Can I run this offline?
Yes, using manual config files and disabling probes. Entra ID collection requires internet access.

How do I target a specific AAL/IAL/FAL?
Use configuration or CLI flags if supported by your version (e.g., --aal 2 --ial 2 --fal 2). Otherwise set them in the YAML input.

Does this change my tenant?
No. It uses read-only calls. Ensure your app registration is configured with only read permissions.

📂 Appendix A — Example .env
ENTRA_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
ENTRA_CLIENT_SECRET=your-secret
HTTP_PROXY=
HTTPS_PROXY=
NO_PROXY=localhost,127.0.0.1


Load it with:

export $(grep -v '^#' .env | xargs)

📂 Appendix B — Example CI Usage (GitHub Actions)
name: NIST Auditor
on: [workflow_dispatch]
jobs:
  run-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: |
          python auditor.py --entra --format json --out reports
        env:
          ENTRA_TENANT_ID: ${{ secrets.ENTRA_TENANT_ID }}
          ENTRA_CLIENT_ID: ${{ secrets.ENTRA_CLIENT_ID }}
          ENTRA_CLIENT_SECRET: ${{ secrets.ENTRA_CLIENT_SECRET }}
      - uses: actions/upload-artifact@v4
        with:
          name: nist-auditor-reports
          path: reports

📜 License

For internal organizational use.
This guide does not replace formal compliance advice. Align with NIST SP 800-63-4 and your enterprise policies.
