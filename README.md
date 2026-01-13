# Jetstream Takehome

A Chrome extension that prevents sensitive data from being sent to AI tools like ChatGPT and Claude. When a user attempts to send a message containing PII (Social Security Numbers, email addresses, phone numbers, etc.), the extension blocks the request, notifies the user, and logs the event for admin review. Administrators can then approve specific messages, allowing them through on subsequent attempts.

## Table of Contents

- [Installation](#installation)
  - [Backend Setup](#1-backend-setup)
  - [Chrome Extension](#2-chrome-extension)
  - [Admin Dashboard](#3-admin-dashboard)
- [Detection Logic](#detection-logic)
- [Guardrails AI Integration](#guardrails-ai-integration)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)

---

## Installation

### 1. Backend Setup

The backend is a Python FastAPI server that handles event logging, approval management, and PII validation via Guardrails AI.

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure Guardrails AI
# Get your token from https://hub.guardrailsai.com/keys
guardrails configure --token YOUR_TOKEN_HERE

# Install PII detection validators from Guardrails Hub
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/secrets_present

# Download the spaCy language model (required for NER-based PII detection)
python -m spacy download en_core_web_lg

# Start the server
uvicorn main:app --reload --port 8000
```

The backend will be running at `http://localhost:8000`. You can verify it's working by visiting `http://localhost:8000/api/health`.

### 2. Chrome Extension

Load the extension in Chrome's developer mode:

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** using the toggle in the top-right corner
3. Click **Load unpacked**
4. Select the `extension/` folder from this repository
5. The extension icon should appear in your toolbar

The extension automatically activates on:
- `chatgpt.com`
- `claude.ai`

### 3. Admin Dashboard

The admin dashboard is a static HTML/JS application for reviewing and approving blocked events.

```bash
cd admin-ui

# Serve the dashboard locally
python -m http.server 3000
```

Open `http://localhost:3000` in your browser to view blocked events and approve requests.

---

## Detection Logic

The extension uses a **two-layer detection approach** for optimal performance and coverage:

### Layer 1: Client-Side (Instant)

Before any request leaves the browser, the content script performs a fast regex check for Social Security Numbers:

```
Pattern: \b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b
Matches: 123-45-6789, 123 45 6789, 123456789
```

This provides zero-latency blocking for the most common sensitive data pattern.

### Layer 2: Server-Side (Comprehensive)

The message is also sent to the backend's `/api/validate` endpoint, which uses Guardrails AI to detect a broader range of PII:

- Email addresses
- Phone numbers
- Credit card numbers
- Bank account numbers
- Passport numbers
- Driver's license numbers
- API keys and secrets

### Blocking Behavior

| Platform | SSN Detection | Other PII Detection |
|----------|--------------|---------------------|
| ChatGPT (fetch) | Blocked before send | Blocked before send |
| Claude (WebSocket) | Blocked before send | Detected after send* |

*WebSocket.send() is synchronous, so we can only block SSNs instantly. Other PII is validated async and reported/notified, but the message may have already been sent.

### Analytics Filtering

The extension intelligently skips analytics and telemetry payloads (Segment, Sentry, etc.) by checking for telemetry-specific fields like `integrations`, `writeKey`, `anonymousId`, and `type: "track"`.

---

## Guardrails AI Integration

We chose [Guardrails AI](https://www.guardrailsai.com/) for server-side PII detection because:

1. **Prebuilt Validators**: The Hub provides battle-tested validators for common use cases
2. **NER-Based Detection**: Uses spaCy's named entity recognition for accurate PII identification
3. **Extensible**: Easy to add custom validators for domain-specific patterns
4. **Auto-Remediation**: The `on_fail="fix"` mode automatically redacts detected PII

### Validators Used

**DetectPII** (`hub://guardrails/detect_pii`)
- Detects: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_BANK_NUMBER, US_PASSPORT, US_DRIVER_LICENSE
- Returns sanitized text with PII replaced by category tags (e.g., `<EMAIL_ADDRESS>`)

**SecretsPresent** (`hub://guardrails/secrets_present`)
- Detects: API keys, passwords, tokens, and other secrets
- Uses pattern matching and entropy analysis

### Usage in Code

```python
from guardrails import Guard
from guardrails.hub import DetectPII, SecretsPresent

pii_guard = Guard().use(DetectPII(pii_entities=PII_ENTITIES, on_fail="fix"))
secrets_guard = Guard().use(SecretsPresent(on_fail="fix"))

# Validate text
result = pii_guard.validate(user_message)
if any(s.validator_status == "fail" for s in result.validation_summaries):
    # PII detected - extract categories from sanitized output
    categories = extract_pii_categories(result.validated_output)
```

---

## Project Structure

```
jetstream-takehome/
├── extension/                    # Chrome Extension (Manifest V3)
│   ├── manifest.json             # Extension configuration
│   └── src/
│       ├── content/
│       │   ├── index.js          # Main detection + blocking logic (MAIN world)
│       │   └── bridge.js         # Message relay to background (ISOLATED world)
│       ├── background/
│       │   └── index.js          # API calls to backend (bypasses CSP)
│       └── popup/                # Extension popup UI
│
├── backend/                      # FastAPI Backend
│   ├── main.py                   # API server + Guardrails AI integration
│   ├── events.json               # Blocked events storage
│   ├── approvals.json            # Approved content hashes
│   └── requirements.txt          # Python dependencies
│
├── admin-ui/                     # Admin Dashboard
│   ├── index.html                # Dashboard layout
│   ├── css/styles.css            # Styling
│   └── js/
│       ├── api.js                # Backend API client
│       └── main.js               # Dashboard logic
│
├── README.md                     # This file
└── DESIGN.md                     # Architecture and design decisions
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/validate` | Validate text for PII/secrets using Guardrails AI |
| `GET` | `/api/events` | List blocked events (paginated, filterable by status) |
| `GET` | `/api/events/:id` | Get single event details |
| `POST` | `/api/events` | Log a new blocked event |
| `PATCH` | `/api/events/:id` | Update event status (approve/reject) |
| `GET` | `/api/approvals` | List all approved content hashes |
| `GET` | `/api/approvals/check/:hash` | Check if a content hash is approved |
| `GET` | `/api/health` | Health check endpoint |
