# Jetstream Takehome

A Chrome extension that prevents sensitive data from being sent to AI tools like ChatGPT and Claude. When a user attempts to send a message containing PII (Social Security Numbers, email addresses, phone numbers, etc.), the extension blocks the request, notifies the user, and logs the event for admin review. Administrators can then approve specific messages, allowing them through on subsequent attempts.

## Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Detection Logic](#detection-logic)
- [Approval System](#approval-system)
- [Data Privacy](#data-privacy)
- [API Reference](#api-reference)

---

## Installation

### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure Guardrails AI (get token from https://hub.guardrailsai.com/keys)
guardrails configure --token YOUR_TOKEN_HERE

# Install validators from Guardrails Hub
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/secrets_present

# Download spaCy language model
python -m spacy download en_core_web_lg

# Start the server
uvicorn main:app --reload --port 8000
```

### 2. Chrome Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` folder

### 3. Admin Dashboard

```bash
cd admin-ui
python -m http.server 3000
```

Open `http://localhost:3000` to review and approve blocked events.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BROWSER                                         │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        Chrome Extension                                 │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │  Content Script (MAIN world)                                     │   │ │
│  │  │  • Overrides fetch() - intercepts ChatGPT requests               │   │ │
│  │  │  • Overrides WebSocket.send() - intercepts Claude messages       │   │ │
│  │  │  • Client-side SSN regex detection (instant blocking)            │   │ │
│  │  │  • File upload interception and validation                       │   │ │
│  │  │  • Shows block notification banner                               │   │ │
│  │  └──────────────────────────┬──────────────────────────────────────┘   │ │
│  │                             │ Custom Events                             │ │
│  │  ┌──────────────────────────▼──────────────────────────────────────┐   │ │
│  │  │  Bridge Script (ISOLATED world)                                  │   │ │
│  │  │  • Relays messages between MAIN world and background             │   │ │
│  │  │  • Required because MAIN world cannot access chrome.runtime      │   │ │
│  │  └──────────────────────────┬──────────────────────────────────────┘   │ │
│  │                             │ chrome.runtime.sendMessage               │ │
│  │  ┌──────────────────────────▼──────────────────────────────────────┐   │ │
│  │  │  Background Service Worker                                       │   │ │
│  │  │  • Makes HTTP requests to backend (bypasses page CSP)            │   │ │
│  │  │  • Caches approved hashes for quick lookups                      │   │ │
│  │  └──────────────────────────┬──────────────────────────────────────┘   │ │
│  └─────────────────────────────┼───────────────────────────────────────────┘ │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  │ HTTP (localhost:8000)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                                      │
│                                                                              │
│  • /api/validate - Validates text using Guardrails AI                        │
│  • /api/extract-text - Extracts text from PDFs for validation                │
│  • /api/events - Stores blocked events with censored messages                │
│  • /api/approvals - Stores approved content hashes (SHA-256)                 │
│                                                                              │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ HTTP (localhost:8000)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Admin Dashboard                                      │
│                                                                              │
│  • Lists all blocked events with metadata                                    │
│  • Admin can approve events → hash added to approvals.json                   │
│  • Future requests with same content hash are allowed through                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
jetstream-takehome/
├── extension/                    # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   └── src/
│       ├── content/
│       │   ├── index.js          # Main detection + blocking logic (MAIN world)
│       │   └── bridge.js         # Message relay to background (ISOLATED world)
│       ├── background/
│       │   └── index.js          # API calls to backend (bypasses CSP)
│       └── popup/
│
├── backend/                      # FastAPI Backend
│   ├── main.py                   # API server + Guardrails AI integration
│   ├── events.json               # Blocked events storage
│   ├── approvals.json            # Approved content hashes
│   └── requirements.txt
│
└── admin-ui/                     # Admin Dashboard
    ├── index.html
    ├── css/styles.css
    └── js/
        ├── api.js
        └── main.js
```

---

## Detection Logic

### Layer 1: Client-Side (Instant)

Fast regex check for SSNs before any request leaves the browser:

```
Pattern: \b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b
Matches: 123-45-6789, 123 45 6789, 123456789
```

### Layer 2: Server-Side (Comprehensive)

Guardrails AI detects a broader range of PII via `/api/validate`:

- Email addresses
- Phone numbers
- Credit card numbers
- Bank account numbers
- Passport numbers
- Driver's license numbers
- API keys and secrets

### File Validation

Files are validated before upload:

| File Type | Extraction |
|-----------|------------|
| .txt, .csv, .json, .md | Client-side (FileReader API) |
| .pdf | Server-side (pdfplumber) |

### Blocking Behavior

| Platform | SSN Detection | Other PII Detection |
|----------|--------------|---------------------|
| ChatGPT (fetch) | Blocked before send | Blocked before send |
| Claude (WebSocket) | Blocked before send | Blocked before send |

All PII types are now blocked before send. The WebSocket interceptor validates messages asynchronously and only calls the original `send()` if validation passes. If validation fails or times out, the message is never sent.

---

## Approval System

### Storage Format

Approvals are stored as SHA-256 content hashes in `approvals.json`:

```json
["a1b2c3d4e5f6...64-char-hex-hash..."]
```

### Hash Generation

```javascript
async function hash(text) {
  const data = new TextEncoder().encode(text);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}
```

The hash is computed on the **original, uncensored message** so identical messages produce identical hashes.

### Approval Flow

1. Admin reviews blocked event in dashboard
2. Clicks "Approve" → content hash added to `approvals.json`
3. Extension checks approvals before blocking (cached + real-time)
4. User retries same message → allowed through

---

## Data Privacy

### What Gets Stored

| Data | Stored? | Format |
|------|---------|--------|
| Original message | No | - |
| Content hash | Yes | SHA-256 (irreversible) |
| Censored message | Yes | SSNs masked, PII tagged |
| Detection types | Yes | Category names only |
| Metadata | Yes | URL, domain, timestamp |

### Sanitization

- **Client-side**: SSNs replaced with `***-**-****`
- **Server-side**: Guardrails replaces PII with category tags (e.g., `<EMAIL_ADDRESS>`)

The admin can make approval decisions without seeing actual sensitive values.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/validate` | Validate text for PII/secrets |
| `POST` | `/api/extract-text` | Extract text from PDF files |
| `GET` | `/api/events` | List blocked events |
| `GET` | `/api/events/:id` | Get single event |
| `POST` | `/api/events` | Log a blocked event |
| `PATCH` | `/api/events/:id` | Update event status |
| `GET` | `/api/approvals` | List approved hashes |
| `GET` | `/api/approvals/check/:hash` | Check if hash is approved |
| `GET` | `/api/health` | Health check |
