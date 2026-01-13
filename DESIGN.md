## Architecture and Data Flow

The system consists of three main components that work together to intercept, validate, and manage sensitive data in AI tool requests.

### Component Overview

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
│  │                             │                                           │ │
│  └─────────────────────────────┼───────────────────────────────────────────┘ │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  │ HTTP (localhost:8000)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                                      │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  /api/validate                                                       │    │
│  │  • Validates text using Guardrails AI                                │    │
│  │  • Returns detected PII categories (EMAIL_ADDRESS, PHONE_NUMBER...)  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  /api/events                                                         │    │
│  │  • Stores blocked events with censored messages                      │    │
│  │  • Persisted to events.json                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  /api/approvals                                                      │    │
│  │  • Stores approved content hashes (SHA-256)                          │    │
│  │  • Persisted to approvals.json                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │ HTTP (localhost:8000)
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Admin Dashboard                                      │
│                                                                              │
│  • Lists all blocked events with metadata                                    │
│  • Shows: timestamp, URL, domain, content type, detection type, message      │
│  • Admin can approve events → hash added to approvals.json                   │
│  • Future requests with same content hash are allowed through                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Request Flow (Blocking)

1. **User types message** in ChatGPT or Claude
2. **Content script intercepts** the outgoing request (fetch or WebSocket)
3. **Client-side SSN check** runs immediately (regex, ~0ms)
4. **Backend validation** via `/api/validate` using Guardrails AI (~100-500ms)
5. **If PII detected**:
   - Request is blocked (returns fake 200 response to prevent retries)
   - Notification banner shown to user
   - Event logged to backend with censored message
6. **If no PII**: Request proceeds normally

### Approval Flow

1. **Admin opens dashboard** at `http://localhost:3000`
2. **Reviews blocked events** - sees censored message, detection types, metadata
3. **Clicks "Approve"** on an event
4. **Backend updates**:
   - Event status → "approved"
   - Content hash added to `approvals.json`
5. **Extension checks approvals** before blocking (cached + real-time)
6. **User retries** the same message → allowed through

---

## Approval State Storage and Checking

### Storage Format

Approvals are stored as a simple JSON array of SHA-256 content hashes:

```json
// approvals.json
[
  "a1b2c3d4e5f6...64-char-hex-hash...",
  "f6e5d4c3b2a1...64-char-hex-hash..."
]
```

Events include the content hash for correlation:

```json
// events.json
[
  {
    "id": 1,
    "url": "https://chatgpt.com/c/abc123",
    "domain": "chatgpt.com",
    "content_type": "prompt",
    "detection_type": "SSN, EMAIL_ADDRESS",
    "message": "My SSN is ***-**-**** and email is <EMAIL_ADDRESS>",
    "content_hash": "a1b2c3d4e5f6...",
    "status": "pending",
    "created_at": "2024-01-15T10:30:00"
  }
]
```

### Hash Generation

Content hashes are generated client-side using the Web Crypto API:

```javascript
async function hash(text) {
  const data = new TextEncoder().encode(text);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}
```

The hash is computed on the **original, uncensored message** so that:
- Identical messages produce identical hashes
- Approving one instance approves all identical future attempts

### Approval Checking

The extension checks approvals at two levels:

1. **Background cache**: The background worker maintains a Set of approved hashes, refreshed every 5 minutes
2. **Real-time check**: Each blocked message triggers a `/api/approvals/check/:hash` API call

```javascript
async function isApproved(hash) {
  // First check cache
  if (approvedHashes.has(hash)) return true;
  
  // Then check backend
  const response = await fetch(`/api/approvals/check/${hash}`);
  const data = await response.json();
  if (data.approved) approvedHashes.add(hash);
  return data.approved;
}
```

---

## Avoiding Raw Sensitive Data Leakage

### 1. Client-Side Censoring

Before any message is sent to the backend, SSNs are replaced with a masked pattern:

```javascript
function censorSSNs(text) {
  return text.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '***-**-****');
}

// "My SSN is 123-45-6789" → "My SSN is ***-**-****"
```

### 2. Server-Side Sanitization

Guardrails AI validators run with `on_fail="fix"`, which replaces detected PII with category tags:

```python
pii_guard = Guard().use(DetectPII(pii_entities=PII_ENTITIES, on_fail="fix"))
result = pii_guard.validate("Contact me at john@example.com")
# result.validated_output = "Contact me at <EMAIL_ADDRESS>"
```

### 3. What Gets Stored

| Data | Stored? | Format |
|------|---------|--------|
| Original message | ❌ Never | - |
| Content hash | ✅ Yes | SHA-256 (irreversible) |
| Censored message | ✅ Yes | SSNs masked, PII tagged |
| Detection types | ✅ Yes | Category names only |
| Metadata | ✅ Yes | URL, domain, timestamp |

### 4. What Admin Sees

The admin dashboard displays:
- **Censored message**: `"My SSN is ***-**-**** and email is <EMAIL_ADDRESS>"`
- **Detection types**: `SSN, EMAIL_ADDRESS`
- **Metadata**: URL, domain, timestamp, content type

The admin can make an informed approval decision without ever seeing the actual sensitive values.

### 5. Hash-Based Approval

Approvals are stored as content hashes, not the original text. This means:
- The backend never needs to store raw sensitive data
- Approvals can be matched without comparing plaintext
- Even if `approvals.json` is leaked, it contains only meaningless hashes
