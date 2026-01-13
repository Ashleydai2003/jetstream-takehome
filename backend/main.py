"""
Jetstream Takehome - Backend API
FastAPI server with Guardrails AI for PII detection.
"""

import re
import json
import base64
import io
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from guardrails import Guard
from guardrails.hub import DetectPII, SecretsPresent
import pdfplumber

app = FastAPI(title="Jetstream Takehome API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Guardrails Setup ---

PII_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
]

pii_guard = Guard().use(DetectPII(pii_entities=PII_ENTITIES, on_fail="fix"))
secrets_guard = Guard().use(SecretsPresent(on_fail="fix"))


def extract_pii_categories(sanitized: str) -> list[str]:
    """Extract PII category tags from sanitized output (e.g., <EMAIL_ADDRESS>)."""
    pattern = r'<([A-Z_]+)>'
    matches = re.findall(pattern, sanitized)
    return list(set(matches))  # Unique categories

# --- Data Storage ---

DATA_DIR = Path(__file__).parent
EVENTS_FILE = DATA_DIR / "events.json"
APPROVALS_FILE = DATA_DIR / "approvals.json"


def load_json(file: Path) -> list:
    return json.loads(file.read_text()) if file.exists() else []


def save_json(file: Path, data: list):
    file.write_text(json.dumps(data, indent=2, default=str))


# --- Schemas ---

class Detection(BaseModel):
    type: str
    masked: str | None = None


class EventCreate(BaseModel):
    url: str
    domain: str
    content_type: str = "prompt"  # "prompt" or "document"
    detection_type: str
    summary: str
    detections: list[Detection]
    content_hash: str | None = None
    message: str | None = None


class EventUpdate(BaseModel):
    status: str


class ValidateRequest(BaseModel):
    text: str


class ValidateResponse(BaseModel):
    has_pii: bool
    has_secrets: bool
    sanitized: str
    detections: list[str]


class ExtractTextRequest(BaseModel):
    file_data: str  # Base64 encoded file
    filename: str
    mime_type: str


class ExtractTextResponse(BaseModel):
    text: str
    success: bool
    error: str | None = None


# --- Text Extraction Endpoint ---

@app.post("/api/extract-text", response_model=ExtractTextResponse)
def extract_text(req: ExtractTextRequest):
    """Extract text from uploaded file (PDF, etc.)."""
    try:
        file_bytes = base64.b64decode(req.file_data)

        if req.mime_type == "application/pdf":
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                text = "\n".join(page.extract_text() or "" for page in pdf.pages)
            return ExtractTextResponse(text=text.strip(), success=True)

        # For text-based files, just decode
        if req.mime_type.startswith("text/") or req.mime_type in ["application/json"]:
            text = file_bytes.decode("utf-8", errors="ignore")
            return ExtractTextResponse(text=text, success=True)

        return ExtractTextResponse(text="", success=False, error=f"Unsupported file type: {req.mime_type}")

    except Exception as e:
        return ExtractTextResponse(text="", success=False, error=str(e))


# --- Validation Endpoint ---

@app.post("/api/validate", response_model=ValidateResponse)
def validate_text(req: ValidateRequest):
    """Validate text for PII and secrets using Guardrails AI."""
    detections = []
    sanitized = req.text
    has_pii = False
    has_secrets = False

    # Check for PII
    try:
        pii_result = pii_guard.validate(req.text)
        pii_failed = any(s.validator_status == "fail" for s in pii_result.validation_summaries)
        if pii_failed:
            has_pii = True
            sanitized = pii_result.validated_output or sanitized
            # Extract specific PII categories from sanitized output
            categories = extract_pii_categories(sanitized)
            detections.extend(categories if categories else ["PII"])
    except Exception as e:
        has_pii = True
        detections.append(f"PII check error: {str(e)}")

    # Check for secrets
    try:
        secrets_result = secrets_guard.validate(sanitized)
        secrets_failed = any(s.validator_status == "fail" for s in secrets_result.validation_summaries)
        if secrets_failed:
            has_secrets = True
            sanitized = secrets_result.validated_output or sanitized
            detections.append("Secrets detected")
    except Exception as e:
        has_secrets = True
        detections.append(f"Secrets check error: {str(e)}")

    return ValidateResponse(
        has_pii=has_pii,
        has_secrets=has_secrets,
        sanitized=sanitized,
        detections=detections
    )


# --- Events API ---

@app.get("/api/events")
def list_events(page: int = 1, limit: int = 50, status: str | None = None):
    events = load_json(EVENTS_FILE)
    if status:
        events = [e for e in events if e["status"] == status]
    events = sorted(events, key=lambda x: x.get("created_at", ""), reverse=True)
    total = len(events)
    start = (page - 1) * limit
    return {"items": events[start:start + limit], "total": total, "page": page}


@app.get("/api/events/{event_id}")
def get_event(event_id: int):
    for event in load_json(EVENTS_FILE):
        if event["id"] == event_id:
            return event
    raise HTTPException(404, "Event not found")


@app.post("/api/events")
def create_event(data: EventCreate):
    events = load_json(EVENTS_FILE)
    
    # Run Guardrails validation on the message
    guardrails_detections = []
    if data.message:
        try:
            pii_result = pii_guard.validate(data.message)
            if any(s.validator_status == "fail" for s in pii_result.validation_summaries):
                # Extract specific PII categories
                categories = extract_pii_categories(pii_result.validated_output or "")
                guardrails_detections.extend(categories if categories else ["PII"])
            
            secrets_result = secrets_guard.validate(data.message)
            if any(s.validator_status == "fail" for s in secrets_result.validation_summaries):
                guardrails_detections.append("SECRETS")
        except Exception:
            pass
    
    event = {
        "id": len(events) + 1,
        "url": data.url,
        "domain": data.domain,
        "content_type": data.content_type,
        "detection_type": data.detection_type,
        "summary": data.summary,
        "detections": [d.model_dump() for d in data.detections],
        "guardrails_detections": guardrails_detections,
        "content_hash": data.content_hash,
        "message": data.message,
        "status": "pending",
        "created_at": datetime.now().isoformat(),
    }
    events.append(event)
    save_json(EVENTS_FILE, events)
    return event


@app.patch("/api/events/{event_id}")
def update_event(event_id: int, data: EventUpdate):
    events = load_json(EVENTS_FILE)
    for event in events:
        if event["id"] == event_id:
            event["status"] = data.status
            event["updated_at"] = datetime.now().isoformat()
            
            if data.status == "approved" and event.get("content_hash"):
                approvals = load_json(APPROVALS_FILE)
                if event["content_hash"] not in approvals:
                    approvals.append(event["content_hash"])
                    save_json(APPROVALS_FILE, approvals)
            
            save_json(EVENTS_FILE, events)
            return event
    raise HTTPException(404, "Event not found")


# --- Approvals API ---

@app.get("/api/approvals")
def list_approvals():
    return {"hashes": load_json(APPROVALS_FILE)}


@app.get("/api/approvals/check/{content_hash}")
def check_approval(content_hash: str):
    return {"approved": content_hash in load_json(APPROVALS_FILE)}


@app.get("/api/health")
def health():
    return {"status": "ok", "guardrails": "enabled"}
