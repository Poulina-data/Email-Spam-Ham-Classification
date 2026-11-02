import os
import io
import csv
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.data.db import (
    init_db,
    get_quarantined_items,
    update_quarantine_status,
    delete_quarantine_item,
    get_all_scans,
    get_analytics_summary,
    get_rules,
    add_rule,
    delete_rule
)
from src.services.detector_service import (
    scan_email,
    scan_batch,
    get_pipeline_metadata
)
from src.quarantine.store import quarantine_email

# Initialize DB on launch
init_db()

app = FastAPI(
    title="AegisMail AI — Intelligent Email Spam & Threat Detection System",
    description="Full-stack AI email threat detection platform powered by Multinomial Naive Bayes, spaCy NLP, and explainable feature attribution.",
    version="2.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)


# Pydantic Request Models
class EmailScanRequest(BaseModel):
    sender: Optional[str] = Field(default="", description="Sender email address")
    subject: Optional[str] = Field(default="", description="Email subject line")
    body: str = Field(..., min_length=1, description="Email body content")
    threshold: Optional[float] = Field(default=0.5, ge=0.05, le=0.95, description="Classification sensitivity threshold")


class LegacyEmailRequest(BaseModel):
    text: str


class BatchEmailItem(BaseModel):
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    body: str


class BatchScanRequest(BaseModel):
    emails: List[BatchEmailItem]
    threshold: Optional[float] = 0.5


class RuleCreateRequest(BaseModel):
    rule_type: str = Field(..., description="whitelist_sender, blacklist_sender, whitelist_domain, blacklist_domain, custom_keyword")
    value: str = Field(..., min_length=2, description="Domain, email, or keyword")
    action: str = Field(..., description="force_ham, force_spam, flag_suspicious")


# --- Static UI Routes ---

@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "AegisMail AI backend active. Please build static frontend."}


# Mount static assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --- Legacy Route (100% Backward Compatibility) ---

@app.post("/predict")
def legacy_predict(email: LegacyEmailRequest):
    """
    Backwards-compatible endpoint for existing CLI scripts / tests.
    """
    result = scan_email(sender="", subject="", body=email.text, sensitivity_threshold=0.5)
    return {
        "label": result["label"],
        "spam_probability": result["spam_probability"],
        "ham_probability": result["ham_probability"]
    }


# --- Core Detection API Routes ---

@app.post("/api/scan")
def api_scan_email(req: EmailScanRequest):
    """
    Analyzes an email with full NLP feature attribution, explainability, and security heuristics.
    """
    try:
        result = scan_email(
            sender=req.sender or "",
            subject=req.subject or "",
            body=req.body,
            sensitivity_threshold=req.threshold or 0.5
        )
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-batch")
def api_scan_batch(req: BatchScanRequest):
    """
    Processes multiple emails in batch with aggregated threat statistics.
    """
    try:
        raw_items = [e.dict() for e in req.emails]
        results = scan_batch(raw_items, sensitivity_threshold=req.threshold or 0.5)
        return {"success": True, "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Quarantine Vault Management ---

@app.get("/api/quarantine")
def api_get_quarantine(status: Optional[str] = "ALL", search: Optional[str] = None):
    """
    Retrieves quarantined emails with optional filtering by status or search keyword.
    """
    try:
        items = get_quarantined_items(status=status, search=search)
        return {"success": True, "count": len(items), "data": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/quarantine/{item_id}/release")
def api_release_quarantine(item_id: int):
    """
    Releases an email from quarantine to the user's inbox.
    """
    success = update_quarantine_status(item_id, "RELEASED")
    if not success:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {"success": True, "message": f"Email #{item_id} released successfully"}


@app.delete("/api/quarantine/{item_id}")
def api_delete_quarantine(item_id: int):
    """
    Permanently purges a quarantined email.
    """
    success = delete_quarantine_item(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {"success": True, "message": f"Email #{item_id} permanently deleted"}


@app.get("/api/quarantine/export")
def api_export_quarantine():
    """
    Exports all quarantine entries as a CSV file.
    """
    items = get_quarantined_items(status="ALL")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Sender", "Subject", "Body", "Spam Probability", "Risk Tier", "Status", "Reason"])

    for item in items:
        writer.writerow([
            item.get("id"),
            item.get("timestamp"),
            item.get("sender"),
            item.get("subject"),
            item.get("body", "").replace("\n", " "),
            item.get("spam_probability"),
            item.get("risk_tier"),
            item.get("status"),
            item.get("reason")
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegismail_quarantine_export.csv"}
    )


# --- Scans History & Analytics ---

@app.get("/api/scans")
def api_get_scans(limit: int = 50, offset: int = 0, label: Optional[str] = None, search: Optional[str] = None):
    """
    Fetches paginated scan audit logs.
    """
    try:
        data = get_all_scans(limit=limit, offset=offset, label=label, search=search)
        return {"success": True, "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics")
def api_get_analytics():
    """
    Returns executive metrics, KPIs, detection rate, and risk tier distribution.
    """
    try:
        stats = get_analytics_summary()
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Model Pipeline Information & Explainability Explorer ---

@app.get("/api/model-info")
def api_get_model_info():
    """
    Returns detailed architectural overview of the 8 training stages, metrics, and top n-grams.
    """
    try:
        meta = get_pipeline_metadata()
        return {"success": True, "data": meta}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Custom Security Rules Engine ---

@app.get("/api/rules")
def api_get_rules():
    """
    Retrieves active whitelist and blacklist security rules.
    """
    try:
        rules = get_rules()
        return {"success": True, "data": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules")
def api_add_rule(req: RuleCreateRequest):
    """
    Adds a custom rule (sender, domain, keyword).
    """
    try:
        new_rule = add_rule(req.rule_type, req.value, req.action)
        return {"success": True, "data": new_rule}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/rules/{rule_id}")
def api_delete_rule(rule_id: int):
    """
    Deletes a custom security rule.
    """
    success = delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "message": f"Rule #{rule_id} removed"}
