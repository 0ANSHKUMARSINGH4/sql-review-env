from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class RedactionItem(BaseModel):
    """Details of a detected and redacted sensitive item."""
    category: str = Field(description="Classification: credential, secret, pii, etc.")
    token: str = Field(description="Placeholder token (e.g., <PASSWORD_001>).")
    confidence: float = Field(default=1.0, description="Detection confidence score between 0.0 and 1.0.")
    reason: str = Field(description="Explanation of why this item was classified as sensitive.")


class PrivacyReport(BaseModel):
    """Audit metadata of the privacy sanitization pass. Safe for logging and dashboard."""
    secrets_detected: int = Field(default=0, description="Count of credentials/secrets detected.")
    pii_detected: int = Field(default=0, description="Count of PII items detected.")
    redacted_items: int = Field(default=0, description="Total count of redacted items.")
    llm_safe: bool = Field(default=True, description="True if input has been sanitized and is safe for LLM inference.")
    details: List[RedactionItem] = Field(default_factory=list, description="Safe details of redaction items.")


class SanitizedContext(BaseModel):
    """Sanitized SQL query and schema ready for safe LLM inference."""
    query: str = Field(description="Sanitized SQL query with sensitive literals tokenized.")
    schema_context: Optional[str] = Field(None, description="Sanitized database schema context.")
    report: PrivacyReport = Field(description="Privacy report metadata.")
