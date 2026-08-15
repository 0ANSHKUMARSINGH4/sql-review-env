from __future__ import annotations
import re
from typing import List, Tuple, Dict, Any


class DetectedPII:
    def __init__(self, value: str, category: str, confidence: float, reason: str):
        self.value = value
        self.category = category
        self.confidence = confidence
        self.reason = reason


class PIIDetector:
    """
    Detects high-confidence PII (Personally Identifiable Information) in text,
    such as emails, phone numbers, customer/employee IDs, dates of birth,
    and financial identifiers in string literals.
    """

    def __init__(self):
        self.pii_patterns = [
            # Standard email pattern
            (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "email", 1.0, "Email Address"),
            # International / US phone number pattern (supports +1-555-012-3456, 555-012-3456, +1 555 012 3456)
            (r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone", 0.9, "Phone Number"),
            # Credit Card pattern (16 digits with optional dashes)
            (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "financial", 0.95, "Payment Card Number"),
            # Synthetic / standard Customer ID format (e.g. CUST-12345)
            (r"\b(CUST-[0-9]{4,8}|EMP-[0-9]{4,8})\b", "customer_id", 0.95, "Customer / Employee Identifier"),
        ]

        self.pii_field_keywords = {
            "email", "phone", "mobile", "ssn", "dob", "birth_date",
            "date_of_birth", "customer_id", "emp_id", "credit_card"
        }

    def detect(self, text: str) -> List[DetectedPII]:
        if not text:
            return []

        detected: List[DetectedPII] = []
        seen_values = set()

        # 1. Regex pattern matching for standalone PII formats (e.g. john@example.com)
        for pattern, category, confidence, reason in self.pii_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                val = match.group(0)
                if val not in seen_values:
                    seen_values.add(val)
                    detected.append(DetectedPII(val, category, confidence, reason))

        # 2. Context-aware PII literals in SQL assignments (e.g. dob = '1990-05-15')
        sql_pii_pattern = r"(?i)\b(" + "|".join(self.pii_field_keywords) + r")\s*[:=]\s*'([^']+)'"
        for match in re.finditer(sql_pii_pattern, text):
            field_name = match.group(1)
            literal_val = match.group(2)
            if literal_val and literal_val not in seen_values:
                seen_values.add(literal_val)
                detected.append(DetectedPII(
                    literal_val,
                    "pii",
                    0.90,
                    f"Literal assigned to PII field '{field_name}'"
                ))

        return detected
