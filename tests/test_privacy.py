from __future__ import annotations
import os
import io
import logging
import pytest
from privacy import (
    PrivacyGateway,
    SecretDetector,
    PIIDetector,
    TokenizedSanitizer,
    SanitizedLogger,
    SecurityPolicyException,
)


def test_secret_detector_synthetic_secrets():
    detector = SecretDetector()
    sample_text = (
        "SELECT * FROM users WHERE password = 'TEST_PASSWORD_123' "
        "AND api_key = 'TEST_API_KEY_456'"
    )
    detected = detector.detect(sample_text)
    secret_vals = [d.value for d in detected]
    
    assert "TEST_PASSWORD_123" in secret_vals
    assert "TEST_API_KEY_456" in secret_vals


def test_pii_detector_email_and_phone():
    detector = PIIDetector()
    sample_text = (
        "INSERT INTO customers (email, phone) VALUES ('test@example.invalid', '+1-555-012-3456')"
    )
    detected = detector.detect(sample_text)
    pii_vals = [d.value for d in detected]
    
    assert "test@example.invalid" in pii_vals
    assert "+1-555-012-3456" in pii_vals


def test_tokenizer_preserves_sql_structure():
    gateway = PrivacyGateway()
    query = (
        "SELECT id, email, password_hash FROM users "
        "WHERE email = 'john@example.invalid' AND password = 'TEST_PASSWORD_999';"
    )
    schema = "Table: users (id INT, email VARCHAR, password_hash VARCHAR)"
    
    sanitized = gateway.sanitize_context(query, schema)
    
    # 1. Structural identifiers must remain
    assert "password_hash" in sanitized.query
    assert "SELECT id, email, password_hash FROM users" in sanitized.query
    assert "password_hash VARCHAR" in sanitized.schema_context
    
    # 2. Literals must be tokenized
    assert "john@example.invalid" not in sanitized.query
    assert "TEST_PASSWORD_999" not in sanitized.query
    assert "<EMAIL_001>" in sanitized.query or "<EMAIL_002>" in sanitized.query
    assert "<PASSWORD_001>" in sanitized.query or "<PASSWORD_002>" in sanitized.query
    assert sanitized.report.secrets_detected >= 1
    assert sanitized.report.pii_detected >= 1


def test_sanitized_logger():
    log_output = io.StringIO()
    handler = logging.StreamHandler(log_output)
    
    from privacy.logger import SanitizedFormatter
    handler.setFormatter(SanitizedFormatter("%(message)s"))
    
    logger = logging.getLogger("test_privacy_logger")
    logger.setLevel(logging.INFO)
    logger.handlers = [handler]
    
    msg = "User logged in with password TEST_PASSWORD_777 and email user@example.invalid"
    logger.info(msg)
    
    output = log_output.getvalue()
    assert "TEST_PASSWORD_777" not in output
    assert "user@example.invalid" not in output
    assert "<REDACTED_" in output


def test_enterprise_privacy_mode_fail_closed():
    # Force Enterprise Privacy Mode ON
    gateway = PrivacyGateway(enterprise_mode=True)
    assert gateway.enterprise_mode is True
    
    query = "SELECT * FROM secrets WHERE key = 'TEST_API_KEY_000'"
    sanitized = gateway.sanitize_context(query)
    
    # Verify input was sanitized successfully
    assert "TEST_API_KEY_000" not in sanitized.query
    assert sanitized.report.llm_safe is True
