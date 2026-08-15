from __future__ import annotations
import io
import logging
from unittest.mock import MagicMock
import pytest

from privacy import PrivacyGateway
from privacy.logger import SanitizedFormatter


def test_security_regression_privacy_boundary_mock_llm():
    """
    Security Acceptance Test (Phase 1):
    Validates that sensitive synthetic test secrets supplied to the PrivacyGateway
    NEVER reach outbound LLM request payloads or application log outputs.
    """
    synthetic_password = "TEST_PASSWORD_123"
    synthetic_api_key = "TEST_API_KEY_456"
    synthetic_email = "test@example.invalid"

    raw_query = (
        f"SELECT * FROM users WHERE email = '{synthetic_email}' "
        f"AND password = '{synthetic_password}' AND token = '{synthetic_api_key}';"
    )
    raw_schema = f"Context: Authenticating user {synthetic_email} with API Key {synthetic_api_key}"

    # 1. Process through PrivacyGateway
    gateway = PrivacyGateway()
    sanitized_ctx = gateway.sanitize_context(raw_query, raw_schema)

    # 2. Simulate Outbound LLM Client Call
    mock_llm_client = MagicMock()
    
    # Construct model prompt using SanitizedContext
    system_prompt = "You are a SQL reviewer."
    user_prompt = f"SQL: {sanitized_ctx.query}\nSchema: {sanitized_ctx.schema_context}"

    mock_llm_client.chat.completions.create(
        model="mock-llm-model",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    # 3. Inspect Mock Outbound Payload Arguments
    call_args = mock_llm_client.chat.completions.create.call_args
    sent_messages = call_args.kwargs["messages"]
    outbound_payload_str = str(sent_messages)

    # STRICT ASSERTIONS: Outbound payload must NOT contain synthetic secrets
    assert synthetic_password not in outbound_payload_str, (
        f"SECURITY BREACH: {synthetic_password} found in mock LLM request payload!"
    )
    assert synthetic_api_key not in outbound_payload_str, (
        f"SECURITY BREACH: {synthetic_api_key} found in mock LLM request payload!"
    )
    assert synthetic_email not in outbound_payload_str, (
        f"SECURITY BREACH: {synthetic_email} found in mock LLM request payload!"
    )

    # Structure must still be present for LLM SQL reasoning
    assert "SELECT * FROM users WHERE email =" in sanitized_ctx.query
    assert "AND password =" in sanitized_ctx.query

    # 4. Verify Log Sanitization
    log_output = io.StringIO()
    handler = logging.StreamHandler(log_output)
    handler.setFormatter(SanitizedFormatter("%(message)s"))

    logger = logging.getLogger("test_security_regression_logger")
    logger.setLevel(logging.INFO)
    logger.handlers = [handler]

    logger.info(f"Processing query for {synthetic_email} with pass {synthetic_password} and key {synthetic_api_key}")

    log_str = log_output.getvalue()
    assert synthetic_password not in log_str, "SECURITY BREACH: Password found in log output!"
    assert synthetic_api_key not in log_str, "SECURITY BREACH: API key found in log output!"
    assert synthetic_email not in log_str, "SECURITY BREACH: Email found in log output!"
