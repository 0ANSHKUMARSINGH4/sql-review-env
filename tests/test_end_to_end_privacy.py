from __future__ import annotations
import io
import logging
import pytest

from security import MockModelProvider
from inference import get_model_review
from privacy.logger import SanitizedFormatter


def test_end_to_end_privacy_boundary_mock_provider():
    """
    Critical Security Regression Test (Phase 6):
    Exercises the real end-to-end inference path (get_model_review) using a MockModelProvider.
    Asserts that raw synthetic secrets (TEST_PASSWORD_123, TEST_API_KEY_456, test@example.invalid)
    NEVER appear in the provider payload or captured log streams.
    """
    synthetic_password = "TEST_PASSWORD_123"
    synthetic_api_key = "TEST_API_KEY_456"
    synthetic_email = "test@example.invalid"

    raw_query = (
        f"SELECT * FROM users WHERE email = '{synthetic_email}' "
        f"AND password = '{synthetic_password}' AND token = '{synthetic_api_key}';"
    )
    raw_schema = f"Context: Authenticating user {synthetic_email} with API Key {synthetic_api_key}"

    provider = MockModelProvider()
    history = []

    # Execute get_model_review (real end-to-end path)
    action_dict, raw_resp = get_model_review(provider, raw_query, raw_schema, history)

    # 1. Assert Provider Payload Inspection
    payload = provider.last_payload_str
    assert payload is not None, "MockModelProvider did not record payload!"

    assert synthetic_password not in payload, f"SECURITY BREACH: {synthetic_password} leaked to model provider payload!"
    assert synthetic_api_key not in payload, f"SECURITY BREACH: {synthetic_api_key} leaked to model provider payload!"
    assert synthetic_email not in payload, f"SECURITY BREACH: {synthetic_email} leaked to model provider payload!"

    # 2. Tokenized Placeholders present in Provider Payload
    assert "<EMAIL_001>" in payload or "<EMAIL_002>" in payload
    assert "<PASSWORD_001>" in payload or "<PASSWORD_002>" in payload
    assert "<API_KEY_001>" in payload or "<API_KEY_002>" in payload

    # 3. Assert Logging Safety
    log_output = io.StringIO()
    handler = logging.StreamHandler(log_output)
    handler.setFormatter(SanitizedFormatter("%(message)s"))

    logger = logging.getLogger("test_e2e_privacy_logger")
    logger.setLevel(logging.INFO)
    logger.handlers = [handler]

    logger.info(f"Payload sent: {payload}")
    log_str = log_output.getvalue()

    assert synthetic_password not in log_str, "SECURITY BREACH: Password found in log output!"
    assert synthetic_api_key not in log_str, "SECURITY BREACH: API key found in log output!"
    assert synthetic_email not in log_str, "SECURITY BREACH: Email found in log output!"
