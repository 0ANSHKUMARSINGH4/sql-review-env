from __future__ import annotations
import os
from typing import Optional, Tuple, Dict, Any
from privacy.models import PrivacyReport, RedactionItem, SanitizedContext
from privacy.secret_detector import SecretDetector
from privacy.pii_detector import PIIDetector
from privacy.tokenizer import TokenizedSanitizer


class SecurityPolicyException(Exception):
    """Raised when privacy policy enforcement fails or input cannot be safely sanitized."""
    pass


class PrivacyGateway:
    """
    Central Privacy Gateway for SQL Review Environment V2.
    
    Intercepts raw SQL queries and schema contexts before AI model processing,
    detects secrets & PII, tokenizes sensitive values into safe placeholders,
    and enforces Enterprise Privacy Mode policies (fail-closed behavior).
    """

    def __init__(self, enterprise_mode: Optional[bool] = None):
        self.secret_detector = SecretDetector()
        self.pii_detector = PIIDetector()
        self.tokenizer = TokenizedSanitizer()
        
        if enterprise_mode is not None:
            self._enterprise_mode = enterprise_mode
        else:
            env_val = os.getenv("ENTERPRISE_PRIVACY_MODE", "false").lower()
            self._enterprise_mode = env_val in ("true", "1", "yes", "on")

    @property
    def enterprise_mode(self) -> bool:
        return self._enterprise_mode

    def sanitize_context(
        self, query: str, schema_context: Optional[str] = None
    ) -> SanitizedContext:
        """
        Sanitizes SQL query and schema context.
        Returns a SanitizedContext object containing safe text and PrivacyReport audit metadata.
        """
        try:
            full_text = f"{query or ''}\n{schema_context or ''}"
            
            # Detect secrets & PII
            secrets = self.secret_detector.detect(full_text)
            pii = self.pii_detector.detect(full_text)
            
            # Tokenize query
            sanitized_query, redactions_q, _ = self.tokenizer.sanitize(query or "", secrets, pii)
            
            # Tokenize schema if present
            sanitized_schema = None
            redactions_s = []
            if schema_context:
                sanitized_schema, redactions_s, _ = self.tokenizer.sanitize(schema_context, secrets, pii)
            
            all_redactions = redactions_q + redactions_s
            
            report = PrivacyReport(
                secrets_detected=len(secrets),
                pii_detected=len(pii),
                redacted_items=len(all_redactions),
                llm_safe=True,
                details=all_redactions,
            )

            # Assert sanitization guarantee: ensure no raw secret value remains in sanitized text
            for sec in secrets:
                if sec.value in sanitized_query or (sanitized_schema and sec.value in sanitized_schema):
                    report.llm_safe = False
                    if self._enterprise_mode:
                        raise SecurityPolicyException("Unable to safely sanitize secret input. Analysis blocked.")

            for p in pii:
                if p.value in sanitized_query or (sanitized_schema and p.value in sanitized_schema):
                    report.llm_safe = False
                    if self._enterprise_mode:
                        raise SecurityPolicyException("Unable to safely sanitize PII input. Analysis blocked.")

            return SanitizedContext(
                query=sanitized_query,
                schema_context=sanitized_schema,
                report=report,
            )

        except Exception as exc:
            if isinstance(exc, SecurityPolicyException):
                raise
            if self._enterprise_mode:
                raise SecurityPolicyException(f"Privacy gateway error in Enterprise Privacy Mode: {exc}") from exc
            
            # Fallback for non-enterprise mode
            return SanitizedContext(
                query=query or "",
                schema_context=schema_context,
                report=PrivacyReport(
                    secrets_detected=0,
                    pii_detected=0,
                    redacted_items=0,
                    llm_safe=False,
                    details=[],
                ),
            )
