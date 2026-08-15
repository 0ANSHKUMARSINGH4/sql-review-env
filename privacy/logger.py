from __future__ import annotations
import logging
import sys
from typing import Optional, Any
from privacy.secret_detector import SecretDetector
from privacy.pii_detector import PIIDetector


class SanitizedFormatter(logging.Formatter):
    """Logging formatter that redacts secrets and PII before output."""

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt, datefmt)
        self.secret_detector = SecretDetector()
        self.pii_detector = PIIDetector()

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        
        # Detect and redact any secrets or PII in log text
        secrets = self.secret_detector.detect(formatted)
        pii = self.pii_detector.detect(formatted)

        sanitized = formatted
        for sec in secrets:
            sanitized = sanitized.replace(sec.value, f"<REDACTED_{sec.category.upper()}>")
        for p in pii:
            sanitized = sanitized.replace(p.value, f"<REDACTED_{p.category.upper()}>")

        return sanitized


class SanitizedLogger:
    """Central logger that guarantees logs do not contain raw sensitive information."""

    def __init__(self, name: str = "sql-review-privacy"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = SanitizedFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.logger.error(msg, *args, **kwargs)
