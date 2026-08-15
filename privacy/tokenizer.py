from __future__ import annotations
from typing import List, Dict, Tuple
from privacy.models import RedactionItem
from privacy.secret_detector import DetectedSecret
from privacy.pii_detector import DetectedPII


class TokenizedSanitizer:
    """
    Sanitizes SQL queries and schema contexts by replacing sensitive literal values
    with stable, request-scoped placeholder tokens (e.g. <EMAIL_001>, <PASSWORD_001>).
    
    Preserves SQL structural identifiers, operators, and syntax.
    Token mappings are strictly ephemeral and discarded after request completion.
    """

    def __init__(self):
        pass

    def sanitize(
        self, text: str, secrets: List[DetectedSecret], pii: List[DetectedPII]
    ) -> Tuple[str, List[RedactionItem], Dict[str, str]]:
        if not text:
            return "", [], {}

        sanitized_text = text
        redaction_items: List[RedactionItem] = []
        token_map: Dict[str, str] = {}  # token -> original_value (ephemeral)

        counters: Dict[str, int] = {
            "PASSWORD": 0,
            "API_KEY": 0,
            "CREDENTIAL": 0,
            "EMAIL": 0,
            "PHONE": 0,
            "SECRET": 0,
            "PII": 0,
        }

        # Process secrets first (higher priority)
        for sec in secrets:
            raw_val = sec.value
            if not raw_val or raw_val not in sanitized_text:
                continue

            category_upper = sec.category.upper()
            if "KEY" in category_upper or "TOKEN" in category_upper:
                tag = "API_KEY"
            elif "PASS" in category_upper or "CREDENTIAL" in category_upper:
                tag = "PASSWORD"
            else:
                tag = "SECRET"

            counters[tag] += 1
            token = f"<{tag}_{counters[tag]:03d}>"

            sanitized_text = sanitized_text.replace(raw_val, token)
            token_map[token] = raw_val

            redaction_items.append(
                RedactionItem(
                    category=sec.category,
                    token=token,
                    confidence=sec.confidence,
                    reason=sec.reason,
                )
            )

        # Process PII second
        for p in pii:
            raw_val = p.value
            if not raw_val or raw_val not in sanitized_text:
                continue

            category_upper = p.category.upper()
            if "EMAIL" in category_upper:
                tag = "EMAIL"
            elif "PHONE" in category_upper:
                tag = "PHONE"
            else:
                tag = "PII"

            counters[tag] += 1
            token = f"<{tag}_{counters[tag]:03d}>"

            sanitized_text = sanitized_text.replace(raw_val, token)
            token_map[token] = raw_val

            redaction_items.append(
                RedactionItem(
                    category=p.category,
                    token=token,
                    confidence=p.confidence,
                    reason=p.reason,
                )
            )

        return sanitized_text, redaction_items, token_map
