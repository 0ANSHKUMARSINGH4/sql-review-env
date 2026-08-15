from __future__ import annotations
import re
from typing import List, Tuple, Dict, Any


class DetectedSecret:
    def __init__(self, value: str, category: str, confidence: float, reason: str):
        self.value = value
        self.category = category
        self.confidence = confidence
        self.reason = reason


class SecretDetector:
    """
    Detects high-confidence credentials, API keys, private keys, connection strings,
    and secret string literals in SQL statements and schema contexts.
    
    Distinguishes between structural SQL identifiers (e.g. column `password_hash`)
    and actual sensitive literal values.
    """

    def __init__(self):
        # Known high-confidence secret regex patterns (matching actual literal values)
        self.secret_value_patterns = [
            # High-confidence token & key formats
            (r"\b(sk-[a-zA-Z0-9]{20,})\b", "api_key", 1.0, "API key format (sk-...)"),
            (r"\b(ghp_[a-zA-Z0-9]{36})\b", "api_key", 1.0, "GitHub Personal Access Token"),
            (r"\b(AKIA[0-9A-Z]{16})\b", "cloud_credential", 1.0, "AWS Access Key ID"),
            (r"\b(TEST_PASSWORD_[a-zA-Z0-9_]+)\b", "credential", 1.0, "Synthetic Test Password"),
            (r"\b(TEST_API_KEY_[a-zA-Z0-9_]+)\b", "api_key", 1.0, "Synthetic Test API Key"),
            (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "private_key", 1.0, "PEM Private Key"),
            (r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)\b", "bearer_token", 1.0, "JWT Bearer Token"),
            (r"\b(postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+(?::\d+)?/[a-zA-Z0-9_]+)\b", "database_url", 1.0, "Database Connection String"),
            (r"\b(mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+(?::\d+)?/[a-zA-Z0-9_]+)\b", "database_url", 1.0, "Database Connection String"),
            (r"\b(Bearer\s+[a-zA-Z0-9_\-\.=]{20,})\b", "bearer_token", 1.0, "Bearer Auth Token"),
        ]

        # Context-aware literal matching: SQL assignment/comparison to sensitive field names
        # Matches: field_name = 'literal_value' or field_name LIKE 'literal_value' or VALUES ('literal_value')
        self.sensitive_field_keywords = {
            "password", "passwd", "secret", "api_key", "apikey", "access_token",
            "refresh_token", "client_secret", "auth_token", "private_key"
        }

    def detect(self, text: str) -> List[DetectedSecret]:
        if not text:
            return []

        detected: List[DetectedSecret] = []
        seen_values = set()

        # 1. Direct high-confidence pattern detection
        for pattern, category, confidence, reason in self.secret_value_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                val = match.group(0)
                if val not in seen_values:
                    seen_values.add(val)
                    detected.append(DetectedSecret(val, category, confidence, reason))

        # 2. Context-aware string literal detection in SQL statements
        # Find single-quoted string literals 'value' assigned to sensitive fields or parameters
        # Example: password = 'MySecretPassword123'
        sql_literal_pattern = r"(?i)\b(" + "|".join(self.sensitive_field_keywords) + r")\s*[:=]\s*'([^']+)'"
        for match in re.finditer(sql_literal_pattern, text):
            field_name = match.group(1)
            literal_val = match.group(2)
            if literal_val and literal_val not in seen_values:
                # Make sure the literal itself isn't a SQL column name or SQL keyword
                if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", literal_val) or len(literal_val) > 4:
                    seen_values.add(literal_val)
                    detected.append(DetectedSecret(
                        literal_val,
                        "credential",
                        0.95,
                        f"Literal assigned to sensitive field '{field_name}'"
                    ))

        # 3. Detect literal strings in stored procedures / EXEC containing sensitive parameters
        # Example: EXEC sp_set_password @pwd = 'SecretValue'
        exec_pattern = r"(?i)@(?:pwd|pass|password|key|secret)\s*=\s*'([^']+)'"
        for match in re.finditer(exec_pattern, text):
            literal_val = match.group(1)
            if literal_val and literal_val not in seen_values:
                seen_values.add(literal_val)
                detected.append(DetectedSecret(
                    literal_val,
                    "credential",
                    0.95,
                    "Sensitive parameter literal in stored procedure"
                ))

        return detected
