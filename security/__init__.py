"""
Security module for SQL Review Environment V2.
Provides prompt injection defense, trust boundary isolation, and structured prompt building.
"""

from security.prompt_injection import PromptIsolationManager, SuspiciousInjectionSignal

__all__ = [
    "PromptIsolationManager",
    "SuspiciousInjectionSignal",
]
