from __future__ import annotations
import os
import json
import re
from typing import List, Dict, Any, Optional, Tuple, Protocol
from models import StructuredFinding, SQLReviewAction


class ModelProvider:
    """Base interface for model providers in SQL Review Environment V2."""

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError


class MockModelProvider(ModelProvider):
    """
    Deterministic mock provider for offline testing and security regression assertions.
    Captures exact system and user prompts sent to the model for payload inspection.
    """

    def __init__(self, default_response: Optional[str] = None):
        self.last_system_prompt: Optional[str] = None
        self.last_user_prompt: Optional[str] = None
        self.last_payload_str: Optional[str] = None
        self.default_response = default_response

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        self.last_payload_str = f"SYSTEM: {system_prompt}\nUSER: {user_prompt}"

        if self.default_response is not None:
            return self.default_response

        # Default deterministic mock response returning structured findings
        mock_payload = {
            "findings": [
                {
                    "issue": "sql_injection",
                    "severity": "critical",
                    "line": 1,
                    "evidence": "Dynamic user-controlled input concatenated into SQL query.",
                    "recommendation": "Use parameterized queries."
                }
            ]
        }
        return json.dumps(mock_payload)


class OpenAIModelProvider(ModelProvider):
    """
    OpenAI-compatible client provider (Hugging Face Inference API / VLLM / OpenAI).
    Configured strictly via environment variables. Never logs or prints credentials.
    """

    def __init__(self):
        from openai import OpenAI
        
        api_base = os.getenv("API_BASE_URL", "https://api-inference.huggingface.co/v1")
        model_name = os.getenv("MODEL_NAME", "mistralai/Mistral-7B-Instruct-v0.3")
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("HF_TOKEN") or "dummy_key_for_mock"
        
        self.model_name = model_name
        self.client = OpenAI(base_url=api_base, api_key=api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        completion = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=250,
        )
        return completion.choices[0].message.content or ""


def get_model_provider() -> ModelProvider:
    """Factory creating configured ModelProvider based on environment variables."""
    llm_enabled = os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes", "on")
    provider_name = os.getenv("MODEL_PROVIDER", "mock").lower()

    if not llm_enabled or provider_name == "mock":
        return MockModelProvider()
    
    if provider_name == "openai":
        return OpenAIModelProvider()
    
    return MockModelProvider()


def parse_model_findings_json(response_text: str) -> Tuple[List[StructuredFinding], Optional[str]]:
    """
    Safely parses model output string into a validated List[StructuredFinding].
    Handles Markdown codeblocks (```json ... ```), raw JSON, and validation errors.
    Returns (findings_list, error_message).
    """
    if not response_text or not response_text.strip():
        return [], "Empty response from model."

    text = response_text.strip()

    # Extract JSON if wrapped in Markdown code fences
    markdown_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if markdown_match:
        text = markdown_match.group(1).strip()

    try:
        data = json.loads(text)
    except Exception as exc:
        return [], f"Invalid JSON output from model: {exc}"

    # Normalize data dictionary
    findings_raw = []
    if isinstance(data, dict):
        if "findings" in data and isinstance(data["findings"], list):
            findings_raw = data["findings"]
        elif "issue" in data:
            findings_raw = [data]
    elif isinstance(data, list):
        findings_raw = data

    validated_findings: List[StructuredFinding] = []
    for item in findings_raw:
        if isinstance(item, dict):
            try:
                validated_findings.append(StructuredFinding(**item))
            except Exception:
                continue  # Skip malformed individual items deterministically

    return validated_findings, None
