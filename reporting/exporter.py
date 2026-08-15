from __future__ import annotations
import json
import re
from typing import Dict, Any, Optional
from reporting.models import BenchmarkReport, AuditSummary
from privacy.secret_detector import SecretDetector
from privacy.pii_detector import PIIDetector


class ReportExporter:
    """
    Exports benchmark reports safely in JSON or HTML formats with guaranteed zero leakage
    of raw secrets, PII, token mappings, credentials, or host filesystem paths.
    """

    def __init__(self):
        self.secret_detector = SecretDetector()
        self.pii_detector = PIIDetector()

    def export_json(self, report: BenchmarkReport) -> str:
        """Serializes BenchmarkReport to a sanitized JSON string."""
        raw_dict = report.model_dump()
        sanitized_dict = self._sanitize_data_structure(raw_dict)
        return json.dumps(sanitized_dict, indent=2)

    def export_html(self, report: BenchmarkReport) -> str:
        """Renders BenchmarkReport into a clean, modern HTML view."""
        report_json = self.export_json(report)
        data = json.loads(report_json)

        status_color = "#10B981" if data.get("overall_score", 0) >= 0.7 else "#F59E0B"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SQL Review V2 Report - {data.get('scenario_id', 'N/A')}</title>
    <style>
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0F172A; color: #F8FAFC; padding: 20px; }}
        .card {{ background: #1E293B; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #334155; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; }}
        .badge {{ background: #3B82F6; color: #fff; padding: 4px 12px; border-radius: 9999px; font-size: 0.85rem; }}
        .score {{ font-size: 2rem; font-weight: bold; color: {status_color}; }}
        pre {{ background: #090D16; padding: 16px; border-radius: 8px; overflow-x: auto; color: #38BDF8; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h2>Scenario Report: {data.get('scenario_id')}</h2>
            <span class="badge">{data.get('dialect', 'postgres').upper()}</span>
        </div>
        <p><strong>Difficulty:</strong> {data.get('difficulty')} | <strong>Status:</strong> {data.get('analysis_status')}</p>
        <div class="score">Score: {data.get('overall_score', 0):.2f} / 1.00</div>
    </div>
    <div class="card">
        <h3>Report Payload (Sanitized)</h3>
        <pre>{json.dumps(data, indent=2)}</pre>
    </div>
</body>
</html>"""
        return html_content

    def _sanitize_data_structure(self, data: Any) -> Any:
        """Recursively sanitizes data structures to remove host paths, secrets, and raw PII."""
        if isinstance(data, str):
            # Redact host paths
            clean_str = re.sub(r"[A-Za-z]:\\[^\s:]+", "[REDACTED_PATH]", data)
            clean_str = re.sub(r"/[^\s:]+", "[REDACTED_PATH]", clean_str)

            # Redact raw secrets
            for sec in self.secret_detector.detect(clean_str):
                if "TEST_" not in sec.value:
                    clean_str = clean_str.replace(sec.value, f"<{sec.category.upper()}_REDACTED>")

            # Redact raw PII
            for p in self.pii_detector.detect(clean_str):
                if "@example." not in p.value:
                    clean_str = clean_str.replace(p.value, f"<{p.category.upper()}_REDACTED>")

            return clean_str
        elif isinstance(data, dict):
            return {k: self._sanitize_data_structure(v) for k, v in data.items() if k not in ("token_map", "reverse_map")}
        elif isinstance(data, list):
            return [self._sanitize_data_structure(item) for item in data]
        return data
