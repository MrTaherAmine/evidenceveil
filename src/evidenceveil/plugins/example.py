from __future__ import annotations

from typing import Any

from .base import SemanticDetectorPlugin


class ExampleTicketDetector(SemanticDetectorPlugin):
    name = "example-ticket-detector"
    version = "1.0.0"

    def classify(self, field: str, value: Any) -> str | None:
        if "ticket" in field.lower() and isinstance(value, str):
            return "incident.ticket"
        return None
