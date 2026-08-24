from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SemanticDetectorPlugin(ABC):
    """Trusted-code plugin interface for local semantic detectors."""

    name: str
    version: str

    @abstractmethod
    def classify(self, field: str, value: Any) -> str | None:
        raise NotImplementedError
