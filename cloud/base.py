"""Abstract base class for cloud identity collectors.

Modified from EscalateGPT (Tenable, GPL-3.0), 2026-10-21: moved from
cloud/cloud.py; imports updated for the main/cloud package split.
"""

from abc import ABC, abstractmethod

from main.logger import MyLogger


class Cloud(ABC):
    def __init__(self):
        self.logger = MyLogger(__name__)

    @abstractmethod
    def _connect(self, **kwargs):
        """Establish the platform connection; returns a client or a token."""
        pass

    @abstractmethod
    def start(self) -> str:
        """Collect IAM data and return the fully formatted prompt."""
        pass
