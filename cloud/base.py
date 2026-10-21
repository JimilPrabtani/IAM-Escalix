"""Abstract base class for cloud identity collectors.

Each collector connects to its platform, gathers IAM data and returns the
fully formatted analysis prompt.
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
