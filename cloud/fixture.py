"""Offline collector: replays a stored IAM policy snapshot instead of a live cloud.

New in IAM-Escalix (2026-10-21). Lets you exercise the full analysis pipeline
without any cloud credentials - useful for safe testing and reproducible
comparisons between models.
"""

import json
from pathlib import Path

from cloud.base import Cloud
from main.prompts import PROMPTS


class Fixture(Cloud):
    """Reads a policies snapshot (as produced by cloud.aws.AWS.start) from disk."""

    def __init__(self, policies_file: str):
        super().__init__()
        self.policies_file = Path(policies_file)

    def _connect(self, **kwargs):
        return None  # no live connection in offline mode

    def start(self) -> str:
        if not self.policies_file.exists():
            raise FileNotFoundError(f"Policies file not found: {self.policies_file}")

        raw = self.policies_file.read_text(encoding="utf-8")
        try:
            json.loads(raw)  # validate early so the LLM never sees mangled data
        except json.JSONDecodeError as exc:
            raise ValueError(f"Policies file is not valid JSON: {self.policies_file} ({exc})") from exc

        self.logger.debug(f"Loaded offline policies snapshot from {self.policies_file}")
        return PROMPTS["AWS"].format(raw)
