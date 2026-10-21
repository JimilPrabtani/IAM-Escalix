"""LLM client used to analyse IAM policy prompts.

Wraps langchain_openai.ChatOpenAI so any OpenAI-compatible endpoint can be
used (OpenCode, OpenRouter, Ollama, OpenAI). Surfaces failures as
LLMClientError instead of silently returning None.
"""

from __future__ import annotations

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


class LLMClientError(Exception):
    """Raised when the LLM client cannot be initialised or a request fails."""


class LLMClient:
    def __init__(
        self,
        model: str,
        api_key: str | None,
        base_url: str | None = None,
        temperature: float = 0.1,
        timeout: int = 180,
        max_retries: int = 3,
    ):
        self.model = model
        self.temperature = temperature

        kwargs: dict = {
            "model": model,
            "api_key": api_key or "not-needed",  # local backends ignore the key
            "temperature": temperature,
            "timeout": timeout,
            "max_retries": max_retries,
        }
        if base_url:
            kwargs["base_url"] = base_url

        try:
            self.llm = ChatOpenAI(**kwargs)
        except Exception as exc:  # pragma: no cover - depends on installed versions
            raise LLMClientError(
                f"Failed to initialise LLM client for model '{model}' "
                f"at endpoint '{base_url or 'OpenAI default'}': {exc}"
            ) from exc

    def ask(self, user_prompt: str) -> str:
        """Send the analysis prompt to the configured model and return raw text."""
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a world-class cloud security researcher analysing IAM configurations."),
                ("user", "{input}"),
            ]
        )
        chain = prompt | self.llm | StrOutputParser()
        try:
            return chain.invoke({"input": user_prompt})
        except Exception as exc:
            raise LLMClientError(f"LLM request failed for model '{self.model}': {exc}") from exc
