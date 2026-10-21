"""Provider registry and configuration resolution.

Modified from EscalateGPT (Tenable, GPL-3.0), 2026-10-21: this file is new.
Replaces the hard-coded OpenAI client so any OpenAI-compatible backend works.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


class ProviderError(Exception):
    """Raised when a provider cannot be resolved (unknown name, missing key)."""


@dataclass(frozen=True)
class Provider:
    """One OpenAI-compatible LLM backend."""

    name: str
    base_url: str | None
    api_key_env: str | None
    default_model: str


PROVIDERS: dict[str, Provider] = {
    "opencode": Provider(
        name="opencode",
        base_url="https://opencode.ai/inference/openai/v1",
        api_key_env="OPENCODE_API_KEY",
        default_model="deepseek-v4.1-flash-free",
    ),
    "openrouter": Provider(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        api_key_env="OPENROUTER_API_KEY",
        default_model="nvidia/nemotron-3-super-120b-a12b:free",
    ),
    "ollama": Provider(
        name="ollama",
        base_url="http://127.0.0.1:11434/v1",
        api_key_env=None,
        default_model="qwen2.5:7b-instruct",
    ),
    "openai": Provider(
        name="openai",
        base_url=None,  # OpenAI default endpoint
        api_key_env="OPENAI_API_KEY",
        default_model="gpt-4o-mini",
    ),
}

DEFAULT_TEMPERATURE = 0.1


def resolve_provider(
    provider_name: str, model: str | None = None, api_key: str | None = None
) -> tuple[Provider, str, str | None]:
    """Resolve a provider selection into (provider, model, api_key).

    Model falls back to the provider default; the API key falls back to the
    provider's environment variable. Raises ProviderError with an actionable
    message when something is missing.
    """
    provider = PROVIDERS.get(provider_name)
    if provider is None:
        raise ProviderError(
            f"Unknown provider '{provider_name}'. Valid providers: {', '.join(sorted(PROVIDERS))}."
        )

    model = model or provider.default_model

    key = api_key or (os.environ.get(provider.api_key_env) if provider.api_key_env else None)
    if provider.api_key_env and not key:
        raise ProviderError(
            f"Provider '{provider.name}' requires an API key: set {provider.api_key_env} "
            "in your environment or a local .env file, or pass --api-key explicitly."
        )

    return provider, model, key
