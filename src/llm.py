"""
VantaOps — LLM provider abstraction with fallback support.

Tries providers in order. If one fails (rate limit, quota, error),
falls to the next. Adding a new provider = adding a class + API key.
"""

import os
import json
import logging
from abc import ABC, abstractmethod

log = logging.getLogger("vantaops-llm")


class LLMProvider(ABC):
    """Base class for LLM providers."""

    name: str

    @abstractmethod
    def chat(self, messages: list[dict], system: str = "") -> str:
        """Send messages and return the assistant's response text."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if this provider has valid credentials."""
        ...


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        self._client = None

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if not self._client:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def chat(self, messages: list[dict], system: str = "") -> str:
        client = self._get_client()
        kwargs = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        response = client.messages.create(**kwargs)
        return response.content[0].text


class AzureOpenAIProvider(LLMProvider):
    name = "azure-openai"

    def __init__(self):
        self.api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        self.endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        self.deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-mini")
        self.api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
        self._client = None

    def is_configured(self) -> bool:
        return bool(self.api_key and self.endpoint)

    def _get_client(self):
        if not self._client:
            from openai import AzureOpenAI
            self._client = AzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.endpoint,
                api_version=self.api_version,
            )
        return self._client

    def chat(self, messages: list[dict], system: str = "") -> str:
        client = self._get_client()
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        response = client.chat.completions.create(
            model=self.deployment,
            messages=msgs,
            max_tokens=1024,
        )
        return response.choices[0].message.content


class GoogleProvider(LLMProvider):
    name = "google"

    def __init__(self):
        self.api_key = os.environ.get("GOOGLE_API_KEY", "")
        self.model = os.environ.get("GOOGLE_MODEL", "gemini-2.0-flash")
        self._client = None

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if not self._client:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    def chat(self, messages: list[dict], system: str = "") -> str:
        client = self._get_client()

        # Convert from OpenAI/Anthropic message format to Gemini format
        contents = []
        for msg in messages:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        config = {}
        if system:
            config["system_instruction"] = system

        response = client.models.generate_content(
            model=self.model,
            contents=contents,
            config=config,
        )
        return response.text


# ---------------------------------------------------------------------------
# Provider registry and fallback router
# ---------------------------------------------------------------------------

# Order matters — first configured provider is primary
PROVIDER_CLASSES = [
    AnthropicProvider,
    AzureOpenAIProvider,
    GoogleProvider,
]


class LLMRouter:
    """Routes chat requests to available providers with automatic fallback."""

    def __init__(self):
        self.providers = [p() for p in PROVIDER_CLASSES if p().is_configured()]
        if not self.providers:
            log.warning("No LLM providers configured. Set ANTHROPIC_API_KEY or GOOGLE_API_KEY.")
        else:
            names = [p.name for p in self.providers]
            log.info(f"LLM providers available: {', '.join(names)} (primary: {names[0]})")

    def chat(self, messages: list[dict], system: str = "") -> str:
        """Try each provider in order until one succeeds."""
        if not self.providers:
            return "No LLM providers configured. Please set ANTHROPIC_API_KEY or GOOGLE_API_KEY."

        last_error = None
        for provider in self.providers:
            try:
                log.info(f"Trying LLM provider: {provider.name}")
                response = provider.chat(messages, system=system)
                return response
            except Exception as e:
                log.warning(f"Provider {provider.name} failed: {e}")
                last_error = e
                continue

        return f"All LLM providers failed. Last error: {last_error}"
