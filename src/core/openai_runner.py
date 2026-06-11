"""Small OpenAI runner that preserves the lab's existing agent/runner shape."""
from __future__ import annotations

import os
from dataclasses import dataclass

from google.genai import types
from openai import AsyncOpenAI


@dataclass
class OpenAIAgent:
    """Minimal agent definition holding model, name, and system instructions."""
    model: str
    name: str
    instruction: str


class OpenAILlmResponse:
    """Tiny response wrapper compatible with the output guardrail plugin."""

    def __init__(self, text: str):
        self.content = types.Content(
            role="model",
            parts=[types.Part.from_text(text=text)],
        )


class OpenAIRunner:
    """Run OpenAI Responses API calls while honoring the lab plugin callbacks."""

    def __init__(self, agent: OpenAIAgent, app_name: str, plugins: list | None = None):
        self.agent = agent
        self.app_name = app_name
        self.plugins = plugins or []
        self.client = AsyncOpenAI()

    @staticmethod
    def _content_text(content: types.Content | None) -> str:
        """Extract text from a Google GenAI Content object used by plugins."""
        if not content or not content.parts:
            return ""
        return "".join(
            part.text
            for part in content.parts
            if hasattr(part, "text") and part.text
        )

    async def chat(self, user_message: str) -> str:
        """Apply guardrail plugins around a single OpenAI model call."""
        user_content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=user_message)],
        )

        for plugin in self.plugins:
            callback = getattr(plugin, "on_user_message_callback", None)
            if callback is None:
                continue
            blocked = await callback(
                invocation_context=None,
                user_message=user_content,
            )
            if blocked is not None:
                return self._content_text(blocked)

        response = await self.client.responses.create(
            model=os.getenv("OPENAI_MODEL", self.agent.model),
            instructions=self.agent.instruction,
            input=user_message,
        )
        llm_response = OpenAILlmResponse(response.output_text)

        for plugin in self.plugins:
            callback = getattr(plugin, "after_model_callback", None)
            if callback is None:
                continue
            maybe_response = await callback(
                callback_context=None,
                llm_response=llm_response,
            )
            if maybe_response is not None:
                llm_response = maybe_response

        return self._content_text(llm_response.content)
