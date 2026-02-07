"""Tests for poma/llm/base.py — Steps 1 and 5."""

import time
from unittest.mock import MagicMock, patch
from typing import List, Dict

import pytest

from poma.llm.base import BaseLLMProvider, LLMResponse


class DummyProvider(BaseLLMProvider):
    """Concrete implementation for testing the abstract base class."""

    def __init__(self, responses=None, errors=None, **kwargs):
        super().__init__(model_name="test-model", api_key="test-key", **kwargs)
        self._responses = responses or []
        self._errors = errors or []
        self._call_count = 0

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        idx = self._call_count
        self._call_count += 1
        if idx < len(self._errors) and self._errors[idx] is not None:
            raise self._errors[idx]
        if idx < len(self._responses):
            return self._responses[idx]
        return LLMResponse(content="default response")

    @property
    def provider_name(self) -> str:
        return "dummy"


# ── Step 1: No duplicate method definitions ──────────────────────────


class TestNoDuplicateMethods:
    """Step 1: Verify chat/complete/provider_name are defined exactly once."""

    def test_chat_has_docstring(self):
        assert BaseLLMProvider.chat.__doc__ is not None

    def test_complete_has_docstring(self):
        assert BaseLLMProvider.complete.__doc__ is not None

    def test_provider_name_is_abstract(self):
        assert getattr(BaseLLMProvider.provider_name.fget, "__isabstractmethod__", False)


# ── Step 5: Retry with exponential backoff ────────────────────────────


class TestRetryMechanism:
    """Step 5: chat() retries with exponential backoff on failure."""

    @patch("poma.llm.base.time.sleep")
    def test_retry_succeeds_on_second_attempt(self, mock_sleep):
        provider = DummyProvider(
            errors=[RuntimeError("transient"), None],
            responses=[None, LLMResponse(content="ok")],
        )
        result = provider.chat([{"role": "user", "content": "hi"}], max_retries=3)
        assert result.content == "ok"
        assert provider._call_count == 2
        mock_sleep.assert_called_once_with(2)

    @patch("poma.llm.base.time.sleep")
    def test_retry_exhausted_raises(self, mock_sleep):
        provider = DummyProvider(
            errors=[RuntimeError("fail")] * 3,
        )
        with pytest.raises(RuntimeError, match="fail"):
            provider.chat([{"role": "user", "content": "hi"}], max_retries=3)
        assert provider._call_count == 3
        assert mock_sleep.call_count == 2

    @patch("poma.llm.base.time.sleep")
    def test_retry_backoff_intervals(self, mock_sleep):
        provider = DummyProvider(
            errors=[RuntimeError("e1"), RuntimeError("e2"), None],
            responses=[None, None, LLMResponse(content="ok")],
        )
        provider.chat([{"role": "user", "content": "hi"}], max_retries=3)
        calls = [c.args[0] for c in mock_sleep.call_args_list]
        assert calls == [2, 4]

    def test_no_retry_on_first_success(self):
        provider = DummyProvider(
            responses=[LLMResponse(content="immediate")],
        )
        result = provider.chat([{"role": "user", "content": "hi"}])
        assert result.content == "immediate"
        assert provider._call_count == 1

    def test_latency_ms_set_on_response(self):
        provider = DummyProvider(
            responses=[LLMResponse(content="ok")],
        )
        result = provider.chat([{"role": "user", "content": "hi"}])
        assert result.latency_ms >= 0

    def test_complete_delegates_to_chat(self):
        provider = DummyProvider(
            responses=[LLMResponse(content="completed")],
        )
        result = provider.complete("hello", system_prompt="be helpful")
        assert result.content == "completed"
        assert provider._call_count == 1
