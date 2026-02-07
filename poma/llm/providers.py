"""
LLM 提供商具体实现

本模块实现了POMA框架支持的所有LLM API提供商，每个提供商继承BaseLLMProvider
并实现_make_request()方法来对接各自的API格式。

支持的提供商：
- OpenAI: gpt-4o, gpt-4-turbo等（标准Chat Completions API）
- Anthropic: claude-3-5-sonnet, claude-3-opus等（Messages API，需特殊处理system消息）
- DeepSeek: deepseek-chat（OpenAI兼容格式）
- Qwen: qwen2.5-72b-instruct（通义千问，OpenAI兼容格式，通过DashScope接入）
- OpenRouter: API聚合服务，统一接口访问多个提供商的模型

所有提供商的base_url均可通过default.yaml配置文件自定义，
API密钥通过环境变量注入（不硬编码在代码中）。

工厂函数 create_provider() 根据ModelConfig自动创建对应的提供商实例。
"""

import os
from typing import Dict, Any, List, Optional, TYPE_CHECKING
import httpx

from .base import BaseLLMProvider, LLMResponse
from poma.config import config

if TYPE_CHECKING:
    from poma.schemas.models import ModelConfig


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API提供商实现

    使用标准的Chat Completions API格式，支持gpt-4o、gpt-4-turbo等模型。
    API密钥通过Authorization Bearer头传递。
    """

    @property
    def provider_name(self) -> str:
        return "openai"

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """调用OpenAI Chat Completions API

        Args:
            messages: 消息列表，格式为[{"role": "system/user/assistant", "content": "..."}]
            **kwargs: 可覆盖temperature和max_tokens

        Returns:
            LLMResponse: 包含生成内容和token统计的响应对象

        Raises:
            httpx.HTTPStatusError: API请求失败时抛出
        """
        default_url = config.get(
            "llm.providers.openai.base_url", "https://api.openai.com/v1/chat/completions"
        )
        url = self.base_url or default_url

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return LLMResponse(
            content=choice["message"]["content"],
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", self.model_name),
            finish_reason=choice.get("finish_reason", ""),
            raw_response=data,
        )


class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic API提供商实现

    特殊处理：
    - system消息需要从messages中提取并作为单独的system参数
    - 响应content是数组格式，需要拼接text块
    """

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """调用Anthropic Messages API"""
        default_url = config.get(
            "llm.providers.anthropic.base_url", "https://api.anthropic.com/v1/messages"
        )
        api_version = config.get("llm.providers.anthropic.api_version", "2023-06-01")
        url = self.base_url or default_url

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": api_version,
            "Content-Type": "application/json",
        }

        system_content = None
        filtered_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                filtered_messages.append(msg)

        payload = {
            "model": self.model_name,
            "messages": filtered_messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
        }

        if system_content:
            payload["system"] = system_content

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        usage = data.get("usage", {})

        return LLMResponse(
            content=content,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            model=data.get("model", self.model_name),
            finish_reason=data.get("stop_reason", ""),
            raw_response=data,
        )


class DeepSeekProvider(BaseLLMProvider):
    """DeepSeek API提供商实现

    采用OpenAI兼容的Chat Completions API格式。
    默认API端点为 https://api.deepseek.com/v1/chat/completions
    """

    @property
    def provider_name(self) -> str:
        return "deepseek"

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """调用DeepSeek Chat Completions API

        Args:
            messages: 消息列表（OpenAI格式）
            **kwargs: 可覆盖temperature和max_tokens

        Returns:
            LLMResponse: 包含生成内容和token统计的响应对象
        """
        default_url = config.get(
            "llm.providers.deepseek.base_url", "https://api.deepseek.com/v1/chat/completions"
        )
        url = self.base_url or default_url

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return LLMResponse(
            content=choice["message"]["content"],
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", self.model_name),
            finish_reason=choice.get("finish_reason", ""),
            raw_response=data,
        )


class QwenProvider(BaseLLMProvider):
    """通义千问API提供商实现

    采用OpenAI兼容的Chat Completions API格式，通过阿里云DashScope服务接入。
    默认API端点为 https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions
    API密钥环境变量通常为 DASHSCOPE_API_KEY。
    """

    @property
    def provider_name(self) -> str:
        return "qwen"

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """调用通义千问 Chat Completions API

        Args:
            messages: 消息列表（OpenAI格式）
            **kwargs: 可覆盖temperature和max_tokens

        Returns:
            LLMResponse: 包含生成内容和token统计的响应对象
        """
        default_url = config.get(
            "llm.providers.qwen.base_url",
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        )
        url = self.base_url or default_url

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return LLMResponse(
            content=choice["message"]["content"],
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", self.model_name),
            finish_reason=choice.get("finish_reason", ""),
            raw_response=data,
        )


class OpenRouterProvider(BaseLLMProvider):
    """OpenRouter API提供商实现（OpenAI兼容格式）

    OpenRouter是一个API聚合服务，提供统一接口访问多个LLM提供商
    支持的模型包括：anthropic/claude, openai/gpt, google/gemini等
    """

    @property
    def provider_name(self) -> str:
        return "openrouter"

    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """调用OpenRouter Chat Completions API

        OpenRouter特殊处理：
        - 需要额外的HTTP-Referer和X-Title请求头
        - 错误响应包含详细的诊断信息（余额不足、模型不可用等）

        Args:
            messages: 消息列表（OpenAI格式）
            **kwargs: 可覆盖temperature和max_tokens

        Returns:
            LLMResponse: 包含生成内容和token统计的响应对象

        Raises:
            ValueError: API返回错误时，附带详细诊断信息
        """
        default_url = config.get(
            "llm.providers.openrouter.base_url",
            "https://openrouter.ai/api/v1/chat/completions",
        )
        url = self.base_url or default_url

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/poma-framework/poma",
            "X-Title": "POMA Framework",
        }

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            error_detail = ""
            try:
                error_data = e.response.json()
                error_detail = error_data.get("error", {}).get("message", str(error_data))
            except Exception:
                error_detail = e.response.text

            raise ValueError(
                f"OpenRouter API error ({e.response.status_code}): {error_detail}\n"
                f"Please check:\n"
                f"1. API key is valid: {self.api_key[:10]}...\n"
                f"2. Account has sufficient credits\n"
                f"3. Model name is correct: {self.model_name}\n"
                f"Visit https://openrouter.ai/settings/credits to check your balance"
            ) from e

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return LLMResponse(
            content=choice["message"]["content"],
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", self.model_name),
            finish_reason=choice.get("finish_reason", ""),
            raw_response=data,
        )


def create_provider(config: "ModelConfig") -> BaseLLMProvider:
    """
    LLM提供商工厂函数

    根据配置创建对应的LLM提供商实例。
    自动从环境变量读取API密钥。

    Args:
        config: 模型配置对象

    Returns:
        BaseLLMProvider: 对应的提供商实例

    Raises:
        ValueError: API密钥未找到或提供商类型未知
    """
    api_key = os.environ.get(config.api_key_env, "")
    if not api_key:
        raise ValueError(f"API key not found in environment variable: {config.api_key_env}")

    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "deepseek": DeepSeekProvider,
        "qwen": QwenProvider,
        "openrouter": OpenRouterProvider,
    }

    provider_class = providers.get(config.provider)
    if not provider_class:
        raise ValueError(f"Unknown provider: {config.provider}")

    return provider_class(
        model_name=config.model_name,
        api_key=api_key,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout=config.timeout,
        base_url=config.base_url,
    )
