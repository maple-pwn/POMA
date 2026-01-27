"""
LLM 提供商抽象基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import time


@dataclass
class LLMResponse:
    """
    LLM响应数据类

    封装LLM API响应的所有信息，包括内容、token统计、延迟和元数据

    Attributes:
        content: LLM生成的文本内容
        input_tokens: 输入token数
        output_tokens: 输出token数
        latency_ms: 请求延迟（毫秒）
        model: 实际使用的模型名称
        finish_reason: 结束原因（stop, length, content_filter等）
        raw_response: 原始API响应字典（用于调试）
    """

    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    model: str = ""
    finish_reason: str = ""
    raw_response: Optional[Dict[str, Any]] = None


class BaseLLMProvider(ABC):
    """
    LLM提供商抽象基类

    定义统一的LLM接口，所有具体提供商需要继承此类并实现抽象方法。
    提供通用的chat和complete接口，自动计时。
    """

    def __init__(self, model_name: str, api_key: str, **kwargs):
        """
        初始化LLM提供商

        Args:
            model_name: 模型名称
            api_key: API密钥
            **kwargs: 其他可选参数（temperature, max_tokens, timeout, base_url）
        """
        self.model_name = model_name
        self.api_key = api_key
        self.temperature = kwargs.get("temperature", 0.0)
        self.max_tokens = kwargs.get("max_tokens", 4096)
        self.timeout = kwargs.get("timeout", 120)
        self.base_url = kwargs.get("base_url")

    @abstractmethod
    def _make_request(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """
        执行LLM API请求（抽象方法，由子类实现）

        Args:
            messages: 消息列表，每个消息包含role和content
            **kwargs: 其他可选参数

        Returns:
            LLMResponse: LLM响应对象
        """
        pass

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """
        多轮对话接口（自动计时）

        Args:
            messages: 消息列表
            **kwargs: 其他可选参数

        Returns:
            LLMResponse: LLM响应对象（包含延迟信息）
        """
        start_time = time.time()
        response = self._make_request(messages, **kwargs)
        response.latency_ms = int((time.time() - start_time) * 1000)
        return response

    def complete(self, prompt: str, system_prompt: Optional[str] = None, **kwargs) -> LLMResponse:
        """
        单轮补全接口（便捷方法）

        自动构造消息列表并调用chat方法

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词（可选）
            **kwargs: 其他可选参数

        Returns:
            LLMResponse: LLM响应对象
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, **kwargs)

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """提供商名称（抽象属性，由子类实现）"""
        pass

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        start_time = time.time()
        response = self._make_request(messages, **kwargs)
        response.latency_ms = int((time.time() - start_time) * 1000)
        return response

    def complete(self, prompt: str, system_prompt: Optional[str] = None, **kwargs) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, **kwargs)

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass
