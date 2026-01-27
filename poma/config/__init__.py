"""
POMA 配置加载器模块

提供单例模式的配置加载和访问功能，支持：
- 默认配置自动加载（default.yaml）
- 用户自定义配置覆盖
- 深度合并配置字典
- 便捷的配置访问接口
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml


class ConfigLoader:
    """
    配置加载器（单例模式）

    自动加载 default.yaml 作为默认配置，支持用户自定义配置覆盖。
    提供便捷的配置访问接口，支持点分路径访问嵌套配置项。

    Attributes:
        _instance: 单例实例
        _config: 配置字典（合并后的最终配置）
    """

    _instance: Optional["ConfigLoader"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        """
        单例模式实现：确保全局只有一个ConfigLoader实例

        Returns:
            ConfigLoader: 单例实例
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_default_config()
        return cls._instance

    def _load_default_config(self) -> None:
        """加载默认配置文件（poma/config/default.yaml）"""
        default_config_path = Path(__file__).parent / "default.yaml"
        if default_config_path.exists():
            with open(default_config_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f)

    def load_config(self, config_path: Optional[str] = None) -> None:
        """
        加载用户自定义配置并与默认配置深度合并

        Args:
            config_path: 用户配置文件路径（YAML格式）
        """
        if config_path and Path(config_path).exists():
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            self._config = self._deep_merge(self._config, user_config)

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """
        深度合并两个字典（递归合并嵌套字典）

        Args:
            base: 基础配置字典
            override: 覆盖配置字典

        Returns:
            Dict: 合并后的配置字典
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        通用配置访问方法（支持点分路径）

        Args:
            key_path: 配置路径，使用点号分隔，如 "llm.providers.openai.base_url"
            default: 未找到配置时的默认值

        Returns:
            Any: 配置值或默认值

        Example:
            >>> config.get("evaluation.max_iterations", 10)
            10
        """
        keys = key_path.split(".")
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def get_llm_provider_config(self, provider: str) -> Dict[str, Any]:
        """获取指定LLM提供商的配置（base_url, api_key_env等）"""
        return self.get(f"llm.providers.{provider}", {})

    def get_llm_defaults(self) -> Dict[str, Any]:
        """获取LLM默认参数（temperature, max_tokens, timeout）"""
        return self.get("llm.defaults", {"temperature": 0.0, "max_tokens": 4096, "timeout": 120})

    def get_error_patterns(self) -> Dict[str, List[str]]:
        """获取错误分类正则表达式模式字典"""
        return self.get("error_patterns", {})

    def get_success_patterns(self) -> List[str]:
        """获取成功检测正则表达式模式列表"""
        return self.get("success_patterns", [])

    def get_boundary_violation_keywords(self) -> List[str]:
        """获取Phase 1边界违规检测关键词列表"""
        return self.get("boundary_violation_keywords", [])

    def get_diagnosis_keywords(self) -> Dict[str, List[str]]:
        """获取诊断准确性检测关键词字典"""
        return self.get("diagnosis_keywords", {})

    def get_scoring_config(self, phase: str) -> Dict[str, Any]:
        """获取指定阶段的评分配置"""
        return self.get(f"scoring.{phase}", {})

    def get_evaluation_config(self) -> Dict[str, Any]:
        """获取评估设置（max_iterations, timeouts等）"""
        return self.get("evaluation", {})

    def get_docker_config(self) -> Dict[str, Any]:
        """获取Docker配置（端口、延迟、镜像前缀等）"""
        return self.get("docker", {})

    def get_ablation_condition(self, condition: str) -> Dict[str, Any]:
        """获取指定消融实验条件的配置"""
        return self.get(f"ablation_conditions.{condition}", {})

    def get_hypothesis_config(self) -> Dict[str, Any]:
        """获取假设验证阈值配置"""
        return self.get("hypothesis_validation", {})

    def get_output_config(self) -> Dict[str, Any]:
        """获取输出设置（目录、文件名等）"""
        return self.get("output", {})

    @property
    def config(self) -> Dict[str, Any]:
        """获取完整配置字典"""
        return self._config


def get_config() -> ConfigLoader:
    """工厂函数：获取ConfigLoader单例实例"""
    return ConfigLoader()


config = get_config()
