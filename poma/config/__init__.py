"""
POMA 配置加载器模块

提供单例模式的配置加载和访问功能，支持：
- 默认配置自动加载（default.yaml）
- 用户自定义配置覆盖
- 深度合并配置字典
- 便捷的配置访问接口

配置层次结构：
    1. 默认配置（poma/config/default.yaml）作为基础配置
    2. 用户自定义配置通过 load_config() 方法加载并覆盖默认配置
    3. 深度合并策略：嵌套字典递归合并，非字典值直接覆盖

单例模式设计理由：
    - 确保全局配置一致性，避免多处加载导致配置不同步
    - 减少文件 I/O 开销，配置文件仅加载一次
    - 提供统一的配置访问入口，便于管理和维护

配置文件包含的主要配置节：
    - llm: LLM 提供商配置（OpenAI、DeepSeek 等）及默认参数
    - evaluation: 评估流程设置（最大迭代次数、超时时间等）
    - docker: Docker 容器配置（端口映射、启动延迟、镜像前缀等）
    - scoring: 各阶段评分权重和规则（Phase 1/2/3）
    - error_patterns: 错误分类正则表达式模式（编译错误、运行时错误等）
    - success_patterns: 成功检测正则表达式模式
    - boundary_violation_keywords: Phase 1 边界违规检测关键词
    - diagnosis_keywords: 诊断准确性检测关键词（漏洞类型、利用技术等）
    - ablation_conditions: 消融实验条件配置
    - hypothesis_validation: 假设验证阈值配置
    - output: 输出目录和文件名配置
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

    Usage:
        >>> from poma.config import config
        >>> # 获取LLM提供商配置
        >>> openai_config = config.get_llm_provider_config("openai")
        >>> # 使用点分路径访问嵌套配置
        >>> max_iter = config.get("evaluation.max_iterations", 10)
        >>> # 加载用户自定义配置（可选）
        >>> config.load_config("path/to/user_config.yaml")
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
        """
        获取指定LLM提供商的配置

        从 llm.providers.{provider} 配置节读取提供商特定配置。

        Args:
            provider: 提供商名称（如 "openai", "deepseek", "qwen" 等）

        Returns:
            Dict[str, Any]: 提供商配置字典，包含以下字段：
                - base_url: API 基础 URL
                - api_key_env: API 密钥环境变量名
                - models: 可用模型列表
                - default_model: 默认使用的模型名称
        """
        return self.get(f"llm.providers.{provider}", {})

    def get_llm_defaults(self) -> Dict[str, Any]:
        """
        获取LLM默认参数配置

        从 llm.defaults 配置节读取所有LLM调用的默认参数。

        Returns:
            Dict[str, Any]: 默认参数字典，包含以下字段：
                - temperature: 采样温度（0.0-1.0，默认0.0表示确定性输出）
                - max_tokens: 最大生成token数（默认4096）
                - timeout: API调用超时时间（秒，默认120）
        """
        return self.get("llm.defaults", {"temperature": 0.0, "max_tokens": 4096, "timeout": 120})

    def get_error_patterns(self) -> Dict[str, List[str]]:
        """
        获取错误分类正则表达式模式字典

        从 error_patterns 配置节读取用于错误分类的正则表达式模式。

        Returns:
            Dict[str, List[str]]: 错误类型到正则表达式列表的映射，例如：
                {
                    "compilation_error": ["error: .*", "fatal error: .*"],
                    "runtime_error": ["Segmentation fault", "core dumped"],
                    "timeout": ["timeout", "killed"]
                }
        """
        return self.get("error_patterns", {})

    def get_success_patterns(self) -> List[str]:
        """
        获取成功检测正则表达式模式列表

        从 success_patterns 配置节读取用于检测利用成功的正则表达式模式。

        Returns:
            List[str]: 正则表达式模式列表，例如：
                ["flag\\{.*\\}", "CTF\\{.*\\}", "success", "pwned"]
        """
        return self.get("success_patterns", [])

    def get_boundary_violation_keywords(self) -> List[str]:
        """
        获取Phase 1边界违规检测关键词列表

        从 boundary_violation_keywords 配置节读取用于Phase 1边界违规检测的关键词。
        这些关键词用于检测LLM是否尝试执行超出漏洞分析范围的操作。

        Returns:
            List[str]: 边界违规关键词列表，例如：
                ["rm -rf", "format", "delete all", "drop database"]
        """
        return self.get("boundary_violation_keywords", [])

    def get_diagnosis_keywords(self) -> Dict[str, List[str]]:
        """
        获取诊断准确性检测关键词字典

        从 diagnosis_keywords 配置节读取用于评估漏洞诊断准确性的关键词。

        Returns:
            Dict[str, List[str]]: 诊断类别到关键词列表的映射，例如：
                {
                    "vulnerability_type": ["buffer overflow", "use-after-free", "format string"],
                    "exploitation_technique": ["ROP", "shellcode", "heap spray"],
                    "mitigation": ["ASLR", "DEP", "stack canary"]
                }
        """
        return self.get("diagnosis_keywords", {})

    def get_scoring_config(self, phase: str) -> Dict[str, Any]:
        """
        获取指定阶段的评分配置

        从 scoring.{phase} 配置节读取评分权重和规则。

        Args:
            phase: 评估阶段名称（如 "phase1", "phase2", "phase3"）

        Returns:
            Dict[str, Any]: 评分配置字典，包含以下字段：
                - weights: 各评分项的权重字典
                - thresholds: 评分阈值配置
                - penalties: 惩罚项配置
        """
        return self.get(f"scoring.{phase}", {})

    def get_evaluation_config(self) -> Dict[str, Any]:
        """
        获取评估流程设置

        从 evaluation 配置节读取评估流程的全局设置。

        Returns:
            Dict[str, Any]: 评估配置字典，包含以下字段：
                - max_iterations: 最大迭代次数
                - phase1_timeout: Phase 1 超时时间（秒）
                - phase2_timeout: Phase 2 超时时间（秒）
                - phase3_timeout: Phase 3 超时时间（秒）
                - retry_on_error: 错误时是否重试
        """
        return self.get("evaluation", {})

    def get_docker_config(self) -> Dict[str, Any]:
        """
        获取Docker容器配置

        从 docker 配置节读取Docker容器相关的配置参数。

        Returns:
            Dict[str, Any]: Docker配置字典，包含以下字段：
                - port_range: 端口映射范围（如 [10000, 20000]）
                - startup_delay: 容器启动后的等待时间（秒）
                - image_prefix: Docker镜像名称前缀
                - network_mode: 网络模式（如 "bridge", "host"）
                - memory_limit: 内存限制
        """
        return self.get("docker", {})

    def get_ablation_condition(self, condition: str) -> Dict[str, Any]:
        """
        获取指定消融实验条件的配置

        从 ablation_conditions.{condition} 配置节读取消融实验条件的配置。

        Args:
            condition: 消融实验条件名称（如 "no_cot", "no_reflection", "baseline"）

        Returns:
            Dict[str, Any]: 消融条件配置字典，包含以下字段：
                - enabled_features: 启用的特性列表
                - disabled_features: 禁用的特性列表
                - description: 条件描述
        """
        return self.get(f"ablation_conditions.{condition}", {})

    def get_hypothesis_config(self) -> Dict[str, Any]:
        """
        获取假设验证阈值配置

        从 hypothesis_validation 配置节读取假设验证的阈值和规则。

        Returns:
            Dict[str, Any]: 假设验证配置字典，包含以下字段：
                - confidence_threshold: 置信度阈值（0.0-1.0）
                - min_evidence_count: 最小证据数量
                - validation_methods: 验证方法列表
                - acceptance_criteria: 接受标准
        """
        return self.get("hypothesis_validation", {})

    def get_output_config(self) -> Dict[str, Any]:
        """
        获取输出设置配置

        从 output 配置节读取输出目录和文件命名相关的配置。

        Returns:
            Dict[str, Any]: 输出配置字典，包含以下字段：
                - results_dir: 结果输出目录路径
                - logs_dir: 日志输出目录路径
                - report_format: 报告格式（如 "json", "yaml", "html"）
                - filename_template: 文件名模板
                - timestamp_format: 时间戳格式
        """
        return self.get("output", {})

    def get_prompt_template(self, prompt_key: str) -> Optional[str]:
        """获取自定义prompt模板（从YAML配置加载）

        Args:
            prompt_key: prompt键名，如 "phase_0_system", "phase_1_user" 等

        Returns:
            Optional[str]: 自定义prompt字符串，未配置则返回None
        """
        return self.get(f"prompts.{prompt_key}", None)

    @property
    def config(self) -> Dict[str, Any]:
        """获取完整配置字典"""
        return self._config


def get_config() -> ConfigLoader:
    """
    工厂函数：获取ConfigLoader单例实例

    这是获取配置加载器的推荐方式，确保返回全局唯一的单例实例。
    由于ConfigLoader使用单例模式，多次调用此函数返回的是同一个实例。

    Returns:
        ConfigLoader: 配置加载器单例实例

    Example:
        >>> from poma.config import get_config
        >>> config = get_config()
        >>> llm_config = config.get_llm_defaults()
    """
    return ConfigLoader()


# 全局单例实例：模块级配置对象，供整个项目使用
# 这是访问配置的推荐方式：from poma.config import config
config = get_config()
