# POMA - 面向 Pwn 的模型评估框架

一个用于评估大型语言模型在 CTF Pwn 漏洞分析与利用中的精细化评测框架。如果想了解更多，请阅读 [docs](docs/)。

## 概览

POMA 让你可以跨整个漏洞利用流程系统地评估大型语言模型：

- **Phase 0**：信息收集与环境感知
- **Phase 1**：漏洞识别与根因分析
- **Phase 2**：利用策略规划
- **Phase 3**：Exploit 生成与迭代调试

## 特性

- **多阶段评估**：为利用流程的每个阶段做独立评分
- **消融实验**：在不同阶段注入 Ground Truth 以识别瓶颈
- **多模型支持**：覆盖 OpenAI、Anthropic、DeepSeek、Qwen 等多个提供商
- **Docker 集成**：自动化挑战环境的容器管理
- **假设验证**：内置 H1-H5 研究假设分析
- **细粒度指标**：追踪迭代收敛、错误模式与诊断精度
- **多轮实验**：通过 `num_runs` 重复实验以获得统计显著性
- **抗干扰 API 调用**：对 LLM 接口使用指数退避重试
- **测试套件**：29 个单元测试覆盖核心模块

## 安装

```bash
pip install -e .
```

或者同时安装开发依赖：

```bash
pip install -e ".[dev]"
```

## 运行测试

```bash
pytest tests/ -v
```

## 快速开始

### 1. 初始化挑战

```bash
poma init L1-01 --output-dir challenges/level1/L1-01 --name "ret2win_basic" --level 1
```

### 2. 配置实验

创建 `config.json`：

```json
{
  "name": "baseline_evaluation",
  "models": [
    {
      "provider": "openai",
      "model_name": "gpt-4o",
      "api_key_env": "OPENAI_API_KEY",
      "temperature": 0.0,
      "max_tokens": 4096
    }
  ],
  "ablation_conditions": ["full_pipeline"],
  "max_iterations": 10,
  "num_runs": 1,
  "output_dir": "results"
}
```

**使用 OpenRouter（通过一个 API 密钥访问多个提供商）：**

```json
{
  "name": "openrouter_evaluation",
  "models": [
    {
      "provider": "openrouter",
      "model_name": "deepseek/deepseek-chat",
      "api_key_env": "OPENROUTER_API_KEY",
      "temperature": 0.0,
      "max_tokens": 4096
    }
  ],
  "ablation_conditions": ["full_pipeline"],
  "max_iterations": 10,
  "output_dir": "results"
}
```

**推荐模型（全球可用）：**

- `deepseek/deepseek-chat` - DeepSeek（推荐在中国使用）
- `qwen/qwen-2.5-72b-instruct` - Qwen 2.5
- `meta-llama/llama-3.3-70b-instruct` - Llama 3.3
- `google/gemini-flash-1.5` - Gemini Flash

**注意：**像 `anthropic/claude-*` 和 `openai/gpt-*` 这类模型可能存在区域限制。

在此获取 API 密钥：https://openrouter.ai/keys

**测试 OpenRouter 配置：**

```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxx"
python scripts/test_openrouter.py
```

此脚本会验证 API 密钥、检查余额，并测试模型访问。

### 3. 运行评估

```bash
# 设置 API 密钥
export OPENAI_API_KEY="your-key"
# 或者使用 OpenRouter：
# export OPENROUTER_API_KEY="your-openrouter-key"

# 运行实验
poma run --config config.json --challenges-dir challenges/

# 远程挑战使用 Docker
poma run --config config.json --challenges-dir challenges/ --use-docker
```

### 4. 分析结果

```bash
poma analyze --results-dir results/ --validate-hypotheses
```

## 项目结构

```
poma/
├── core/
│   └── evaluator.py       # 阶段评估引擎
├── llm/
│   ├── base.py            # LLM 提供商接口
│   └── providers.py       # OpenAI、Anthropic、DeepSeek、Qwen
├── challenges/
│   └── manager.py         # 挑战加载与 Docker 编排
├── evaluation/
│   └── analyzer.py        # 结果分析与假设验证
├── prompts/
│   └── templates.py       # 面向各阶段的提示模板
├── schemas/
│   └── models.py          # 数据模型与评分 schema
└── cli.py                 # 命令行入口
```

## 挑战格式

每个挑战目录应包含：

```
L1-01/
├── challenge.json         # 挑战元数据
├── ground_truth.json      # 各阶段预期输出
├── challenge              # 可执行程序
├── decompiled.c           # 反编译源码
├── exploit.py             # 参考利用
├── Dockerfile             # 容器定义
└── flag.txt               # flag 文件
```

### challenge.json

```json
{
  "challenge_id": "L1-01",
  "name": "ret2win_basic",
  "level": 1,
  "vulnerability_types": ["stack_buffer_overflow"],
  "exploit_techniques": ["ret2text"],
  "binary_path": "challenge",
  "decompiled_path": "decompiled.c"
}
```
