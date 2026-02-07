"""
POMA 命令行接口

基于 argparse 构建的命令行工具，提供完整的实验管理功能。支持通过 --config-file 参数
覆盖默认 YAML 配置，与 POMA 所有子系统深度集成：LLM 提供者管理、题目管理器、实验
评估器、结果分析器。

架构特点：
- 子命令模式：每个功能独立为一个子命令（run/analyze/list/init）
- 配置灵活：支持 JSON 实验配置 + YAML 全局配置双层配置体系
- 模块化集成：通过 ChallengeManager、ExperimentRunner、ResultAnalyzer 等模块协同工作
- Docker 支持：可选启用 Docker 容器化运行远程题目

提供以下子命令：
1. run: 运行评估实验（支持多模型、消融实验、Docker 容器化）
2. analyze: 分析实验结果（生成统计报告、假设验证）
3. list: 列出可用题目（按难度和 ID 排序）
4. init: 初始化新题目模板（生成完整目录结构）

使用方法：
    poma [--config-file custom.yaml] <command> [options]

示例：
    poma run --config experiments/exp1.json --use-docker
    poma analyze --results-dir results/exp1 --validate-hypotheses
    poma list --challenges-dir challenges
    poma init L1-01 --output-dir challenges/level1/L1-01 --level 1
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from poma.schemas.models import (
    ModelConfig,
    ExperimentConfig,
    AblationCondition,
    DifficultyLevel,
)
from poma.llm import create_provider
from poma.challenges.manager import ChallengeManager, DockerOrchestrator
from poma.core.evaluator import ExperimentRunner
from poma.evaluation.analyzer import ResultAnalyzer
from poma.config import config


def load_config(config_path: Path) -> ExperimentConfig:
    """从 JSON 文件加载实验配置

    解析 JSON 配置文件并构建 ExperimentConfig 对象。配置文件定义了完整的实验参数，
    包括模型列表、题目范围、消融条件、并行度等。支持多模型配置，每个模型可独立
    设置 API 密钥、温度、超时等参数。

    Args:
        config_path: JSON 配置文件路径

    Returns:
        ExperimentConfig: 实验配置对象，包含以下字段：
            - name: 实验名称
            - description: 实验描述
            - models: ModelConfig 列表，每个包含 provider、model_name、api_key_env、
                     temperature、max_tokens、timeout、base_url 等字段
            - challenge_ids: 要测试的题目 ID 列表（空则测试全部）
            - ablation_conditions: 消融实验条件列表（如 full_pipeline、no_decompiled_code）
            - max_iterations: 每个题目的最大迭代次数
            - parallel_workers: 并行工作进程数
            - output_dir: 结果输出目录
            - num_runs: 每个配置的重复运行次数
    """
    with open(config_path) as f:
        data = json.load(f)

    models = [
        ModelConfig(
            provider=m["provider"],
            model_name=m["model_name"],
            api_key_env=m["api_key_env"],
            temperature=m.get("temperature", 0.0),
            max_tokens=m.get("max_tokens", 4096),
            timeout=m.get("timeout", 120),
            base_url=m.get("base_url"),
        )
        for m in data.get("models", [])
    ]

    ablation_conditions = [
        AblationCondition(c) for c in data.get("ablation_conditions", ["full_pipeline"])
    ]

    return ExperimentConfig(
        name=data.get("name", "experiment"),
        description=data.get("description", ""),
        models=models,
        challenge_ids=data.get("challenge_ids", []),
        ablation_conditions=ablation_conditions,
        max_iterations=data.get("max_iterations", 10),
        parallel_workers=data.get("parallel_workers", 1),
        output_dir=data.get("output_dir", "results"),
        num_runs=data.get("num_runs", 1),
    )


def cmd_run(args):
    """执行评估实验的完整流程

    这是 POMA 的核心命令，执行完整的实验评估流程。按照以下步骤运行：
    1. 加载 JSON 实验配置（模型、题目、消融条件等）
    2. 从指定目录加载题目集合（challenge.json + ground_truth.json）
    3. 为每个模型创建 LLM 提供者实例
    4. 可选：启动 Docker 容器化环境（用于远程题目）
    5. 逐模型运行实验：对每个题目执行指定次数的评估
    6. 收集所有结果并保存汇总报告（summary.json）

    支持多模型并行评估、消融实验（如移除反编译代码）、多次重复运行以评估稳定性。
    实验结果按模型分目录保存，包含详细的交互日志、评分、成功率等指标。

    Args:
        args: 命令行参数对象，包含：
            - config: 实验配置文件路径（JSON 格式）
            - challenges_dir: 题目目录路径
            - use_docker: 是否启用 Docker 容器化

    Returns:
        int: 退出码，0 表示成功，1 表示失败
    """
    config = load_config(Path(args.config))

    challenge_manager = ChallengeManager(Path(args.challenges_dir))
    challenge_manager.load_challenges()

    if config.challenge_ids:
        challenges_list = []
        for cid in config.challenge_ids:
            challenge = challenge_manager.get_challenge(cid)
            if challenge is not None:
                challenges_list.append(challenge)
        challenges = challenges_list
    else:
        challenges = challenge_manager.all_challenges

    if not challenges:
        print("No challenges found to run")
        return 1

    ground_truths = challenge_manager.all_ground_truths
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    docker_orchestrator = None
    if args.use_docker:
        docker_orchestrator = DockerOrchestrator()

    all_results = []

    try:
        for model_config in config.models:
            print(f"\n{'=' * 60}")
            print(f"Running experiments with model: {model_config.model_name}")
            print(f"{'=' * 60}")

            try:
                provider = create_provider(model_config)
            except Exception as e:
                print(f"Failed to create provider for {model_config.model_name}: {e}")
                continue

            runner = ExperimentRunner(
                llm_provider=provider,
                challenges=challenges,
                ground_truths=ground_truths,
                max_iterations=config.max_iterations,
                output_dir=output_dir / model_config.model_name,
            )

            for challenge in challenges:
                if docker_orchestrator and challenge.dockerfile_path:
                    print(f"Starting Docker container for {challenge.challenge_id}...")
                    container = docker_orchestrator.start_challenge(challenge)
                    if container:
                        print(f"Container started at {container.host}:{container.port}")

            results = runner.run_full_experiment(
                challenge_ids=[c.challenge_id for c in challenges],
                ablation_conditions=config.ablation_conditions,
                num_runs=config.num_runs,
            )

            all_results.extend(results)

            print(f"\nCompleted {len(results)} experiments for {model_config.model_name}")
            success_count = sum(1 for r in results if r.success)
            if len(results) > 0:
                print(
                    f"Success rate: {success_count}/{len(results)} ({success_count / len(results) * 100:.1f}%)"
                )
            else:
                print("Success rate: 0/0 (No experiments completed)")

    finally:
        if docker_orchestrator:
            print("\nStopping all Docker containers...")
            docker_orchestrator.stop_all()

    summary_path = output_dir / "summary.json"
    summary = {
        "total_experiments": len(all_results),
        "total_success": sum(1 for r in all_results if r.success),
        "models": [m.model_name for m in config.models],
        "challenges": [c.challenge_id for c in challenges],
    }
    summary_path.write_text(json.dumps(summary, indent=2))

    print(f"\n{'=' * 60}")
    print(f"All experiments completed. Results saved to {output_dir}")
    print(
        f"Total: {summary['total_experiments']} experiments, {summary['total_success']} successful"
    )

    return 0


def cmd_analyze(args):
    """分析实验结果并生成统计报告

    对已完成的实验结果进行深度分析，生成包含成功率、各阶段得分、错误模式等的
    综合报告。可选启用假设验证功能，对论文中提出的研究假设进行统计检验。

    执行流程：
    1. 从结果目录加载所有实验数据（ExperimentResult 对象）
    2. 计算统计指标：总体成功率、各阶段平均分、模型对比等
    3. 生成 JSON 格式的分析报告（包含图表数据）
    4. 可选：执行假设验证（如"提供反编译代码能显著提升成功率"）

    Args:
        args: 命令行参数对象，包含：
            - results_dir: 实验结果目录路径
            - output: 输出报告路径（可选，默认为 results_dir/analysis_report.json）
            - validate_hypotheses: 是否执行假设验证（布尔值）

    Returns:
        int: 退出码，0 表示成功
    """
    analyzer = ResultAnalyzer(Path(args.results_dir))
    analyzer.load_results()

    output_path = (
        Path(args.output) if args.output else Path(args.results_dir) / "analysis_report.json"
    )
    analyzer.generate_report(output_path)

    if args.validate_hypotheses:
        hypotheses = analyzer.validate_hypotheses()
        print("\n=== Hypothesis Validation ===")
        for h_name, h_result in hypotheses.items():
            supported = h_result.get("hypothesis_supported", "N/A")
            print(
                f"{h_name}: {'SUPPORTED' if supported else 'NOT SUPPORTED' if supported is False else 'REQUIRES ANALYSIS'}"
            )

    return 0


def cmd_list_challenges(args):
    """列出所有可用题目并以表格形式展示

    从指定目录加载所有题目，按难度等级和题目 ID 排序后以表格形式输出。
    表格包含题目 ID、名称、难度等级、漏洞类型等关键信息，便于快速浏览题库。

    输出格式：
    - 表头：ID（20字符宽）、Name（25字符宽）、Level（8字符宽）、Vuln Types（25字符宽）
    - 排序：先按难度等级（1-6），再按题目 ID 字母序
    - 漏洞类型：最多显示前2个类型，超过则显示"..."

    Args:
        args: 命令行参数对象，包含：
            - challenges_dir: 题目目录路径

    Returns:
        int: 退出码，0 表示成功
    """
    challenge_manager = ChallengeManager(Path(args.challenges_dir))
    challenge_manager.load_challenges()

    print(f"\n{'=' * 80}")
    print(f"{'ID':<20} {'Name':<25} {'Level':<8} {'Vuln Types':<25}")
    print(f"{'=' * 80}")

    for challenge in sorted(
        challenge_manager.all_challenges, key=lambda c: (c.level.value, c.challenge_id)
    ):
        vuln_types = ", ".join(v.value[:15] for v in challenge.vulnerability_types[:2])
        if len(challenge.vulnerability_types) > 2:
            vuln_types += "..."

        print(
            f"{challenge.challenge_id:<20} {challenge.name[:24]:<25} {challenge.level.value:<8} {vuln_types:<25}"
        )

    print(f"\nTotal: {len(challenge_manager.all_challenges)} challenges")

    return 0


def cmd_init_challenge(args):
    """初始化新题目的完整目录结构和模板文件

    为新题目创建标准化的目录结构，生成所有必需的模板文件。这些模板遵循 POMA
    的题目规范，包含完整的元数据结构、评估标准、容器化配置等。

    生成的文件：
    1. challenge.json: 题目元数据（ID、名称、难度、漏洞类型、文件路径等）
    2. ground_truth.json: 评估标准（四阶段的预期答案和评分依据）
       - phase_0: 程序理解（架构、保护机制、函数列表）
       - phase_1: 漏洞识别（类型、位置、根因、触发条件）
       - phase_2: 利用策略（原语、绕过方法、技术选择）
       - phase_3: 利用实现（关键偏移、地址、payload 结构）
    3. Dockerfile: 容器化配置（基于 Ubuntu 22.04 + socat）
    4. flag.txt: 占位符 flag 文件
    5. decompiled.c: 反编译代码占位符

    Args:
        args: 命令行参数对象，包含：
            - challenge_id: 题目 ID（如 L1-01）
            - output_dir: 输出目录路径
            - name: 题目名称（可选，默认使用 challenge_id）
            - level: 难度等级（1-6，默认为 1）

    Returns:
        int: 退出码，0 表示成功
    """
    challenge_dir = Path(args.output_dir)
    challenge_dir.mkdir(parents=True, exist_ok=True)

    challenge_template = {
        "challenge_id": args.challenge_id,
        "name": args.name or args.challenge_id,
        "level": args.level,
        "vulnerability_types": [],
        "exploit_techniques": [],
        "source": "",
        "binary_path": "challenge",
        "source_path": None,
        "decompiled_path": "decompiled.c",
        "dockerfile_path": "Dockerfile",
        "libc_version": None,
        "description": "",
        "hints": [],
        "tags": [],
    }

    (challenge_dir / "challenge.json").write_text(json.dumps(challenge_template, indent=2))

    ground_truth_template = {
        "phase_0": {
            "architecture": "",
            "protections": {"relro": "none", "canary": False, "nx": True, "pie": False},
            "program_functions": [],
            "key_observations": [],
            "libc_info": None,
        },
        "phase_1": {
            "vulnerability": {"type": "", "subtype": None, "cwe": None},
            "location": {
                "function": "",
                "line": None,
                "instruction": None,
                "variable": None,
            },
            "root_cause": {
                "description": "",
                "unsafe_function": None,
                "buffer_size": None,
            },
            "trigger_condition": {
                "description": "",
                "minimum_input_length": None,
                "constraints": [],
            },
        },
        "phase_2": {
            "primitives": [],
            "protection_bypass": {},
            "exploitation_path": [],
            "technique": {"name": "", "reason": ""},
            "alternative_techniques": [],
        },
        "phase_3": {
            "reference_exploit_path": "exploit.py",
            "key_offsets": {},
            "key_addresses": {},
            "payload_structure": "",
            "critical_interactions": [],
            "expected_output_pattern": "",
        },
    }

    (challenge_dir / "ground_truth.json").write_text(json.dumps(ground_truth_template, indent=2))

    dockerfile_template = """FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \\
    socat \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

COPY challenge /challenge/
COPY flag.txt /challenge/

RUN chmod +x /challenge/challenge

EXPOSE 9999

CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/challenge/challenge"]
"""

    (challenge_dir / "Dockerfile").write_text(dockerfile_template)
    (challenge_dir / "flag.txt").write_text("flag{placeholder}")
    (challenge_dir / "decompiled.c").write_text("// Decompiled code goes here\n")

    print(f"Challenge template created at: {challenge_dir}")
    print("Files created:")
    print("  - challenge.json (challenge metadata)")
    print("  - ground_truth.json (evaluation ground truth)")
    print("  - Dockerfile (container definition)")
    print("  - flag.txt (placeholder flag)")
    print("  - decompiled.c (placeholder for decompiled code)")
    print("\nNext steps:")
    print("  1. Add your binary as 'challenge'")
    print("  2. Fill in challenge.json with challenge details")
    print("  3. Fill in ground_truth.json with expected answers")
    print("  4. Update decompiled.c with actual decompiled code")

    return 0


def main():
    """POMA 命令行工具的主入口函数

    基于 argparse 构建完整的命令行界面，支持四个主要子命令和全局配置选项。
    负责解析命令行参数、加载自定义 YAML 配置文件、分发到对应的子命令处理函数。

    命令行结构：
    - 全局选项：--config-file（可选，用于覆盖默认 YAML 配置）
    - 子命令：
      1. run: 运行评估实验
         - --config/-c: 实验配置文件（JSON，必需）
         - --challenges-dir/-d: 题目目录（默认 "challenges"）
         - --use-docker: 启用 Docker 容器化（可选）
      2. analyze: 分析实验结果
         - --results-dir/-r: 结果目录（必需）
         - --output/-o: 输出报告路径（可选）
         - --validate-hypotheses: 执行假设验证（可选）
      3. list: 列出可用题目
         - --challenges-dir/-d: 题目目录（默认 "challenges"）
      4. init: 初始化新题目
         - challenge_id: 题目 ID（位置参数，必需）
         - --output-dir/-o: 输出目录（必需）
         - --name/-n: 题目名称（可选）
         - --level/-l: 难度等级 1-6（默认 1）

    Returns:
        int: 退出码，0 表示成功，1 表示失败或无效命令
    """
    parser = argparse.ArgumentParser(
        description="POMA - Pwn-Oriented Model Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config-file",
        help="Custom YAML configuration file to override default settings",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    run_parser = subparsers.add_parser("run", help="Run evaluation experiments")
    run_parser.add_argument("--config", "-c", required=True, help="Experiment configuration file")
    run_parser.add_argument(
        "--challenges-dir", "-d", default="challenges", help="Challenges directory"
    )
    run_parser.add_argument(
        "--use-docker", action="store_true", help="Use Docker for remote challenges"
    )
    run_parser.set_defaults(func=cmd_run)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze experiment results")
    analyze_parser.add_argument("--results-dir", "-r", required=True, help="Results directory")
    analyze_parser.add_argument("--output", "-o", help="Output report path")
    analyze_parser.add_argument(
        "--validate-hypotheses",
        action="store_true",
        help="Validate research hypotheses",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    list_parser = subparsers.add_parser("list", help="List available challenges")
    list_parser.add_argument(
        "--challenges-dir", "-d", default="challenges", help="Challenges directory"
    )
    list_parser.set_defaults(func=cmd_list_challenges)

    init_parser = subparsers.add_parser("init", help="Initialize a new challenge")
    init_parser.add_argument("challenge_id", help="Challenge ID (e.g., L1-01)")
    init_parser.add_argument(
        "--output-dir", "-o", required=True, help="Output directory for challenge files"
    )
    init_parser.add_argument("--name", "-n", help="Challenge name")
    init_parser.add_argument(
        "--level",
        "-l",
        type=int,
        default=1,
        choices=[1, 2, 3, 4, 5, 6],
        help="Difficulty level",
    )
    init_parser.set_defaults(func=cmd_init_challenge)

    args = parser.parse_args()

    if args.config_file:
        config.load_config(args.config_file)

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
