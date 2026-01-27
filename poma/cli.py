"""
POMA 命令行接口

提供以下子命令：
1. run: 运行评估实验（支持多模型、消融实验、Docker）
2. analyze: 分析实验结果（生成报告、假设验证）
3. list: 列出可用题目
4. init: 初始化新题目模板

使用方法：
    poma [--config-file custom.yaml] <command> [options]
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
    """从JSON文件加载实验配置"""
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
    )


def cmd_run(args):
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
