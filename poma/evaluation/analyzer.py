"""
实验结果分析模块

包含以下核心类：
1. PhaseStatistics: 阶段统计数据（均值、标准差、得分率等）
2. ModelProfile: 模型能力画像（各阶段表现、成功率等）
3. ResultAnalyzer: 结果分析器（对比、消融实验、假设验证）
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field
import statistics

from poma.schemas.models import (
    ExperimentResult,
    DifficultyLevel,
    VulnerabilityType,
    AblationCondition,
    PhaseType,
)
from poma.config import config


@dataclass
class PhaseStatistics:
    """单个阶段的统计数据

    包含计数、总分、最大可能分和所有分数列表
    提供mean、std、min、max、percentage等计算属性
    """

    phase: str
    count: int = 0
    total_score: float = 0.0
    max_possible: float = 0.0
    scores: List[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        return statistics.mean(self.scores) if self.scores else 0.0

    @property
    def std(self) -> float:
        return statistics.stdev(self.scores) if len(self.scores) > 1 else 0.0

    @property
    def min_score(self) -> float:
        return min(self.scores) if self.scores else 0.0

    @property
    def max_score(self) -> float:
        return max(self.scores) if self.scores else 0.0

    @property
    def percentage(self) -> float:
        return (self.total_score / self.max_possible * 100) if self.max_possible > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "count": self.count,
            "mean": round(self.mean, 2),
            "std": round(self.std, 2),
            "min": round(self.min_score, 2),
            "max": round(self.max_score, 2),
            "percentage": round(self.percentage, 2),
        }


@dataclass
class ModelProfile:
    model_name: str
    total_experiments: int = 0
    total_success: int = 0
    phase_stats: Dict[str, PhaseStatistics] = field(default_factory=dict)
    level_stats: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    vuln_type_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    iteration_stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return (
            (self.total_success / self.total_experiments * 100)
            if self.total_experiments > 0
            else 0.0
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "total_experiments": self.total_experiments,
            "total_success": self.total_success,
            "success_rate": round(self.success_rate, 2),
            "phase_stats": {k: v.to_dict() for k, v in self.phase_stats.items()},
            "level_stats": self.level_stats,
            "vuln_type_stats": self.vuln_type_stats,
            "iteration_stats": self.iteration_stats,
        }


class ResultAnalyzer:
    def __init__(self, results_dir: Path):
        self.results_dir = Path(results_dir)
        self._results: List[ExperimentResult] = []

    def load_results(self) -> None:
        self._results = []

        for json_file in self.results_dir.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)

                result = self._parse_result(data)
                if result:
                    self._results.append(result)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

    def _parse_result(self, data: Dict[str, Any]) -> Optional[ExperimentResult]:
        try:
            result = ExperimentResult(
                experiment_id=data.get("experiment_id", ""),
                challenge_id=data.get("challenge_id", ""),
                model_name=data.get("model_name", ""),
                model_version=data.get("model_version", ""),
                ablation_condition=AblationCondition(
                    data.get("ablation_condition", "full_pipeline")
                ),
                success=data.get("success", False),
                total_duration_ms=data.get("total_duration_ms", 0),
            )
            return result
        except Exception:
            return None

    def get_model_profile(self, model_name: str) -> ModelProfile:
        model_results = [r for r in self._results if r.model_name == model_name]

        profile = ModelProfile(model_name=model_name)
        profile.total_experiments = len(model_results)
        profile.total_success = sum(1 for r in model_results if r.success)

        for phase in ["phase_0", "phase_1", "phase_2", "phase_3"]:
            stats = PhaseStatistics(phase=phase)

            for result in model_results:
                if phase in result.phase_results:
                    phase_result = result.phase_results[phase]
                    if hasattr(phase_result.score, "total"):
                        stats.scores.append(phase_result.score.total)
                        stats.total_score += phase_result.score.total
                        stats.max_possible += phase_result.score.max_score
                        stats.count += 1

            profile.phase_stats[phase] = stats

        return profile

    def compare_models(self, model_names: List[str]) -> Dict[str, Any]:
        comparison = {
            "models": [],
            "phase_comparison": defaultdict(dict),
            "success_rates": {},
            "best_per_phase": {},
        }

        for model_name in model_names:
            profile = self.get_model_profile(model_name)
            comparison["models"].append(profile.to_dict())
            comparison["success_rates"][model_name] = profile.success_rate

            for phase, stats in profile.phase_stats.items():
                comparison["phase_comparison"][phase][model_name] = stats.percentage

        for phase in ["phase_0", "phase_1", "phase_2", "phase_3"]:
            if phase in comparison["phase_comparison"]:
                phase_scores = comparison["phase_comparison"][phase]
                if phase_scores:
                    best_model = max(phase_scores, key=phase_scores.get)
                    comparison["best_per_phase"][phase] = best_model

        return comparison

    def analyze_ablation(self, model_name: str) -> Dict[str, Any]:
        model_results = [r for r in self._results if r.model_name == model_name]

        condition_stats = {}

        for condition in AblationCondition:
            condition_results = [r for r in model_results if r.ablation_condition == condition]

            if condition_results:
                success_count = sum(1 for r in condition_results if r.success)
                condition_stats[condition.value] = {
                    "count": len(condition_results),
                    "success_count": success_count,
                    "success_rate": round(success_count / len(condition_results) * 100, 2),
                }

        bottleneck_analysis = self._identify_bottlenecks(condition_stats)

        return {
            "model_name": model_name,
            "condition_stats": condition_stats,
            "bottleneck_analysis": bottleneck_analysis,
        }

    def _identify_bottlenecks(self, condition_stats: Dict[str, Dict]) -> Dict[str, Any]:
        bottlenecks = {}

        hypothesis_config = config.get_hypothesis_config()
        ablation_config = hypothesis_config.get("ablation_bottleneck", {})
        threshold = ablation_config.get("threshold", 10)
        high_severity_threshold = ablation_config.get("high_severity_threshold", 20)

        conditions = ["full_pipeline", "gt_phase0", "gt_phase0_1", "gt_phase0_1_2"]
        rates = {}

        for cond in conditions:
            if cond in condition_stats:
                rates[cond] = condition_stats[cond]["success_rate"]

        if "full_pipeline" in rates and "gt_phase0" in rates:
            diff = rates["gt_phase0"] - rates["full_pipeline"]
            if diff > threshold:
                bottlenecks["information_gathering"] = {
                    "impact": round(diff, 2),
                    "severity": "high" if diff > high_severity_threshold else "medium",
                }

        if "gt_phase0" in rates and "gt_phase0_1" in rates:
            diff = rates["gt_phase0_1"] - rates["gt_phase0"]
            if diff > threshold:
                bottlenecks["vulnerability_analysis"] = {
                    "impact": round(diff, 2),
                    "severity": "high" if diff > high_severity_threshold else "medium",
                }

        if "gt_phase0_1" in rates and "gt_phase0_1_2" in rates:
            diff = rates["gt_phase0_1_2"] - rates["gt_phase0_1"]
            if diff > threshold:
                bottlenecks["strategy_planning"] = {
                    "impact": round(diff, 2),
                    "severity": "high" if diff > high_severity_threshold else "medium",
                }

        if "gt_phase0_1_2" in rates and rates["gt_phase0_1_2"] < 70:
            bottlenecks["exploit_generation"] = {
                "impact": 100 - rates["gt_phase0_1_2"],
                "severity": "high" if rates["gt_phase0_1_2"] < 50 else "medium",
            }

        return bottlenecks

    def analyze_by_difficulty(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        if model_name:
            results = [r for r in self._results if r.model_name == model_name]
        else:
            results = self._results

        level_stats: Dict[int, Dict[str, Any]] = {}

        for result in results:
            level = self._extract_level(result.challenge_id)
            if level:
                if level not in level_stats:
                    level_stats[level] = {"count": 0, "success": 0, "scores": []}
                level_stats[level]["count"] += 1
                if result.success:
                    level_stats[level]["success"] += 1
                level_stats[level]["scores"].append(result.scores.total if result.scores else 0)

        analysis = {}
        for level in sorted(level_stats.keys()):
            stats = level_stats[level]
            count = int(stats["count"])
            success = int(stats["success"])
            scores_list: List[float] = stats["scores"]
            analysis[f"level_{level}"] = {
                "count": count,
                "success_count": success,
                "success_rate": round(success / count * 100, 2) if count > 0 else 0,
                "avg_score": round(statistics.mean(scores_list), 2) if scores_list else 0,
            }

        return analysis

    def _extract_level(self, challenge_id: str) -> Optional[int]:
        import re

        match = re.search(r"L(\d+)", challenge_id, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def analyze_error_patterns(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        if model_name:
            results = [r for r in self._results if r.model_name == model_name]
        else:
            results = self._results

        error_counts = defaultdict(int)
        diagnosis_accuracy = {"accurate": 0, "inaccurate": 0}
        convergence_patterns = defaultdict(int)

        for result in results:
            for iteration in result.iterations:
                if iteration.error_type:
                    error_counts[iteration.error_type] += 1

                if iteration.diagnosis_accurate:
                    diagnosis_accuracy["accurate"] += 1
                else:
                    diagnosis_accuracy["inaccurate"] += 1

            if result.phase_results.get("phase_3"):
                phase_3 = result.phase_results["phase_3"]
                if hasattr(phase_3.score, "convergence_pattern"):
                    convergence_patterns[phase_3.score.convergence_pattern] += 1

        total_diagnoses = diagnosis_accuracy["accurate"] + diagnosis_accuracy["inaccurate"]

        return {
            "error_frequency": dict(error_counts),
            "diagnosis_accuracy": {
                "accurate": diagnosis_accuracy["accurate"],
                "inaccurate": diagnosis_accuracy["inaccurate"],
                "accuracy_rate": round(diagnosis_accuracy["accurate"] / total_diagnoses * 100, 2)
                if total_diagnoses > 0
                else 0,
            },
            "convergence_patterns": dict(convergence_patterns),
        }

    def generate_report(self, output_path: Path) -> None:
        model_names = list(set(r.model_name for r in self._results))

        report = {
            "summary": {
                "total_experiments": len(self._results),
                "models_evaluated": model_names,
                "overall_success_rate": round(
                    sum(1 for r in self._results if r.success) / len(self._results) * 100,
                    2,
                )
                if self._results
                else 0,
            },
            "model_profiles": {},
            "model_comparison": self.compare_models(model_names) if len(model_names) > 1 else None,
            "difficulty_analysis": self.analyze_by_difficulty(),
            "error_patterns": self.analyze_error_patterns(),
        }

        for model_name in model_names:
            report["model_profiles"][model_name] = self.get_model_profile(model_name).to_dict()
            report["model_profiles"][model_name]["ablation"] = self.analyze_ablation(model_name)

        output_path.write_text(json.dumps(report, indent=2))
        print(f"Report generated: {output_path}")

    def validate_hypotheses(self) -> Dict[str, Any]:
        h1 = self._validate_h1_phase_degradation()
        h2 = self._validate_h2_pattern_matching()
        h3 = self._validate_h3_numerical_bottleneck()
        h4 = self._validate_h4_difficulty_nonlinear()
        h5 = self._validate_h5_error_propagation()

        return {
            "H1_phase_degradation": h1,
            "H2_pattern_matching": h2,
            "H3_numerical_bottleneck": h3,
            "H4_difficulty_nonlinear": h4,
            "H5_error_propagation": h5,
        }

    def _validate_h1_phase_degradation(self) -> Dict[str, Any]:
        phase_means = {}

        for phase in ["phase_0", "phase_1", "phase_2", "phase_3"]:
            scores = []
            for result in self._results:
                if phase in result.phase_results:
                    phase_result = result.phase_results[phase]
                    if hasattr(phase_result.score, "total") and hasattr(
                        phase_result.score, "max_score"
                    ):
                        if phase_result.score.max_score > 0:
                            pct = phase_result.score.total / phase_result.score.max_score * 100
                            scores.append(pct)

            if scores:
                phase_means[phase] = round(statistics.mean(scores), 2)

        is_degrading = True
        phases = ["phase_0", "phase_1", "phase_2", "phase_3"]
        for i in range(len(phases) - 1):
            if phases[i] in phase_means and phases[i + 1] in phase_means:
                if phase_means[phases[i]] < phase_means[phases[i + 1]]:
                    is_degrading = False
                    break

        return {
            "phase_performance": phase_means,
            "hypothesis_supported": is_degrading,
            "notes": "Performance should decrease: Phase 0 > Phase 1 > Phase 2 > Phase 3",
        }

    def _validate_h2_pattern_matching(self) -> Dict[str, Any]:
        return {
            "status": "requires_manual_analysis",
            "notes": "Requires categorization of vulnerabilities as 'textbook' vs 'variant'",
        }

    def _validate_h3_numerical_bottleneck(self) -> Dict[str, Any]:
        numerical_errors = 0
        framework_errors = 0

        for result in self._results:
            for iteration in result.iterations:
                if iteration.error_type in ["offset_error", "address_error"]:
                    numerical_errors += 1
                elif iteration.error_type in [
                    "syntax_error",
                    "import_error",
                    "io_error",
                ]:
                    framework_errors += 1

        total = numerical_errors + framework_errors

        return {
            "numerical_errors": numerical_errors,
            "framework_errors": framework_errors,
            "numerical_error_rate": round(numerical_errors / total * 100, 2) if total > 0 else 0,
            "hypothesis_supported": numerical_errors > framework_errors,
            "notes": "Numerical errors should be more frequent than framework errors",
        }

    def _validate_h4_difficulty_nonlinear(self) -> Dict[str, Any]:
        difficulty_analysis = self.analyze_by_difficulty()

        hypothesis_config = config.get_hypothesis_config()
        h4_config = hypothesis_config.get("h4_difficulty_nonlinear", {})
        cliff_threshold = h4_config.get("cliff_threshold", 30)

        success_rates = []
        for level in range(1, 7):
            key = f"level_{level}"
            if key in difficulty_analysis:
                success_rates.append(difficulty_analysis[key]["success_rate"])

        cliff_detected = False
        cliff_level = None

        for i in range(1, len(success_rates)):
            drop = success_rates[i - 1] - success_rates[i]
            if drop > cliff_threshold:
                cliff_detected = True
                cliff_level = i + 1
                break

        return {
            "success_by_level": success_rates,
            "cliff_detected": cliff_detected,
            "cliff_level": cliff_level,
            "hypothesis_supported": cliff_detected,
            "notes": f"Should see non-linear drop (>{cliff_threshold}%) at some difficulty threshold",
        }

    def _validate_h5_error_propagation(self) -> Dict[str, Any]:
        return {
            "status": "requires_ablation_data",
            "notes": "Compare ablation conditions to measure error propagation impact",
        }
