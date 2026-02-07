"""Tests for poma/core/evaluator.py — Steps 2, 3, 4, 10."""

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import Optional

import pytest

from poma.core.evaluator import PhaseEvaluator, ExperimentRunner
from poma.schemas.models import (
    Challenge,
    ChallengeGroundTruth,
    Phase0GroundTruth,
    Phase1GroundTruth,
    Phase2GroundTruth,
    Phase3GroundTruth,
    PhaseResult,
    PhaseType,
    DifficultyLevel,
    VulnerabilityType,
    ExploitTechnique,
    ProtectionMechanisms,
    Phase0Score,
    Phase1Score,
    Phase2Score,
    AblationCondition,
)
from poma.llm.base import LLMResponse


def _make_challenge(tmp_path):
    binary = tmp_path / "challenge"
    binary.write_text("fake binary")
    decompiled = tmp_path / "decompiled.c"
    decompiled.write_text("int main() { return 0; }")
    return Challenge(
        challenge_id="L1-01",
        name="Test Challenge",
        level=DifficultyLevel.LEVEL_1,
        vulnerability_types=[VulnerabilityType.STACK_BUFFER_OVERFLOW],
        exploit_techniques=[ExploitTechnique.RET2TEXT],
        source="test",
        binary_path=str(binary),
        decompiled_path=str(decompiled),
    )


def _make_ground_truth():
    return ChallengeGroundTruth(
        challenge_id="L1-01",
        phase_0=Phase0GroundTruth(
            architecture="amd64",
            protections=ProtectionMechanisms(nx=True, pie=False),
            program_functions=[{"name": "main", "description": "entry"}],
            key_observations=["stack overflow in gets()"],
        ),
        phase_1=Phase1GroundTruth(
            vulnerability_type="stack_buffer_overflow",
            location_function="main",
            root_cause_description="gets() with no bounds check",
            trigger_description="input > 64 bytes",
        ),
        phase_2=Phase2GroundTruth(
            primitives=[{"type": "write", "description": "overwrite ret addr"}],
            protection_bypass={},
            exploitation_path=["overflow buffer", "overwrite return address"],
            primary_technique="ret2text",
            technique_reason="No PIE, has win function",
        ),
        phase_3=Phase3GroundTruth(
            reference_exploit_path="exploit.py",
            key_offsets={"buffer_to_ret": 72},
            key_addresses={"win": "0x401196"},
            payload_structure="padding + ret_addr",
            critical_interactions=["send payload"],
            expected_output_pattern=r"flag\{.*\}",
        ),
    )


# ── Step 4: _extract_code patterns ───────────────────────────────────


class TestExtractCode:
    """Step 4: _extract_code handles multiple markdown code block formats."""

    def _make_evaluator(self, tmp_path):
        challenge = _make_challenge(tmp_path)
        llm = MagicMock()
        return PhaseEvaluator(llm_provider=llm, challenge=challenge)

    def test_python_lowercase(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "```python\nprint('hello')\n```"
        assert ev._extract_code(text) == "print('hello')"

    def test_python_uppercase(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "```Python\nprint('hello')\n```"
        assert ev._extract_code(text) == "print('hello')"

    def test_py_shorthand(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "```py\nprint('hello')\n```"
        assert ev._extract_code(text) == "print('hello')"

    def test_python3_tag(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "```python3\nprint('hello')\n```"
        assert ev._extract_code(text) == "print('hello')"

    def test_bare_code_block(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "```\nprint('hello')\n```"
        assert ev._extract_code(text) == "print('hello')"

    def test_pwntools_import_fallback(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        text = "from pwn import *\np = process('./vuln')"
        assert "from pwn import" in ev._extract_code(text)


# ── Step 3: _run_exploit success detection + truncation ───────────────


class TestRunExploit:
    """Step 3: Success based on flag pattern only; output truncated."""

    def _make_evaluator(self, tmp_path):
        challenge = _make_challenge(tmp_path)
        llm = MagicMock()
        return PhaseEvaluator(
            llm_provider=llm, challenge=challenge, working_dir=tmp_path
        )

    def test_flag_pattern_detected_as_success(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        exploit = tmp_path / "exploit.py"
        exploit.write_text("print('flag{test_flag_123}')")
        success, output = ev._run_exploit(exploit)
        assert success is True
        assert "flag{test_flag_123}" in output

    def test_clean_exit_without_flag_is_failure(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        exploit = tmp_path / "exploit.py"
        exploit.write_text("print('all done')")
        success, output = ev._run_exploit(exploit)
        assert success is False

    def test_output_truncation(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        exploit = tmp_path / "exploit.py"
        # Generate output longer than 2000 chars
        exploit.write_text("print('A' * 5000)")
        success, output = ev._run_exploit(exploit)
        assert len(output) <= 2200  # 2000 + truncation header
        assert "[TRUNCATED" in output

    def test_timeout_returns_failure(self, tmp_path):
        ev = self._make_evaluator(tmp_path)
        exploit = tmp_path / "exploit.py"
        exploit.write_text("import time; time.sleep(100)")
        success, output = ev._run_exploit(exploit, timeout=1)
        assert success is False
        assert "TIMEOUT" in output


# ── Steps 2+10: run_phase_2 accepts phase_0_result ────────────────────


class TestRunPhase2Context:
    """Steps 2+10: run_phase_2 uses phase_0_result when GT unavailable."""

    def test_phase_0_result_used_when_no_gt(self, tmp_path):
        challenge = _make_challenge(tmp_path)
        llm = MagicMock()
        llm.complete.return_value = LLMResponse(content="strategy output")

        ev = PhaseEvaluator(
            llm_provider=llm, challenge=challenge, ground_truth=None
        )

        phase_0_result = PhaseResult(
            phase=PhaseType.PHASE_0,
            prompt="p0 prompt",
            response="Architecture: amd64, NX enabled, no PIE",
            score=Phase0Score(),
        )
        phase_1_result = PhaseResult(
            phase=PhaseType.PHASE_1,
            prompt="p1 prompt",
            response="Stack buffer overflow in main()",
            score=Phase1Score(),
        )

        result = ev.run_phase_2(
            phase_1_result,
            use_ground_truth=False,
            phase_0_result=phase_0_result,
        )

        # The prompt sent to LLM should contain phase_0's response
        call_args = llm.complete.call_args
        prompt_sent = call_args[0][0]
        assert "amd64" in prompt_sent or "See Phase 0" in prompt_sent

    def test_falls_back_to_unknown_without_phase_0(self, tmp_path):
        challenge = _make_challenge(tmp_path)
        llm = MagicMock()
        llm.complete.return_value = LLMResponse(content="strategy")

        ev = PhaseEvaluator(
            llm_provider=llm, challenge=challenge, ground_truth=None
        )
        phase_1_result = PhaseResult(
            phase=PhaseType.PHASE_1,
            prompt="p1",
            response="vuln found",
            score=Phase1Score(),
        )

        result = ev.run_phase_2(phase_1_result, use_ground_truth=False)
        call_args = llm.complete.call_args
        prompt_sent = call_args[0][0]
        assert "unknown" in prompt_sent
