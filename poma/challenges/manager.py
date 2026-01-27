"""
题目管理模块

包含两个核心类：
1. ChallengeManager: 加载和管理CTF题目及Ground Truth
2. DockerOrchestrator: 管理题目的Docker容器生命周期
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

from poma.schemas.models import (
    Challenge,
    ChallengeGroundTruth,
    DifficultyLevel,
    VulnerabilityType,
    ExploitTechnique,
    Phase0GroundTruth,
    Phase1GroundTruth,
    Phase2GroundTruth,
    Phase3GroundTruth,
    ProtectionMechanisms,
)
from poma.config import config


@dataclass
class DockerContainer:
    """
    Docker容器信息数据类

    Attributes:
        container_id: Docker容器ID
        challenge_id: 关联的题目ID
        host: 容器主机地址
        port: 容器映射的主机端口
        status: 容器状态（running/stopped）
    """

    container_id: str
    challenge_id: str
    host: str
    port: int
    status: str = "running"


class ChallengeManager:
    """
    题目管理器

    负责从文件系统加载CTF题目和Ground Truth数据。
    支持按难度、漏洞类型等维度查询题目。
    """

    def __init__(self, challenges_dir: Path):
        self.challenges_dir = Path(challenges_dir)
        self._challenges: Dict[str, Challenge] = {}
        self._ground_truths: Dict[str, ChallengeGroundTruth] = {}
        self._containers: Dict[str, DockerContainer] = {}

    def load_challenges(self) -> None:
        for level_dir in sorted(self.challenges_dir.iterdir()):
            if not level_dir.is_dir() or not level_dir.name.startswith("level"):
                continue

            for challenge_dir in level_dir.iterdir():
                if not challenge_dir.is_dir():
                    continue

                challenge_json = challenge_dir / "challenge.json"
                if challenge_json.exists():
                    challenge = self._load_challenge(challenge_json)
                    self._challenges[challenge.challenge_id] = challenge

                    gt_json = challenge_dir / "ground_truth.json"
                    if gt_json.exists():
                        gt = self._load_ground_truth(gt_json, challenge.challenge_id)
                        self._ground_truths[challenge.challenge_id] = gt

    def _load_challenge(self, json_path: Path) -> Challenge:
        with open(json_path) as f:
            data = json.load(f)

        challenge_dir = json_path.parent

        return Challenge(
            challenge_id=data["challenge_id"],
            name=data["name"],
            level=DifficultyLevel(data["level"]),
            vulnerability_types=[VulnerabilityType(v) for v in data.get("vulnerability_types", [])],
            exploit_techniques=[ExploitTechnique(t) for t in data.get("exploit_techniques", [])],
            source=data.get("source", ""),
            binary_path=str(challenge_dir / data["binary_path"]),
            source_path=str(challenge_dir / data["source_path"])
            if data.get("source_path")
            else None,
            decompiled_path=str(challenge_dir / data["decompiled_path"])
            if data.get("decompiled_path")
            else None,
            dockerfile_path=str(challenge_dir / data["dockerfile_path"])
            if data.get("dockerfile_path")
            else None,
            ground_truth_path=str(challenge_dir / "ground_truth.json"),
            libc_version=data.get("libc_version"),
            description=data.get("description", ""),
            hints=data.get("hints", []),
            tags=data.get("tags", []),
        )

    def _load_ground_truth(self, json_path: Path, challenge_id: str) -> ChallengeGroundTruth:
        with open(json_path) as f:
            data = json.load(f)

        p0 = data.get("phase_0", {})
        phase_0 = Phase0GroundTruth(
            architecture=p0.get("architecture", ""),
            protections=ProtectionMechanisms(**p0.get("protections", {})),
            program_functions=p0.get("program_functions", []),
            key_observations=p0.get("key_observations", []),
            libc_info=p0.get("libc_info"),
            environment_notes=p0.get("environment_notes"),
        )

        p1 = data.get("phase_1", {})
        vuln = p1.get("vulnerability", {})
        loc = p1.get("location", {})
        root = p1.get("root_cause", {})
        trigger = p1.get("trigger_condition", {})

        phase_1 = Phase1GroundTruth(
            vulnerability_type=vuln.get("type", ""),
            vulnerability_subtype=vuln.get("subtype"),
            cwe_id=vuln.get("cwe"),
            location_function=loc.get("function", ""),
            location_line=loc.get("line"),
            location_instruction=loc.get("instruction"),
            vulnerable_variable=loc.get("variable"),
            root_cause_description=root.get("description", ""),
            unsafe_function=root.get("unsafe_function"),
            buffer_size=root.get("buffer_size"),
            trigger_description=trigger.get("description", ""),
            minimum_input_length=trigger.get("minimum_input_length"),
            trigger_constraints=trigger.get("constraints", []),
        )

        p2 = data.get("phase_2", {})
        tech = p2.get("technique", {})

        phase_2 = Phase2GroundTruth(
            primitives=p2.get("primitives", []),
            protection_bypass=p2.get("protection_bypass", {}),
            exploitation_path=p2.get("exploitation_path", []),
            primary_technique=tech.get("name", ""),
            technique_reason=tech.get("reason", ""),
            alternative_techniques=p2.get("alternative_techniques", []),
        )

        p3 = data.get("phase_3", {})
        phase_3 = Phase3GroundTruth(
            reference_exploit_path=p3.get("reference_exploit_path", ""),
            key_offsets=p3.get("key_offsets", {}),
            key_addresses=p3.get("key_addresses", {}),
            payload_structure=p3.get("payload_structure", ""),
            critical_interactions=p3.get("critical_interactions", []),
            expected_output_pattern=p3.get("expected_output_pattern", ""),
        )

        return ChallengeGroundTruth(
            challenge_id=challenge_id,
            phase_0=phase_0,
            phase_1=phase_1,
            phase_2=phase_2,
            phase_3=phase_3,
        )

    def get_challenge(self, challenge_id: str) -> Optional[Challenge]:
        return self._challenges.get(challenge_id)

    def get_ground_truth(self, challenge_id: str) -> Optional[ChallengeGroundTruth]:
        return self._ground_truths.get(challenge_id)

    def get_challenges_by_level(self, level: DifficultyLevel) -> List[Challenge]:
        return [c for c in self._challenges.values() if c.level == level]

    def get_challenges_by_vuln_type(self, vuln_type: VulnerabilityType) -> List[Challenge]:
        return [c for c in self._challenges.values() if vuln_type in c.vulnerability_types]

    @property
    def all_challenges(self) -> List[Challenge]:
        return list(self._challenges.values())

    @property
    def all_ground_truths(self) -> Dict[str, ChallengeGroundTruth]:
        return self._ground_truths.copy()


class DockerOrchestrator:
    def __init__(self, base_port: Optional[int] = None):
        docker_config = config.get_docker_config()
        self.base_port = base_port or docker_config.get("base_port", 10000)
        self.internal_port = docker_config.get("internal_port", 9999)
        self.startup_delay = docker_config.get("startup_delay", 2)
        self.image_prefix = docker_config.get("image_prefix", "poma")
        self._port_counter = self.base_port
        self._containers: Dict[str, DockerContainer] = {}

    def _get_next_port(self) -> int:
        port = self._port_counter
        self._port_counter += 1
        return port

    def start_challenge(self, challenge: Challenge) -> Optional[DockerContainer]:
        if not challenge.dockerfile_path or not Path(challenge.dockerfile_path).exists():
            return None

        eval_config = config.get_evaluation_config()
        build_timeout = eval_config.get("docker_build_timeout", 300)

        dockerfile_dir = Path(challenge.dockerfile_path).parent
        image_name = f"{self.image_prefix}-{challenge.challenge_id}".lower()

        try:
            subprocess.run(
                ["docker", "build", "-t", image_name, "."],
                cwd=str(dockerfile_dir),
                capture_output=True,
                check=True,
                timeout=build_timeout,
            )
        except subprocess.CalledProcessError as e:
            print(f"Failed to build Docker image: {e.stderr}")
            return None
        except subprocess.TimeoutExpired:
            print("Docker build timed out")
            return None

        port = self._get_next_port()

        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "-p",
                    f"{port}:{self.internal_port}",
                    "--name",
                    f"{self.image_prefix}-{challenge.challenge_id}-{port}",
                    image_name,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            container_id = result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Failed to start container: {e.stderr}")
            return None

        time.sleep(self.startup_delay)

        container = DockerContainer(
            container_id=container_id,
            challenge_id=challenge.challenge_id,
            host="127.0.0.1",
            port=port,
        )

        self._containers[challenge.challenge_id] = container

        challenge.remote_host = container.host
        challenge.remote_port = container.port

        return container

    def stop_challenge(self, challenge_id: str) -> bool:
        container = self._containers.get(challenge_id)
        if not container:
            return False

        eval_config = config.get_evaluation_config()
        stop_timeout = eval_config.get("docker_stop_timeout", 30)

        try:
            subprocess.run(
                ["docker", "stop", container.container_id],
                capture_output=True,
                check=True,
                timeout=stop_timeout,
            )
            subprocess.run(
                ["docker", "rm", container.container_id],
                capture_output=True,
                check=True,
                timeout=stop_timeout,
            )

            del self._containers[challenge_id]
            return True

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"Failed to stop container: {e}")
            return False

    def stop_all(self) -> None:
        for challenge_id in list(self._containers.keys()):
            self.stop_challenge(challenge_id)

    def get_container(self, challenge_id: str) -> Optional[DockerContainer]:
        return self._containers.get(challenge_id)

    def is_running(self, challenge_id: str) -> bool:
        container = self._containers.get(challenge_id)
        if not container:
            return False

        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    container.container_id,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip().lower() == "true"
        except subprocess.CalledProcessError:
            return False
