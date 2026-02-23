"""
题目管理模块

本模块是POMA框架中题目管理的核心组件，负责从文件系统加载CTF Pwn题目及其Ground Truth数据，
并管理Docker容器的完整生命周期以支持远程漏洞利用测试。

主要功能：
1. 题目加载：从标准化的目录结构（challenges/levelN/challenge_id/）中扫描并加载题目
2. 数据解析：解析challenge.json和ground_truth.json，构建结构化的题目对象
3. 查询接口：支持按难度等级、漏洞类型等维度查询题目
4. 容器编排：自动构建Docker镜像、启动容器、分配端口，提供隔离的远程测试环境

包含两个核心类：
1. ChallengeManager: 加载和管理CTF题目及Ground Truth数据
2. DockerOrchestrator: 管理题目的Docker容器生命周期（构建、启动、停止、端口分配）
"""

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

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

    负责从文件系统加载CTF题目和Ground Truth数据，提供多维度的题目查询接口。

    目录结构要求：
    challenges/
    ├── level1/
    │   ├── L1-01/
    │   │   ├── challenge.json      # 题目元数据
    │   │   ├── ground_truth.json   # Ground Truth数据（可选）
    │   │   ├── binary              # 二进制文件
    │   │   └── Dockerfile          # Docker配置（可选）
    │   └── L1-02/
    └── level2/
        └── L2-01/

    加载流程：
    1. 第一遍扫描：遍历levelN目录，加载所有challenge.json文件
    2. 第二遍扫描：加载对应的ground_truth.json文件（如果存在）
    3. 路径解析：所有相对路径（binary_path、source_path等）相对于challenge_dir解析为绝对路径

    查询能力：
    - 按challenge_id精确查询
    - 按难度等级（DifficultyLevel）筛选
    - 按漏洞类型（VulnerabilityType）筛选
    - 获取所有题目列表
    """

    def __init__(self, challenges_dir: Path):
        self.challenges_dir = Path(challenges_dir)
        self._challenges: Dict[str, Challenge] = {}
        self._ground_truths: Dict[str, ChallengeGroundTruth] = {}
        self._containers: Dict[str, DockerContainer] = {}

    def load_challenges(self) -> None:
        """
        扫描challenges目录，加载所有题目和Ground Truth数据

        扫描模式：
        1. 遍历challenges_dir下所有以"level"开头的目录（如level1、level2）
        2. 在每个level目录下遍历所有子目录（每个子目录代表一个题目）
        3. 查找challenge.json文件，解析并加载题目元数据
        4. 查找ground_truth.json文件（可选），解析并加载Ground Truth数据

        目录扫描顺序：按字母顺序排序（level1 → level2 → ...）

        异常处理：
        - 跳过非目录项
        - 跳过不以"level"开头的目录
        - 跳过缺少challenge.json的题目目录
        - ground_truth.json缺失不影响题目加载
        """
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
        """
        从challenge.json文件解析并构造Challenge对象

        解析challenge.json中的元数据，并将所有相对路径转换为绝对路径。

        Args:
            json_path: challenge.json文件的绝对路径

        Returns:
            Challenge: 构造完成的题目对象

        路径解析规则：
        - binary_path: 相对于challenge_dir解析（必需）
        - source_path: 相对于challenge_dir解析（可选）
        - decompiled_path: 相对于challenge_dir解析（可选）
        - dockerfile_path: 相对于challenge_dir解析（可选）
        - ground_truth_path: 固定为challenge_dir/ground_truth.json

        枚举类型转换：
        - level → DifficultyLevel枚举
        - vulnerability_types → VulnerabilityType枚举列表
        - exploit_techniques → ExploitTechnique枚举列表
        """
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
        """
        从ground_truth.json文件解析四个阶段的Ground Truth数据

        解析ground_truth.json中的四阶段标准答案数据，构建完整的Ground Truth对象。

        Args:
            json_path: ground_truth.json文件的绝对路径
            challenge_id: 关联的题目ID

        Returns:
            ChallengeGroundTruth: 包含四个阶段Ground Truth的完整对象

        四阶段结构：
        - Phase 0 (程序分析): 架构、保护机制、函数列表、关键观察
        - Phase 1 (漏洞识别): 漏洞类型、位置、根因、触发条件
        - Phase 2 (利用策略): 利用原语、保护绕过、利用路径、技术选择
        - Phase 3 (Exploit实现): 参考exploit、关键偏移/地址、payload结构、交互流程

        数据转换：
        - 嵌套字典展平为对应的Phase对象
        - ProtectionMechanisms从字典转换为数据类
        - 缺失字段使用默认值（空字符串、空列表、None）
        """
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
        """
        按ID获取题目，不存在则返回None

        Args:
            challenge_id: 题目唯一标识符

        Returns:
            Optional[Challenge]: 题目对象，不存在时返回None
        """
        return self._challenges.get(challenge_id)

    def get_ground_truth(self, challenge_id: str) -> Optional[ChallengeGroundTruth]:
        """
        按ID获取Ground Truth，不存在则返回None

        Args:
            challenge_id: 题目唯一标识符

        Returns:
            Optional[ChallengeGroundTruth]: Ground Truth对象，不存在时返回None
        """
        return self._ground_truths.get(challenge_id)

    def get_challenges_by_level(self, level: DifficultyLevel) -> List[Challenge]:
        """
        按难度等级筛选题目

        Args:
            level: 难度等级枚举值（如DifficultyLevel.LEVEL1）

        Returns:
            List[Challenge]: 符合指定难度等级的题目列表
        """
        return [c for c in self._challenges.values() if c.level == level]

    def get_challenges_by_vuln_type(self, vuln_type: VulnerabilityType) -> List[Challenge]:
        """
        按漏洞类型筛选题目

        Args:
            vuln_type: 漏洞类型枚举值（如VulnerabilityType.BUFFER_OVERFLOW）

        Returns:
            List[Challenge]: 包含指定漏洞类型的题目列表（题目可能包含多种漏洞类型）
        """
        return [c for c in self._challenges.values() if vuln_type in c.vulnerability_types]

    @property
    def all_challenges(self) -> List[Challenge]:
        """获取所有已加载的题目列表"""
        return list(self._challenges.values())

    @property
    def all_ground_truths(self) -> Dict[str, ChallengeGroundTruth]:
        """获取所有已加载的Ground Truth数据（challenge_id → ChallengeGroundTruth映射）"""
        return self._ground_truths.copy()


class DockerOrchestrator:
    """
    Docker容器编排器

    管理CTF题目的Docker容器完整生命周期，为远程漏洞利用测试提供隔离环境。

    核心功能：
    1. 镜像构建：根据Dockerfile自动构建题目镜像（命名规则：{image_prefix}-{challenge_id}）
    2. 容器启动：启动容器并映射端口（内部端口 → 主机端口）
    3. 端口分配：从base_port开始递增分配可用端口
    4. 容器停止：优雅停止并清理容器资源
    5. 状态查询：检查容器运行状态

    配置来源：
    从config.get_docker_config()读取以下配置项：
    - base_port: 起始端口号（默认10000）
    - internal_port: 容器内部服务端口（默认9999）
    - startup_delay: 容器启动后等待时间（默认2秒）
    - image_prefix: Docker镜像名称前缀（默认"poma"）

    超时配置：
    从config.get_evaluation_config()读取：
    - docker_build_timeout: 镜像构建超时（默认300秒）
    - docker_stop_timeout: 容器停止超时（默认30秒）
    """

    def __init__(self, base_port: Optional[int] = None):
        """
        初始化Docker编排器

        Args:
            base_port: 起始端口号（可选）。如果未指定，从配置文件读取默认值
        """
        docker_config = config.get_docker_config()
        self.base_port = base_port or docker_config.get("base_port", 10000)
        self.internal_port = docker_config.get("internal_port", 9999)
        self.startup_delay = docker_config.get("startup_delay", 2)
        self.image_prefix = docker_config.get("image_prefix", "poma")
        self._port_counter = self.base_port
        self._containers: Dict[str, DockerContainer] = {}

    def _get_next_port(self) -> int:
        """分配下一个可用端口（从base_port递增）"""
        port = self._port_counter
        self._port_counter += 1
        return port

    def _get_challenge_internal_port(self, challenge: Challenge) -> int:
        if not challenge.dockerfile_path:
            return self.internal_port

        dockerfile_path = Path(challenge.dockerfile_path)
        if not dockerfile_path.exists():
            return self.internal_port

        try:
            for line in dockerfile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                text = line.strip()
                if not text or text.startswith("#"):
                    continue

                if text.upper().startswith("EXPOSE"):
                    parts = text.split()[1:]
                    for part in parts:
                        port_text = part.split("/", 1)[0]
                        if port_text.isdigit():
                            return int(port_text)
        except OSError:
            return self.internal_port

        return self.internal_port

    def start_challenge(self, challenge: Challenge) -> Optional[DockerContainer]:
        """
        构建Docker镜像并启动容器，返回DockerContainer对象（失败返回None）

        完整流程：
        1. 验证Dockerfile存在性
        2. 构建Docker镜像（docker build -t {image_name} .）
        3. 分配可用端口
        4. 启动容器（docker run -d -p {host_port}:{internal_port}）
        5. 等待容器启动（startup_delay秒）
        6. 更新Challenge对象的remote_host和remote_port字段

        Args:
            challenge: 待启动的题目对象（必须包含有效的dockerfile_path）

        Returns:
            Optional[DockerContainer]: 成功返回容器信息对象，失败返回None

        失败场景：
        - dockerfile_path为空或文件不存在
        - Docker镜像构建失败或超时
        - 容器启动失败

        副作用：
        - 成功时会修改challenge.remote_host和challenge.remote_port
        - 容器信息会缓存到self._containers字典中
        """
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
        internal_port = self._get_challenge_internal_port(challenge)

        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "-p",
                    f"{port}:{internal_port}",
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
        """
        停止并移除指定题目的Docker容器

        执行流程：
        1. 查找容器信息
        2. 停止容器（docker stop）
        3. 移除容器（docker rm）
        4. 从缓存中删除容器记录

        Args:
            challenge_id: 题目唯一标识符

        Returns:
            bool: 成功返回True，失败返回False

        失败场景：
        - 容器不存在（未启动或已停止）
        - docker stop命令失败或超时
        - docker rm命令失败或超时
        """
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
        """停止所有运行中的Docker容器"""
        for challenge_id in list(self._containers.keys()):
            self.stop_challenge(challenge_id)

    def get_container(self, challenge_id: str) -> Optional[DockerContainer]:
        """
        获取指定题目的容器信息

        Args:
            challenge_id: 题目唯一标识符

        Returns:
            Optional[DockerContainer]: 容器信息对象，不存在时返回None
        """
        return self._containers.get(challenge_id)

    def is_running(self, challenge_id: str) -> bool:
        """
        检查指定题目的容器是否正在运行

        通过docker inspect命令查询容器的实际运行状态。

        Args:
            challenge_id: 题目唯一标识符

        Returns:
            bool: 容器正在运行返回True，否则返回False

        检查逻辑：
        1. 从缓存中查找容器信息
        2. 执行docker inspect -f "{{.State.Running}}" {container_id}
        3. 解析输出判断状态（"true"表示运行中）

        返回False的场景：
        - 容器不存在于缓存中
        - docker inspect命令执行失败
        - 容器状态为非运行状态
        """
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

    def exec_in_container(
        self,
        challenge_id: str,
        exploit_code: str,
        timeout: int = 30,
    ) -> tuple:
        """在Docker容器内执行exploit代码。

        将exploit代码复制到容器内并执行，捕获输出结果。

        Args:
            challenge_id: 题目唯一标识符
            exploit_code: exploit的Python源代码
            timeout: 执行超时时间（秒）

        Returns:
            tuple: (success: bool, output: str)
        """
        container = self._containers.get(challenge_id)
        if not container:
            return (False, "容器未找到")

        import tempfile

        tmp_file = None
        try:
            # 写入临时文件
            tmp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
            tmp_file.write(exploit_code)
            tmp_file.close()

            # 复制到容器内
            subprocess.run(
                [
                    "docker",
                    "cp",
                    tmp_file.name,
                    f"{container.container_id}:/tmp/exploit.py",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            # 在容器内执行
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container.container_id,
                    "python3",
                    "/tmp/exploit.py",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout + result.stderr
            # 截断过长输出，保留尾部
            if len(output) > 2000:
                output = "...(truncated)...\n" + output[-2000:]

            # 检查成功模式
            from poma.config import config

            success_patterns = config.get_success_patterns()
            import re

            success = any(re.search(p, output) for p in success_patterns)

            return (success, output)

        except subprocess.TimeoutExpired:
            return (False, f"执行超时（{timeout}秒）")
        except subprocess.CalledProcessError as e:
            return (False, f"执行失败: {e.stderr or str(e)}")
        except Exception as e:
            return (False, f"未知错误: {str(e)}")
        finally:
            if tmp_file:
                import os

                try:
                    os.unlink(tmp_file.name)
                except OSError:
                    pass
