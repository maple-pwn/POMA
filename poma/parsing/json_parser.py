"""
POMA JSON响应解析模块

当structured_output模式启用时，LLM输出JSON格式的响应。
本模块负责将JSON文本解析为对应阶段的结构化数据类实例。

解析链路：json.loads → 提取代码块 → 修复常见错误 → 回退regex_parser
"""

import json
import re
from typing import Optional

from poma.schemas.models import (
    ParsedPhase0Response,
    ParsedPhase1Response,
    ParsedPhase2Response,
    ParsedPhase3DebugResponse,
    ParsedPhase3Response,
    ParsedResponse,
)

# ```json ... ``` 代码块正则
_JSON_BLOCK_RE = re.compile(r"```json\s*\n?(.*?)\n?\s*```", re.DOTALL)
# ``` ... ``` 通用代码块正则
_GENERIC_BLOCK_RE = re.compile(r"```\s*\n?(.*?)\n?\s*```", re.DOTALL)


def _extract_json_block(text: str) -> Optional[str]:
    """从文本中提取JSON块（```json块 > ```块 > 最外层{}）。"""
    match = _JSON_BLOCK_RE.search(text)
    if match:
        return match.group(1).strip()

    match = _GENERIC_BLOCK_RE.search(text)
    if match:
        candidate = match.group(1).strip()
        if candidate.startswith("{"):
            return candidate

    brace_start = text.find("{")
    if brace_start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False
    for i in range(brace_start, len(text)):
        ch = text[i]
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            if in_string:
                escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start : i + 1]

    return None


def _fix_common_json_errors(text: str) -> str:
    """修复尾部逗号、单引号、未加引号键名等常见JSON错误。"""
    result = text
    # 尾部逗号: ,] 或 ,}
    result = re.sub(r",\s*([}\]])", r"\1", result)
    # 单引号 → 双引号（仅当无双引号时安全替换）
    if '"' not in result and "'" in result:
        result = result.replace("'", '"')
    # 未加引号键名: {key: "val"} → {"key": "val"}
    result = re.sub(
        r"(?<=[\{,])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:",
        r' "\1":',
        result,
    )
    return result


def _safe_json_loads(
    text: str,
) -> Optional[dict[str, object]]:
    """安全JSON解析，依次尝试直接/提取/修复/提取+修复。"""
    if not text or not text.strip():
        return None

    stripped = text.strip()

    try:
        result = json.loads(stripped)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    extracted = _extract_json_block(stripped)
    if extracted:
        try:
            result = json.loads(extracted)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    fixed = _fix_common_json_errors(stripped)
    try:
        result = json.loads(fixed)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    if extracted:
        fixed_extracted = _fix_common_json_errors(extracted)
        try:
            result = json.loads(fixed_extracted)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _ensure_str(value: object) -> str:
    """将任意值安全转换为字符串。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _ensure_list_str(value: object) -> list[str]:
    """将任意值安全转换为字符串列表。"""
    if not isinstance(value, list):
        return []
    return [_ensure_str(item) for item in value]


def _ensure_dict_str(
    value: object,
) -> dict[str, str]:
    """将任意值安全转换为字符串字典。"""
    if not isinstance(value, dict):
        return {}
    return {_ensure_str(k): _ensure_str(v) for k, v in value.items()}


def _ensure_list_dict(
    value: object,
) -> list[dict[str, str]]:
    """将任意值安全转换为字典列表。"""
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            result.append({_ensure_str(k): _ensure_str(v) for k, v in item.items()})
    return result


def parse_phase0_json(
    text: str,
) -> ParsedPhase0Response:
    """解析P0阶段（信息收集）的JSON响应，失败回退regex。"""
    data = _safe_json_loads(text)
    if data is not None:
        return ParsedPhase0Response(
            architecture=_ensure_str(data.get("architecture", "")),
            protections=_ensure_list_str(data.get("protections", [])),
            program_functionality=_ensure_str(data.get("program_functionality", "")),
            key_functions=_ensure_list_str(data.get("key_functions", [])),
            data_structures=_ensure_list_str(data.get("data_structures", [])),
            libc_version=_ensure_str(data.get("libc_version", "")),
            environment_notes=_ensure_str(data.get("environment_notes", "")),
            raw_sections={},
        )

    try:
        from poma.parsing.regex_parser import (
            parse_phase0_response,
        )

        return parse_phase0_response(text)
    except ImportError:
        return ParsedPhase0Response()


def parse_phase1_json(
    text: str,
) -> ParsedPhase1Response:
    """解析P1阶段（漏洞分析）的JSON响应，失败回退regex。"""
    data = _safe_json_loads(text)
    if data is not None:
        return ParsedPhase1Response(
            vulnerability_type=_ensure_str(data.get("vulnerability_type", "")),
            vulnerability_location=_ensure_str(data.get("vulnerability_location", "")),
            root_cause=_ensure_str(data.get("root_cause", "")),
            trigger_conditions=_ensure_str(data.get("trigger_conditions", "")),
            additional_vulns=_ensure_list_dict(data.get("additional_vulns", [])),
            raw_sections={},
        )

    try:
        from poma.parsing.regex_parser import (
            parse_phase1_response,
        )

        return parse_phase1_response(text)
    except ImportError:
        return ParsedPhase1Response()


def parse_phase2_json(
    text: str,
) -> ParsedPhase2Response:
    """解析P2阶段（策略制定）的JSON响应，失败回退regex。"""
    data = _safe_json_loads(text)
    if data is not None:
        return ParsedPhase2Response(
            exploitation_primitives=_ensure_list_str(data.get("exploitation_primitives", [])),
            protection_bypass=_ensure_dict_str(data.get("protection_bypass", {})),
            exploitation_path=_ensure_list_str(data.get("exploitation_path", [])),
            technique=_ensure_str(data.get("technique", "")),
            technique_justification=_ensure_str(data.get("technique_justification", "")),
            raw_sections={},
        )

    try:
        from poma.parsing.regex_parser import (
            parse_phase2_response,
        )

        return parse_phase2_response(text)
    except ImportError:
        return ParsedPhase2Response()


def parse_phase3_json(
    text: str,
) -> ParsedPhase3Response:
    """解析P3阶段（Exploit生成）的JSON响应，失败回退regex。"""
    data = _safe_json_loads(text)
    if data is not None:
        return ParsedPhase3Response(
            exploit_code=_ensure_str(data.get("exploit_code", "")),
            key_offsets=_ensure_dict_str(data.get("key_offsets", {})),
            key_addresses=_ensure_dict_str(data.get("key_addresses", {})),
            payload_summary=_ensure_str(data.get("payload_summary", "")),
            raw_sections={},
        )

    try:
        from poma.parsing.regex_parser import (
            parse_phase3_response,
        )

        return parse_phase3_response(text)
    except ImportError:
        return ParsedPhase3Response()


def parse_phase3_debug_json(
    text: str,
) -> ParsedPhase3DebugResponse:
    """解析P3调试迭代的JSON响应，失败回退regex。"""
    data = _safe_json_loads(text)
    if data is not None:
        return ParsedPhase3DebugResponse(
            error_diagnosis=_ensure_str(data.get("error_diagnosis", "")),
            root_cause=_ensure_str(data.get("root_cause", "")),
            fix_description=_ensure_str(data.get("fix_description", "")),
            fixed_code=_ensure_str(data.get("fixed_code", "")),
            raw_sections={},
        )

    try:
        from poma.parsing.regex_parser import (
            parse_phase3_debug_response,
        )

        return parse_phase3_debug_response(text)
    except ImportError:
        return ParsedPhase3DebugResponse()


# ============================================================
# ResponseParser — 统一解析入口
# ============================================================

# 阶段名称到JSON解析函数的映射
_JSON_PARSERS = {
    "phase_0": parse_phase0_json,
    "phase_1": parse_phase1_json,
    "phase_2": parse_phase2_json,
    "phase_3": parse_phase3_json,
    "phase_3_debug": parse_phase3_debug_json,
}


class ResponseParser:
    """LLM响应解析器，根据structured_output配置选择JSON或正则解析模式。

    当structured_output=True时，优先使用JSON解析器；
    当structured_output=False时，使用正则表达式解析器。
    两种模式均不抛出异常，解析失败时返回默认值。
    """

    def __init__(self, structured_output: bool = False) -> None:
        """初始化解析器。

        Args:
            structured_output: 是否启用结构化输出模式
        """
        self.structured_output = structured_output

    def parse(self, phase: str, text: str) -> ParsedResponse:
        """解析LLM响应文本，返回ParsedResponse包装对象。

        Args:
            phase: 阶段名称，如 "phase_0", "phase_1", "phase_2",
                   "phase_3", "phase_3_debug"
            text: LLM原始响应文本

        Returns:
            ParsedResponse包装对象，包含解析结果和元信息
        """
        parse_errors: list[str] = []

        if self.structured_output:
            parsed, mode, success = self._parse_json(
                phase,
                text,
                parse_errors,
            )
        else:
            parsed, mode, success = self._parse_regex(
                phase,
                text,
                parse_errors,
            )

        return ParsedResponse(
            phase=phase,
            parsed=parsed,
            parse_mode=mode,
            parse_success=success,
            parse_errors=parse_errors,
        )

    def _parse_json(
        self,
        phase: str,
        text: str,
        errors: list[str],
    ) -> tuple:
        """使用JSON解析器解析响应。

        Returns:
            (parsed_object, mode_str, success_bool)
        """
        json_fn = _JSON_PARSERS.get(phase)
        if json_fn is None:
            errors.append(f"未知阶段: {phase}")
            return None, "json", False

        try:
            result = json_fn(text)
        except Exception as exc:
            errors.append(f"JSON解析异常: {exc}")
            return None, "json", False

        success = self._check_non_empty(result)
        if not success:
            errors.append("JSON解析结果全部为默认值")
        return result, "json", success

    def _parse_regex(
        self,
        phase: str,
        text: str,
        errors: list[str],
    ) -> tuple:
        """使用正则表达式解析器解析响应。

        Returns:
            (parsed_object, mode_str, success_bool)
        """
        try:
            from poma.parsing.regex_parser import (
                parse_phase0_response,
                parse_phase1_response,
                parse_phase2_response,
                parse_phase3_debug_response,
                parse_phase3_response,
            )
        except ImportError as exc:
            errors.append(f"正则解析器导入失败: {exc}")
            return None, "regex", False

        regex_parsers = {
            "phase_0": parse_phase0_response,
            "phase_1": parse_phase1_response,
            "phase_2": parse_phase2_response,
            "phase_3": parse_phase3_response,
            "phase_3_debug": parse_phase3_debug_response,
        }

        regex_fn = regex_parsers.get(phase)
        if regex_fn is None:
            errors.append(f"未知阶段: {phase}")
            return None, "regex", False

        try:
            result = regex_fn(text)
        except Exception as exc:
            errors.append(f"正则解析异常: {exc}")
            return None, "regex", False

        success = self._check_non_empty(result)
        if not success:
            errors.append("正则解析结果全部为默认值")
        return result, "regex", success

    @staticmethod
    def _check_non_empty(obj: object) -> bool:
        """检查解析结果是否包含非默认值字段。"""
        if obj is None:
            return False
        fields = getattr(obj, "__dataclass_fields__", None)
        if fields is None:
            return False
        for field_name in fields:
            val = getattr(obj, field_name, None)
            if val is None:
                continue
            if isinstance(val, str) and val:
                return True
            if isinstance(val, (list, dict)) and val:
                return True
        return False
