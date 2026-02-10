"""
基于正则表达式的LLM响应解析器

从Markdown格式的自由文本响应中提取结构化数据，
支持 **Section**: 和 ## Section 两种标题格式。
解析失败时返回默认值，不抛出异常。
"""

import re

from poma.schemas.models import (
    ParsedPhase0Response,
    ParsedPhase1Response,
    ParsedPhase2Response,
    ParsedPhase3DebugResponse,
    ParsedPhase3Response,
)

# Markdown标题模式：匹配 **Title**: 或 ##/### Title
_SECTION_BOLD_RE = re.compile(
    r"\*\*([^*]+?)\*\*\s*[:：]",
)
_SECTION_HEADING_RE = re.compile(
    r"^#{2,3}\s+(.+?)$",
    re.MULTILINE,
)

# 列表项模式：匹配 - item / * item / 1. item / 1) item
_LIST_ITEM_RE = re.compile(
    r"^\s*(?:[-*]|\d+[.)]\s)\s*(.+)$",
    re.MULTILINE,
)

# 键值对模式：匹配 key: value（排除URL中的冒号）
_KV_RE = re.compile(
    r"^\s*([A-Za-z_\u4e00-\u9fff][\w\s\u4e00-\u9fff]*?)"
    r"\s*[:：]\s*(.+)$",
    re.MULTILINE,
)

# 代码块模式：匹配 ```python ... ``` 或 ```py ... ```
_CODE_BLOCK_RE = re.compile(
    r"```(?:python|py)?\s*\n(.*?)```",
    re.DOTALL,
)

# 十六进制/偏移量模式：匹配 name = 0x... 或 name = 123
_OFFSET_RE = re.compile(
    r"(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)",
)

# pwntools导入检测
_PWNTOOLS_RE = re.compile(
    r"(?:from\s+pwn\s+import|import\s+pwn)",
)


def _split_markdown_sections(text: str) -> dict[str, str]:
    """将Markdown文本按标题拆分为 {节名: 内容} 字典。"""
    anchors: list[tuple[int, str]] = []

    for m in _SECTION_BOLD_RE.finditer(text):
        anchors.append((m.start(), m.group(1).strip()))
    for m in _SECTION_HEADING_RE.finditer(text):
        anchors.append((m.start(), m.group(1).strip()))

    anchors.sort(key=lambda x: x[0])

    sections: dict[str, str] = {}
    for i, (pos, name) in enumerate(anchors):
        header_end = text.index("\n", pos) + 1 if "\n" in text[pos:] else len(text)
        next_pos = anchors[i + 1][0] if i + 1 < len(anchors) else len(text)
        body = text[header_end:next_pos].strip()
        sections[name.lower()] = body

    return sections


def _extract_list_items(text: str) -> list[str]:
    """从文本中提取列表项（支持-/*和数字编号格式）。"""
    return [m.group(1).strip() for m in _LIST_ITEM_RE.finditer(text)]


def _extract_key_value_pairs(text: str) -> dict[str, str]:
    """从文本中提取 key: value 键值对。"""
    pairs: dict[str, str] = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        pairs[key] = val
    return pairs


def _extract_code_block(text: str) -> str:
    """从文本中提取第一个Python代码块。"""
    m = _CODE_BLOCK_RE.search(text)
    if m:
        return m.group(1).strip()
    if _PWNTOOLS_RE.search(text):
        return text.strip()
    return ""


def _find_section(
    sections: dict[str, str],
    *candidates: str,
) -> str:
    """按候选关键词在sections中模糊匹配首个命中。"""
    for candidate in candidates:
        candidate_lower = candidate.lower()
        for key, val in sections.items():
            if candidate_lower in key:
                return val
    return ""


def parse_phase0_response(text: str) -> ParsedPhase0Response:
    """解析P0阶段（信息收集）的LLM自由文本响应。"""
    sections = _split_markdown_sections(text)

    arch_text = _find_section(
        sections,
        "architecture",
        "架构",
        "arch",
    )
    prot_text = _find_section(
        sections,
        "protection",
        "保护",
        "安全",
    )
    func_text = _find_section(
        sections,
        "functionality",
        "功能",
        "program",
    )
    key_fn_text = _find_section(
        sections,
        "key function",
        "关键函数",
        "function",
    )
    ds_text = _find_section(
        sections,
        "data structure",
        "数据结构",
        "struct",
    )
    libc_text = _find_section(sections, "libc", "版本")
    env_text = _find_section(
        sections,
        "environment",
        "环境",
        "note",
    )

    protections = _extract_list_items(prot_text) if prot_text else []
    if not protections and prot_text:
        protections = [prot_text]

    key_functions = _extract_list_items(key_fn_text) if key_fn_text else []
    data_structures = _extract_list_items(ds_text) if ds_text else []

    return ParsedPhase0Response(
        architecture=arch_text,
        protections=protections,
        program_functionality=func_text,
        key_functions=key_functions,
        data_structures=data_structures,
        libc_version=libc_text,
        environment_notes=env_text,
        raw_sections=sections,
    )


def _extract_offsets(text: str) -> dict[str, str]:
    """从文本中提取偏移量/地址赋值（name = 0x...）。"""
    result: dict[str, str] = {}
    for m in _OFFSET_RE.finditer(text):
        result[m.group(1)] = m.group(2)
    return result


def parse_phase1_response(text: str) -> ParsedPhase1Response:
    """解析P1阶段（漏洞分析）的LLM自由文本响应。"""
    sections = _split_markdown_sections(text)

    vuln_type = _find_section(
        sections,
        "vulnerability type",
        "漏洞类型",
        "type",
    )
    vuln_loc = _find_section(
        sections,
        "location",
        "位置",
        "漏洞位置",
    )
    root_cause = _find_section(
        sections,
        "root cause",
        "根因",
        "根本原因",
        "cause",
    )
    trigger = _find_section(
        sections,
        "trigger",
        "触发条件",
        "触发",
        "condition",
    )

    additional: list[dict[str, str]] = []
    addl_text = _find_section(
        sections,
        "additional",
        "其他漏洞",
        "其它",
    )
    if addl_text:
        for item in _extract_list_items(addl_text):
            additional.append({"description": item})

    return ParsedPhase1Response(
        vulnerability_type=vuln_type,
        vulnerability_location=vuln_loc,
        root_cause=root_cause,
        trigger_conditions=trigger,
        additional_vulns=additional,
        raw_sections=sections,
    )


def parse_phase2_response(text: str) -> ParsedPhase2Response:
    """解析P2阶段（策略制定）的LLM自由文本响应。"""
    sections = _split_markdown_sections(text)

    prim_text = _find_section(
        sections,
        "primitive",
        "利用原语",
        "exploitation primitive",
    )
    bypass_text = _find_section(
        sections,
        "bypass",
        "保护绕过",
        "protection bypass",
    )
    path_text = _find_section(
        sections,
        "exploitation path",
        "利用路径",
        "path",
        "step",
    )
    tech_text = _find_section(
        sections,
        "technique",
        "技术",
        "利用技术",
    )
    just_text = _find_section(
        sections,
        "justification",
        "理由",
        "reason",
        "选择原因",
    )

    primitives = _extract_list_items(prim_text) if prim_text else []
    bypass_pairs = _extract_key_value_pairs(bypass_text) if bypass_text else {}
    path_steps = _extract_list_items(path_text) if path_text else []

    return ParsedPhase2Response(
        exploitation_primitives=primitives,
        protection_bypass=bypass_pairs,
        exploitation_path=path_steps,
        technique=tech_text,
        technique_justification=just_text,
        raw_sections=sections,
    )


def parse_phase3_response(text: str) -> ParsedPhase3Response:
    """解析P3阶段（漏洞利用生成）的LLM自由文本响应。"""
    sections = _split_markdown_sections(text)

    code_text = _find_section(
        sections,
        "exploit",
        "code",
        "漏洞利用",
        "exploit code",
        "利用代码",
    )
    exploit_code = _extract_code_block(code_text) if code_text else ""
    if not exploit_code:
        exploit_code = _extract_code_block(text)

    offset_text = _find_section(
        sections,
        "offset",
        "偏移",
        "key offset",
        "关键偏移",
    )
    key_offsets: dict[str, str] = {}
    if offset_text:
        for m in _OFFSET_RE.finditer(offset_text):
            key_offsets[m.group(1)] = m.group(2)

    addr_text = _find_section(
        sections,
        "address",
        "地址",
        "key address",
        "关键地址",
    )
    key_addresses: dict[str, str] = {}
    if addr_text:
        for m in _OFFSET_RE.finditer(addr_text):
            key_addresses[m.group(1)] = m.group(2)

    payload_text = _find_section(
        sections,
        "payload",
        "载荷",
        "summary",
        "摘要",
    )

    return ParsedPhase3Response(
        exploit_code=exploit_code,
        key_offsets=key_offsets,
        key_addresses=key_addresses,
        payload_summary=payload_text,
        raw_sections=sections,
    )


def parse_phase3_debug_response(
    text: str,
) -> ParsedPhase3DebugResponse:
    """解析P3调试迭代的LLM自由文本响应。"""
    sections = _split_markdown_sections(text)

    error_diag = _find_section(
        sections,
        "error",
        "错误诊断",
        "diagnosis",
        "诊断",
    )
    root_cause = _find_section(
        sections,
        "root cause",
        "根因",
        "根本原因",
        "cause",
    )
    fix_desc = _find_section(
        sections,
        "fix",
        "修复",
        "修复方案",
        "solution",
    )

    code_text = _find_section(
        sections,
        "fixed code",
        "修复代码",
        "code",
        "修正代码",
    )
    fixed_code = _extract_code_block(code_text) if code_text else ""
    if not fixed_code:
        fixed_code = _extract_code_block(text)

    return ParsedPhase3DebugResponse(
        error_diagnosis=error_diag,
        root_cause=root_cause,
        fix_description=fix_desc,
        fixed_code=fixed_code,
        raw_sections=sections,
    )
