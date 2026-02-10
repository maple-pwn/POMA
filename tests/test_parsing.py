"""Tests for poma/parsing/ — 正则解析、JSON解析、ResponseParser及数据类集成。"""

import json
import textwrap

from poma.parsing import (
    ResponseParser,
    parse_phase0_json,
    parse_phase0_response,
    parse_phase1_json,
    parse_phase1_response,
    parse_phase2_response,
    parse_phase3_debug_response,
    parse_phase3_response,
)
from poma.schemas.models import (
    ParsedPhase0Response,
    ParsedPhase1Response,
    ParsedPhase2Response,
    ParsedPhase3DebugResponse,
    ParsedPhase3Response,
    ParsedResponse,
    Phase0Score,
    PhaseResult,
    PhaseType,
)

# ── Regex Parser Tests ────────────────────────────────────────────────


class TestRegexParserPhase0:
    """正则解析器：P0阶段（信息收集）响应解析。"""

    def test_parse_phase0_response_basic(self):
        """基本Markdown格式的P0响应 → 正确提取各字段。"""
        text = textwrap.dedent("""\
            ## Architecture
            ELF 64-bit LSB executable, x86-64 (amd64)

            ## Protections
            - NX enabled
            - No PIE
            - Partial RELRO

            ## Program Functionality
            该程序实现了一个简单的echo服务，读取用户输入并回显。

            ## Key Functions
            - main: 程序入口，调用vuln()
            - vuln: 包含gets()的危险函数

            ## Data Structures
            - char buf[64]: 栈上缓冲区

            ## Libc
            libc-2.31

            ## Environment Notes
            Ubuntu 20.04, ASLR enabled
        """)
        result = parse_phase0_response(text)
        assert isinstance(result, ParsedPhase0Response)
        assert "amd64" in result.architecture or "x86-64" in result.architecture
        assert len(result.protections) >= 2
        assert "echo" in result.program_functionality or "回显" in result.program_functionality
        assert len(result.key_functions) >= 2
        assert len(result.data_structures) >= 1
        assert "2.31" in result.libc_version or "libc" in result.libc_version
        assert result.raw_sections

    def test_parse_phase0_bold_format(self):
        text = textwrap.dedent("""\
            **Architecture**:
            i386, 32-bit ELF

            **Protections**:
            - NX enabled
            - no canary
        """)
        result = parse_phase0_response(text)
        assert "i386" in result.architecture or "32-bit" in result.architecture
        assert len(result.protections) >= 1


class TestRegexParserPhase1:
    """正则解析器：P1阶段（漏洞分析）响应解析。"""

    def test_parse_phase1_response_basic(self):
        """基本Markdown格式的P1响应 → 正确提取漏洞信息。"""
        text = textwrap.dedent("""\
            ## Vulnerability Type
            Stack Buffer Overflow (CWE-121)

            ## Location
            函数 vuln() 中第15行的 gets(buf) 调用

            ## Root Cause
            gets()函数不检查输入长度，buf仅有64字节，
            攻击者可输入超过64字节覆盖返回地址。

            ## Trigger Conditions
            输入超过72字节（64字节buffer + 8字节saved rbp）即可控制RIP
        """)
        result = parse_phase1_response(text)
        assert isinstance(result, ParsedPhase1Response)
        assert (
            "overflow" in result.vulnerability_type.lower() or "溢出" in result.vulnerability_type
        )
        assert "vuln" in result.vulnerability_location
        assert "gets" in result.root_cause
        assert "72" in result.trigger_conditions or "64" in result.trigger_conditions


class TestRegexParserPhase2:
    """正则解析器：P2阶段（策略制定）响应解析。"""

    def test_parse_phase2_response_basic(self):
        """基本Markdown格式的P2响应 → 正确提取利用策略。"""
        text = textwrap.dedent("""\
            ## Exploitation Primitives
            - 栈缓冲区溢出可覆盖返回地址
            - 可控制RIP跳转到任意地址

            ## Protection Bypass
            NX: 使用ret2text绕过，无需执行shellcode
            ASLR: 程序无PIE，地址固定

            ## Exploitation Path
            1. 构造padding填充buffer和saved rbp
            2. 覆盖返回地址为win函数地址
            3. 触发函数返回，跳转到win()

            ## Technique
            ret2text — 返回到程序已有的后门函数

            ## Justification
            程序存在win()后门函数且无PIE，直接覆盖返回地址即可
        """)
        result = parse_phase2_response(text)
        assert isinstance(result, ParsedPhase2Response)
        assert len(result.exploitation_primitives) >= 2
        assert len(result.exploitation_path) >= 2
        assert "ret2text" in result.technique.lower() or "返回" in result.technique


class TestRegexParserPhase3:
    """正则解析器：P3阶段（Exploit生成）响应解析。"""

    def test_parse_phase3_response_basic(self):
        """包含代码块和偏移量的P3响应 → 正确提取exploit代码。"""
        text = textwrap.dedent("""\
            ## Exploit Code
            ```python
            from pwn import *
            p = process('./vuln')
            payload = b'A' * 72 + p64(0x401196)
            p.sendline(payload)
            p.interactive()
            ```

            ## Key Offsets
            buffer_to_ret = 72
            buf_size = 64

            ## Key Addresses
            win = 0x401196

            ## Payload Summary
            72字节padding + win函数地址(little-endian)
        """)
        result = parse_phase3_response(text)
        assert isinstance(result, ParsedPhase3Response)
        assert "from pwn import" in result.exploit_code
        assert "72" in result.key_offsets.get("buffer_to_ret", "")
        assert "0x401196" in result.key_addresses.get("win", "")
        assert result.payload_summary

    def test_parse_phase3_debug_response_basic(self):
        """P3调试迭代响应 → 正确提取错误诊断和修复代码。"""
        text = textwrap.dedent("""\
            ## Error Diagnosis
            exploit执行时出现EOFError，程序在接收payload前就关闭了连接。

            ## Root Cause
            程序先输出提示信息，需要先recv()再发送payload。

            ## Fix Description
            在sendline之前添加recvuntil(b'> ')等待提示符。

            ## Fixed Code
            ```python
            from pwn import *
            p = process('./vuln')
            p.recvuntil(b'> ')
            payload = b'A' * 72 + p64(0x401196)
            p.sendline(payload)
            p.interactive()
            ```
        """)
        result = parse_phase3_debug_response(text)
        assert isinstance(result, ParsedPhase3DebugResponse)
        assert "EOFError" in result.error_diagnosis or "关闭" in result.error_diagnosis
        assert result.root_cause
        assert "recvuntil" in result.fix_description or "recv" in result.fix_description
        assert "recvuntil" in result.fixed_code


class TestRegexParserEdgeCases:
    """正则解析器：边界情况处理。"""

    def test_regex_parser_empty_input(self):
        """空字符串 → 返回默认值的数据类，不抛异常。"""
        r0 = parse_phase0_response("")
        assert isinstance(r0, ParsedPhase0Response)
        assert r0.architecture == ""
        assert r0.protections == []

        r1 = parse_phase1_response("")
        assert isinstance(r1, ParsedPhase1Response)
        assert r1.vulnerability_type == ""

    def test_regex_parser_garbage_input(self):
        """随机无关文本 → 返回默认值的数据类，不抛异常。"""
        garbage = "Lorem ipsum dolor sit amet, 这是一段无关的中文文本 12345 !@#$%"
        r0 = parse_phase0_response(garbage)
        assert isinstance(r0, ParsedPhase0Response)

        r2 = parse_phase2_response(garbage)
        assert isinstance(r2, ParsedPhase2Response)
        assert r2.exploitation_primitives == []
        assert r2.technique == ""


# ── JSON Parser Tests ─────────────────────────────────────────────────


class TestJsonParserPhase0:
    """JSON解析器：P0阶段响应解析。"""

    def test_parse_phase0_json_valid(self):
        text = json.dumps(
            {
                "architecture": "amd64",
                "protections": ["NX", "Partial RELRO"],
                "program_functionality": "Echo server",
                "key_functions": ["main", "vuln"],
                "data_structures": ["char buf[64]"],
                "libc_version": "2.31",
                "environment_notes": "Ubuntu 20.04",
            }
        )
        result = parse_phase0_json(text)
        assert isinstance(result, ParsedPhase0Response)
        assert result.architecture == "amd64"
        assert result.protections == ["NX", "Partial RELRO"]
        assert result.key_functions == ["main", "vuln"]
        assert result.libc_version == "2.31"

    def test_parse_phase0_json_with_markdown_wrapper(self):
        inner = json.dumps(
            {
                "architecture": "i386",
                "protections": ["NX"],
                "program_functionality": "Calculator",
            }
        )
        text = f"```json\n{inner}\n```"
        result = parse_phase0_json(text)
        assert isinstance(result, ParsedPhase0Response)
        assert result.architecture == "i386"
        assert result.protections == ["NX"]


class TestJsonParserPhase1:
    def test_parse_phase1_json_valid(self):
        text = json.dumps(
            {
                "vulnerability_type": "stack_buffer_overflow",
                "vulnerability_location": "vuln() line 15",
                "root_cause": "gets() no bounds check",
                "trigger_conditions": "input > 72 bytes",
                "additional_vulns": [{"description": "info leak via printf"}],
            }
        )
        result = parse_phase1_json(text)
        assert isinstance(result, ParsedPhase1Response)
        assert result.vulnerability_type == "stack_buffer_overflow"
        assert result.root_cause == "gets() no bounds check"
        assert len(result.additional_vulns) == 1


class TestJsonParserFallback:
    def test_parse_json_invalid_falls_back_to_regex(self):
        markdown_text = textwrap.dedent("""\
            ## Architecture
            amd64 ELF binary

            ## Protections
            - NX enabled
        """)
        result = parse_phase0_json(markdown_text)
        assert isinstance(result, ParsedPhase0Response)
        assert "amd64" in result.architecture or "ELF" in result.architecture

    def test_parse_json_malformed_trailing_comma(self):
        text = '{"architecture": "amd64", "protections": ["NX",],}'
        result = parse_phase0_json(text)
        assert isinstance(result, ParsedPhase0Response)
        assert result.architecture == "amd64"


# ── ResponseParser Tests ──────────────────────────────────────────────


class TestResponseParserRegexMode:
    def test_response_parser_regex_mode(self):
        parser = ResponseParser(structured_output=False)
        text = textwrap.dedent("""\
            ## Architecture
            amd64

            ## Protections
            - NX enabled
        """)
        result = parser.parse("phase_0", text)
        assert isinstance(result, ParsedResponse)
        assert result.parse_mode == "regex"
        assert result.parse_success is True
        assert isinstance(result.parsed, ParsedPhase0Response)


class TestResponseParserJsonMode:
    def test_response_parser_json_mode(self):
        parser = ResponseParser(structured_output=True)
        text = json.dumps(
            {
                "architecture": "amd64",
                "protections": ["NX"],
                "program_functionality": "echo server",
            }
        )
        result = parser.parse("phase_0", text)
        assert isinstance(result, ParsedResponse)
        assert result.parse_mode == "json"
        assert result.parse_success is True
        assert isinstance(result.parsed, ParsedPhase0Response)
        assert result.parsed.architecture == "amd64"


class TestResponseParserUnknownPhase:
    def test_response_parser_unknown_phase(self):
        parser = ResponseParser(structured_output=False)
        result = parser.parse("unknown_phase", "some text")
        assert isinstance(result, ParsedResponse)
        assert result.parse_success is False
        assert len(result.parse_errors) >= 1

    def test_response_parser_json_unknown_phase(self):
        parser = ResponseParser(structured_output=True)
        result = parser.parse("nonexistent", '{"key": "val"}')
        assert result.parse_success is False


# ── Dataclass Integration Tests ───────────────────────────────────────


class TestParsedResponseToDict:
    def test_parsed_response_to_dict(self):
        parsed_p0 = ParsedPhase0Response(
            architecture="amd64",
            protections=["NX"],
            program_functionality="echo",
        )
        resp = ParsedResponse(
            phase="phase_0",
            parsed=parsed_p0,
            parse_mode="json",
            parse_success=True,
        )
        d = resp.to_dict()
        assert d["phase"] == "phase_0"
        assert d["parse_mode"] == "json"
        assert d["parse_success"] is True
        assert d["parsed"]["architecture"] == "amd64"
        assert d["parsed"]["protections"] == ["NX"]


class TestPhaseResultWithParsedResponse:
    def test_phase_result_with_parsed_response(self):
        parsed_p1 = ParsedPhase1Response(
            vulnerability_type="stack_buffer_overflow",
            vulnerability_location="vuln()",
            root_cause="gets() no bounds check",
        )
        parsed_resp = ParsedResponse(
            phase="phase_1",
            parsed=parsed_p1,
            parse_mode="regex",
            parse_success=True,
        )
        phase_result = PhaseResult(
            phase=PhaseType.PHASE_1,
            prompt="Analyze the binary",
            response="Found stack overflow",
            score=Phase0Score(),
            parsed_response=parsed_resp,
        )
        d = phase_result.to_dict()
        assert "parsed_response" in d
        assert d["parsed_response"]["phase"] == "phase_1"
        assert d["parsed_response"]["parse_mode"] == "regex"
        assert d["parsed_response"]["parsed"]["vulnerability_type"] == "stack_buffer_overflow"

    def test_phase_result_without_parsed_response(self):
        phase_result = PhaseResult(
            phase=PhaseType.PHASE_0,
            prompt="p0",
            response="resp",
            score=Phase0Score(),
        )
        d = phase_result.to_dict()
        assert "parsed_response" not in d
