#!/usr/bin/env python3
"""
OpenRouter 连接测试脚本

用于诊断和测试 OpenRouter API 配置
"""

import os
import sys
import httpx
import json
from pathlib import Path


def check_api_key():
    """检查 API Key 是否设置"""
    api_key = os.environ.get("OPENROUTER_API_KEY", "")

    if not api_key:
        print("❌ 错误: 未设置 OPENROUTER_API_KEY 环境变量")
        print("\n请运行:")
        print("  export OPENROUTER_API_KEY='sk-or-v1-xxxxxxxxxxxxx'")
        return None

    if not api_key.startswith("sk-or-v1-"):
        print("⚠️  警告: API Key 格式可能不正确")
        print(f"   当前格式: {api_key[:15]}...")
        print("   正确格式应以 'sk-or-v1-' 开头")
    else:
        print(f"✅ API Key 格式正确: {api_key[:15]}...")

    return api_key


def test_list_models(api_key):
    """测试获取模型列表"""
    print("\n测试 1: 获取可用模型列表...")

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )

            if response.status_code == 200:
                data = response.json()
                models = data.get("data", [])
                print(f"✅ 成功获取 {len(models)} 个模型")

                # 显示推荐模型（全球可用）
                print("\n推荐的 CTF Pwn 模型（全球可用）:")
                recommended = [
                    "deepseek/deepseek-chat",
                    "qwen/qwen-2.5-72b-instruct",
                    "meta-llama/llama-3.3-70b-instruct",
                    "google/gemini-flash-1.5",
                ]

                available_models = [m["id"] for m in models]
                for model_id in recommended:
                    if model_id in available_models:
                        print(f"  ✅ {model_id}")
                    else:
                        print(f"  ⚠️  {model_id} (不可用)")

                return True
            else:
                print(f"❌ 获取模型列表失败 ({response.status_code})")
                print(f"   响应: {response.text}")
                return False

    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return False


def test_chat_completion(api_key, model_name="deepseek/deepseek-chat"):
    """测试聊天补全"""
    print(f"\n测试 2: 测试 {model_name} 聊天补全...")

    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/poma-framework/poma",
                    "X-Title": "POMA Framework Test",
                },
                json={
                    "model": model_name,
                    "messages": [{"role": "user", "content": "Say 'Hello from POMA!' in one line"}],
                    "max_tokens": 50,
                },
            )

            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})

                print(f"✅ 聊天补全成功!")
                print(f"   响应: {content}")
                print(
                    f"   Token 使用: input={usage.get('prompt_tokens', 0)}, "
                    f"output={usage.get('completion_tokens', 0)}, "
                    f"total={usage.get('total_tokens', 0)}"
                )
                return True
            else:
                print(f"❌ 聊天补全失败 ({response.status_code})")
                error_msg = response.text
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", {}).get("message", response.text)
                    print(f"   错误: {error_msg}")
                except Exception:
                    print(f"   响应: {response.text}")

                # 提供诊断建议
                if response.status_code == 403:
                    print("\n💡 403 错误诊断:")

                    # 检查是否是地区限制
                    if (
                        "not available in your region" in error_msg.lower()
                        or "region" in error_msg.lower()
                    ):
                        print("   ❌ 地区限制：该模型在你的地区不可用")
                        print("\n   推荐解决方案：")
                        print("   1. 使用全球可用的模型（推荐）:")
                        print("      - deepseek/deepseek-chat")
                        print("      - qwen/qwen-2.5-72b-instruct")
                        print("      - meta-llama/llama-3.3-70b-instruct")
                        print("\n   2. 使用示例配置:")
                        print("      poma run --config examples/config_openrouter_china.json ...")
                        print("\n   3. 或使用原生API (deepseek, qwen)")
                    else:
                        print("   1. 检查 API Key 是否有效")
                        print("   2. 访问 https://openrouter.ai/settings/credits 检查余额")
                        print("   3. 确认账户已充值（最低 $5）")
                elif response.status_code == 401:
                    print("\n💡 401 错误诊断:")
                    print("   API Key 无效或已过期")
                    print("   访问 https://openrouter.ai/keys 重新生成")
                elif response.status_code == 400:
                    print("\n💡 400 错误诊断:")
                    print("   请求格式错误或模型名称不正确")
                    print(f"   检查模型名称: {model_name}")

                return False

    except httpx.TimeoutException:
        print(f"❌ 请求超时")
        print("   可能是网络问题或模型响应较慢")
        return False
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        return False


def check_balance(api_key):
    """检查账户余额（如果API支持）"""
    print("\n测试 3: 检查账户信息...")

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                "https://openrouter.ai/api/v1/auth/key",
                headers={"Authorization": f"Bearer {api_key}"},
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                limit = data.get("limit", 0)
                usage = data.get("usage", 0)

                print("✅ 账户信息:")
                print(f"   额度: ${limit}")
                print(f"   已用: ${usage}")
                print(f"   剩余: ${limit - usage}")

                if limit - usage < 1:
                    print("\n⚠️  警告: 余额不足，建议充值")
                    print("   访问: https://openrouter.ai/settings/credits")

                return True
            else:
                print(f"⚠️  无法获取账户信息 ({response.status_code})")
                return False

    except Exception as e:
        print(f"⚠️  无法获取账户信息: {e}")
        return False


def main():
    print("=" * 60)
    print("OpenRouter 连接测试")
    print("=" * 60)

    # 检查 API Key
    api_key = check_api_key()
    if not api_key:
        sys.exit(1)

    # 运行测试
    test1 = test_list_models(api_key)
    test2 = test_chat_completion(api_key)
    test3 = check_balance(api_key)

    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)

    results = [
        ("获取模型列表", test1),
        ("聊天补全", test2),
        ("账户信息", test3),
    ]

    for name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"{name}: {status}")

    if all([test1, test2]):
        print("\n🎉 所有关键测试通过！OpenRouter 配置正确")
        print("\n你现在可以运行 POMA 实验:")
        print("  poma run --config examples/config_openrouter.json --challenges-dir challenges/")
        sys.exit(0)
    else:
        print("\n❌ 部分测试失败，请检查上述错误信息")
        print("\n故障排除:")
        print("  1. 访问 https://openrouter.ai/keys 检查 API Key")
        print("  2. 访问 https://openrouter.ai/settings/credits 检查余额")
        print("  3. 参考文档: docs/OPENROUTER_GUIDE.md")
        sys.exit(1)


if __name__ == "__main__":
    main()
