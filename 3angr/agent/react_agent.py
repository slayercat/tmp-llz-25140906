from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openai import OpenAI

from agent.angr_tools import AngrSession, direct_angr_test


SYSTEM_PROMPT = """你是一个控制 angr 工具的逆向分析 Agent。
目标：找到一组输入，使程序输出包含 "Success!"。
约束：优先使用有界探索；尽量避开输出中包含 trapped、dead loop 或明显失败信息的状态。

协议：
必须严格按下面格式回复：
Thought: 一句简短中文理由
Action: tool_name(JSON_OBJECT)

可用工具：
1. explore({"find_text": string, "avoid_texts": [string], "max_steps": integer})
   有界推进 SimulationManager。stdout 包含 find_text 的状态进入 found；匹配 avoid_texts 的状态进入 avoid。
2. solve_input({})
   从第一个 found 状态求解具体 stdin 字节。只能在 explore 返回 found: True 后调用。
3. finish({"answer": string})
   已经求出具体输入后停止。
"""


@dataclass
class Action:
    name: str
    arguments: dict[str, Any]


def parse_action(text: str) -> Action:
    match = re.search(r"Action:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((\{.*\})\)\s*$", text, re.S)
    if not match:
        raise ValueError(f"无法从模型输出中解析 Action：\n{text}")
    return Action(match.group(1), json.loads(match.group(2)))


class DeepSeekReActAgent:
    def __init__(
        self,
        binary_path: str | Path,
        api_key: str,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com",
        max_rounds: int = 6,
    ):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.max_rounds = max_rounds
        self.session = AngrSession(binary_path)
        self.messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

    def run(self) -> list[str]:
        trace: list[str] = []
        self.messages.append(
            {
                "role": "user",
                "content": (
                    "从二进制入口开始分析。请寻找能到达 Success! 输出的 stdin，"
                    "同时避开 trapped/dead-loop 路径。调用 solve_input 前至少先调用一次 explore。"
                ),
            }
        )

        for _ in range(self.max_rounds):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                temperature=0,
            )
            content = response.choices[0].message.content or ""
            trace.append(content)
            self.messages.append({"role": "assistant", "content": content})

            action = parse_action(content)
            observation = self.dispatch(action)
            trace.append(observation)
            if action.name == "finish":
                break
            self.messages.append({"role": "user", "content": observation})

        return trace

    def dispatch(self, action: Action) -> str:
        if action.name == "explore":
            return self.session.explore(**action.arguments).to_text()
        if action.name == "solve_input":
            return self.session.solve_input().to_text()
        if action.name == "finish":
            return "Observation:\n  tool: finish\n  stopped: True"
        raise ValueError(f"未知工具：{action.name}")


def run_scripted_demo(binary_path: str | Path) -> list[str]:
    session = AngrSession(binary_path)
    outputs = [
        'Thought: 先做一次很小步数的有界探索，确认程序能继续推进。\n'
        'Action: explore({"find_text":"Success!","avoid_texts":["trapped","dead loop"],"max_steps":1})',
        'Thought: 还没有命中成功路径，继续有界探索并避开陷阱输出。\n'
        'Action: explore({"find_text":"Success!","avoid_texts":["trapped","dead loop"],"max_steps":40})',
        "Thought: 已经存在 found 状态，从该符号状态求解具体 stdin。\n"
        "Action: solve_input({})",
    ]
    trace: list[str] = []
    for output in outputs:
        trace.append(output)
        action = parse_action(output)
        if action.name == "explore":
            trace.append(session.explore(**action.arguments).to_text())
        elif action.name == "solve_input":
            trace.append(session.solve_input().to_text())
        else:
            raise ValueError(f"脚本演示中出现了非预期动作：{action.name}")
    return trace


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="驱动 angr 工具的 DeepSeek ReAct 主循环。")
    parser.add_argument("--binary", default="a/a.out", help="目标 ELF 二进制路径。")
    parser.add_argument("--model", default="deepseek-chat", help="DeepSeek 模型名称。")
    parser.add_argument("--base-url", default="https://api.deepseek.com", help="OpenAI 兼容接口地址。")
    parser.add_argument("--api-key", default=os.getenv("DEEPSEEK_API_KEY"), help="DeepSeek API 密钥。")
    parser.add_argument("--max-rounds", type=int, default=6, help="最大 ReAct 轮数。")
    parser.add_argument("--scripted-demo", action="store_true", help="无 API 访问时复现确定性的三轮轨迹。")
    parser.add_argument("--direct-angr", action="store_true", help="直接调用 angr 的 simgr.explore 做对照测试。")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.scripted_demo:
        for item in run_scripted_demo(args.binary):
            print(item)
            print()
        return 0

    if args.direct_angr:
        print(direct_angr_test(args.binary))
        return 0

    if not args.api_key:
        raise SystemExit("缺少 DeepSeek 密钥。请传入 --api-key 或设置 DEEPSEEK_API_KEY。")

    agent = DeepSeekReActAgent(
        binary_path=args.binary,
        api_key=args.api_key,
        model=args.model,
        base_url=args.base_url,
        max_rounds=args.max_rounds,
    )
    for item in agent.run():
        print(item)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
