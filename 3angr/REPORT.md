# angr ReAct Agent 报告

## 1. 工程结构

- `agent/angr_tools.py`：封装可被 Agent 调用的 angr 原子工具。
- `agent/react_agent.py`：DeepSeek/OpenAI 格式接口的 ReAct 主循环、Action 解析与工具派发。
- `tests/test_agent.py`：核心解析、探索、求解与 3 轮演示轨迹测试。
- `requirements.txt`：Python 依赖。
- `a/a.out`：目标 ELF；`a/c.c` 是对应源码。

安装依赖：

```bash
python -m pip install -r requirements.txt
```

运行 DeepSeek 版本：

```bash
export DEEPSEEK_API_KEY='sk-你的秘钥'
python -m agent.react_agent --binary a/a.out
```

无 API key 时复现本文日志：

```bash
python -m agent.react_agent --binary a/a.out --scripted-demo
```

直接 angr 对照测试：

```bash
python -m agent.react_agent --binary a/a.out --direct-angr
```

## 2. 原子工具封装

工具 1：受控探索

```python
AngrSession.explore(
    find_text: str = "Success!",
    avoid_texts: Iterable[str] = ("trapped", "dead loop"),
    max_steps: int = 50,
) -> ExploreObservation
```

含义：驱动 `SimulationManager` 做有界单步推进。每轮根据 stdout 文本谓词移动状态：

- stdout 含 `find_text` 的状态进入 `found` stash。
- stdout 含任一 `avoid_texts` 的状态进入 `avoid` stash。
- 达到 `max_steps`、无 active state 或找到目标时停止。

合理性：本样例的成功和陷阱都直接体现在输出字符串中，文本谓词比硬编码地址更稳健；同时 `max_steps` 防止死循环或路径爆炸导致 Agent 卡住。

工具 2：输入求解

```python
AngrSession.solve_input() -> SolveObservation
```

含义：在已有 `found` 状态时，从该符号状态求解 `agent_stdin` 的具体字节，并返回 hex、可读文本和成功状态 stdout。

合理性：Agent 不需要直接操作 claripy AST，只需在观察到 `found: True` 后调用该工具得到可提交输入。本目标二进制用 `scanf("%9s")` 读取输入，所以工程将 stdin 建模为 9 个可打印符号字节，并使用 `SimFileStream(has_end=False)` 表示“至少提供前 9 字节”。

工具 3：直接 angr 对照

```python
direct_angr_test(binary_path: str | Path) -> str
```

含义：不经过 LLM，不经过 ReAct 工具循环，也不做额外的输入可打印约束，直接使用最简单 angr 代码：

```python
project = angr.Project(binary_path, auto_load_libs=False)
stdin_symbol = claripy.BVS("stdin", 9 * 8)
state = project.factory.full_init_state(args=[binary_path], stdin=stdin_symbol)
simgr = project.factory.simulation_manager(state)
simgr.explore(
    find=lambda state: b"Success!" in state.posix.dumps(1),
    avoid=lambda state: b"trapped" in state.posix.dumps(1) or b"dead loop" in state.posix.dumps(1),
)
```

用途：作为 Agent 封装版本的对照基线，观察“直接写 angr”能否得到相近效果，以及两者在可控性、日志结构和输入约束上的差异。

## 3. ReAct 主循环设计

主循环使用 DeepSeek 的 OpenAI 兼容接口：

```python
OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
```

系统提示显式描述目标和约束：

- 目标：找到能到达 stdout 包含 `Success!` 的 stdin。
- 约束：倾向有界探索；避免 stdout 提到 `trapped`、`dead loop` 或明显失败路径。
- 协议：模型必须输出 `Thought:` 和 `Action: tool_name(JSON_OBJECT)`。

Action 解析由正则和 JSON 完成，格式可复现：

```text
Action: explore({"find_text":"Success!","avoid_texts":["trapped","dead loop"],"max_steps":40})
```

工具执行后的 Observation 以结构化文本反馈给下一轮 LLM，包括：

- `steps`
- `found`
- `hit_avoid`
- active/found/avoid/deadended/errored 状态数量
- stdout 预览或求解输入

## 4. 运行日志

下面日志来自：

```bash
python -m agent.react_agent --binary a/a.out --scripted-demo
```

该模式使用与 DeepSeek 主循环相同的 Action 解析和工具派发，只是用固定的三轮模型输出复现轨迹，便于在没有 API key 时核对闭环。

### Round 1

```text
Thought: 先做一次很小步数的有界探索，确认程序能继续推进。
Action: explore({"find_text":"Success!","avoid_texts":["trapped","dead loop"],"max_steps":1})

Observation:
  tool: explore
  steps: 1
  found: False
  hit_avoid: False
  active_states: 1
  found_states: 0
  avoided_states: 0
  deadended_states: 0
  errored_states: 0
  notes: 达到 max_steps 后仍未产生 found 状态
```

### Round 2

```text
Thought: 还没有命中成功路径，继续有界探索并避开陷阱输出。
Action: explore({"find_text":"Success!","avoid_texts":["trapped","dead loop"],"max_steps":40})

Observation:
  tool: explore
  steps: 22
  found: True
  hit_avoid: True
  active_states: 2
  found_states: 1
  avoided_states: 1
  deadended_states: 0
  errored_states: 0
  stdout_preview: 'Enter password: Success! Flag is found.\n'
```

### Round 3

```text
Thought: 已经存在 found 状态，从该符号状态求解具体 stdin。
Action: solve_input({})

Observation:
  tool: solve_input
  input_hex: 415a21212121212121
  input_text: 'AZ!!!!!!!'
  stdout: 'Enter password: Success! Flag is found.\n'
```

求解结果说明：`scanf("%9s")` 只要求前两字节满足成功路径约束，因此 `AZ!!!!!!!` 是一组合法具体输入，关键前缀为 `AZ`。

## 5. 直接 angr 对照结果

运行命令：

```bash
python -m agent.react_agent --binary a/a.out --direct-angr
```

输出：

```text
直接 angr 对照结果：
  found_states: 1
  avoided_states: 1
  active_states: 2
  input: b'AZ\x00\x00\x00\x00\x00\x00\x00'
  stdout: 'Enter password: Success! Flag is found.\n'
```

对比结论：

- 直接 angr 代码更短，适合做基线测试。
- Agent 封装版本的 Observation 更结构化，便于 LLM 多轮决策。
- 直接 angr 没有可打印输入约束，因此求出的尾部字节可能是 `\x00`；Agent 封装版本返回 `AZ!!!!!!!`，更适合作为人工可输入样例。

## 6. 验证

本地测试命令：

```bash
python -m pytest tests/test_agent.py
```

当前结果：

```text
4 passed
```
