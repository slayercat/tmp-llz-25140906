import json
import os
import sys
import time
from datetime import datetime
from openai import OpenAI

from tools.r2_tool import R2Tool
from tools.ghidra_tool import GhidraTool

BINARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets", "challenge")
R2_PATH = "/opt/radare2-6.1.6/bin/r2"
GHIDRA_HOME = "/opt/ghidra_12.1.2_PUBLIC"
GHIDRA_PROJECT = "/tmp/ghidra_react_project"
MODEL_NAME = "deepseek-chat"
MAX_ITERATIONS = 15

SYSTEM_PROMPT = """You are a cybersecurity static analysis expert analyzing a stripped Linux x86_64 ELF binary for security vulnerabilities. Use only the provided tools to perform static analysis. Do NOT speculate — base all findings on tool output.

## Available Tools

1. **r2_cmd(command)** — Execute radare2 commands on the binary. Useful commands:
   - `iI` — binary info (arch, bits, canary, NX, PIE, stripped)
   - `ii` — imported functions
   - `izz` — all strings
   - `afl` — function list with addresses
   - `pdf @ 0xADDR` — disassemble function at address
   - `p8 64 @ 0xADDR` — hexdump 64 bytes at address
   - `iS` — section list

2. **ghidra_decompile(address)** — Decompile function at hex address (e.g., "0x401264") using Ghidra. Returns C-like pseudocode.

3. **ghidra_list_funcs()** — List all functions Ghidra identified with names and addresses.

## Analysis Workflow

1. Start with `r2_cmd("iI")` to get binary metadata
2. Check imports with `r2_cmd("ii")` — look for dangerous functions (strcpy, gets, sprintf, memcpy, strcat, system, exec)
3. Check strings with `r2_cmd("izz~ascii")` for hints
4. Get function list with `r2_cmd("afl")`
5. Call `ghidra_list_funcs()` to cross-check function discovery
6. Disassemble interesting functions with `r2_cmd("pdf @ 0xADDR")`
7. For deep analysis, decompile with `ghidra_decompile("0xADDR")`
7. Cross-reference: trace user input sources to dangerous sinks

## Vulnerability Checklist (check each)

- Stack buffer overflow: fgets/read → strcpy/strcat/memcpy on stack buffer without proper bounds
- Heap overflow: malloc(N) then write > N bytes
- Format string: printf(user_input) without format specifier
- Integer overflow: arithmetic before size check
- Use-after-free: free then use

## Final Answer

When confident, output ONLY a JSON object (no other text):
{"vuln_type": "...", "location": "...", "cause": "..."}

vuln_type examples: stack_buffer_overflow, heap_overflow, format_string, integer_overflow, use_after_free, null_pointer_dereference
location: function name or address plus brief description (e.g., "main @ 0x401377")
cause: one sentence explaining how untrusted input reaches the dangerous operation
"""


class ReActAgent:
    def __init__(self):
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise RuntimeError("DEEPSEEK_API_KEY environment variable not set")

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        self.r2 = R2Tool(BINARY_PATH, R2_PATH)
        self.ghidra = GhidraTool(BINARY_PATH, GHIDRA_HOME, GHIDRA_PROJECT)
        self.log_entries = []

    def _log(self, entry_type, content):
        entry = {
            "type": entry_type,
            "content": str(content)[:8000],
            "timestamp": datetime.now().isoformat()
        }
        self.log_entries.append(entry)

    def _build_tools_schema(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": "r2_cmd",
                    "description": "Execute a radare2 command on the target binary and return output. Use for: binary info (iI), imports (ii), strings (izz), function list (afl), disassembly (pdf @ 0xADDR), hexdump (px), sections (iS).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The r2 command to execute, e.g. 'iI', 'afl', 'pdf @ 0x401264'"
                            }
                        },
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ghidra_decompile",
                    "description": "Decompile the function containing a given hex address using Ghidra's decompiler. Returns C-like pseudocode. Example: ghidra_decompile('0x401264')",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "address": {
                                "type": "string",
                                "description": "Hex address of the function, e.g. '0x401264'"
                            }
                        },
                        "required": ["address"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ghidra_list_funcs",
                    "description": "List all functions identified by Ghidra with their addresses and names. Use for program structure overview.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            }
        ]

    def _execute_tool(self, func_name, func_args):
        start = time.time()
        if func_name == "r2_cmd":
            result = self.r2.execute(func_args["command"])
        elif func_name == "ghidra_decompile":
            result = self.ghidra.decompile(func_args["address"])
        elif func_name == "ghidra_list_funcs":
            result = self.ghidra.list_functions()
        else:
            result = f"Unknown tool: {func_name}"
        elapsed = time.time() - start
        return result, elapsed

    def _extract_json(self, text):
        json_start = text.find('{')
        json_end = text.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            try:
                return json.loads(text[json_start:json_end])
            except json.JSONDecodeError:
                pass
        return None

    def _finalize_from_observations(self, messages):
        self._log("finalization_request", "Requesting final JSON based only on accumulated tool observations")
        final_messages = messages + [{
            "role": "user",
            "content": (
                "Stop calling tools. Based only on the observations already returned by r2 and Ghidra, "
                "produce the final vulnerability result as ONLY a JSON object with exactly these fields: "
                "vuln_type, location, cause. Do not include markdown or explanatory text."
            )
        }]
        response = self.client.chat.completions.create(
            model=MODEL_NAME,
            messages=final_messages,
            tool_choice="none",
            temperature=0.0,
        )
        content = response.choices[0].message.content or ""
        self._log("final_answer", content)
        vuln_data = self._extract_json(content)
        if vuln_data and all(k in vuln_data for k in ("vuln_type", "location", "cause")):
            return vuln_data
        return {
            "vuln_type": "analysis_incomplete",
            "location": "unknown",
            "cause": "Agent finalization did not produce the required JSON structure"
        }

    def run(self):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                "Analyze the binary at targets/challenge for security vulnerabilities. "
                "Follow the analysis workflow: start with basic binary info, check imports, "
                "inspect strings, examine suspicious functions with disassembly and decompilation. "
                "Report your final finding as a JSON object with vuln_type, location, and cause."
            )}
        ]
        tools_schema = self._build_tools_schema()

        for iteration in range(1, MAX_ITERATIONS + 1):
            self._log("iteration", f"--- Iteration {iteration}/{MAX_ITERATIONS} ---")

            response = self.client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                tools=tools_schema,
                tool_choice="auto",
                temperature=0.1,
            )

            msg = response.choices[0].message

            if msg.content:
                self._log("thought", msg.content)

            if msg.tool_calls:
                messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [{
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments
                        }
                    } for tool_call in msg.tool_calls]
                })
                for tool_call in msg.tool_calls:
                    func_name = tool_call.function.name
                    func_args = json.loads(tool_call.function.arguments)
                    self._log("action", f"{func_name}({json.dumps(func_args, ensure_ascii=False)})")

                    result, elapsed = self._execute_tool(func_name, func_args)
                    truncated = result[:4000] + ("\n... [truncated]" if len(result) > 4000 else "")
                    self._log("observation", f"[{elapsed:.1f}s]\n{truncated}")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": truncated
                    })
            else:
                content = msg.content or ""
                vuln_data = self._extract_json(content)
                if vuln_data and all(k in vuln_data for k in ("vuln_type", "location", "cause")):
                    self._log("final_answer", json.dumps(vuln_data, indent=2, ensure_ascii=False))
                    return vuln_data

                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": (
                        "Provide your final vulnerability analysis as a JSON object with fields: "
                        'vuln_type, location, cause. Example: {"vuln_type": "stack_buffer_overflow", '
                        '"location": "main @ 0x401377", "cause": "fgets reads user input, strcpy_chk '
                        'copies to stack with insufficient bounds check"}\n\n'
                        "If you need more information, call a tool. Otherwise output ONLY the JSON."
                    )
                })

        return self._finalize_from_observations(messages)

    def save_logs(self, filepath):
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"ReAct Agent Static Analysis Log\n")
            f.write(f"Model: {MODEL_NAME}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {BINARY_PATH}\n")
            f.write(f"Tools: radare2 ({R2_PATH}), Ghidra ({GHIDRA_HOME})\n")
            f.write("=" * 80 + "\n\n")

            for entry in self.log_entries:
                f.write(f"[{entry['type'].upper()}] {entry['timestamp']}\n")
                f.write(f"{entry['content']}\n")
                f.write("-" * 80 + "\n\n")

    def save_vuln(self, filepath, vuln_data):
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(vuln_data, f, indent=2, ensure_ascii=False)
            f.write("\n")


def main():
    agent = ReActAgent()
    print(f"Starting ReAct agent (model={MODEL_NAME}, max_iterations={MAX_ITERATIONS})")
    print(f"Target: {BINARY_PATH}")
    print()

    vuln_data = agent.run()

    agent.save_vuln("output/vuln.json", vuln_data)
    agent.save_logs("logs/run.txt")

    print(f"\nAnalysis complete.")
    print(f"Vulnerability result saved to output/vuln.json")
    print(f"Full log saved to logs/run.txt")
    print(f"\nResult: {json.dumps(vuln_data, indent=2, ensure_ascii=False)}")


if __name__ == "__main__":
    main()
