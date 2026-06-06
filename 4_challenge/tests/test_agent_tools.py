import json
from pathlib import Path

import pytest

from agent import ReActAgent
from tools.ghidra_tool import GhidraTool
from tools.r2_tool import R2Tool


def test_r2_tool_blocks_write_style_commands_without_invoking_r2(monkeypatch, tmp_path):
    binary = tmp_path / "challenge"
    binary.write_bytes(b"\x7fELF")

    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args)

        class Result:
            stdout = "radare2 6.1.6"
            stderr = ""
            returncode = 0

        return Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    tool = R2Tool(str(binary), "r2")

    blocked = tool.execute("s 0x401000; wx 9090")

    assert "[BLOCKED]" in blocked
    assert len(calls) == 1


def test_ghidra_tool_uses_per_instance_query_and_output_files(monkeypatch, tmp_path):
    binary = tmp_path / "challenge"
    binary.write_bytes(b"\x7fELF")
    ghidra_home = tmp_path / "ghidra"
    support = ghidra_home / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(GhidraTool, "_ensure_project", lambda self: None)

    first = GhidraTool(str(binary), str(ghidra_home), str(tmp_path / "project1"))
    second = GhidraTool(str(binary), str(ghidra_home), str(tmp_path / "project2"))

    assert first.query_file != second.query_file
    assert first.output_file != second.output_file
    assert str(first.query_file).startswith(str(tmp_path / "project1"))
    assert str(second.query_file).startswith(str(tmp_path / "project2"))


def test_save_vuln_preserves_agent_final_answer(tmp_path):
    data = {
        "vuln_type": "stack_buffer_overflow",
        "location": "main @ 0x401234",
        "cause": "stdin reaches strcpy into a fixed stack buffer",
    }
    path = tmp_path / "output" / "vuln.json"
    agent = object.__new__(ReActAgent)

    ReActAgent.save_vuln(agent, str(path), data)

    assert json.loads(path.read_text(encoding="utf-8")) == data
