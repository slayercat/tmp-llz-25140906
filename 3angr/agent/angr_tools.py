from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import angr
import claripy


@dataclass
class ExploreObservation:
    tool: str
    steps: int
    found: bool
    hit_avoid: bool
    active: int
    found_count: int
    avoided_count: int
    deadended: int
    errored: int
    stdout_preview: str = ""
    notes: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            "Observation:",
            f"  tool: {self.tool}",
            f"  steps: {self.steps}",
            f"  found: {self.found}",
            f"  hit_avoid: {self.hit_avoid}",
            f"  active_states: {self.active}",
            f"  found_states: {self.found_count}",
            f"  avoided_states: {self.avoided_count}",
            f"  deadended_states: {self.deadended}",
            f"  errored_states: {self.errored}",
        ]
        if self.stdout_preview:
            lines.append(f"  stdout_preview: {self.stdout_preview!r}")
        if self.notes:
            lines.append(f"  notes: {'; '.join(self.notes)}")
        return "\n".join(lines)


@dataclass
class SolveObservation:
    tool: str
    input_hex: str
    input_text: str
    stdout: str

    def to_text(self) -> str:
        return "\n".join(
            [
                "Observation:",
                f"  tool: {self.tool}",
                f"  input_hex: {self.input_hex}",
                f"  input_text: {self.input_text!r}",
                f"  stdout: {self.stdout!r}",
            ]
        )


class AngrSession:
    """面向 ReAct 主循环的有状态 angr 原子工具封装。"""

    def __init__(self, binary_path: str | Path, stdin_size: int = 9):
        self.binary_path = Path(binary_path)
        self.stdin_size = stdin_size
        self.project = angr.Project(str(self.binary_path), auto_load_libs=False)
        self.stdin_symbol = claripy.BVS("agent_stdin", stdin_size * 8)
        symbolic_stdin = angr.SimFileStream(
            name="stdin",
            content=self.stdin_symbol,
            has_end=False,
        )
        self.state = self.project.factory.full_init_state(
            args=[str(self.binary_path)],
            stdin=symbolic_stdin,
        )
        for byte in self.stdin_symbol.chop(bits=8):
            self.state.solver.add(byte >= 0x20)
            self.state.solver.add(byte <= 0x7E)
            self.state.solver.add(byte != ord("\n"))
            self.state.solver.add(byte != ord("\x00"))
        self.simgr = self.project.factory.simulation_manager(self.state)
        self.simgr.stashes.setdefault("found", [])
        self.simgr.stashes.setdefault("avoid", [])

    def explore(
        self,
        find_text: str = "Success!",
        avoid_texts: Iterable[str] = ("trapped", "dead loop"),
        max_steps: int = 50,
    ) -> ExploreObservation:
        """基于 stdout 文本谓词执行有界单步/探索。"""
        find_bytes = find_text.encode()
        avoid_bytes = [item.encode() for item in avoid_texts]
        steps = 0
        notes: list[str] = []

        def stdout(state: angr.SimState) -> bytes:
            return state.posix.dumps(1)

        while steps < max_steps and self.simgr.active and not self.simgr.found:
            self.simgr.move(
                from_stash="active",
                to_stash="found",
                filter_func=lambda state: find_bytes in stdout(state),
            )
            self.simgr.move(
                from_stash="active",
                to_stash="avoid",
                filter_func=lambda state: any(text in stdout(state) for text in avoid_bytes),
            )
            if self.simgr.found:
                break
            self.simgr.step()
            steps += 1

        if steps >= max_steps and not self.simgr.found:
            notes.append("达到 max_steps 后仍未产生 found 状态")
        if not self.simgr.active and not self.simgr.found:
            notes.append("没有剩余 active 状态")

        preview = ""
        if self.simgr.found:
            preview = _decode_lossy(self.simgr.found[0].posix.dumps(1))
        elif self.simgr.active:
            preview = _decode_lossy(self.simgr.active[0].posix.dumps(1))

        return ExploreObservation(
            tool="explore",
            steps=steps,
            found=bool(self.simgr.found),
            hit_avoid=bool(self.simgr.avoid),
            active=len(self.simgr.active),
            found_count=len(self.simgr.found),
            avoided_count=len(self.simgr.avoid),
            deadended=len(self.simgr.deadended),
            errored=len(self.simgr.errored),
            stdout_preview=preview,
            notes=notes,
        )

    def solve_input(self) -> SolveObservation:
        """从第一个 found 状态求解具体 stdin 字节。"""
        if not self.simgr.found:
            raise RuntimeError("solve_input 至少需要一个 found 状态")

        found_state = self.simgr.found[0]
        concrete = bytes(found_state.solver.min(byte) for byte in self.stdin_symbol.chop(bits=8))
        input_text = concrete.decode("utf-8", errors="replace")
        return SolveObservation(
            tool="solve_input",
            input_hex=concrete.hex(),
            input_text=input_text,
            stdout=_decode_lossy(found_state.posix.dumps(1)),
        )


def _decode_lossy(data: bytes, limit: int = 240) -> str:
    text = data[:limit].decode("utf-8", errors="replace")
    if len(data) > limit:
        return text + "...<truncated>"
    return text


def direct_angr_test(
    binary_path: str | Path,
    find_text: str = "Success!",
    avoid_texts: Iterable[str] = ("trapped", "dead loop"),
    stdin_size: int = 9,
) -> str:
    """最小化直接 angr 对照：不经过 Agent，只调用 simgr.explore。"""
    project = angr.Project(str(Path(binary_path)), auto_load_libs=False)
    stdin_symbol = claripy.BVS("stdin", stdin_size * 8)
    state = project.factory.full_init_state(args=[str(binary_path)], stdin=stdin_symbol)
    simgr = project.factory.simulation_manager(state)

    simgr.explore(
        find=lambda state: find_text.encode() in state.posix.dumps(1),
        avoid=lambda state: any(text.encode() in state.posix.dumps(1) for text in avoid_texts),
    )

    lines = [
        "直接 angr 对照结果：",
        f"  found_states: {len(simgr.found)}",
        f"  avoided_states: {len(simgr.avoid)}",
        f"  active_states: {len(simgr.active)}",
    ]
    if simgr.found:
        found_state = simgr.found[0]
        concrete = found_state.solver.eval(stdin_symbol, cast_to=bytes)
        lines.append(f"  input: {concrete!r}")
        lines.append(f"  stdout: {_decode_lossy(found_state.posix.dumps(1))!r}")
    return "\n".join(lines)
