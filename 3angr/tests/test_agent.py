from pathlib import Path

from agent.react_agent import parse_action, run_scripted_demo
from agent.angr_tools import AngrSession, direct_angr_test


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "a" / "a.out"


def test_parse_action_extracts_json_payload():
    text = """
Thought: 尝试一次有界搜索。
Action: explore({"find_text": "Success!", "avoid_texts": ["trapped"], "max_steps": 12})
"""

    action = parse_action(text)

    assert action.name == "explore"
    assert action.arguments["find_text"] == "Success!"
    assert action.arguments["avoid_texts"] == ["trapped"]
    assert action.arguments["max_steps"] == 12


def test_explore_finds_success_path_and_solver_returns_input():
    session = AngrSession(BINARY, stdin_size=9)

    observation = session.explore(
        find_text="Success!",
        avoid_texts=["trapped", "dead loop"],
        max_steps=80,
    )
    solution = session.solve_input()

    assert observation.found is True
    assert solution.input_text.startswith("AZ")
    assert "Success!" in solution.stdout


def test_scripted_demo_contains_three_action_observation_pairs():
    trace = run_scripted_demo(BINARY)

    assert len([item for item in trace if item.startswith("Thought:")]) == 3
    assert len([item for item in trace if item.startswith("Observation:")]) == 3
    assert "Success!" in trace[-1]


def test_direct_angr_test_returns_basic_statistics():
    output = direct_angr_test(BINARY)

    assert "直接 angr 对照结果" in output
    assert "found_states:" in output
    assert "avoided_states:" in output
