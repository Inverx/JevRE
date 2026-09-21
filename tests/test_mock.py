from __future__ import annotations

import json
from pathlib import Path

import pytest

from jevre.mock import MockDecisionEngine
from jevre.models import ReverseState


EXAMPLES = Path(__file__).parents[1] / "examples"


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("packed.json", "unpack"),
        ("signed_traffic.json", "locate_signature"),
        ("hidden_traffic.json", "inspect_network_stack"),
    ],
)
def test_required_examples_are_deterministic(fixture: str, expected: str) -> None:
    state = ReverseState.from_dict(json.loads((EXAMPLES / fixture).read_text("utf-8")))
    engine = MockDecisionEngine()

    first = engine.decide_next_action(state)
    second = engine.decide_next_action(state)

    assert first.action == expected
    assert first == second
    assert sum(first.probabilities.values()) == pytest.approx(1.0)
    assert first.engine == "MOCK"
    assert first.confidence is None


def test_mock_priority_and_native_threshold() -> None:
    engine = MockDecisionEngine()
    collision = ReverseState(
        packer_suspected=True,
        traffic_visible=True,
        sign_present=True,
        framework="flutter",
    )
    assert engine.decide_next_action(collision).action == "unpack"
    assert (
        engine.decide_next_action(
            ReverseState(framework="android", dex_count=2, native_library_count=8)
        ).action
        == "hook_native"
    )
    assert (
        engine.decide_next_action(
            ReverseState(framework="android", dex_count=3, native_library_count=8)
        ).action
        == "static_analysis"
    )


def test_mock_capture_traffic_branch() -> None:
    decision = MockDecisionEngine().decide_next_action(ReverseState(traffic_visible=False))
    assert decision.action == "capture_traffic"


def test_ssl_pinning_is_enough_to_inspect_network_stack() -> None:
    decision = MockDecisionEngine().decide_next_action(
        ReverseState(ssl_pinning_suspected=True)
    )
    assert decision.action == "inspect_network_stack"
