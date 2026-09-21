import pytest

from jevre.models import ACTIONS, Decision, ReverseState, StateValidationError


def test_reverse_state_round_trip_and_omit_none() -> None:
    source = {
        "framework": "flutter",
        "dex_count": 2,
        "native_library_count": 14,
        "packer_suspected": None,
        "traffic_visible": False,
        "ssl_pinning_suspected": True,
        "sign_present": None,
        "runtime_crash": False,
        "notes": ["network works", "network works"],
    }
    state = ReverseState.from_dict(source)

    assert state.notes == ["network works"]
    assert state.to_dict()["packer_suspected"] is None
    assert "packer_suspected" not in state.to_dict(omit_none=True)
    assert state.to_dict(omit_none=True)["traffic_visible"] is False


@pytest.mark.parametrize(
    "value,message",
    [
        ({"unknown": 1}, "unknown ReverseState"),
        ({"dex_count": True}, "dex_count"),
        ({"dex_count": -1}, "dex_count"),
        ({"traffic_visible": 1}, "traffic_visible"),
        ({"notes": ["ok", 3]}, "notes"),
        ([], "JSON object"),
    ],
)
def test_reverse_state_rejects_invalid_values(value, message: str) -> None:
    with pytest.raises(StateValidationError, match=message):
        ReverseState.from_dict(value)


def test_decision_keeps_confidence_separate_from_selected_probability() -> None:
    probabilities = {action: 0.0 for action in ACTIONS}
    probabilities["unpack"] = 0.88
    probabilities["static_analysis"] = 0.12
    decision = Decision(
        action="unpack",
        probabilities=probabilities,
        confidence=0.81,
        engine="Jev",
        model="jev-1.13.0",
        requested_model="jev-latest",
    )

    assert decision.selected_probability == 0.88
    assert decision.confidence == 0.81


def test_state_and_decision_reject_terminal_controls() -> None:
    with pytest.raises(StateValidationError, match="control"):
        ReverseState(framework="flutter\nspoofed")
    with pytest.raises(StateValidationError, match="control"):
        ReverseState(notes=["ok\x1b[2J"])


def test_decision_enforces_engine_specific_confidence_and_evidence() -> None:
    probabilities = {action: 0.0 for action in ACTIONS}
    probabilities["static_analysis"] = 1.0
    with pytest.raises(ValueError, match="include confidence"):
        Decision(
            action="static_analysis",
            probabilities=probabilities,
            confidence=None,
            engine="Jev",
            model="jev-1.13.0",
            requested_model="jev-latest",
        )
    with pytest.raises(ValueError, match="must not claim"):
        Decision(
            action="static_analysis",
            probabilities=probabilities,
            confidence=0.9,
            engine="MOCK",
        )
    with pytest.raises(ValueError, match="evidence"):
        Decision(
            action="static_analysis",
            probabilities=probabilities,
            confidence=None,
            engine="MOCK",
            evidence=[3],
        )
