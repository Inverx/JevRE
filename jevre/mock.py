from __future__ import annotations

from .models import ACTIONS, Decision, ReverseState


MOCK_PROFILES = {
    "unpack": (0.84, 0.05, 0.01, 0.01, 0.01, 0.02, 0.03, 0.03),
    "locate_signature": (0.01, 0.04, 0.03, 0.04, 0.80, 0.03, 0.02, 0.03),
    "inspect_network_stack": (0.01, 0.04, 0.08, 0.78, 0.02, 0.02, 0.02, 0.03),
    "hook_native": (0.02, 0.07, 0.02, 0.03, 0.01, 0.04, 0.77, 0.04),
    "capture_traffic": (0.01, 0.10, 0.68, 0.06, 0.03, 0.04, 0.03, 0.05),
    "static_analysis": (0.02, 0.72, 0.06, 0.04, 0.03, 0.05, 0.04, 0.04),
}


class MockDecisionEngine:
    """Small deterministic offline demo. It does not use Jev."""

    def decide_next_action(self, state: ReverseState) -> Decision:
        if state.packer_suspected is True:
            action = "unpack"
            evidence = ["Packer indicators are marked as present"]
        elif state.traffic_visible is True and state.sign_present is True:
            action = "locate_signature"
            evidence = [
                "Application traffic is visible",
                "A dynamic request signature is present",
            ]
        elif state.ssl_pinning_suspected is True or (
            state.traffic_visible is False and _notes_report_working_network(state.notes)
        ):
            action = "inspect_network_stack"
            evidence = []
            if state.traffic_visible is False:
                evidence.append("Application traffic is not visible")
            if state.ssl_pinning_suspected is True:
                evidence.append("TLS pinning is suspected")
            else:
                evidence.append("Notes report that application networking still works")
        elif _native_heavy(state):
            action = "hook_native"
            evidence = []
            if state.framework and state.framework.casefold() in {"flutter", "unity"}:
                evidence.append(f"Framework is {state.framework}")
            if state.native_library_count is not None:
                evidence.append(f"Native libraries: {state.native_library_count}")
        elif state.traffic_visible is False:
            action = "capture_traffic"
            evidence = ["Application traffic has not been captured"]
        else:
            action = "static_analysis"
            evidence = state.observed_signals() or ["(none supplied)"]

        probabilities = dict(zip(ACTIONS, MOCK_PROFILES[action], strict=True))
        return Decision(
            action=action,
            probabilities=probabilities,
            confidence=None,
            engine="MOCK",
            evidence=evidence,
        )


def _notes_report_working_network(notes: list[str]) -> bool:
    text = " ".join(notes).casefold()
    return any(
        phrase in text for phrase in ("network works", "network activity", "requests succeed")
    )


def _native_heavy(state: ReverseState) -> bool:
    if state.framework and state.framework.casefold() in {"flutter", "unity"}:
        return True
    return (
        state.native_library_count is not None
        and state.native_library_count >= 8
        and (state.dex_count is None or state.dex_count <= 2)
    )
