from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


ACTIONS = (
    "unpack",
    "static_analysis",
    "capture_traffic",
    "inspect_network_stack",
    "locate_signature",
    "hook_java",
    "hook_native",
    "collect_more_evidence",
)


class StateValidationError(ValueError):
    """Raised when a ReverseState does not match its small, strict schema."""


@dataclass(slots=True)
class ReverseState:
    framework: str | None = None
    dex_count: int | None = None
    native_library_count: int | None = None
    packer_suspected: bool | None = None
    traffic_visible: bool | None = None
    ssl_pinning_suspected: bool | None = None
    sign_present: bool | None = None
    runtime_crash: bool | None = None
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.framework is not None:
            if not isinstance(self.framework, str) or not self.framework.strip():
                raise StateValidationError("framework must be a non-empty string or null")
            self.framework = self.framework.strip()
            _reject_controls(self.framework, "framework")

        for name in ("dex_count", "native_library_count"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise StateValidationError(f"{name} must be a non-negative integer or null")

        for name in (
            "packer_suspected",
            "traffic_visible",
            "ssl_pinning_suspected",
            "sign_present",
            "runtime_crash",
        ):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise StateValidationError(f"{name} must be true, false, or null")

        if not isinstance(self.notes, list) or any(
            not isinstance(note, str) for note in self.notes
        ):
            raise StateValidationError("notes must be an array of strings")
        normalized_notes: list[str] = []
        for note in self.notes:
            note = note.strip()
            if note:
                _reject_controls(note, "notes")
                normalized_notes.append(note)
        self.notes = list(dict.fromkeys(normalized_notes))

    @classmethod
    def from_dict(cls, value: Any) -> "ReverseState":
        if not isinstance(value, dict):
            raise StateValidationError("reverse state must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StateValidationError(f"unknown ReverseState field(s): {', '.join(unknown)}")
        return cls(**value)

    def to_dict(self, *, omit_none: bool = False) -> dict[str, Any]:
        result = asdict(self)
        if omit_none:
            return {
                key: value
                for key, value in result.items()
                if value is not None and value != []
            }
        return result

    def observed_signals(self) -> list[str]:
        signals: list[str] = []
        if self.framework:
            signals.append(f"Framework: {self.framework.replace('_', ' ').title()}")
        if self.dex_count is not None:
            signals.append(f"DEX files: {self.dex_count}")
        if self.native_library_count is not None:
            signals.append(f"Native libraries: {self.native_library_count}")
        if self.packer_suspected is True:
            signals.append("Packer indicators detected")
        elif self.packer_suspected is False:
            signals.append("State explicitly reports no suspected packer")
        if self.traffic_visible is True:
            signals.append("Application traffic is visible")
        elif self.traffic_visible is False:
            signals.append("Application traffic is not visible")
        if self.ssl_pinning_suspected is True:
            signals.append("TLS pinning is suspected")
        if self.sign_present is True:
            signals.append("Dynamic request signature is present")
        if self.runtime_crash is True:
            signals.append("The application crashes at runtime")
        signals.extend(self.notes)
        return list(dict.fromkeys(signals))


@dataclass(slots=True)
class ApkAnalysis:
    target: Path
    sha256: str
    file_size: int
    abis: tuple[str, ...]
    asset_count: int
    indicators: tuple[str, ...]
    state: ReverseState


@dataclass(slots=True)
class Decision:
    action: str
    probabilities: dict[str, float]
    confidence: float | None
    engine: str
    model: str | None = None
    requested_model: str | None = None
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown decision action: {self.action}")
        if self.engine not in {"Jev", "MOCK"}:
            raise ValueError("engine must be Jev or MOCK")
        if self.engine == "Jev" and self.confidence is None:
            raise ValueError("Jev decisions must include confidence")
        if self.engine == "MOCK" and self.confidence is not None:
            raise ValueError("Mock decisions must not claim calibrated confidence")
        if self.confidence is not None and not _is_probability(self.confidence):
            raise ValueError("confidence must be between 0 and 1 or null")
        if self.engine == "Jev" and (not isinstance(self.model, str) or not self.model.strip()):
            raise ValueError("Jev decisions must include the resolved model")
        if self.engine == "Jev" and (
            not isinstance(self.requested_model, str) or not self.requested_model.strip()
        ):
            raise ValueError("Jev decisions must include the requested model")
        if self.engine == "MOCK" and (
            self.model is not None or self.requested_model is not None
        ):
            raise ValueError("Mock decisions must not include a Jev model")
        if not isinstance(self.evidence, list) or any(
            not isinstance(item, str) for item in self.evidence
        ):
            raise ValueError("evidence must be an array of strings")
        normalized_evidence: list[str] = []
        for item in self.evidence:
            item = item.strip()
            if item:
                _reject_controls(item, "evidence")
                normalized_evidence.append(item)
        self.evidence = list(dict.fromkeys(normalized_evidence))
        if set(self.probabilities) != set(ACTIONS):
            raise ValueError("probabilities must contain every supported action exactly once")
        for action, probability in self.probabilities.items():
            if not _is_probability(probability):
                raise ValueError(f"invalid probability for {action}")
        if not math.isclose(sum(self.probabilities.values()), 1.0, abs_tol=1e-6):
            raise ValueError("probabilities must sum to approximately 1")
        maximum = max(self.probabilities.values())
        if self.probabilities[self.action] + 1e-12 < maximum:
            raise ValueError("selected action is not a highest-probability option")

    @property
    def selected_probability(self) -> float:
        return self.probabilities[self.action]

    def alternatives(self) -> list[tuple[str, float]]:
        order = {action: index for index, action in enumerate(ACTIONS)}
        return sorted(
            (
                (action, probability)
                for action, probability in self.probabilities.items()
                if action != self.action
            ),
            key=lambda item: (-item[1], order[item[0]]),
        )


def _is_probability(value: object) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def _reject_controls(value: str, field: str) -> None:
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise StateValidationError(f"{field} must not contain terminal control characters")
