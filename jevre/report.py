from __future__ import annotations

from .models import ApkAnalysis, Decision, ReverseState


RULE = "-" * 36


def render_report(
    state: ReverseState,
    decision: Decision,
    *,
    target: str,
    analysis: ApkAnalysis | None = None,
) -> str:
    lines = ["JevRE", "", "Target", RULE, target]
    if analysis is not None:
        lines.extend(
            [
                _row("SHA256", analysis.sha256),
                _row("Size", f"{analysis.file_size:,} bytes"),
            ]
        )

    lines.extend(
        [
            "",
            "Observed State",
            RULE,
            _row("Framework", _framework(state.framework)),
            _row("DEX", _unknown(state.dex_count)),
            _row("Native libs", _unknown(state.native_library_count)),
        ]
    )
    if analysis is not None:
        lines.extend(
            [
                _row("ABIs", ", ".join(analysis.abis) if analysis.abis else "None"),
                _row("Assets", str(analysis.asset_count)),
            ]
        )
    lines.extend(
        [
            _row("Packed", _tristate(state.packer_suspected, "Suspected", "Not suspected")),
            _row("Traffic", _tristate(state.traffic_visible, "Visible", "Not visible")),
            "",
            "Decision Engine",
            RULE,
            _row("Engine", decision.engine),
        ]
    )
    if decision.engine == "Jev":
        lines.append(_row("Requested model", decision.requested_model or "Unknown"))
        lines.append(_row("Resolved model", decision.model or "Unknown"))
    else:
        lines.append("Mock mode does not use Jev.")

    lines.extend(["", "Recommended Next Action", RULE, decision.action])
    if decision.engine == "Jev":
        lines.extend(
            [
                _row("Selected probability", f"{decision.selected_probability:.2f}"),
                _row("Confidence", f"{decision.confidence:.2f}"),
            ]
        )
    else:
        lines.extend(
            [
                _row("Heuristic score", f"{decision.selected_probability:.2f}"),
                _row("Confidence", "n/a (Mock is not calibrated Jev)"),
            ]
        )

    alternatives_title = (
        "Alternatives" if decision.engine == "Jev" else "Alternative Heuristic Scores"
    )
    lines.extend(["", alternatives_title, RULE])
    for action, probability in decision.alternatives():
        lines.append(_row(action, f"{probability:.2f}"))

    lines.extend(["", "Observed Signals", RULE])
    lines.extend(f"- {item}" for item in decision.evidence)
    return "\n".join(lines) + "\n"


def _row(label: str, value: object) -> str:
    return f"{label:<22}{value}"


def _unknown(value: object | None) -> str:
    return "Unknown" if value is None else str(value)


def _framework(value: str | None) -> str:
    return "Unknown" if value is None else value.replace("_", " ").title()


def _tristate(value: bool | None, yes: str, no: str) -> str:
    if value is None:
        return "Unknown"
    return yes if value else no
