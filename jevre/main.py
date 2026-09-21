from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .analyzer import ApkAnalysisError, analyze_apk
from .jev import JevAPIError, JevConfigError, JevDecisionEngine, JevResponseError
from .mock import MockDecisionEngine
from .models import ReverseState, StateValidationError
from .report import render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jevre",
        description=(
            "Jev-powered decision layer for Android reverse engineering. "
            "Default mode calls Jev; use --mock explicitly for the offline demo."
        ),
    )
    parser.add_argument("--version", action="version", version=f"JevRE {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="analyze an APK and decide what to do next")
    analyze.add_argument("apk", type=Path)
    analyze.add_argument(
        "--mock", action="store_true", help="use deterministic offline heuristics; does not use Jev"
    )

    decide = subparsers.add_parser("decide", help="decide from an existing ReverseState JSON file")
    decide.add_argument("state", type=Path)
    decide.add_argument(
        "--mock", action="store_true", help="use deterministic offline heuristics; does not use Jev"
    )

    subparsers.add_parser("doctor", help="show local configuration without making an API call")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _doctor()
        if args.command == "analyze":
            engine = _engine(args.mock)
            analysis = analyze_apk(args.apk)
            decision = engine.decide_next_action(analysis.state)
            print(
                render_report(
                    analysis.state,
                    decision,
                    target=str(analysis.target),
                    analysis=analysis,
                ),
                end="",
            )
            return 0
        if args.command == "decide":
            state = _load_state(args.state)
            decision = _engine(args.mock).decide_next_action(state)
            print(render_report(state, decision, target=str(args.state.resolve())), end="")
            return 0
    except (ApkAnalysisError, StateValidationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except JevConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Mock mode does not use Jev and must be selected with --mock.", file=sys.stderr)
        return 2
    except (JevAPIError, JevResponseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("No mock fallback was used.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 2


def _engine(use_mock: bool) -> JevDecisionEngine | MockDecisionEngine:
    if use_mock:
        return MockDecisionEngine()
    return JevDecisionEngine()


def _load_state(path: Path) -> ReverseState:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise StateValidationError(f"cannot read state file {path}: {exc}") from exc
    try:
        value = json.loads(text, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise StateValidationError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    return ReverseState.from_dict(value)


def _reject_json_constant(value: str) -> None:
    raise StateValidationError(f"invalid JSON numeric constant: {value}")


def _doctor() -> int:
    key_configured = bool(os.environ.get("TYPESAFE_API_KEY", "").strip())
    model = os.environ.get("JEV_MODEL", "jev-latest")
    base_url = os.environ.get("JEV_BASE_URL", "https://api.typesafe.ai").rstrip("/")
    config_error: str | None = None
    try:
        from .jev import JevClient

        JevClient(
            os.environ.get("TYPESAFE_API_KEY", "") or "doctor-placeholder",
            model=model,
            base_url=base_url,
        )
    except JevConfigError as exc:
        config_error = str(exc)
    model_display = model if not _contains_controls(model) else "invalid"
    base_url_display = base_url if not _contains_controls(base_url) else "invalid"
    print("JevRE doctor")
    print(f"{'Python':<22}{sys.version.split()[0]}")
    print(f"{'TYPESAFE_API_KEY':<22}{'configured' if key_configured else 'missing'}")
    print(f"{'JEV_MODEL':<22}{model_display}")
    print(f"{'JEV_BASE_URL':<22}{base_url_display}")
    endpoint_display = (
        f"{base_url_display}/v1/systemone" if base_url_display != "invalid" else "invalid"
    )
    print(f"{'Jev endpoint':<22}{endpoint_display}")
    print(f"{'Live API call':<22}not performed")
    print(f"{'Mock mode':<22}available with --mock; does not use Jev")
    print(f"{'Configuration':<22}{'invalid: ' + config_error if config_error else 'valid'}")
    return 0 if key_configured and config_error is None else 1


def entrypoint() -> None:
    raise SystemExit(main())


def _contains_controls(value: str) -> bool:
    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
