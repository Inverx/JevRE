from __future__ import annotations

import json
import math
import os
import socket
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .models import ACTIONS, Decision, ReverseState


QUESTION_ID = "next_action"
QUESTION_INSTRUCTIONS = (
    "Given the current Android reverse-engineering state, "
    "which investigation step should be performed next?"
)
ACTION_CRITERIA = {
    "unpack": (
        "Choose when application protection or packing prevents meaningful static analysis."
    ),
    "static_analysis": (
        "Choose when application code is available and static inspection is the highest-value step."
    ),
    "capture_traffic": (
        "Choose when network behavior has not been observed and collecting traffic is likely useful."
    ),
    "inspect_network_stack": (
        "Choose when the application has network activity but ordinary proxy traffic is unavailable."
    ),
    "locate_signature": (
        "Choose when requests are observable but dynamic signature parameters block reproduction."
    ),
    "hook_java": (
        "Choose when important behavior is likely in Java or Kotlin and runtime observation is valuable."
    ),
    "hook_native": (
        "Choose when relevant behavior appears native or native libraries dominate the implementation."
    ),
    "collect_more_evidence": (
        "Choose when available information is insufficient for a reliable next-step decision."
    ),
}
if tuple(ACTION_CRITERIA) != ACTIONS:
    raise RuntimeError("Jev action criteria and supported actions are out of sync")


class JevError(RuntimeError):
    """Base class for expected Jev client failures."""


class JevConfigError(JevError):
    """Raised when real Jev mode is not configured."""


class JevAPIError(JevError):
    """Raised when the TypeSafe API cannot return a successful response."""

    def __init__(
        self, message: str, *, status: int | None = None, request_id: str | None = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.request_id = request_id


class JevResponseError(JevError):
    """Raised when a successful response violates the documented Choice schema."""


def build_choice_payload(state: ReverseState, model: str) -> dict[str, Any]:
    return {
        "model": model,
        "state": state.to_dict(omit_none=True),
        "questions": {
            QUESTION_ID: {
                "type": "choice",
                "instructions": QUESTION_INSTRUCTIONS,
                "criteria": ACTION_CRITERIA,
            }
        },
    }


def parse_choice_response(payload: Any) -> tuple[str, dict[str, float], float, str]:
    location = "TypeSafe API response"
    if not isinstance(payload, dict):
        raise JevResponseError(f"{location} must be a JSON object")

    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise JevResponseError(f"{location}.model must be a non-empty string")

    answers = payload.get("answers")
    if not isinstance(answers, dict):
        raise JevResponseError(f"{location}.answers must be an object")
    answer = answers.get(QUESTION_ID)
    if not isinstance(answer, dict):
        raise JevResponseError(f"{location}.answers.{QUESTION_ID} must be an object")
    if answer.get("type") != "choice":
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.type must be 'choice'"
        )

    choice = answer.get("choice")
    if choice not in ACTIONS:
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.choice is not a supported action"
        )

    confidence = _require_probability(
        answer.get("confidence"), f"{location}.answers.{QUESTION_ID}.confidence"
    )
    raw_probabilities = answer.get("probabilities")
    if not isinstance(raw_probabilities, dict):
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.probabilities must be an object"
        )
    missing = sorted(set(ACTIONS) - set(raw_probabilities))
    extra = sorted(set(raw_probabilities) - set(ACTIONS))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected: {', '.join(extra)}")
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.probabilities has invalid keys "
            f"({'; '.join(details)})"
        )
    probabilities = {
        action: _require_probability(
            raw_probabilities[action],
            f"{location}.answers.{QUESTION_ID}.probabilities.{action}",
        )
        for action in ACTIONS
    }
    if not math.isclose(sum(probabilities.values()), 1.0, abs_tol=1e-6):
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.probabilities must sum to approximately 1"
        )
    maximum = max(probabilities.values())
    if probabilities[choice] + 1e-12 < maximum:
        raise JevResponseError(
            f"{location}.answers.{QUESTION_ID}.choice is not a highest-probability option"
        )

    usage = payload.get("usage")
    if not isinstance(usage, dict):
        raise JevResponseError(f"{location}.usage must be an object")
    for field in ("input_tokens", "output_tokens"):
        value = usage.get(field)
        if type(value) is not int or value < 0:
            raise JevResponseError(f"{location}.usage.{field} must be a non-negative integer")

    return choice, probabilities, confidence, model.strip()


class JevClient:
    """Minimal raw HTTP client for TypeSafe AI's System One endpoint."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "jev-latest",
        base_url: str = "https://api.typesafe.ai",
        timeout: float = 30.0,
        max_retries: int = 2,
        opener: Callable[..., Any] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise JevConfigError(
                "TYPESAFE_API_KEY is not set. Set it to use Jev, or rerun with --mock."
            )
        if not isinstance(model, str) or not model.strip() or _has_controls(model):
            raise JevConfigError("JEV_MODEL must be a non-empty string")
        parsed_base_url = urlparse(base_url) if isinstance(base_url, str) else None
        if (
            parsed_base_url is None
            or parsed_base_url.scheme not in {"http", "https"}
            or not parsed_base_url.netloc
            or parsed_base_url.query
            or parsed_base_url.fragment
            or _has_controls(base_url)
        ):
            raise JevConfigError("JEV_BASE_URL must be an http:// or https:// URL")
        if (
            type(timeout) not in {int, float}
            or not math.isfinite(float(timeout))
            or timeout <= 0
        ):
            raise JevConfigError("Jev timeout must be a positive finite number")
        if type(max_retries) is not int or not 0 <= max_retries <= 5:
            raise JevConfigError("Jev max_retries must be an integer from 0 to 5")
        self.api_key = api_key.strip()
        self.model = model.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max_retries
        self._opener = opener or urlopen
        self._sleeper = sleeper or time.sleep

    @classmethod
    def from_env(cls) -> "JevClient":
        return cls(
            os.environ.get("TYPESAFE_API_KEY", ""),
            model=os.environ.get("JEV_MODEL", "jev-latest"),
            base_url=os.environ.get("JEV_BASE_URL", "https://api.typesafe.ai"),
        )

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1/systemone"

    def decide(self, state: ReverseState) -> Decision:
        payload = build_choice_payload(state, self.model)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        request = Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "JevRE/0.1.0",
            },
        )
        response_body = self._post(request)

        try:
            decoded = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JevResponseError("TypeSafe API returned invalid UTF-8 JSON") from exc
        action, probabilities, confidence, resolved_model = parse_choice_response(decoded)
        evidence = state.observed_signals() or ["(none supplied)"]
        return Decision(
            action=action,
            probabilities=probabilities,
            confidence=confidence,
            engine="Jev",
            model=resolved_model,
            requested_model=self.model,
            evidence=evidence,
        )

    def _post(self, request: Request) -> bytes:
        for attempt in range(self.max_retries + 1):
            try:
                with self._opener(request, timeout=self.timeout) as response:
                    response_body = response.read(2_000_001)
                    if len(response_body) > 2_000_000:
                        raise JevResponseError("TypeSafe API response exceeds 2 MB")
                    return response_body
            except HTTPError as exc:
                try:
                    error_body = exc.read(16_384)
                except HTTPException:
                    error_body = b""
                request_id = (
                    exc.headers.get("x-typesafe-request-id") if exc.headers else None
                )
                if _retryable_status(exc.code) and attempt < self.max_retries:
                    delay = _retry_delay(exc.headers, attempt)
                    exc.close()
                    self._sleeper(delay)
                    continue
                detail = _error_detail(error_body)
                retry_hint = " Retry later." if _retryable_status(exc.code) else ""
                suffix = f" Request ID: {request_id}." if request_id else ""
                raise JevAPIError(
                    f"TypeSafe API returned HTTP {exc.code}: {detail}.{retry_hint}{suffix}",
                    status=exc.code,
                    request_id=request_id,
                ) from exc
            except (URLError, TimeoutError, socket.timeout, HTTPException, OSError) as exc:
                if attempt < self.max_retries:
                    self._sleeper(_retry_delay(None, attempt))
                    continue
                reason = getattr(exc, "reason", exc)
                raise JevAPIError(f"could not reach or read from TypeSafe API: {reason}") from exc
        raise JevAPIError("TypeSafe API request exhausted its retry budget")


class JevDecisionEngine:
    """The primary JevRE decision engine."""

    def __init__(self, client: JevClient | None = None) -> None:
        self.client = client or JevClient.from_env()

    def decide_next_action(self, state: ReverseState) -> Decision:
        return self.client.decide(state)


def decide_next_action(
    state: ReverseState, engine: JevDecisionEngine | None = None
) -> Decision:
    """Decide with Jev; this function never selects Mock implicitly."""

    return (engine or JevDecisionEngine()).decide_next_action(state)


def _require_probability(value: object, location: str) -> float:
    if (
        type(value) not in {int, float}
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise JevResponseError(f"{location} must be a finite number between 0 and 1")
    return float(value)


def _error_detail(body: bytes) -> str:
    if not body:
        return "empty error response"
    text = body.decode("utf-8", errors="replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text.strip()[:500] or "unreadable error response"
    if isinstance(value, dict) and isinstance(value.get("detail"), list):
        messages: list[str] = []
        for item in value["detail"]:
            if not isinstance(item, dict) or not isinstance(item.get("msg"), str):
                continue
            raw_location = item.get("loc", [])
            if isinstance(raw_location, list):
                location = ".".join(
                    str(part) for part in raw_location if str(part) != "body"
                )
            else:
                location = ""
            messages.append(
                f"{location}: {item['msg']}" if location else item["msg"]
            )
        if messages:
            return "; ".join(messages)[:500]
    return json.dumps(value, ensure_ascii=False)[:500]


def _retryable_status(status: int) -> bool:
    return status in {408, 429} or 500 <= status <= 599


def _retry_delay(headers: Any, attempt: int) -> float:
    fallback = min(0.5 * (2**attempt), 5.0)
    if not headers:
        return fallback
    retry_ms = headers.get("retry-after-ms")
    if retry_ms is not None:
        try:
            return min(max(float(retry_ms) / 1000.0, 0.0), 30.0)
        except (TypeError, ValueError):
            pass
    retry_after = headers.get("Retry-After")
    if retry_after is None:
        return fallback
    try:
        return min(max(float(retry_after), 0.0), 30.0)
    except (TypeError, ValueError):
        try:
            when = parsedate_to_datetime(str(retry_after))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return min(max((when - datetime.now(timezone.utc)).total_seconds(), 0.0), 30.0)
        except (TypeError, ValueError, OverflowError):
            return fallback


def _has_controls(value: str) -> bool:
    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
