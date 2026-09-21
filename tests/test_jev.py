from __future__ import annotations

import io
import json
from urllib.error import HTTPError

import pytest

from jevre.jev import (
    ACTION_CRITERIA,
    JevAPIError,
    JevClient,
    JevConfigError,
    JevResponseError,
    build_choice_payload,
    parse_choice_response,
)
from jevre.models import ACTIONS, ReverseState


def canonical_response() -> dict:
    probabilities = {action: 0.0 for action in ACTIONS}
    probabilities.update({"unpack": 0.82, "static_analysis": 0.10, "hook_native": 0.08})
    return {
        "model": "jev-1.13.0",
        "answers": {
            "next_action": {
                "type": "choice",
                "choice": "unpack",
                "confidence": 0.74,
                "probabilities": probabilities,
            }
        },
        "usage": {"input_tokens": 400, "output_tokens": 50},
    }


class FakeResponse:
    def __init__(self, value: dict) -> None:
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.body


def test_choice_payload_matches_official_schema() -> None:
    state = ReverseState(framework="flutter", dex_count=1, packer_suspected=None)
    payload = build_choice_payload(state, "jev-latest")

    assert payload["model"] == "jev-latest"
    assert payload["state"] == {"framework": "flutter", "dex_count": 1}
    question = payload["questions"]["next_action"]
    assert question["type"] == "choice"
    assert question["instructions"]
    assert question["criteria"] == ACTION_CRITERIA
    assert tuple(question["criteria"]) == ACTIONS


def test_client_posts_and_parses_choice_response() -> None:
    captured = {}

    def opener(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(canonical_response())

    client = JevClient("secret", opener=opener)
    decision = client.decide(ReverseState(packer_suspected=True))

    request = captured["request"]
    assert request.full_url == "https://api.typesafe.ai/v1/systemone"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer secret"
    assert json.loads(request.data)["model"] == "jev-latest"
    assert decision.action == "unpack"
    assert decision.selected_probability == 0.82
    assert decision.confidence == 0.74
    assert decision.model == "jev-1.13.0"
    assert decision.requested_model == "jev-latest"


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda value: value.pop("answers"), "answers"),
        (
            lambda value: value["answers"]["next_action"].update({"type": "noul"}),
            "type",
        ),
        (
            lambda value: value["answers"]["next_action"]["probabilities"].pop("hook_java"),
            "missing: hook_java",
        ),
        (
            lambda value: value["answers"]["next_action"].update({"confidence": 2}),
            "confidence",
        ),
        (
            lambda value: value["answers"]["next_action"]["probabilities"].update(
                {"unpack": 0.2, "static_analysis": 0.72}
            ),
            "highest-probability",
        ),
        (lambda value: value.update({"usage": {}}), "input_tokens"),
    ],
)
def test_response_parser_rejects_schema_violations(mutate, message: str) -> None:
    value = canonical_response()
    mutate(value)
    with pytest.raises(JevResponseError, match=message):
        parse_choice_response(value)


def test_client_reports_http_error_without_mock_fallback() -> None:
    def opener(request, timeout):
        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"detail":"invalid key"}'),
        )

    client = JevClient("secret", opener=opener)
    with pytest.raises(JevAPIError, match="HTTP 401"):
        client.decide(ReverseState())


def test_client_requires_api_key() -> None:
    with pytest.raises(JevConfigError, match="TYPESAFE_API_KEY"):
        JevClient("  ")


def test_client_retries_transient_errors_and_honors_retry_header() -> None:
    attempts = []
    delays = []

    def opener(request, timeout):
        attempts.append(1)
        if len(attempts) < 3:
            raise HTTPError(
                request.full_url,
                529,
                "Overloaded",
                {"Retry-After": "0"},
                io.BytesIO(b'{"detail":"overloaded"}'),
            )
        return FakeResponse(canonical_response())

    decision = JevClient("secret", opener=opener, sleeper=delays.append).decide(
        ReverseState()
    )

    assert decision.action == "unpack"
    assert len(attempts) == 3
    assert delays == [0.0, 0.0]


def test_client_rejects_nonfinite_timeout() -> None:
    with pytest.raises(JevConfigError, match="finite"):
        JevClient("secret", timeout=float("nan"))
