from __future__ import annotations

import json

from jevre import main as cli
from jevre.jev import JevAPIError


def test_decide_mock_is_explicit_and_visible(tmp_path, capsys) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"packer_suspected": True}), encoding="utf-8")

    result = cli.main(["decide", str(state_file), "--mock"])
    output = capsys.readouterr()

    assert result == 0
    assert "Engine                MOCK" in output.out
    assert "Mock mode does not use Jev." in output.out
    assert "Recommended Next Action\n------------------------------------\nunpack" in output.out
    assert "Confidence            n/a" in output.out
    assert output.err == ""


def test_analyze_apk_mock(apk_factory, capsys) -> None:
    apk = apk_factory(
        {
            "classes.dex": b"dex",
            "lib/arm64-v8a/libflutter.so": b"native",
        }
    )

    result = cli.main(["analyze", str(apk), "--mock"])
    output = capsys.readouterr()

    assert result == 0
    assert "SHA256" in output.out
    assert "Flutter" in output.out
    assert "Recommended Next Action\n------------------------------------\nhook_native" in output.out
    assert "MOCK" in output.out


def test_missing_key_never_instantiates_mock(tmp_path, monkeypatch, capsys) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)

    class ForbiddenMock:
        def __init__(self):
            raise AssertionError("Mock must not be selected implicitly")

    monkeypatch.setattr(cli, "MockDecisionEngine", ForbiddenMock)
    result = cli.main(["decide", str(state_file)])
    output = capsys.readouterr()

    assert result == 2
    assert "TYPESAFE_API_KEY is not set" in output.err
    assert "--mock" in output.err


def test_jev_failure_never_falls_back_to_mock(tmp_path, monkeypatch, capsys) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")

    class FailingJev:
        def decide_next_action(self, _state):
            raise JevAPIError("network unavailable")

    class ForbiddenMock:
        def __init__(self):
            raise AssertionError("Mock must not be selected after a Jev error")

    monkeypatch.setattr(cli, "JevDecisionEngine", FailingJev)
    monkeypatch.setattr(cli, "MockDecisionEngine", ForbiddenMock)
    result = cli.main(["decide", str(state_file)])
    output = capsys.readouterr()

    assert result == 1
    assert "network unavailable" in output.err
    assert "No mock fallback was used" in output.err


def test_invalid_json_is_a_clean_input_error(tmp_path, capsys) -> None:
    state_file = tmp_path / "bad.json"
    state_file.write_text('{"dex_count":', encoding="utf-8")

    result = cli.main(["decide", str(state_file), "--mock"])
    output = capsys.readouterr()

    assert result == 2
    assert "line 1" in output.err
    assert "Traceback" not in output.err


def test_doctor_does_not_expose_key(monkeypatch, capsys) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "super-secret-value")
    result = cli.main(["doctor"])
    output = capsys.readouterr()

    assert result == 0
    assert "configured" in output.out
    assert "super-secret-value" not in output.out
    assert "not performed" in output.out


def test_doctor_rejects_invalid_model_or_base_url(monkeypatch, capsys) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "secret")
    monkeypatch.setenv("JEV_MODEL", "")
    assert cli.main(["doctor"]) == 1
    assert "Configuration         invalid" in capsys.readouterr().out

    monkeypatch.setenv("JEV_MODEL", "jev-latest")
    monkeypatch.setenv("JEV_BASE_URL", "ftp://example.invalid")
    assert cli.main(["doctor"]) == 1
    assert "Configuration         invalid" in capsys.readouterr().out


def test_explicit_mock_never_constructs_jev(tmp_path, monkeypatch, capsys) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "configured")

    class ForbiddenJev:
        def __init__(self):
            raise AssertionError("Jev must not be constructed in explicit Mock mode")

    monkeypatch.setattr(cli, "JevDecisionEngine", ForbiddenJev)
    assert cli.main(["decide", str(state_file), "--mock"]) == 0
    assert "Alternative Heuristic Scores" in capsys.readouterr().out


def test_analyze_without_key_fails_before_reading_apk(monkeypatch, capsys) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)

    def forbidden_analyzer(_path):
        raise AssertionError("APK must not be read before Jev configuration is validated")

    monkeypatch.setattr(cli, "analyze_apk", forbidden_analyzer)
    assert cli.main(["analyze", "large.apk"]) == 2
    assert "TYPESAFE_API_KEY" in capsys.readouterr().err
