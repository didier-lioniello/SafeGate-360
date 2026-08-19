from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from examples.fixtures import build_fixture
from main import cli


def _env(tmp_path: Path) -> dict[str, str]:
    return {"SAFEGATE_LOG_PATH": str(tmp_path / "audit.jsonl")}


def test_check_command_returns_json_and_writes_audit(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["check", build_fixture("clean")], env=_env(tmp_path))

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["action"] == "allow"
    assert (tmp_path / "audit.jsonl").exists()


def test_guard_command_redacts_runtime_fixture(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "guard",
            "--prompt",
            build_fixture("clean"),
            "--response-fixture",
            "synthetic_email",
        ],
        env=_env(tmp_path),
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["stage"] == "output"
    assert payload["action"] == "redact"
    assert "[REDACTED_EMAIL]" in payload["output_text"]


def test_guard_requires_exactly_one_response_source(tmp_path: Path) -> None:
    missing = CliRunner().invoke(
        cli,
        ["guard", "--prompt", build_fixture("clean")],
        env=_env(tmp_path),
    )
    both = CliRunner().invoke(
        cli,
        [
            "guard",
            "--prompt",
            build_fixture("clean"),
            "--response",
            "safe response",
            "--response-fixture",
            "clean",
        ],
        env=_env(tmp_path),
    )

    assert missing.exit_code == 2
    assert both.exit_code == 2


def test_audit_command_verifies_all_public_probes_without_echoing_them(tmp_path: Path) -> None:
    probes = Path(__file__).parents[1] / "examples" / "probes.jsonl"

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 0
    assert '"mismatches": 0' in result.output
    assert "demo.user" not in result.output
    assert "123-45" not in result.output


def test_audit_rejects_invalid_json_without_echoing_line(tmp_path: Path) -> None:
    probes = tmp_path / "invalid.jsonl"
    probes.write_text("not-json-and-private", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert "invalid JSON" in result.output
    assert "not-json-and-private" not in result.output


def test_audit_rejects_unknown_fixture(tmp_path: Path) -> None:
    probes = tmp_path / "unknown.jsonl"
    probes.write_text(
        json.dumps({"id": "unknown", "fixture": "does-not-exist", "expected_action": "allow"}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert "unknown fixture" in result.output


def test_audit_rejects_unsafe_probe_id_without_echoing_it(tmp_path: Path) -> None:
    unsafe_id = "private value with spaces"
    probes = tmp_path / "unsafe-id.jsonl"
    probes.write_text(
        json.dumps({"id": unsafe_id, "fixture": "clean", "expected_action": "allow"}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert "safe ASCII" in result.output
    assert unsafe_id not in result.output


def test_audit_does_not_echo_a_valid_but_sensitive_looking_id(tmp_path: Path) -> None:
    sensitive_id = "tokenlike_identifier_1234567890"
    probes = tmp_path / "safe-id.jsonl"
    probes.write_text(
        json.dumps({"id": sensitive_id, "fixture": "clean", "expected_action": "allow"}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 0
    assert sensitive_id not in result.output
    assert '"probe_line": 1' in result.output


def test_audit_exits_nonzero_on_expected_action_mismatch(tmp_path: Path) -> None:
    probes = tmp_path / "mismatch.jsonl"
    probes.write_text(
        json.dumps({"id": "mismatch", "fixture": "clean", "expected_action": "block"}),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert '"mismatches": 1' in result.output


def test_audit_rejects_empty_probe_file(tmp_path: Path) -> None:
    probes = tmp_path / "empty.jsonl"
    probes.write_text("\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert "did not contain any probes" in result.output


def test_audit_rejects_oversized_probe_file_without_echoing_it(tmp_path: Path) -> None:
    probes = tmp_path / "oversized.jsonl"
    probes.write_text("x" * 1_000_001, encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["audit", "--input", str(probes)],
        env=_env(tmp_path),
    )

    assert result.exit_code == 1
    assert "size limit" in result.output
    assert "x" * 100 not in result.output
