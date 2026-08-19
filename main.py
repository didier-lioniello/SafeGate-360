"""Offline CLI for the SafeGate-360 reference implementation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import click

from core import Action, AuditWriteError, GuardResult, SafeGate
from examples import FIXTURE_NAMES, build_fixture
from policies import default_policy

_SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_MAX_PROBE_FILE_BYTES = 1_000_000
_MAX_PROBES = 1_000


def _gate(*, llm_fn=None) -> SafeGate:
    return SafeGate(policy=default_policy(), llm_fn=llm_fn)


def _result_payload(result: GuardResult) -> dict[str, Any]:
    return {
        "request_id": result.request_id,
        "allowed": result.allowed,
        "action": result.action.value,
        "stage": result.stage.value,
        "reason": result.reason,
        "latency_ms": round(result.latency_ms, 3),
        "detections": [
            {
                "detector": detection.detector,
                "triggered": detection.triggered,
                "confidence": round(detection.confidence, 3),
                "reason": detection.reason,
            }
            for detection in result.detections
        ],
        "output_text": result.output_text,
    }


def _emit_result(result: GuardResult) -> None:
    click.echo(json.dumps(_result_payload(result), indent=2, sort_keys=True))


@click.group()
def cli() -> None:
    """Exercise deterministic LLM guardrails without a network call."""


@cli.command()
@click.argument("text")
def check(text: str) -> None:
    """Run input guards and print only the safe result."""

    try:
        _emit_result(_gate().check_input(text))
    except AuditWriteError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.option("--prompt", required=True, help="Input to inspect before the model call.")
@click.option("--response", help="Deterministic model response to inspect.")
@click.option(
    "--response-fixture",
    type=click.Choice(FIXTURE_NAMES),
    help="Build a synthetic response at runtime instead of passing one.",
)
def guard(prompt: str, response: str | None, response_fixture: str | None) -> None:
    """Run input and output guards around a supplied deterministic response."""

    if (response is None) == (response_fixture is None):
        raise click.UsageError("provide exactly one of --response or --response-fixture")
    safe_response = response if response is not None else build_fixture(response_fixture or "")
    try:
        _emit_result(_gate(llm_fn=lambda _prompt: safe_response).guard(prompt))
    except AuditWriteError as exc:
        raise click.ClickException(str(exc)) from exc


def _load_probe(record: object, line_number: int) -> tuple[str, Action]:
    if not isinstance(record, dict):
        raise click.ClickException(f"line {line_number}: probe must be a JSON object")

    probe_id = record.get("id")
    if not isinstance(probe_id, str) or not _SAFE_ID.fullmatch(probe_id):
        raise click.ClickException(f"line {line_number}: id must use safe ASCII characters")

    has_text = "text" in record
    has_fixture = "fixture" in record
    if has_text == has_fixture:
        raise click.ClickException(f"line {line_number}: provide text or fixture, not both")

    if has_text:
        text = record["text"]
        if not isinstance(text, str):
            raise click.ClickException(f"line {line_number}: text must be a string")
    else:
        fixture = record["fixture"]
        if not isinstance(fixture, str):
            raise click.ClickException(f"line {line_number}: fixture must be a string")
        try:
            text = build_fixture(fixture)
        except ValueError as exc:
            raise click.ClickException(f"line {line_number}: unknown fixture") from exc

    try:
        expected = Action(record["expected_action"])
    except (KeyError, TypeError, ValueError) as exc:
        raise click.ClickException(f"line {line_number}: invalid expected_action") from exc
    return text, expected


@cli.command()
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="JSONL probes with text or a named synthetic fixture.",
)
def audit(input_path: Path) -> None:
    """Batch-check probes without printing their raw content."""

    try:
        with input_path.open("rb") as probe_file:
            raw = probe_file.read(_MAX_PROBE_FILE_BYTES + 1)
        if len(raw) > _MAX_PROBE_FILE_BYTES:
            raise click.ClickException("probe file exceeds the size limit")
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise click.ClickException("probe file must be valid UTF-8") from exc
    except OSError as exc:
        raise click.ClickException("probe file could not be read") from exc

    gate = _gate()
    checked = mismatches = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if checked >= _MAX_PROBES:
            raise click.ClickException("probe file contains too many probes")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise click.ClickException(f"line {line_number}: invalid JSON") from exc
        text, expected = _load_probe(record, line_number)
        try:
            result = gate.check_input(text)
        except AuditWriteError as exc:
            raise click.ClickException(str(exc)) from exc
        matched = result.action == expected
        checked += 1
        mismatches += int(not matched)
        click.echo(
            json.dumps(
                {
                    "probe_line": line_number,
                    "action": result.action.value,
                    "expected_action": expected.value,
                    "matched": matched,
                },
                sort_keys=True,
            )
        )

    click.echo(json.dumps({"checked": checked, "mismatches": mismatches}, sort_keys=True))
    if checked == 0:
        raise click.ClickException("probe file did not contain any probes")
    if mismatches:
        raise click.exceptions.Exit(1)


if __name__ == "__main__":
    cli()
