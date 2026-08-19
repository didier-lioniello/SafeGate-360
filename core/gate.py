"""Fail-closed orchestration for input, output, redaction, and audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from detectors import DEFAULT_INPUT_DETECTORS, DEFAULT_OUTPUT_DETECTORS

from .policy import Policy, Rule
from .redaction import redact
from .types import Action, Detection, GuardResult, Stage


class AuditWriteError(RuntimeError):
    """Raised when a required audit record cannot be written safely."""


InputDetector = Callable[[str], Detection]
OutputDetector = Callable[[str, str], Detection]


class SafeGate:
    """Apply deterministic guards around an optional model callable.

    This class is a reference implementation, not a security boundary on its own.
    Detector and policy failures become blocked decisions. Audit failures raise
    ``AuditWriteError`` so the caller can stop rather than proceed unaudited.
    """

    def __init__(
        self,
        policy: Policy,
        input_detectors: list[InputDetector] | None = None,
        output_detectors: list[OutputDetector] | None = None,
        llm_fn: Callable[[str], str] | None = None,
        log_path: str | os.PathLike[str] | None = None,
        max_text_chars: int = 50_000,
        audit_hmac_key: bytes | None = None,
    ) -> None:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        if not isinstance(max_text_chars, int) or isinstance(max_text_chars, bool):
            raise TypeError("max_text_chars must be an integer")
        if max_text_chars < 1:
            raise ValueError("max_text_chars must be positive")
        if audit_hmac_key is not None and (
            not isinstance(audit_hmac_key, bytes) or len(audit_hmac_key) < 32
        ):
            raise ValueError("audit_hmac_key must contain at least 32 bytes")

        self.policy = policy
        self.input_detectors = (
            list(DEFAULT_INPUT_DETECTORS) if input_detectors is None else list(input_detectors)
        )
        self.output_detectors = (
            list(DEFAULT_OUTPUT_DETECTORS) if output_detectors is None else list(output_detectors)
        )
        self.llm_fn = llm_fn
        self.log_path = Path(log_path or os.getenv("SAFEGATE_LOG_PATH", ".safegate/audit.jsonl"))
        self.max_text_chars = max_text_chars
        self._audit_key = audit_hmac_key or secrets.token_bytes(32)
        self._audit_session_id = uuid.uuid4().hex
        self._audit_lock = threading.Lock()

    def _fingerprint(self, text: str | None) -> str | None:
        if text is None:
            return None
        return hmac.new(self._audit_key, text.encode(), hashlib.sha256).hexdigest()

    def _write_audit(
        self,
        result: GuardResult,
        *,
        input_text: str | None,
        output_text: str | None,
    ) -> None:
        try:
            record = result.to_audit_record(
                timestamp=datetime.now(UTC).isoformat(),
                audit_session_id=self._audit_session_id,
                input_fingerprint=self._fingerprint(input_text),
                output_fingerprint=self._fingerprint(output_text),
            )
            payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            with self._audit_lock:
                descriptor = os.open(self.log_path, flags, 0o600)
                try:
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError("audit destination is not a regular file")
                    os.fchmod(descriptor, 0o600)
                    view = memoryview(payload)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("audit write was incomplete")
                        view = view[written:]
                finally:
                    os.close(descriptor)
        except (OSError, TypeError, UnicodeError, ValueError) as exc:
            raise AuditWriteError("required audit record could not be written") from exc

    @staticmethod
    def _detector_name(detector: Callable[..., Detection]) -> str:
        name = getattr(detector, "__name__", detector.__class__.__name__)
        safe_name = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(name)).strip("_")
        return (safe_name or "anonymous")[:48]

    def _run_input_detectors(self, text: str) -> tuple[list[Detection], str | None]:
        detections: list[Detection] = []
        for detector in self.input_detectors:
            try:
                detection = detector(text)
                if not isinstance(detection, Detection):
                    raise TypeError("detector returned an invalid result")
                detections.append(detection)
            except Exception:
                return detections, f"input_detector_error:{self._detector_name(detector)}"
        return detections, None

    def _run_output_detectors(
        self, input_text: str, output_text: str
    ) -> tuple[list[Detection], str | None]:
        detections: list[Detection] = []
        for detector in self.output_detectors:
            try:
                detection = detector(input_text, output_text)
                if not isinstance(detection, Detection):
                    raise TypeError("detector returned an invalid result")
                detections.append(detection)
            except Exception:
                return detections, f"output_detector_error:{self._detector_name(detector)}"
        return detections, None

    @staticmethod
    def _reason_for_rules(fired: list[Rule]) -> str:
        if not fired:
            return "clean"
        decisions = sorted({f"{rule.detector}:{rule.action.value}" for rule in fired})
        return "matched_rules=" + ",".join(decisions)

    def _error_result(
        self,
        *,
        request_id: str,
        stage: Stage,
        code: str,
        input_text: str | None,
        output_text: str | None = None,
        started_at: float | None = None,
        prior_detections: list[Detection] | None = None,
    ) -> GuardResult:
        detections = list(prior_detections or [])
        detections.append(
            Detection(
                detector="guard_error",
                triggered=True,
                confidence=1.0,
                reason="guard execution failed closed",
                error_code=code,
            )
        )
        result = GuardResult(
            request_id=request_id,
            allowed=False,
            action=Action.BLOCK,
            stage=stage,
            output_text=None,
            detections=detections,
            reason=code,
            latency_ms=(time.perf_counter() - started_at) * 1000 if started_at else 0.0,
        )
        self._write_audit(result, input_text=input_text, output_text=output_text)
        return result

    def _validate_text(
        self,
        value: object,
        *,
        field: str,
        request_id: str,
        stage: Stage,
        input_text: str | None,
        started_at: float,
    ) -> GuardResult | None:
        if not isinstance(value, str):
            return self._error_result(
                request_id=request_id,
                stage=stage,
                code=f"invalid_{field}_type",
                input_text=input_text,
                started_at=started_at,
            )
        if len(value) > self.max_text_chars:
            return self._error_result(
                request_id=request_id,
                stage=stage,
                code=f"{field}_too_large",
                input_text=input_text,
                output_text=value if field == "output" else None,
                started_at=started_at,
            )
        return None

    def check_input(self, text: str, *, _request_id: str | None = None) -> GuardResult:
        started_at = time.perf_counter()
        request_id = _request_id or uuid.uuid4().hex
        invalid = self._validate_text(
            text,
            field="input",
            request_id=request_id,
            stage=Stage.INPUT,
            input_text=text if isinstance(text, str) else None,
            started_at=started_at,
        )
        if invalid:
            return invalid

        detections, error = self._run_input_detectors(text)
        if error:
            return self._error_result(
                request_id=request_id,
                stage=Stage.INPUT,
                code=error,
                input_text=text,
                started_at=started_at,
                prior_detections=detections,
            )

        try:
            action, fired = self.policy.resolve(Stage.INPUT, detections)
            allowed = action != Action.BLOCK
            safe_text = text
            if action == Action.REDACT:
                redact_names = {rule.detector for rule in fired if rule.action == Action.REDACT}
                safe_text = redact(
                    text,
                    [detection for detection in detections if detection.detector in redact_names],
                )
        except Exception:
            return self._error_result(
                request_id=request_id,
                stage=Stage.INPUT,
                code="input_policy_or_redaction_error",
                input_text=text,
                started_at=started_at,
                prior_detections=detections,
            )

        result = GuardResult(
            request_id=request_id,
            allowed=allowed,
            action=action,
            stage=Stage.INPUT,
            output_text=safe_text if allowed else None,
            detections=detections,
            reason=self._reason_for_rules(fired),
            latency_ms=(time.perf_counter() - started_at) * 1000,
        )
        self._write_audit(result, input_text=text, output_text=safe_text if allowed else None)
        return result

    def check_output(
        self,
        input_text: str,
        output_text: str,
        *,
        _request_id: str | None = None,
    ) -> GuardResult:
        started_at = time.perf_counter()
        request_id = _request_id or uuid.uuid4().hex
        invalid_input = self._validate_text(
            input_text,
            field="input",
            request_id=request_id,
            stage=Stage.OUTPUT,
            input_text=input_text if isinstance(input_text, str) else None,
            started_at=started_at,
        )
        if invalid_input:
            return invalid_input
        invalid_output = self._validate_text(
            output_text,
            field="output",
            request_id=request_id,
            stage=Stage.OUTPUT,
            input_text=input_text,
            started_at=started_at,
        )
        if invalid_output:
            return invalid_output

        detections, error = self._run_output_detectors(input_text, output_text)
        if error:
            return self._error_result(
                request_id=request_id,
                stage=Stage.OUTPUT,
                code=error,
                input_text=input_text,
                output_text=output_text,
                started_at=started_at,
                prior_detections=detections,
            )

        try:
            action, fired = self.policy.resolve(Stage.OUTPUT, detections)
            allowed = action != Action.BLOCK
            safe_text = output_text
            if action == Action.REDACT:
                redact_names = {rule.detector for rule in fired if rule.action == Action.REDACT}
                safe_text = redact(
                    output_text,
                    [detection for detection in detections if detection.detector in redact_names],
                )
        except Exception:
            return self._error_result(
                request_id=request_id,
                stage=Stage.OUTPUT,
                code="output_policy_or_redaction_error",
                input_text=input_text,
                output_text=output_text,
                started_at=started_at,
                prior_detections=detections,
            )

        result = GuardResult(
            request_id=request_id,
            allowed=allowed,
            action=action,
            stage=Stage.OUTPUT,
            output_text=safe_text if allowed else None,
            detections=detections,
            reason=self._reason_for_rules(fired),
            latency_ms=(time.perf_counter() - started_at) * 1000,
        )
        self._write_audit(result, input_text=input_text, output_text=output_text)
        return result

    def guard(self, prompt: str) -> GuardResult:
        """Check input, call the configured model callable, and check output."""

        request_id = uuid.uuid4().hex
        input_result = self.check_input(prompt, _request_id=request_id)
        if not input_result.allowed:
            return input_result
        safe_prompt = input_result.output_text or ""
        if self.llm_fn is None:
            return self._error_result(
                request_id=request_id,
                stage=Stage.OUTPUT,
                code="llm_not_configured",
                input_text=safe_prompt,
            )

        try:
            answer = self.llm_fn(safe_prompt)
        except Exception:
            return self._error_result(
                request_id=request_id,
                stage=Stage.OUTPUT,
                code="llm_execution_error",
                input_text=safe_prompt,
            )

        if not isinstance(answer, str):
            return self._error_result(
                request_id=request_id,
                stage=Stage.OUTPUT,
                code="invalid_llm_output_type",
                input_text=safe_prompt,
            )
        return self.check_output(safe_prompt, answer, _request_id=request_id)
