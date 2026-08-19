#!/usr/bin/env python3
"""Verify direct manifests, the pip-tools lock, and installed QA tools."""

from __future__ import annotations

import argparse
import importlib.metadata
import re
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MANIFEST = ROOT / "requirements.txt"
DEV_MANIFEST = ROOT / "requirements-dev.in"
LOCK = ROOT / "requirements-dev.txt"
PYPROJECT = ROOT / "pyproject.toml"

LOCK_COMMAND = (
    "pip-compile --resolver=backtracking --strip-extras --allow-unsafe "
    "--generate-hashes --no-emit-index-url --no-emit-trusted-host "
    "--output-file=requirements-dev.txt requirements-dev.in"
)
REQUIRED_DEV_PINS = {
    "build",
    "packaging",
    "pip",
    "pip-audit",
    "pip-tools",
    "pytest",
    "ruff",
    "setuptools",
}
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\\|$)")


class VerificationError(RuntimeError):
    """Raised when dependency metadata is internally inconsistent."""


def _requirement_lines(path: Path) -> Iterable[str]:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            yield line


def _exact_pin(raw: str, *, source: Path) -> tuple[str, str]:
    try:
        requirement = Requirement(raw)
    except ValueError as exc:
        raise VerificationError(f"invalid requirement in {source.name}: {raw!r}") from exc
    specs = list(requirement.specifier)
    if requirement.url or requirement.extras or len(specs) != 1 or specs[0].operator != "==":
        raise VerificationError(f"{source.name} must contain exact == pins: {raw!r}")
    return canonicalize_name(requirement.name), specs[0].version


def _read_manifest(path: Path, *, require_runtime_include: bool = False) -> dict[str, str]:
    pins: dict[str, str] = {}
    runtime_includes = 0
    for line in _requirement_lines(path):
        if line.startswith(("-r ", "--requirement ")):
            if require_runtime_include and line.split(maxsplit=1)[1] == RUNTIME_MANIFEST.name:
                runtime_includes += 1
                continue
            raise VerificationError(f"unexpected include in {path.name}: {line!r}")
        name, version = _exact_pin(line, source=path)
        if name in pins:
            raise VerificationError(f"duplicate direct pin in {path.name}: {name}")
        pins[name] = version
    if not pins:
        raise VerificationError(f"{path.name} has no direct pins")
    if require_runtime_include and runtime_includes != 1:
        raise VerificationError(f"{path.name} must include {RUNTIME_MANIFEST.name} exactly once")
    return pins


def _read_lock() -> tuple[dict[str, set[str]], list[str]]:
    text = LOCK.read_text(encoding="utf-8")
    expected_header = f"#    {LOCK_COMMAND}"
    if expected_header not in text.splitlines()[:8]:
        raise VerificationError(
            "lock regeneration header is missing or stale; regenerate with the documented command"
        )

    starts: list[tuple[int, str, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        raw = line.removesuffix("\\").strip()
        try:
            requirement = Requirement(raw)
        except ValueError as exc:
            raise VerificationError(f"invalid locked requirement: {raw!r}") from exc
        specs = list(requirement.specifier)
        if requirement.url or requirement.extras or len(specs) != 1 or specs[0].operator != "==":
            raise VerificationError(f"lock entries must use exact == pins: {raw!r}")
        starts.append((index, canonicalize_name(requirement.name), specs[0].version))

    if not starts:
        raise VerificationError(f"{LOCK.name} has no package entries")

    versions: dict[str, set[str]] = {}
    errors: list[str] = []
    for position, (start, name, version) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        if not any(HASH_RE.search(line.strip()) for line in block[1:]):
            errors.append(f"locked requirement has no SHA-256 hash: {name}=={version}")
        versions.setdefault(name, set()).add(version)
    return versions, errors


def _verify_pyproject(
    runtime: dict[str, str], dev: dict[str, str], lock: dict[str, set[str]]
) -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    errors: list[str] = []

    for raw in data["build-system"]["requires"]:
        name, version = _exact_pin(raw, source=PYPROJECT)
        if dev.get(name) != version:
            errors.append(
                f"build-system pin {name}=={version} is not identical in requirements-dev.in"
            )
        if lock.get(name) != {version}:
            errors.append(f"build-system pin {name}=={version} is not identical in the lock")

    project_dependencies = data["project"].get("dependencies", [])
    project_names = {canonicalize_name(Requirement(raw).name) for raw in project_dependencies}
    if project_names != runtime.keys():
        errors.append(
            "requirements.txt names must exactly match project dependencies: "
            f"manifest={sorted(runtime)}, metadata={sorted(project_names)}"
        )

    for raw in project_dependencies:
        requirement = Requirement(raw)
        name = canonicalize_name(requirement.name)
        version = runtime.get(name)
        if version is None:
            errors.append(f"project dependency {name} is missing from requirements.txt")
            continue
        if Version(version) not in requirement.specifier:
            errors.append(
                f"runtime pin {name}=={version} does not satisfy project metadata {raw!r}"
            )
        if lock.get(name) != {version}:
            errors.append(f"runtime pin {name}=={version} is not identical in the lock")
    return errors


def verify(*, check_installed: bool) -> None:
    runtime = _read_manifest(RUNTIME_MANIFEST)
    dev = _read_manifest(DEV_MANIFEST, require_runtime_include=True)
    missing_dev_pins = REQUIRED_DEV_PINS - dev.keys()
    if missing_dev_pins:
        raise VerificationError(
            "requirements-dev.in is missing required direct dependencies: "
            + ", ".join(sorted(missing_dev_pins))
        )

    direct = runtime | dev
    lock, errors = _read_lock()
    for name, version in direct.items():
        if lock.get(name) != {version}:
            errors.append(f"direct pin {name}=={version} is not identical in the lock")
    errors.extend(_verify_pyproject(runtime, dev, lock))

    if check_installed:
        for name, version in direct.items():
            try:
                installed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                errors.append(f"direct dependency is not installed: {name}=={version}")
            else:
                if installed != version:
                    errors.append(
                        f"installed {name} version {installed} does not match direct pin {version}"
                    )

    if errors:
        raise VerificationError("\n".join(errors))

    suffix = " and installed direct dependencies" if check_installed else ""
    print(f"Verified {len(lock)} locked packages, their SHA-256 hashes{suffix}.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-installed",
        action="store_true",
        help="also require installed direct dependencies to match the manifests",
    )
    args = parser.parse_args()
    try:
        verify(check_installed=args.check_installed)
    except VerificationError as exc:
        print(f"dependency verification failed:\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
