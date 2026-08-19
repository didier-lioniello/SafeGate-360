import subprocess
import sys
from importlib.resources import files
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dependency_manifests_and_installed_tools_are_consistent() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_lock.py", "--check-installed"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_packaged_probe_asset_is_addressable() -> None:
    probe_file = files("examples").joinpath("probes.jsonl")

    assert probe_file.is_file()
    assert '"expected_action"' in probe_file.read_text(encoding="utf-8")
