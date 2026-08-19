# Contributing

Contributions that improve correctness, test coverage, documentation, or defensive
defaults are welcome.

## Local setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
python scripts/verify_lock.py --check-installed
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m pip_audit --strict -r requirements-dev.txt
python -m build --wheel --no-isolation
```

CI runs the same checks on Python 3.11 and 3.12, regenerates the lock, and smoke-tests
the installed wheel, console entry point, and packaged probe asset. Lint failures are
blocking.

## Updating dependencies

- `requirements.txt` contains exact direct runtime pins.
- `requirements-dev.in` includes the runtime manifest and contains exact direct QA tool
  pins.
- `requirements-dev.txt` is the standard `pip-compile` output paired with
  `requirements-dev.in`; it contains transitive pins and SHA-256 hashes so dependency
  automation can update both files together.

After intentionally reviewing and editing a direct pin, regenerate and verify the lock
with the pinned `pip-tools` version already installed from the current lock. Generate
on Python 3.12 to match CI's reproducibility check:

```bash
CUSTOM_COMPILE_COMMAND='pip-compile --resolver=backtracking --strip-extras --allow-unsafe --generate-hashes --no-emit-index-url --no-emit-trusted-host --output-file=requirements-dev.txt requirements-dev.in' \
  pip-compile --resolver=backtracking --strip-extras --allow-unsafe --generate-hashes \
    --no-emit-index-url --no-emit-trusted-host \
    --output-file=requirements-dev.txt requirements-dev.in
python -m pip install --require-hashes -r requirements-dev.txt
python scripts/verify_lock.py --check-installed
python -m pip_audit --strict -r requirements-dev.txt
```

Keep the `setuptools` pin identical in `pyproject.toml` and
`requirements-dev.in`. Confirm that the exact runtime pin still satisfies the
compatibility metadata in `pyproject.toml`. The lock makes the repository QA inputs
hash-checkable, but does not make the interpreter, operating system, package index, or
initial installer hermetic.

## Fixture safety

- Never commit a live credential, token, private key, customer record, personal email,
  phone number, or other real identifier.
- Build credential- or identifier-shaped test values from clearly synthetic fragments
  at runtime, following `examples/fixtures.py`.
- Do not paste production prompts, system architecture, logs, datasets, or incident
  details into issues, tests, or pull requests.
- Audit output must never include raw inspected text or detector reasons supplied by an
  extension.

## Change expectations

Add regression tests for every behavior change. Detector additions should document
false positives, false negatives, supported formats, and resource cost. Policy changes
should explain the threat model and threshold evidence. New runtime dependencies need a
clear justification and should remain optional where possible.

Report suspected vulnerabilities through the private process in `SECURITY.md`.
