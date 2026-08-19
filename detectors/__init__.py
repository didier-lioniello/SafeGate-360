from .hallucination import detect_hallucination
from .injection import detect_prompt_injection
from .jailbreak import detect_jailbreak
from .pii import detect_pii
from .secrets import detect_secret_input, detect_secret_leak
from .toxicity import detect_toxicity_input, detect_toxicity_output


def detect_output_pii(_input_text: str, output_text: str):
    return detect_pii(output_text, label="pii_leak")


DEFAULT_INPUT_DETECTORS = [
    detect_pii,
    detect_secret_input,
    detect_jailbreak,
    detect_prompt_injection,
    detect_toxicity_input,
]

DEFAULT_OUTPUT_DETECTORS = [
    detect_output_pii,
    detect_secret_leak,
    detect_toxicity_output,
    detect_hallucination,
]

__all__ = [
    "detect_pii",
    "detect_jailbreak",
    "detect_prompt_injection",
    "detect_toxicity_input",
    "detect_toxicity_output",
    "detect_secret_leak",
    "detect_secret_input",
    "detect_hallucination",
    "detect_output_pii",
    "DEFAULT_INPUT_DETECTORS",
    "DEFAULT_OUTPUT_DETECTORS",
]
