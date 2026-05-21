"""
security.py — LLM Application Security Layer
Prompt injection detection, input validation, output sanitisation,
and security event logging for the Medical RAG Chatbot.
"""

import re
import logging
import html
from datetime import datetime

# ─── Security Logger ──────────────────────────────────────────────────────────

logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
security_logger = logging.getLogger("security")


def log_security_event(event_type: str, user_input: str, ip: str) -> None:
    """Log a security event with timestamp, event type, IP, and truncated input."""
    truncated = user_input[:120].replace("\n", " ")
    security_logger.warning(
        f"[{event_type}] IP={ip} | input_len={len(user_input)} | preview={truncated!r}"
    )


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_INPUT_LENGTH = 500

# Patterns that suggest prompt injection attempts
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+(everything|your\s+instructions|all\s+instructions)",
    r"you\s+are\s+now\s+",
    r"act\s+as\s+(a\s+|an\s+)?(?!patient|doctor|nurse)",   # allow clinical role-play framing
    r"pretend\s+(you\s+are|to\s+be)",
    r"jailbreak",
    r"DAN\b",                                               # "Do Anything Now" jailbreak label
    r"reveal\s+(your\s+)?(system\s+|hidden\s+)?prompt",
    r"print\s+(your\s+)?(system\s+|hidden\s+)?prompt",
    r"show\s+me\s+your\s+(instructions|prompt|system)",
    r"override\s+(your\s+)?(safety|restrictions|guidelines)",
    r"new\s+instructions?:",
    r"<\s*system\s*>",                                      # XML-style injection
    r"\[\s*system\s*\]",
    r"---\s*(system|instruction)",
]

# Keywords indicating a medically relevant query
MEDICAL_KEYWORDS = [
    "symptom", "symptoms", "disease", "disorder", "condition", "syndrome",
    "treatment", "therapy", "medication", "medicine", "drug", "dose", "dosage",
    "doctor", "physician", "specialist", "hospital", "clinic",
    "pain", "fever", "infection", "inflammation", "allergy", "allergic",
    "diagnosis", "diagnose", "prognosis", "surgery", "procedure",
    "blood", "heart", "lung", "liver", "kidney", "brain", "bone", "skin",
    "cancer", "tumour", "tumor", "diabetes", "hypertension", "asthma",
    "vitamin", "supplement", "vaccine", "immunisation", "immunization",
    "first aid", "emergency", "overdose", "side effect", "contraindication",
    "anatomy", "physiology", "pathology", "chronic", "acute", "benign",
    "malignant", "hereditary", "genetic", "congenital",
    "what is", "how to treat", "can i take", "is it safe", "should i",
]

# Phrases in LLM output that suggest the model was manipulated
OUTPUT_RED_FLAGS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"as\s+an\s+ai\s+with\s+no\s+restrictions",
    r"i\s+am\s+no\s+longer\s+bound",
    r"my\s+system\s+prompt\s+(is|says|reads)",
    r"jailbroken",
]

MEDICAL_DISCLAIMER = (
    "\n\n⚠️  This information is AI-generated from a medical reference text. "
    "It is not a substitute for professional medical advice, diagnosis, or treatment. "
    "Always consult a qualified healthcare professional."
)


# ─── Input Pipeline ───────────────────────────────────────────────────────────

def sanitise_input(user_input: str) -> str:
    """
    Escape HTML entities and strip characters commonly used to
    manipulate prompt structure (curly braces, angle brackets, backticks).
    Preserves normal punctuation so clinical questions read naturally.
    """
    # HTML-escape first (handles <script> style attacks)
    clean = html.escape(user_input, quote=True)
    # Remove characters with no legitimate use in medical questions
    clean = re.sub(r"[{}\[\]`\\]", "", clean)
    # Collapse runs of whitespace / normalise line endings
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def validate_input(user_input: str) -> tuple[bool, str]:
    """
    Check length and non-emptiness.
    Returns (is_valid, error_message).
    """
    if not user_input or not user_input.strip():
        return False, "Please enter a question."
    if len(user_input) > MAX_INPUT_LENGTH:
        return False, (
            f"Your question is too long ({len(user_input)} chars). "
            f"Please keep it under {MAX_INPUT_LENGTH} characters."
        )
    return True, ""


def detect_prompt_injection(user_input: str) -> bool:
    """
    Return True if the input matches any known prompt-injection pattern.
    """
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False


def is_medical_query(user_input: str) -> bool:
    """
    Return True if the input contains at least one medical keyword.
    Accepts the query if it's a short greeting / clarification (≤ 6 words)
    so follow-up messages like "tell me more" still go through.
    """
    word_count = len(user_input.split())
    if word_count <= 6:
        return True     # short follow-ups are allowed through
    lower = user_input.lower()
    return any(keyword in lower for keyword in MEDICAL_KEYWORDS)


# ─── Output Pipeline ──────────────────────────────────────────────────────────

def sanitise_output(response: str) -> str:
    """
    Check LLM output for red-flag content before forwarding to the client.
    Appends the mandatory medical disclaimer.
    """
    if not response or not response.strip():
        return (
            "I wasn't able to generate a response. "
            "Please try rephrasing your question." + MEDICAL_DISCLAIMER
        )

    for pattern in OUTPUT_RED_FLAGS:
        if re.search(pattern, response, re.IGNORECASE):
            log_security_event("FLAGGED_OUTPUT", response, ip="server-side")
            return (
                "The response was flagged by the safety filter. "
                "Please try a different question." + MEDICAL_DISCLAIMER
            )

    return response.strip() + MEDICAL_DISCLAIMER


# ─── Convenience wrapper ──────────────────────────────────────────────────────

class SecurityResult:
    """Tiny value object returned by run_security_pipeline."""
    __slots__ = ("ok", "error", "clean_input")

    def __init__(self, ok: bool, error: str = "", clean_input: str = ""):
        self.ok = ok
        self.error = error
        self.clean_input = clean_input


def run_security_pipeline(raw_input: str, ip: str = "unknown") -> SecurityResult:
    """
    Run the full input security pipeline in one call.
    Returns a SecurityResult with ok=True and the sanitised input on success,
    or ok=False and an error message to return to the client on failure.
    """
    # Step 1 — sanitise
    clean = sanitise_input(raw_input)

    # Step 2 — validate length / emptiness
    valid, err = validate_input(clean)
    if not valid:
        log_security_event("INVALID_INPUT", raw_input, ip)
        return SecurityResult(ok=False, error=err)

    # Step 3 — injection check
    if detect_prompt_injection(clean):
        log_security_event("PROMPT_INJECTION", raw_input, ip)
        return SecurityResult(ok=False, error="Invalid input detected.")

    # Step 4 — topic relevance
    if not is_medical_query(clean):
        log_security_event("OFF_TOPIC", raw_input, ip)
        return SecurityResult(
            ok=False,
            error="I can only answer medical-related questions. Please rephrase your query.",
        )

    return SecurityResult(ok=True, clean_input=clean)
