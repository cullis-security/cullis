"""
Regex patterns for the injection detector fast path.

Cover the most common and direct variants of prompt injection.
Not exhaustive — the LLM judge handles ambiguous cases.
"""
import re

# Each pattern is (name, compiled regex)
# The flags re.IGNORECASE and re.UNICODE are applied to all.
_FLAGS = re.IGNORECASE | re.UNICODE

PATTERNS: list[tuple[str, re.Pattern]] = [
    # Direct override instructions
    ("override_instructions",  re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|context)", _FLAGS)),
    ("disregard",              re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?|prompts?)", _FLAGS)),
    ("forget_instructions",    re.compile(r"forget\s+(everything|all|your)\s+(you\s+know|instructions?|rules?|above)", _FLAGS)),
    ("new_instructions",       re.compile(r"(your\s+new\s+instructions?|new\s+task\s+is|from\s+now\s+on\s+(you\s+are|act))", _FLAGS)),

    # Role hijacking
    ("you_are_now",            re.compile(r"you\s+are\s+now\s+(a\s+|an\s+)?(different|new|evil|unrestricted|free)", _FLAGS)),
    ("act_as",                 re.compile(r"(act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as)\s+.{0,40}(without\s+(restriction|limit|filter)|unrestricted|jailbreak)", _FLAGS)),
    ("dan_jailbreak",          re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b|jailbreak", _FLAGS)),

    # System block injection
    ("system_tag",             re.compile(r"<\s*(system|instructions?|prompt)\s*>", _FLAGS)),
    ("human_assistant_tag",    re.compile(r"(Human|Assistant|User)\s*:\s*\n", _FLAGS)),

    # Exfiltration / side channel
    ("leak_prompt",            re.compile(r"(repeat|print|output|reveal|show|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|context)", _FLAGS)),
    ("summarize_instructions", re.compile(r"summarize\s+(your\s+)?(instructions?|system\s+prompt|rules?)", _FLAGS)),

    # Common escape sequences and encoding
    ("null_byte",              re.compile(r"\x00")),
    ("unicode_direction",      re.compile(r"[\u202e\u200f\u200b\u2066\u2067\u2068\u2069]")),
]


def fast_check(text: str) -> tuple[bool, str | None]:
    """
    Check the text against all patterns.
    Returns (True, pattern_name) on match, (False, None) otherwise.
    """
    for name, pattern in PATTERNS:
        if pattern.search(text):
            return True, name
    return False, None


def extract_strings(payload: dict) -> list[str]:
    """
    Recursively extract all string values from a JSON payload.
    Checks only string leaves — numeric/bool values are not injection vectors.
    """
    result: list[str] = []
    stack = list(payload.values())
    while stack:
        val = stack.pop()
        if isinstance(val, str):
            result.append(val)
        elif isinstance(val, dict):
            stack.extend(val.values())
        elif isinstance(val, list):
            stack.extend(val)
    return result


def is_suspicious(payload: dict) -> bool:
    """
    Lightweight heuristics to decide whether the payload warrants the LLM judge.
    Avoids calling the judge on short, clearly structured messages.
    """
    strings = extract_strings(payload)
    total_len = sum(len(s) for s in strings)

    # Very long messages are more likely injection vectors
    if total_len > 300:
        return True

    # Presence of newlines in string values is unusual in structured B2B messages
    if any("\n" in s for s in strings):
        return True

    # Presence of markdown/HTML in values
    if any(re.search(r"[<>]|```|\*\*|#{1,6}\s", s) for s in strings):
        return True

    return False
