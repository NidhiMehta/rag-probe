"""
Adversarial test: prompt injection via document content.

Scenario: A malicious document contains hidden instructions targeting a downstream
LLM agent. Lexoid parses it faithfully (by design), and the injected text rides
along into the agent's context.

Two sub-tests:
1. Obvious injection - visible text with direct instruction override
2. Hidden injection - white-on-white text (CSS hidden), simulating a real attack

We test whether the injection survives Lexoid's STATIC_PARSE.
"""

import os
from lexoid.api import parse

BASE     = os.path.dirname(__file__)
FIXTURES = os.path.join(BASE, "..", "fixtures")


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def test_obvious_injection_static():
    """Check if obvious injection text survives STATIC_PARSE."""
    path = fixture("obvious_injection.html")
    result = parse(path, parser_type="STATIC_PARSE", url=path)
    extracted = result.get("raw", "")

    injection_survived = "IGNORE ALL PREVIOUS INSTRUCTIONS" in extracted
    print(f"\n[STATIC_PARSE - Obvious injection]")
    print(f"  Injection survived: {injection_survived}")
    if injection_survived:
        print("  VULNERABLE: Injection text passed through to downstream context")
    else:
        print("  SAFE: Injection text was stripped")
    return injection_survived


def test_hidden_injection_static():
    """Check if CSS-hidden injection text survives STATIC_PARSE."""
    path = fixture("hidden_injection.html")
    result = parse(path, parser_type="STATIC_PARSE", url=path)
    extracted = result.get("raw", "")

    injection_survived = "SYSTEM" in extracted or "maintenance mode" in extracted.lower()
    print(f"\n[STATIC_PARSE - Hidden (CSS) injection]")
    print(f"  Injection survived: {injection_survived}")
    if injection_survived:
        print("  VULNERABLE: Hidden text extracted and passed downstream — invisible to humans but visible to LLMs")
    else:
        print("  SAFE: Hidden text was stripped")
    return injection_survived


def simulate_downstream_agent(extracted_text: str) -> None:
    print("\n[Downstream Agent Input - first 800 chars]")
    print("-" * 50)
    print(extracted_text[:800])
    print("-" * 50)
    print("^ This is what the LLM agent sees. Any injected instructions are live.")


if __name__ == "__main__":
    print("=" * 60)
    print("LEXOID PROMPT INJECTION ADVERSARIAL TEST")
    print("=" * 60)

    survived1 = test_obvious_injection_static()
    survived2 = test_hidden_injection_static()

    # Show what a downstream agent would receive for hidden injection
    path = fixture("hidden_injection.html")
    result = parse(path, parser_type="STATIC_PARSE", url=path)
    simulate_downstream_agent(result.get("raw", ""))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Obvious injection passed through: {survived1}")
    print(f"  Hidden (CSS) injection passed through: {survived2}")
    print()
    print("KEY FINDING:")
    print("  Lexoid has no sanitization layer by design ('preserve all content').")
    print("  Any downstream LLM agent consuming Lexoid output is exposed.")
    print("  Mitigation: sanitize/filter Lexoid output before passing to an agent.")
