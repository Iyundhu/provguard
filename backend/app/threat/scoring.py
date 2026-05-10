"""
Risk scoring orchestrator.

Combines the three sub-scores (provenance, threat intelligence, behavioral)
into a single weighted score and a final decision: TRUSTED / SUSPICIOUS / MALICIOUS.

This is where the project's thesis crystallises: provenance + preemptive threat
analysis = trust by verification.
"""
from app.config import settings


def combine_scores(
    provenance_score: float,
    threat_score: float,
    behavioral_score: float
) -> float:
    """Weighted combination. Weights are configured in settings."""
    return (
        settings.WEIGHT_THREAT_INTEL * threat_score
        + settings.WEIGHT_PROVENANCE * provenance_score
        + settings.WEIGHT_BEHAVIORAL * behavioral_score
    )


def decide(final_score: float, threat_verdict: str, behavioral_flags: list[str]) -> str:
    """
    Produce a final decision.

    Hard overrides:
      - VirusTotal verdict MALICIOUS => always MALICIOUS
      - EICAR test signature => always MALICIOUS
      - Embedded PE header in non-executable => always MALICIOUS

    Otherwise use score thresholds.
    """
    # Hard overrides for clear-cut cases
    if threat_verdict == "MALICIOUS":
        return "MALICIOUS"
    if "eicar_test_signature" in behavioral_flags:
        return "MALICIOUS"
    if "embedded_pe_header" in behavioral_flags:
        return "MALICIOUS"

    # Threshold-based decision
    if final_score >= settings.TRUSTED_THRESHOLD:
        return "TRUSTED"
    elif final_score >= settings.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    else:
        return "MALICIOUS"


def explain_decision(decision: str) -> str:
    """Human-readable explanation of what each decision means."""
    explanations = {
        "TRUSTED": (
            "File passed all verification checks. Provenance is intact, "
            "threat intelligence shows no known threats, and no suspicious "
            "behavioral patterns were found. Safe to admit."
        ),
        "SUSPICIOUS": (
            "File raised one or more concerns. Provenance is weak, threat "
            "intelligence is inconclusive, or behavioral patterns are unusual. "
            "Recommend quarantine and manual review."
        ),
        "MALICIOUS": (
            "File matches known threats or shows definitive malicious patterns. "
            "Block and log. Do not open or execute."
        )
    }
    return explanations.get(decision, "Unknown decision state.")
