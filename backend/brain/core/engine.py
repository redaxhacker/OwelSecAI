"""
OwelSec AI Core Engine — parses scan results, dispatches to validators, and
produces a structured list of findings with validation status.

The validator registry maps Nuclei finding keywords to validator functions.
To add a new validator, simply add an entry to VALIDATOR_REGISTRY.
"""

import logging

from analyzer.parser import parse_nuclei_output
from validator.header_validator import test_headers
from validator.tls_validator import test_tls
from validator.xss_validator import test_xss

logger = logging.getLogger("strix.core.engine")


# ── Validator Registry ───────────────────────────────────────────────────────
# Maps a keyword (matched against the finding "type" field) to a validator fn.
# Each validator must accept a URL string and return (bool, str).
VALIDATOR_REGISTRY: list[tuple[str, callable]] = [
    ("xss",                test_xss),
    ("header",             test_headers),
    ("security-headers",   test_headers),
    ("missing-headers",    test_headers),
    ("tls",                test_tls),
    ("ssl",                test_tls),
    ("cipher",             test_tls),
    ("deprecated tls",     test_tls),
    ("weak cipher",        test_tls),
]


def _find_validator(finding_type: str):
    """Return the first matching validator function for a finding type, or None."""
    finding_type_lower = finding_type.lower()
    for keyword, validator_fn in VALIDATOR_REGISTRY:
        if keyword in finding_type_lower:
            return validator_fn
    return None


def analyze_and_validate(nuclei_file: str) -> list[dict]:
    """Parse Nuclei output and validate each finding.

    For each finding, the engine:
      1. Looks up a validator in VALIDATOR_REGISTRY by keyword match.
      2. If a validator exists, runs it and sets status/confidence accordingly.
      3. If no validator exists, marks the finding as "unverified".

    Returns:
        List of enriched finding dicts.
    """
    parsed = parse_nuclei_output(nuclei_file)
    logger.info("Validating %d findings from %s", len(parsed), nuclei_file)

    final_results: list[dict] = []

    for vuln in parsed:
        result = {
            "type": vuln["type"],
            "url": vuln["url"],
            "severity": vuln["severity"],
            "template": vuln.get("template", ""),
            "tags": vuln.get("tags", []),
            "status": "unverified",
            "confidence": 0.5,
            "details": "",
        }

        validator_fn = _find_validator(vuln["type"])

        if validator_fn:
            try:
                confirmed, detail = validator_fn(vuln["url"])
                if confirmed:
                    result["status"] = "confirmed"
                    result["confidence"] = 0.95
                else:
                    result["status"] = "false_positive"
                    result["confidence"] = 0.2
                result["details"] = detail
                logger.info(
                    "  %-30s → %s (confidence=%.2f)",
                    vuln["type"][:30], result["status"], result["confidence"],
                )
            except Exception as exc:
                result["details"] = f"Validator error: {exc}"
                logger.exception("Validator failed for %s: %s", vuln["type"], exc)
        else:
            result["details"] = "No validator available for this finding type."
            logger.debug("  %-30s → skipped (no validator)", vuln["type"][:30])

        final_results.append(result)

    confirmed = sum(1 for r in final_results if r["status"] == "confirmed")
    false_pos = sum(1 for r in final_results if r["status"] == "false_positive")
    unverified = sum(1 for r in final_results if r["status"] == "unverified")

    logger.info(
        "Validation complete: %d confirmed, %d false positives, %d unverified",
        confirmed, false_pos, unverified,
    )

    return final_results
