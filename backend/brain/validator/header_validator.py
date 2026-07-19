"""
OwelSec AI Header Validator — checks for missing HTTP security headers.

Validates whether a URL's response includes recommended security headers
and marks those that are missing.
"""

import logging
from typing import Optional

import requests

logger = logging.getLogger("strix.validator.header")

# Header → (description of what it does, minimum expected value or None)
SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS).",
    "Content-Security-Policy": "Restricts resources the page can load (CSP).",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Prevents clickjacking via iframes.",
    "X-XSS-Protection": "Legacy XSS filter (browser-level).",
    "Referrer-Policy": "Controls Referer header leakage.",
    "Permissions-Policy": "Controls browser features (camera, geolocation, etc.).",
}

REQUEST_TIMEOUT = 8  # seconds


def test_headers(url: str) -> tuple[bool, str]:
    """Check whether *url* returns recommended security headers.

    Returns:
        (True,  detail)  — at least one security header is missing.
        (False, detail)  — all checked headers are present, or request failed.
    """
    try:
        response = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        missing: list[str] = []
        present: list[str] = []

        for header, description in SECURITY_HEADERS.items():
            if header.lower() in headers_lower:
                present.append(header)
            else:
                missing.append(f"{header} — {description}")

        if missing:
            detail = (
                f"{len(missing)} missing security header(s):\n"
                + "\n".join(f"  • {m}" for m in missing)
            )
            logger.info("Header check at %s — %d missing, %d present",
                        url, len(missing), len(present))
            return True, detail

        logger.info("Header check at %s — all %d headers present", url, len(present))
        return False, f"All {len(present)} security headers are present."

    except requests.Timeout:
        logger.warning("Header validation timed out for %s", url)
        return False, "Request timed out during header validation."
    except Exception as exc:
        logger.exception("Header validation error for %s: %s", url, exc)
        return False, f"Validation error: {exc}"
