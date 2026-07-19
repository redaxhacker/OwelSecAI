"""
OwelSec AI XSS Validator — active re-verification of reflected XSS findings.

Tests multiple payloads across all query parameters to confirm whether
a reflected XSS is genuine or a false positive.
"""

import logging
import urllib.parse

import requests

logger = logging.getLogger("strix.validator.xss")

# Payloads ordered from most to least common reflection patterns
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
]

REQUEST_TIMEOUT = 8  # seconds


def test_xss(url: str) -> tuple[bool, str]:
    """Test a URL for reflected XSS by injecting payloads into query params.

    Tries every payload against every query parameter. Returns on first
    confirmed reflection.

    Returns:
        (True,  detail_string)  — payload was reflected in response body.
        (False, detail_string)  — no reflection detected or no params to test.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.query:
            return False, "No query parameters to inject."

        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return False, "No query parameters to inject."

        for payload in XSS_PAYLOADS:
            for idx, (target_key, _) in enumerate(params):
                # Inject payload into one parameter at a time
                injected = [
                    (key, payload if i == idx else value)
                    for i, (key, value) in enumerate(params)
                ]
                test_query = urllib.parse.urlencode(injected, doseq=True)
                test_url = urllib.parse.urlunsplit((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    test_query,
                    parsed.fragment,
                ))

                response = requests.get(test_url, timeout=REQUEST_TIMEOUT)

                if payload in response.text:
                    detail = (
                        f"Payload reflected via parameter '{target_key}' "
                        f"(payload: {payload[:30]}…)"
                    )
                    logger.info("XSS CONFIRMED at %s — %s", url, detail)
                    return True, detail

        logger.info("XSS not confirmed at %s (tested %d payloads × %d params)",
                     url, len(XSS_PAYLOADS), len(params))
        return False, (
            f"No reflection detected "
            f"({len(XSS_PAYLOADS)} payloads × {len(params)} parameters tested)."
        )

    except requests.Timeout:
        logger.warning("XSS validation timed out for %s", url)
        return False, "Request timed out during XSS validation."
    except Exception as exc:
        logger.exception("XSS validation error for %s: %s", url, exc)
        return False, f"Validation error: {exc}"
