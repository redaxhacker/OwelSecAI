"""
OwelSec AI TLS Validator — checks for deprecated TLS versions and weak cipher suites.

Uses an SSL socket connection to determine the negotiated TLS version and
cipher, then flags deprecated protocols (TLS 1.0, 1.1, SSLv3).
"""

import logging
import socket
import ssl
import urllib.parse

logger = logging.getLogger("strix.validator.tls")

DEPRECATED_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHERS_KEYWORDS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"}

CONNECT_TIMEOUT = 8  # seconds


def test_tls(url: str) -> tuple[bool, str]:
    """Check TLS version and cipher suite for *url*.

    Returns:
        (True,  detail)  — deprecated TLS or weak cipher detected.
        (False, detail)  — TLS looks fine, or connection failed.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return False, "Not an HTTPS URL — TLS validation skipped."

        context = ssl.create_default_context()
        # We want to detect, not block — so allow older protocols for detection
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                protocol = tls_sock.version()
                cipher_info = tls_sock.cipher()  # (name, protocol, bits)

        issues: list[str] = []

        # Check protocol version
        if protocol in DEPRECATED_PROTOCOLS:
            issues.append(f"Deprecated TLS version: {protocol}")

        # Check cipher suite
        if cipher_info:
            cipher_name = cipher_info[0]
            cipher_bits = cipher_info[2]
            for weak in WEAK_CIPHERS_KEYWORDS:
                if weak in cipher_name.upper():
                    issues.append(f"Weak cipher suite: {cipher_name}")
                    break
            if cipher_bits and cipher_bits < 128:
                issues.append(f"Weak key length: {cipher_bits} bits (< 128)")

        if issues:
            detail = "TLS issues detected:\n" + "\n".join(f"  • {i}" for i in issues)
            logger.info("TLS check at %s:%d — %d issue(s)", hostname, port, len(issues))
            return True, detail

        detail = f"TLS OK — {protocol}, cipher: {cipher_info[0] if cipher_info else 'unknown'}"
        logger.info("TLS check at %s:%d — %s", hostname, port, detail)
        return False, detail

    except socket.timeout:
        logger.warning("TLS validation timed out for %s", url)
        return False, "Connection timed out during TLS validation."
    except Exception as exc:
        logger.exception("TLS validation error for %s: %s", url, exc)
        return False, f"TLS validation error: {exc}"
