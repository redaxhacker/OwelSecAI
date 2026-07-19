"""
OwelSec AI Scanner — Nuclei wrapper.

Prepares scan metadata and executes the Nuclei binary as a subprocess.
Uses optimized flags to reduce scan time from ~8 min to ~2-3 min.
"""

import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path

logger = logging.getLogger("strix.scanner")

BASE_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = BASE_DIR / "data" / "results"

# ── Scan configuration (overridable via .env) ────────────────────────────────
# Severity filter: only scan for these severity levels
# Set to "critical,high,medium,low,info" to scan everything
NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "critical,high,medium,low")

# Concurrency: how many templates to run in parallel (default 25)
NUCLEI_CONCURRENCY = os.getenv("NUCLEI_CONCURRENCY", "50")

# Rate limit: max requests per second (default 150)
NUCLEI_RATE_LIMIT = os.getenv("NUCLEI_RATE_LIMIT", "150")

# Per-request timeout in seconds (NOT the whole scan — just each HTTP request)
NUCLEI_REQUEST_TIMEOUT = os.getenv("NUCLEI_REQUEST_TIMEOUT", "5")


def prepare_scan(url: str) -> dict:
    """Generate a scan_id and output file path without starting the scan."""
    scan_id = str(uuid.uuid4())
    output_file = str(RESULTS_DIR / f"{scan_id}.jsonl")
    logger.info("Prepared scan %s → %s", scan_id, output_file)
    return {
        "scan_id": scan_id,
        "target": url,
        "output_file": output_file,
    }


def run_nuclei_scan(
    url: str,
    scan_id: str | None = None,
    output_file: str | None = None,
) -> dict:
    """Execute a Nuclei scan against *url*.

    The scan is optimized with:
    - Severity filter (skip 'info' by default — saves ~40% time)
    - Higher concurrency (50 parallel templates instead of 25)
    - Per-request timeout (5s — prevents slow templates from hanging)

    Args:
        url:         Target URL.
        scan_id:     Pre-assigned scan ID (or a new UUID is generated).
        output_file: Explicit path for the JSONL output file.

    Returns:
        dict with ``scan_id`` and ``output_file`` keys.

    Raises:
        RuntimeError: If Nuclei is not installed or the scan fails.
    """
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        raise RuntimeError(
            "Nuclei is not available in PATH. "
            "Run OwelSec AI on Ubuntu with nuclei installed."
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    scan_id = scan_id or str(uuid.uuid4())
    output_path = Path(output_file) if output_file else RESULTS_DIR / f"{scan_id}.jsonl"

    command = [
        nuclei_bin,
        "-u", url,
        "-jsonl",
        "-o", str(output_path),
        # ── Performance flags ──────────────────────
        "-severity", NUCLEI_SEVERITY,          # skip 'info' findings by default
        "-concurrency", NUCLEI_CONCURRENCY,    # more parallel templates
        "-rate-limit", NUCLEI_RATE_LIMIT,      # max requests/sec
        "-timeout", NUCLEI_REQUEST_TIMEOUT,    # per-request timeout (seconds)
        "-silent",                              # suppress banner/progress noise
    ]

    logger.info(
        "Running Nuclei: target=%s severity=%s concurrency=%s rate-limit=%s",
        url, NUCLEI_SEVERITY, NUCLEI_CONCURRENCY, NUCLEI_RATE_LIMIT,
    )

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        error_msg = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "Unknown nuclei error"
        )
        logger.error("Nuclei scan %s failed: %s", scan_id, error_msg)
        raise RuntimeError(f"Nuclei scan failed: {error_msg}")

    logger.info("Nuclei scan %s completed → %s", scan_id, output_path)
    return {
        "scan_id": scan_id,
        "output_file": str(output_path),
    }
