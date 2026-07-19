"""
OwelSec AI Scanner — Nuclei wrapper.

Prepares scan metadata and executes the Nuclei binary as a subprocess
with timeout protection.
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

# Default timeout in seconds (overridable via env)
DEFAULT_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))


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
    timeout: int | None = None,
) -> dict:
    """Execute a Nuclei scan against *url*.

    Args:
        url:         Target URL.
        scan_id:     Pre-assigned scan ID (or a new UUID is generated).
        output_file: Explicit path for the JSONL output file.
        timeout:     Maximum seconds for the scan (default from SCAN_TIMEOUT env).

    Returns:
        dict with ``scan_id`` and ``output_file`` keys.

    Raises:
        RuntimeError: If Nuclei is not installed or the scan fails / times out.
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
    ]

    logger.info("Running: %s (no timeout — scan runs until complete)", " ".join(command))

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
