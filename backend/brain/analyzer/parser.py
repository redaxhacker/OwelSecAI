"""
OwelSec AI Analyzer — Nuclei JSONL parser.

Reads Nuclei's JSONL output and extracts structured vulnerability records.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("strix.analyzer.parser")


def parse_nuclei_output(file_path: str) -> list[dict]:
    """Parse a Nuclei JSONL file into a list of vulnerability dicts.

    Each dict contains:
        type     — vulnerability / template name (lowercased)
        severity — info / low / medium / high / critical
        url      — matched URL or host
        template — original Nuclei template ID
        tags     — list of tags from the template
        matcher  — matcher name (if available)

    Malformed lines are logged and skipped.
    """
    path = Path(file_path)
    results: list[dict] = []

    if not path.exists():
        logger.warning("JSONL file not found: %s — returning empty results", path)
        return results

    if path.stat().st_size == 0:
        logger.info("JSONL file is empty: %s — no findings", path)
        return results

    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipped malformed JSONL at line %d in %s: %s",
                    line_no, path.name, exc,
                )
                continue

            info = data.get("info", {})
            vuln = {
                "type": info.get("name", "unknown").lower(),
                "severity": info.get("severity", "unknown"),
                "url": data.get("matched-at") or data.get("host", ""),
                "template": data.get("template-id", ""),
                "tags": info.get("tags", []),
                "matcher": data.get("matcher-name", ""),
            }
            results.append(vuln)

    logger.info("Parsed %d findings from %s", len(results), path.name)
    return results
