"""
OwelSec AI API — Flask application entry point.

Endpoints:
    POST /login              — Authenticate and get JWT token
    POST /scan               — Start a new async vulnerability scan (auth required)
    GET  /scan/<id>          — Poll scan progress and results (auth required)
    GET  /scans              — List all past scans (auth required)
    GET  /scan/<id>/report/csv — Download CSV report (auth required)
    GET  /scan/<id>/report/pdf — Download PDF report (auth required)
    GET  /health             — Liveness check (public)
"""

import ipaddress
import logging
import os
import socket
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Load .env ────────────────────────────────────────────────────────────────
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=ENV_PATH)

# ── Project root on sys.path ─────────────────────────────────────────────────
import sys
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.ai_analyzer import analyser_scan                          # noqa: E402
from api.auth import login_handler, require_auth                   # noqa: E402
from api.report_generator import generate_csv, generate_pdf        # noqa: E402
from core.engine import analyze_and_validate                       # noqa: E402
from db.database import get_db, init_db                            # noqa: E402
from db.models import Scan                                         # noqa: E402
from scanner.nuclei_scanner import prepare_scan, run_nuclei_scan   # noqa: E402

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("strix.api")

# ── Flask app ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

RATE_LIMIT = os.getenv("RATE_LIMIT", "5")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ── Initialize database ─────────────────────────────────────────────────────
init_db()


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_safe_target(url: str) -> tuple[bool, str]:
    """Block scans against localhost, private IPs, and reserved ranges."""
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname found in URL."

        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)

        if ip_obj.is_loopback:
            return False, "Scanning localhost / loopback addresses is not allowed."
        if ip_obj.is_private:
            return False, "Scanning private / internal IP ranges is not allowed."
        if ip_obj.is_reserved:
            return False, "Scanning reserved IP addresses is not allowed."

        return True, "OK"
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {hostname}"
    except Exception as exc:
        return False, f"URL validation error: {exc}"


def _update_scan(scan_id: str, **changes) -> None:
    """Update a scan record in the database."""
    db = get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            for key, value in changes.items():
                setattr(scan, key, value)
            if changes.get("state") in ("completed", "failed"):
                scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Background worker ───────────────────────────────────────────────────────

def execute_scan(scan_id: str, url: str, output_file: str) -> None:
    """Run the full pipeline: Nuclei → OwelSec AI validation → AI analysis."""
    try:
        logger.info("Scan %s started for %s", scan_id, url)
        _update_scan(scan_id, state="running", progress=10, stage="Running Nuclei scan")

        scan_meta = run_nuclei_scan(url, scan_id=scan_id, output_file=output_file)
        logger.info("Scan %s — Nuclei finished", scan_id)
        _update_scan(
            scan_id,
            progress=50,
            stage="Nuclei scan complete — validating findings",
            output_file=scan_meta["output_file"],
        )

        strix_results = analyze_and_validate(scan_meta["output_file"])
        logger.info("Scan %s — validated %d findings", scan_id, len(strix_results))
        _update_scan(
            scan_id,
            progress=80,
            stage="Validation complete — running AI analysis",
            strix_results=strix_results,
        )

        analysis = analyser_scan(strix_results)
        logger.info("Scan %s — AI analysis finished", scan_id)
        _update_scan(
            scan_id,
            state="completed",
            progress=100,
            stage="Scan complete",
            analysis=analysis,
        )
    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        _update_scan(
            scan_id,
            state="failed",
            progress=100,
            stage="Scan failed",
            error=str(exc),
        )


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "owelsec"}), 200


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    return login_handler()


@app.route("/scan", methods=["POST"])
@limiter.limit(f"{RATE_LIMIT} per minute")
@require_auth
def scan():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL — must start with http:// or https://"}), 422

    safe, reason = is_safe_target(url)
    if not safe:
        logger.warning("Blocked target %s — %s", url, reason)
        return jsonify({"error": reason}), 422

    # Prepare scan
    scan_meta = prepare_scan(url)
    scan_id = scan_meta["scan_id"]

    # Persist to database
    db = get_db()
    try:
        new_scan = Scan(
            id=scan_id,
            target=url,
            state="queued",
            progress=1,
            stage="Queued",
            output_file=scan_meta["output_file"],
        )
        db.add(new_scan)
        db.commit()
    finally:
        db.close()

    # Launch background worker
    worker = threading.Thread(
        target=execute_scan,
        args=(scan_id, url, scan_meta["output_file"]),
        daemon=True,
    )
    worker.start()

    logger.info("Scan %s queued for %s", scan_id, url)
    return jsonify({
        "message": "Scan started",
        "scan_id": scan_id,
        "target": url,
        "progress": 1,
        "stage": "Queued",
    }), 202


@app.route("/scan/<scan_id>", methods=["GET"])
@require_auth
def scan_status(scan_id):
    db = get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(scan.to_dict()), 200
    finally:
        db.close()


@app.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    """List all scans, newest first. Supports ?limit=N (default 50)."""
    limit = min(int(request.args.get("limit", 50)), 200)
    db = get_db()
    try:
        scans = (
            db.query(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .all()
        )
        return jsonify([s.to_dict() for s in scans]), 200
    finally:
        db.close()


@app.route("/scan/<scan_id>/report/csv", methods=["GET"])
@require_auth
def download_csv(scan_id):
    db = get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if scan.state != "completed":
            return jsonify({"error": "Scan not yet completed"}), 400

        csv_content = generate_csv(scan.to_dict())
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=owelsec_{scan_id[:8]}.csv"},
        )
    finally:
        db.close()


@app.route("/scan/<scan_id>/report/pdf", methods=["GET"])
@require_auth
def download_pdf(scan_id):
    db = get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if scan.state != "completed":
            return jsonify({"error": "Scan not yet completed"}), 400

        pdf_bytes = generate_pdf(scan.to_dict())
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=owelsec_{scan_id[:8]}.pdf"},
        )
    finally:
        db.close()


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    logger.info("Starting OwelSec AI API on %s:%s", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True)
