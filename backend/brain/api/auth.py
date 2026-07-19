"""
OwelSec AI Authentication — JWT-based admin login.

Single-admin model: credentials are set in .env.
Endpoints:
    POST /login  — returns JWT token
All other endpoints are protected by @require_auth.
"""

import functools
import hashlib
import hmac
import logging
import os
import time

import jwt
from dotenv import load_dotenv
from flask import jsonify, request

load_dotenv()
logger = logging.getLogger("strix.auth")

# ── Config ───────────────────────────────────────────────────────────────────
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))


def _check_credentials(username: str, password: str) -> bool:
    """Constant-time comparison of credentials against .env values."""
    if not ADMIN_PASSWORD:
        logger.error("ADMIN_PASSWORD not set in .env — login disabled")
        return False
    user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
    pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)
    return user_ok and pass_ok


def create_token(username: str) -> str:
    """Generate a JWT token for the given username."""
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + (JWT_EXPIRY_HOURS * 3600),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    """Decode and verify a JWT token. Returns payload or None."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token presented")
        return None
    except jwt.InvalidTokenError as exc:
        logger.warning("Invalid token: %s", exc)
        return None


def require_auth(fn):
    """Decorator to protect endpoints with JWT authentication."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]  # strip "Bearer "
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        return fn(*args, **kwargs)
    return wrapper


def login_handler():
    """Handle POST /login requests."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 422

    if not _check_credentials(username, password):
        logger.warning("Failed login attempt for user: %s", username)
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(username)
    logger.info("User %s logged in successfully", username)
    return jsonify({
        "message": "Login successful",
        "token": token,
        "expires_in": JWT_EXPIRY_HOURS * 3600,
    }), 200
