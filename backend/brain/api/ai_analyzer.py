"""
OwelSec AI Analyzer — sends validated findings to an LLM for analysis.

Uses the Groq API (OpenAI-compatible) with Llama 3.3 70B.
"""

import json
import logging
import os

from dotenv import load_dotenv
from openai import OpenAI

# ── Config ───────────────────────────────────────────────────────────────────
load_dotenv()

BASE_URL = "https://api.groq.com/openai/v1"
MODEL = "llama-3.3-70b-versatile"
MAX_FINDINGS = 25           # cap to avoid token overflow
REQUEST_TIMEOUT = 60        # seconds

logger = logging.getLogger("strix.ai_analyzer")


# ── System prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
Tu es un Analyste SOC Senior expert en cybersecurite.
Tu analyses des vulnerabilites validees par le moteur intelligent OwelSec AI.
Tu reponds exclusivement en francais, de maniere claire, structuree et professionnelle.
Utilise du Markdown pour structurer ta reponse (titres, listes, gras, etc.).
"""


def _build_user_prompt(findings: list[dict]) -> str:
    """Format the findings into a structured prompt for the LLM."""
    payload = json.dumps(findings, indent=2, ensure_ascii=False)
    return f"""\
Voici les resultats d'analyse OwelSec AI :

{payload}

Ta tache :
1. Resume les vulnerabilites confirmees.
2. Ignore ou mentionne brievement les faux positifs.
3. Explique pourquoi elles sont dangereuses.
4. Donne des recommandations techniques precises.
5. Evalue le niveau de risque global (Faible, Moyen, Eleve, Critique).
"""


def analyser_scan(strix_results: list[dict]) -> str:
    """Analyse OwelSec AI results via the configured LLM.

    Returns a Markdown-formatted string with the AI analysis report.
    """
    logger.info("Starting AI analysis on %d findings", len(strix_results))

    if not strix_results:
        return "Aucune vulnerabilite detectee ou confirmee."

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        logger.error("GROQ_API_KEY not set — AI analysis unavailable")
        return "Analyse IA indisponible : la variable d'environnement GROQ_API_KEY est absente."

    client = OpenAI(
        api_key=api_key,
        base_url=BASE_URL,
        timeout=REQUEST_TIMEOUT,
    )

    # Truncate to MAX_FINDINGS to stay within token limits
    truncated = strix_results[:MAX_FINDINGS]
    findings = [
        {
            "type": item.get("type"),
            "url": item.get("url"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "confidence": item.get("confidence"),
            "details": item.get("details"),
        }
        for item in truncated
    ]

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(findings)},
            ],
            temperature=0.2,
        )
        result = response.choices[0].message.content
        logger.info("AI analysis completed (%d chars)", len(result))
        return result

    except Exception as exc:
        logger.exception("LLM request failed: %s", exc)
        return f"Erreur lors de la communication avec l'IA : {exc}"
