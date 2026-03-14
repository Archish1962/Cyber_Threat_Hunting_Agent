"""
llm_client.py - Ollama LLM Integration
---------------------------------------
Handles ALL communication with the local Ollama model (llama3.1:8b).
This module is used in TWO places by the agent:

  1. generate_hypothesis()  → Called right after a rule fires. Turns a raw
                              observation string into a human-like attack
                              scenario description.  The threat type is passed
                              explicitly so the LLM knows exactly which of the
                              8 attack categories it is annotating.

  2. generate_incident_report() → Called after the agent has made its final
                                   deterministic decision. Takes the hard facts
                                   (threat type, IP, observation, mitigations)
                                   and formats them into a polished SOC
                                   paragraph for the dashboard. The LLM adds
                                   NO new logic here — it is purely a text
                                   formatter.

The AI never makes security decisions. It only talks.

Caching
-------
Both hypothesis and incident-report responses are cached in memory, keyed on
(threat_type, source_ip, kind) with separate TTLs:

  "hyp" → 60 s  (_CACHE_HYP_TTL_SECONDS)
  "rep" → 360 s (_CACHE_REP_TTL_SECONDS)

IMPORTANT — why threat_type is part of the hypothesis key
----------------------------------------------------------
An earlier version keyed the hypothesis cache on (source_ip, kind) only,
intentionally sharing one Ollama call across all rules that fire for the same
IP in a single cycle.  That optimisation is incorrect when *different* threat
types fire for the same IP (e.g. Brute Force + Credential Stuffing + Auth Scan
all from 192.168.1.4 in the same 5-second poll).  Without threat_type in the
key every subsequent alert gets the cached hypothesis from the first rule that
fired — completely wrong context for the dashboard.

The fix: key on (threat_type, source_ip, kind) for both hypothesis and report.
Each unique (attack-type, attacker-IP) pair now gets its own targeted Ollama
call the first time and a cache hit on the second.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import requests

# ── Ollama connection settings ──────────────────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"  # used for health-check

# Model is configured via the OLLAMA_MODEL environment variable so the same
# codebase works on different machines without any code changes:
#   Local (RTX 4060 GPU): env var not set → falls back to "llama3.1:8b"
#   AWS EC2 (CPU only):   set OLLAMA_MODEL=llama3.2:1b in the server env
# To override locally:  export OLLAMA_MODEL=llama3.2:1b  (or any pulled model)
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# Generation options — tuned for RTX 4060 GPU inference.
DEFAULT_OPTIONS = {
    "temperature": 0.3,  # low = more focused / deterministic output
    "num_predict": 250,  # enough for 3-4 polished sentences
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_ctx": 2048,  # full context window — no longer a speed concern on GPU
}

# How long to wait for Ollama before giving up (seconds).
# llama3.1:8b on RTX 4060 GPU takes ~1-3 s per response.
REQUEST_TIMEOUT = 30


# ── In-memory LLM response cache ─────────────────────────────────────────────
#
# Structure:
#   key   → (threat_type: str, source_ip: str, kind: str)
#              where kind is "hyp" (hypothesis) or "rep" (incident report)
#   value → (response_text: str, unix_timestamp: float)
#
# Both "hyp" and "rep" use the same three-part key so that:
#   • Multiple different threat types firing for the same IP each get their
#     own hypothesis — no cross-contamination between attack categories.
#   • The per-threat-type report cache still outlasts the 300 s alert cooldown
#     (TTL = 360 s) so a re-alert finds a warm cache entry.
#
# This is a plain module-level dict — it is shared across all calls within
# the same agent process and requires no locking (the agent is single-threaded).

_LLM_CACHE: dict[tuple, tuple] = {}

# Hypothesis TTL — 60 s is short enough to stay fresh across adjacent cycles
# while still preventing duplicate calls within the same 5-second poll window.
_CACHE_HYP_TTL_SECONDS: int = 60

# Report TTL — intentionally 60 s LONGER than the 300 s alert cooldown.
# This guarantees a cache hit when the same alert re-fires after the cooldown
# lifts: cooldown expires at t=300, cache expires at t=360, so the re-alert
# at t=300 still finds a warm cache entry.
_CACHE_REP_TTL_SECONDS: int = 360


def _cache_get(threat_type: str, source_ip: str, kind: str) -> str | None:
    """
    Return a cached LLM response if a fresh entry exists, otherwise None.

    Cache key: (threat_type, source_ip, kind) for BOTH hypothesis and report.

    Including threat_type in the hypothesis key ensures that when multiple
    different attack types fire for the same IP in the same agent cycle
    (e.g. Brute Force + Credential Stuffing + DoS Flood all from 10.0.0.5),
    each one gets its own correctly-contextualised Ollama call rather than
    every alert after the first receiving the cached response of whichever
    rule happened to fire first.

    TTL:
      "hyp" → _CACHE_HYP_TTL_SECONDS (60 s)
      "rep" → _CACHE_REP_TTL_SECONDS (360 s)

    Args:
        threat_type: e.g. "Brute Force Attack"
        source_ip:   e.g. "192.168.1.4"
        kind:        "hyp" for hypothesis, "rep" for incident report

    Returns:
        Cached response string, or None if no valid entry exists.
    """
    if not source_ip or not threat_type:
        return None

    key = (threat_type, source_ip, kind)
    ttl = _CACHE_HYP_TTL_SECONDS if kind == "hyp" else _CACHE_REP_TTL_SECONDS

    entry = _LLM_CACHE.get(key)
    if entry is None:
        return None

    text, ts = entry
    if (time.time() - ts) < ttl:
        return text

    # Expired — evict so the dict doesn't grow unboundedly
    del _LLM_CACHE[key]
    return None


def _cache_set(threat_type: str, source_ip: str, kind: str, value: str) -> None:
    """Store a fresh LLM response in the cache using the same key logic as _cache_get."""
    if not source_ip or not threat_type:
        return
    key = (threat_type, source_ip, kind)
    _LLM_CACHE[key] = (value, time.time())


# ── Internal helpers ─────────────────────────────────────────────────────────


def _is_ollama_running() -> bool:
    """Quick ping to see if the Ollama server is up."""
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=3)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def _query_ollama(prompt: str, system_prompt: str = "") -> str:
    """
    Low-level POST to the Ollama /api/generate endpoint.

    Returns the model's response text, or a fallback string if the
    server is unreachable / returns an error.  The agent continues
    working even when the LLM is offline — it just loses the pretty
    text formatting.
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,  # wait for full response before returning
        "options": DEFAULT_OPTIONS,
    }

    try:
        response = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
        text = result.get("response", "").strip()
        return text if text else "[LLM returned an empty response]"

    except requests.exceptions.ConnectionError:
        return "[LLM Offline] Could not reach Ollama. Is it running? → ollama serve"
    except requests.exceptions.Timeout:
        return f"[LLM Timeout] Model took longer than {REQUEST_TIMEOUT}s to respond."
    except requests.exceptions.HTTPError as e:
        return f"[LLM HTTP Error] {e}"
    except (KeyError, json.JSONDecodeError) as e:
        return f"[LLM Parse Error] Unexpected response format: {e}"
    except Exception as e:
        return f"[LLM Unknown Error] {e}"


# ── Public API ────────────────────────────────────────────────────────────────


def check_ollama_health() -> dict:
    """
    Returns a status dict so main.py can log a friendly startup message.

    Example return values:
        {"status": "ok",      "message": "Ollama is running with model llama3.1:8b"}
        {"status": "warning", "message": "Ollama is running but llama3.1:8b is not pulled yet."}
        {"status": "error",   "message": "Cannot connect to Ollama on localhost:11434"}
    """
    if not _is_ollama_running():
        return {
            "status": "error",
            "message": (
                f"Cannot connect to Ollama on {OLLAMA_BASE_URL}. "
                "Make sure it is installed and run: ollama serve"
            ),
        }

    # Check that our specific model is available locally
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=3)
        models = [m["name"] for m in r.json().get("models", [])]
        # Model names can be "llama3.1:8b" or "llama3.1:8b-instruct-q4_K_M" etc.
        model_present = any(MODEL_NAME.split(":")[0] in m for m in models)
        if model_present:
            return {
                "status": "ok",
                "message": f"Ollama is running with model {MODEL_NAME} ✓",
            }
        else:
            return {
                "status": "warning",
                "message": (
                    f"Ollama is running but '{MODEL_NAME}' is not pulled yet. "
                    f"Run: ollama pull {MODEL_NAME}"
                ),
            }
    except Exception:
        return {"status": "ok", "message": "Ollama is running (model check skipped)."}


# ── Per-threat-type hypothesis context ───────────────────────────────────────
# These one-line descriptions are injected into the hypothesis system prompt
# so the LLM immediately understands which of the 8 attack categories it is
# analysing — without having to infer it from the observation alone.

_THREAT_CONTEXT: dict[str, str] = {
    "Brute Force Attack": (
        "A brute force attack is an automated, repeated attempt to guess "
        "credentials by cycling through passwords against a single target account."
    ),
    "Endpoint Reconnaissance": (
        "Endpoint reconnaissance involves systematically probing restricted or "
        "admin paths to map the application's attack surface before a deeper intrusion."
    ),
    "Unauthorized Access Scan": (
        "An unauthorized access scan is a broad sweep of application endpoints "
        "to find weakly-protected resources, identified by a flood of 401/403 responses."
    ),
    "Credential Stuffing": (
        "Credential stuffing uses a leaked credentials list to test many different "
        "usernames against the login endpoint — each attempt uses a distinct account, "
        "unlike brute force which hammers a single account."
    ),
    "Account Takeover": (
        "An account takeover is confirmed when prior failed login attempts from an IP "
        "are followed by a successful authentication — the attacker found a valid credential."
    ),
    "Data Exfiltration": (
        "Data exfiltration is high-volume automated retrieval of data from API or "
        "download endpoints, indicating bulk data theft or scraping."
    ),
    "Path Traversal Attack": (
        "A path traversal attack uses ../ or URL-encoded sequences in request paths "
        "to escape the web root and read arbitrary server-side files (e.g. /etc/passwd)."
    ),
    "DoS Rate Flood": (
        "A denial-of-service rate flood overwhelms the server by sending an extreme "
        "volume of requests per minute from a single IP, exhausting resources."
    ),
}


def generate_hypothesis(
    observation: str,
    threat_type: str = "",
    source_ip: str = "",
) -> tuple[str, bool]:
    """
    Step 2 of the agent loop: Hypothesize.

    Takes the plain-English observation produced by _build_observation() and
    asks the LLM to explain what this specific attack is doing and why it is
    dangerous.  Unlike the old version, the threat_type is injected into both
    the system prompt (via _THREAT_CONTEXT) and the user prompt, so the LLM
    produces a precisely-targeted explanation for each of the 8 attack categories
    rather than a generic guess.

    Cache behaviour:
        Keyed on (threat_type, source_ip, "hyp") — TTL 60 s.
        Each unique (attack-type, IP) pair caches independently, so Brute Force
        and Credential Stuffing firing from the same IP in the same cycle each
        get their own correctly-contextualised hypothesis.

    Args:
        observation:  Plain-English summary from _build_observation(), e.g.:
                      "45 failed login attempts from IP 192.168.1.4 in 60 s
                       targeting account(s): admin."
        threat_type:  One of the 8 canonical threat-type strings.
        source_ip:    The attacker's IP — used as part of the cache key.

    Returns:
        (hypothesis_text, from_cache)
        hypothesis_text: 1-2 sentence explanation of the attack.
        from_cache:      True if the response came from the in-memory cache.
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "hyp")
    if cached is not None:
        return cached, True  # served from cache — no Ollama call made

    # ── Build threat-type-aware prompts ──────────────────────────────────────
    threat_context = _THREAT_CONTEXT.get(
        threat_type,
        "This is a suspicious security event that requires investigation.",
    )

    system = (
        "You are a concise SOC analyst assistant. "
        "You will be given the confirmed detection type and a precise observation "
        "captured from live traffic logs. "
        "Respond with exactly ONE to TWO sentences that explain what the attacker "
        "is doing, why this specific technique is dangerous, and what asset or "
        "capability is at immediate risk. "
        "Do not re-state the detection type label verbatim. "
        "Do not include greetings, bullet points, or extra explanation. "
        "Be direct, technical, and specific to the evidence provided."
    )

    prompt = (
        f"Detection Type: {threat_type}\n"
        f"Attack Context: {threat_context}\n"
        f"Live Observation: {observation}\n\n"
        "In 1-2 sentences, explain what this attacker is doing and the immediate risk."
    )

    result = _query_ollama(prompt, system)

    # ── Cache store ──────────────────────────────────────────────────────────
    _cache_set(threat_type, source_ip, "hyp", result)

    return result, False  # generated live by Ollama


def generate_incident_report(
    threat_type: str,
    source_ip: str,
    details: dict,
    mitigation: str,
    hypothesis: str = "",
    observation: str = "",
) -> tuple[str, bool]:
    """
    Final step of the agent loop: Explain.

    The agent has already made ALL security decisions deterministically.
    This function hands those pre-calculated facts to the LLM and asks it
    to write a polished incident report paragraph for the dashboard.

    The LLM adds NO new logic. It is a text formatter only.

    Compared to the previous version, the prompt now includes:
      • observation  — the plain-English summary from _build_observation(),
                       giving the LLM a narrative starting point specific to
                       the attack type rather than only a raw JSON evidence blob.
      • threat_type  — already included; ensures the report is titled and
                       framed correctly for each of the 8 attack categories.

    Cache behaviour:
        Keyed on (threat_type, source_ip, "rep") — TTL 360 s.
        360 s > 300 s alert cooldown so a re-alert after the cooldown lifts
        still finds a warm cache entry.

    Args:
        threat_type:  "Brute Force Attack", "Endpoint Reconnaissance", etc.
        source_ip:    The attacker's IP address.
        details:      Dict of supporting evidence (counts, endpoints, etc.)
        mitigation:   The exact mitigation string decided by the rules engine.
        hypothesis:   (Optional) The hypothesis generated earlier in the loop.
        observation:  (Optional) Plain-English summary from _build_observation().
                      Included in the prompt for richer, more specific output.

    Returns:
        (report_text, from_cache)
        report_text: 2-3 sentence professional SOC incident report paragraph.
        from_cache:  True if the response came from the in-memory cache.
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "rep")
    if cached is not None:
        return cached, True  # served from cache — no Ollama call made

    # ── Build prompt ─────────────────────────────────────────────────────────
    IST = timezone(timedelta(hours=5, minutes=30))
    detected_at = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    system = (
        "You are a professional SOC analyst writing a concise incident report. "
        "You will receive the confirmed threat type, the exact detection timestamp, "
        "a plain-English observation of the live traffic, supporting evidence, "
        "an analyst hypothesis, and the recommended mitigation. "
        "Write a 2-3 sentence incident report paragraph that covers: "
        "(1) what happened and from which IP, "
        "(2) what the attack technique is and what it targets, "
        "(3) what immediate action should be taken. "
        "Always use the provided Detection Time value exactly as given — "
        "never write [date], [time], or any placeholder. "
        "Be factual, professional, and concise. No bullet points. No headings."
    )

    details_str = json.dumps(details, indent=None)
    observation_line = f"Observation: {observation}\n" if observation else ""
    hypothesis_line = f"Analyst Hypothesis: {hypothesis}\n" if hypothesis else ""

    prompt = (
        f"Detection Time: {detected_at}\n"
        f"Threat Type: {threat_type}\n"
        f"Source IP: {source_ip}\n"
        f"{observation_line}"
        f"Evidence: {details_str}\n"
        f"{hypothesis_line}"
        f"Recommended Mitigation: {mitigation}\n\n"
        "Write a 2-3 sentence incident report paragraph using the exact "
        "Detection Time above and referencing the specific evidence provided."
    )

    result = _query_ollama(prompt, system)

    # ── Cache store ──────────────────────────────────────────────────────────
    _cache_set(threat_type, source_ip, "rep", result)

    return result, False  # generated live by Ollama
