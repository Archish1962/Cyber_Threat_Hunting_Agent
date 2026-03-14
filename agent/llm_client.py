"""
llm_client.py - Ollama LLM Integration
---------------------------------------
Handles ALL communication with the local Ollama model (llama3.1:8b).
This module is used in TWO places by the agent:

  1. generate_hypothesis()  → Called right after a rule fires. Turns a raw
                              observation string into a human-like attack
                              scenario description.

  2. generate_incident_report() → Called after the agent has made its final
                                   deterministic decision. Takes the hard facts
                                   (threat type, IP, mitigations) and formats
                                   them into a polished SOC paragraph for the
                                   dashboard. The LLM adds NO new logic here —
                                   it is purely a text formatter.

The AI never makes security decisions. It only talks.

Caching
-------
An in-memory response cache is keyed on (threat_type, source_ip) with a
5-minute TTL (matching the alert cooldown in rules_engine.py).

Why this matters: during a DDoS/flood scenario, multiple rules can fire for
the same attacker IP in the same agent cycle (e.g., DoS Flood + Brute Force +
Auth Scan all trigger at once). Without a cache, every confirmed alert fires
two Ollama calls each — that's 6 calls in one cycle for the same attacker.
With the cache, the first alert pays the cost; the rest get instant responses.

The cache lives in-memory only — it is intentionally NOT persisted to disk.
It resets whenever the agent process restarts, which is the correct behaviour.
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
#                         ~1-3 s/response on GPU, uses ~4.7 GB VRAM.
#   AWS EC2 (CPU only):   set OLLAMA_MODEL=llama3.2:1b in the server env
#                         → uses the smaller model that fits in 8 GB RAM.
# To override locally:  export OLLAMA_MODEL=llama3.2:1b  (or any pulled model)
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# Generation options — tuned for RTX 4060 GPU inference.
# GPU is fast enough that we no longer need to sacrifice quality for speed.
DEFAULT_OPTIONS = {
    "temperature": 0.3,  # low = more focused / deterministic output
    "num_predict": 220,  # enough for 3-4 polished sentences
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_ctx": 2048,  # full context window — no longer a speed concern on GPU
}

# How long to wait for Ollama before giving up (seconds).
# llama3.1:8b on RTX 4060 GPU takes ~1-3 s per response.
# 30 s is generous headroom while still failing fast if something is wrong.
REQUEST_TIMEOUT = 30


# ── In-memory LLM response cache ─────────────────────────────────────────────
#
# Structure:
#   key   → (threat_type: str, source_ip: str, kind: str)
#              where kind is "hyp" (hypothesis) or "rep" (incident report)
#   value → (response_text: str, unix_timestamp: float)
#
# TTL matches the alert cooldown so cached entries expire at the same rate
# as the _already_alerted() guard in rules_engine.py.
#
# This is a plain module-level dict — it is shared across all calls within
# the same agent process and requires no locking (the agent is single-threaded).

_LLM_CACHE: dict[tuple, tuple] = {}

# Two separate TTLs for the two kinds of LLM call:
#
#   Hypothesis (kind="hyp") — answers "what is this IP doing?"
#     Keyed on (source_ip, kind) only — no threat_type.
#     Shared across ALL rules that fire for the same IP in the same window.
#     This is what makes multi-rule same-IP cycles pay only ONE Ollama call.
#     Short TTL (60 s) so the hypothesis stays fresh across adjacent cycles.
#
#   Report (kind="rep") — formatted SOC incident paragraph, threat-type specific.
#     Keyed on (threat_type, source_ip, kind).
#     TTL is 360 s — intentionally 60 s LONGER than the 300 s alert cooldown.
#     This guarantees a cache hit when the same alert re-fires after the
#     cooldown lifts: cooldown expires at t=300, cache expires at t=360,
#     so the re-alert at t=300 still finds a warm cache entry.
_CACHE_HYP_TTL_SECONDS: int = 60  # hypothesis: IP-scoped, short window
_CACHE_REP_TTL_SECONDS: int = 360  # report:     outlasts the 300 s cooldown


def _cache_get(threat_type: str, source_ip: str, kind: str) -> str | None:
    """
    Return a cached LLM response if a fresh entry exists, otherwise None.

    Cache key strategy:
      "hyp" → keyed on (source_ip, kind) only.
              Hypothesis is about what the IP is doing, not which specific
              rule fired. Dropping threat_type from the key lets all rules
              that fire for the same IP in the same cycle share one call.
              TTL = 60 s (_CACHE_HYP_TTL_SECONDS).

      "rep" → keyed on (threat_type, source_ip, kind).
              Reports are threat-type specific (they name the attack in prose).
              TTL = 360 s (_CACHE_REP_TTL_SECONDS) — 60 s longer than the
              300 s alert cooldown — so a re-alert after the cooldown lifts
              still finds a warm cache entry.

    Args:
        threat_type: e.g. "Brute Force Attack"
        source_ip:   e.g. "192.168.1.4"
        kind:        "hyp" for hypothesis, "rep" for incident report
    """
    if not source_ip:
        return None
    if kind == "hyp":
        key = (source_ip, kind)
        ttl = _CACHE_HYP_TTL_SECONDS
    else:
        if not threat_type:
            return None
        key = (threat_type, source_ip, kind)
        ttl = _CACHE_REP_TTL_SECONDS

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
    if not source_ip:
        return
    if kind == "hyp":
        key = (source_ip, kind)
    else:
        if not threat_type:
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


def generate_hypothesis(
    observation: str,
    threat_type: str = "",
    source_ip: str = "",
) -> tuple[str, bool]:
    """
    Step 2 of the agent loop: Hypothesize.

    Takes a plain-English observation produced by the rules engine and asks
    the LLM to identify the most likely attack scenario.  The result is
    stored on the ThreatAlert and shown in the dashboard under
    "AI Hypothesis".

    Cache behaviour:
        If threat_type and source_ip are provided, a cache lookup is
        performed first.  If a fresh entry exists (< 5 min old), the cached
        string is returned immediately without calling Ollama.  This prevents
        redundant calls when multiple rules fire for the same attacker in one
        agent cycle.

    Args:
        observation:  e.g. "45 failed login attempts from IP 192.168.1.4
                           in 60 seconds targeting the 'admin' account."
        threat_type:  Optional — used as part of the cache key.
        source_ip:    Optional — used as part of the cache key.

    Returns:
        A 1-2 sentence hypothesis string, e.g.:
        "This strongly indicates a credential brute-force or dictionary
         attack targeting a privileged account."
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "hyp")
    if cached is not None:
        return cached, True  # served from cache — no Ollama call made

    # ── Build prompt ─────────────────────────────────────────────────────────
    system = (
        "You are a concise SOC analyst assistant. "
        "When given a security observation, respond with ONE to TWO sentences "
        "identifying the most likely attack scenario. "
        "Do not include greetings, bullet points, or extra explanation. "
        "Be direct and technical."
    )
    prompt = (
        f"Security Observation: {observation}\n\n"
        "What is the most likely attack scenario in 1-2 sentences?"
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
) -> tuple[str, bool]:
    """
    Final step of the agent loop: Explain.

    The agent has already made ALL security decisions deterministically.
    This function hands those pre-calculated facts to the LLM and asks it
    to write a polished incident report paragraph for the dashboard.

    The LLM adds NO new logic. It is a text formatter only.

    Cache behaviour:
        Keyed on (threat_type, source_ip).  If the same threat type fires
        again from the same IP within 5 minutes, the cached report is
        returned.  The details dict (counts) may differ slightly between
        calls, but the narrative content is essentially identical — the
        cache trade-off is worth it during high-volume attacks.

    Args:
        threat_type:  "Brute Force Attack", "Endpoint Reconnaissance", etc.
        source_ip:    The attacker's IP address.
        details:      Dict of supporting evidence (counts, endpoints, etc.)
        mitigation:   The exact mitigation string decided by the rules engine.
        hypothesis:   (Optional) The hypothesis generated earlier in the loop.

    Returns:
        A 2-3 sentence professional SOC incident report paragraph.
    """
    # ── Cache lookup ─────────────────────────────────────────────────────────
    cached = _cache_get(threat_type, source_ip, "rep")
    if cached is not None:
        return cached, True  # served from cache — no Ollama call made

    # ── Build prompt ─────────────────────────────────────────────────────────
    IST = timezone(timedelta(hours=5, minutes=30))
    detected_at = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    system = (
        "You are a professional SOC analyst writing a brief incident report. "
        "You will be given structured threat data including the exact detection timestamp. "
        "Summarise the incident in 2-3 sentences: what happened, from where, "
        "and what action is recommended. "
        "Always use the provided Detection Time value exactly as given — never write [date] or any placeholder. "
        "Be factual, professional, and concise. No bullet points."
    )

    details_str = json.dumps(details, indent=None)
    hypothesis_line = f"Analyst Hypothesis: {hypothesis}\n" if hypothesis else ""

    prompt = (
        f"Detection Time: {detected_at}\n"
        f"Threat Type: {threat_type}\n"
        f"Source IP: {source_ip}\n"
        f"Evidence: {details_str}\n"
        f"{hypothesis_line}"
        f"Recommended Mitigation: {mitigation}\n\n"
        "Write a 2-3 sentence incident report paragraph using the exact Detection Time above."
    )

    result = _query_ollama(prompt, system)

    # ── Cache store ──────────────────────────────────────────────────────────
    _cache_set(threat_type, source_ip, "rep", result)

    return result, False  # generated live by Ollama


# ── CLI smoke-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    """
    Quick sanity-check. Run from the agent/ directory:
        python llm_client.py
    """
    print("=" * 60)
    print("LLM Client Smoke Test")
    print("=" * 60)

    # 1. Health check
    health = check_ollama_health()
    print(f"[Health] Status : {health['status'].upper()}")
    print(f"[Health] Message: {health['message']}")
    print()

    if health["status"] == "error":
        print("Cannot run tests — Ollama is not reachable.")
        exit(1)

    # 2. Hypothesis test (first call — hits Ollama)
    print("[Test 1] Generating hypothesis (live call)...")
    obs = (
        "52 failed login attempts from IP 192.168.1.4 "
        "in 60 seconds targeting the 'admin' account."
    )
    hyp, hyp_cached = generate_hypothesis(
        obs, threat_type="Brute Force Attack", source_ip="192.168.1.4"
    )
    print(f"  Observation : {obs}")
    print(f"  From cache  : {hyp_cached}")
    print(f"  Hypothesis  : {hyp}")
    print()

    # 3. Hypothesis test (second call — should hit cache)
    print(
        "[Test 2] Generating hypothesis again for same (threat_type, source_ip) — should be cached..."
    )
    t0 = time.time()
    hyp2, hyp2_cached = generate_hypothesis(
        obs, threat_type="Brute Force Attack", source_ip="192.168.1.4"
    )
    elapsed = time.time() - t0
    print(
        f"  Elapsed     : {elapsed:.4f}s  ({'CACHE HIT ✓' if hyp2_cached else 'cache miss — unexpected'})"
    )
    print(f"  Hypothesis  : {hyp2}")
    print()

    # 4. Incident report test (first call — hits Ollama)
    print("[Test 3] Generating incident report (live call)...")
    report, rep_cached = generate_incident_report(
        threat_type="Brute Force Attack",
        source_ip="192.168.1.4",
        details={"failed_attempts": 52, "target_user": "admin", "window_seconds": 60},
        mitigation="Block IP 192.168.1.4 at firewall level and enforce immediate password reset.",
        hypothesis=hyp,
    )
    print(f"  From cache  : {rep_cached}")
    print(f"  Report: {report}")
    print()

    # 5. Incident report test (second call — should hit cache)
    print("[Test 4] Generating report again for same IP — should be cached...")
    t0 = time.time()
    report2, rep2_cached = generate_incident_report(
        threat_type="Brute Force Attack",
        source_ip="192.168.1.4",
        details={"failed_attempts": 99, "target_user": "admin", "window_seconds": 60},
        mitigation="Block IP 192.168.1.4 at firewall level and enforce immediate password reset.",
        hypothesis=hyp,
    )
    elapsed = time.time() - t0
    print(
        f"  Elapsed : {elapsed:.4f}s  ({'CACHE HIT ✓' if rep2_cached else 'cache miss — unexpected'})"
    )
    print(f"  Report  : {report2}")
    print()

    print("Smoke test complete.")
