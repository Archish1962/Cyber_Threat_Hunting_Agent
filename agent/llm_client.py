"""
llm_client.py - Ollama LLM Integration
---------------------------------------
Handles ALL communication with the local Ollama model (llama3.2:1b).
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
"""

import json

import requests

# ── Ollama connection settings ──────────────────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"  # used for health-check

# Optimised for RTX 4060 (8 GB VRAM). Run once to download:  ollama pull llama3.1:8b
# Uses ~4.7 GB VRAM — fits the 8 GB card with ~3 GB to spare.
# Ollama automatically detects and uses the GPU (CUDA) — no config needed.
# Response time: ~1-3 s per call on GPU (was 20-40 s on CPU).
MODEL_NAME = "llama3.1:8b"

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
        {"status": "ok",      "message": "Ollama is running with model llama3.2:1b"}
        {"status": "warning", "message": "Ollama is running but llama3.2:1b is not pulled yet."}
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
        # Model names can be "llama3.2:1b" or "llama3.2:1b-instruct-q4_K_M" etc.
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


def generate_hypothesis(observation: str) -> str:
    """
    Step 2 of the agent loop: Hypothesize.

    Takes a plain-English observation produced by the rules engine and asks
    the LLM to identify the most likely attack scenario.  The result is
    stored on the ThreatAlert and shown in the dashboard under
    "AI Hypothesis".

    Args:
        observation: e.g. "45 failed login attempts from IP 192.168.1.4
                          in 60 seconds targeting the 'admin' account."

    Returns:
        A 1-2 sentence hypothesis string, e.g.:
        "This strongly indicates a credential brute-force or dictionary
         attack targeting a privileged account."
    """
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
    return _query_ollama(prompt, system)


def generate_incident_report(
    threat_type: str,
    source_ip: str,
    details: dict,
    mitigation: str,
    hypothesis: str = "",
) -> str:
    """
    Final step of the agent loop: Explain.

    The agent has already made ALL security decisions deterministically.
    This function hands those pre-calculated facts to the LLM and asks it
    to write a polished incident report paragraph for the dashboard.

    The LLM adds NO new logic. It is a text formatter only.

    Args:
        threat_type:  "Brute Force Attack", "Endpoint Reconnaissance", etc.
        source_ip:    The attacker's IP address.
        details:      Dict of supporting evidence (counts, endpoints, etc.)
        mitigation:   The exact mitigation string decided by the rules engine.
        hypothesis:   (Optional) The hypothesis generated earlier in the loop.

    Returns:
        A 2-3 sentence professional SOC incident report paragraph.
    """
    system = (
        "You are a professional SOC analyst writing a brief incident report. "
        "You will be given structured threat data. "
        "Summarise the incident in 2-3 sentences: what happened, from where, "
        "and what action is recommended. "
        "Be factual, professional, and concise. No bullet points."
    )

    details_str = json.dumps(details, indent=None)
    hypothesis_line = f"Analyst Hypothesis: {hypothesis}\n" if hypothesis else ""

    prompt = (
        f"Threat Type: {threat_type}\n"
        f"Source IP: {source_ip}\n"
        f"Evidence: {details_str}\n"
        f"{hypothesis_line}"
        f"Recommended Mitigation: {mitigation}\n\n"
        "Write a 2-3 sentence incident report paragraph."
    )
    return _query_ollama(prompt, system)


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

    # 2. Hypothesis test
    print("[Test 1] Generating hypothesis...")
    obs = (
        "52 failed login attempts from IP 192.168.1.4 "
        "in 60 seconds targeting the 'admin' account."
    )
    hyp = generate_hypothesis(obs)
    print(f"  Observation : {obs}")
    print(f"  Hypothesis  : {hyp}")
    print()

    # 3. Incident report test
    print("[Test 2] Generating incident report...")
    report = generate_incident_report(
        threat_type="Brute Force Attack",
        source_ip="192.168.1.4",
        details={"failed_attempts": 52, "target_user": "admin", "window_seconds": 60},
        mitigation="Block IP 192.168.1.4 at firewall level and enforce immediate password reset.",
        hypothesis=hyp,
    )
    print(f"  Report: {report}")
    print()
    print("Smoke test complete.")
