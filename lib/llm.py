#!/usr/bin/env python3
"""Tiered LLM + generation client for AutoBounty sub-agents.

Text tiers (each falls through to the next provider on failure):
  fast  -> agnes-3.0-flash  (~1.3s)   bulk triage + report drafting
  deep  -> NVIDIA NIM kimi-k3 / nemotron     critical/high verification
  vulkan-> local Mali-G615 GPU via llama-server (~8 tok/s). Offline-only tier,
          competitive only for SHORT classification jobs. Not available on
          GitHub Actions / HF Spaces runners (no GPU).

Generation:
  image -> agnes-image-2.5-flash (verified working on this account)

NOTE on nvidia/muse-glimmer-30b: listed by the NIM catalog but NOT provisioned for
this account — 404 on both /chat/completions and /images/generations (verified
2026-09-27, see skills/telepi-models-json). Not used.
NOTE on GitHub Copilot Models: models.github.ai answers "OK" to every path from
this network (stub), and api.githubcopilot.com rejects PATs (needs a Copilot JWT
refresh). Left as a TODO provider.
NOTE on HuggingFace inference: monthly free credits are depleted (402). HF is
used for *compute* (HF Spaces runner), not inference.
"""
import json, os, sys, time

_AUTH = os.path.expanduser("~/.pi/agent/auth.json")


def _keys():
    """Keys come from env first (GitHub Actions secrets), then the local
    auth.json on the Termux box."""
    import os
    agnes = os.environ.get("AGNES_API_KEY")
    nvidia = os.environ.get("NVIDIA_API_KEY")
    if not agnes or not nvidia:
        try:
            with open(_AUTH) as f:
                d = json.load(f)
            agnes = agnes or d.get("agnes", {}).get("key")
            nvidia = nvidia or d.get("nvidia", {}).get("key")
        except Exception:
            pass
    return agnes, nvidia


def _chat(url, key, model, messages, max_tokens, temperature, timeout):
    import requests
    r = requests.post(url, headers={"Authorization": f"Bearer {key}",
                                    "Content-Type": "application/json"},
                      json={"model": model, "messages": messages,
                            "max_tokens": max_tokens,
                            "temperature": temperature},
                      timeout=timeout)
    if r.status_code != 200:
        return None
    msg = r.json().get("choices", [{}])[0].get("message", {})
    # NIM reasoning models sometimes emit reasoning_content instead of content
    return (msg.get("content") or msg.get("reasoning_content") or "").strip() or None


def agnes(messages, model, max_tokens, temperature, timeout):
    key, _ = _keys()
    if not key:
        return None
    return _chat("https://apihub.agnes-ai.com/v1/chat/completions", key, model,
                 messages, max_tokens, temperature, timeout)


def nim(messages, model, max_tokens, temperature, timeout):
    _, key = _keys()
    if not key:
        return None
    return _chat("https://integrate.api.nvidia.com/v1/chat/completions", key, model,
                 messages, max_tokens, temperature, timeout)


# Only NIM models proven working on this account (see skills/telepi-models-json).
TIERS = {
    "fast": [("agnes", "agnes-3.0-flash"), ("agnes", "agnes-2.5-pro"),
             ("nim", "z-ai/glm-5.3-flash"), ("nim", "moonshotai/kimi-k3")],
    "deep": [("nim", "moonshotai/kimi-k3"), ("nim", "nvidia/nemotron-3-super-120b-a12b"),
             ("nim", "nvidia/nemotron-3.5-lightning-30b-a3b"),
             ("agnes", "agnes-2.5-pro"), ("vulkan", None)],
    # short classification jobs where the local GPU's ~8 tok/s is competitive
    "vulkan": [("vulkan", None), ("agnes", "agnes-3.0-flash")],
}


def vulkan(messages, model, max_tokens, temperature, timeout):
    """Local GPU (Mali-G615) via llama-server on the Vulkan backend.
    Requires llama-server running locally (scripts/serve_vulkan.sh).
    Returns None when unavailable so the tier falls through."""
    import requests
    url = os.environ.get("LOCAL_LLM_URL", "http://127.0.0.1:8080")
    try:
        r = requests.post(f"{url}/v1/chat/completions",
                          json={"messages": messages, "max_tokens": max_tokens,
                                "temperature": temperature, "stream": False},
                          timeout=timeout)
        if r.status_code == 200:
            return (r.json()["choices"][0]["message"]["content"] or "").strip() or None
    except Exception:
        pass
    return None


PROVIDERS = {"agnes": agnes, "nim": nim, "vulkan": vulkan}


def ask(messages, tier="fast", max_tokens=1600, temperature=0.4, timeout=120):
    """Returns text or None, trying providers in tier order."""
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    for provider, model in TIERS.get(tier, TIERS["fast"]):
        try:
            out = PROVIDERS[provider](messages, model, max_tokens,
                                      temperature, timeout)
            if out:
                return out
        except Exception:
            continue
    return None


def ask_json(messages, tier="fast", max_tokens=800, timeout=120):
    """Ask for structured JSON and return the parsed object, or None.
    temperature=0 + extraction of the first JSON value makes this robust to
    models that leak chain-of-thought before the answer."""
    import re
    text = ask(messages, tier=tier, max_tokens=max_tokens,
               temperature=0.0, timeout=timeout)
    if not text:
        return None
    for m in re.finditer(r"[\[{]", text):
        try:
            val, _ = json.JSONDecoder().raw_decode(text[m.start():])
            if isinstance(val, (dict, list)):
                return val
        except json.JSONDecodeError:
            continue
    return None


# ------------------------------------------------------------------ images
def image(prompt, size="1024x1024", model="agnes-image-2.5-flash", timeout=300):
    """Generate an image; returns the URL or None."""
    import requests
    key, _ = _keys()
    if not key:
        return None
    try:
        r = requests.post("https://apihub.agnes-ai.com/v1/images/generations",
                          headers={"Authorization": f"Bearer {key}",
                                   "Content-Type": "application/json"},
                          json={"model": model, "prompt": prompt,
                                "size": size, "n": 1}, timeout=timeout)
        if r.status_code == 200:
            return r.json()["data"][0].get("url")
    except Exception:
        pass
    return None


def health():
    out = {}
    for tier in ("fast", "deep"):
        t0 = time.time()
        out[tier] = bool(ask("reply with exactly: OK", tier, max_tokens=8, timeout=90))
        out[tier + "_ms"] = round((time.time() - t0) * 1000)
    t0 = time.time()
    out["image"] = bool(image("a blue padlock, dark background"))
    out["image_ms"] = round((time.time() - t0) * 1000)
    return out


if __name__ == "__main__":
    print(json.dumps(health(), indent=1))
