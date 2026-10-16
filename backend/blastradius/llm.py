"""Minimal Gemini JSON-mode client used at BUILD time (extraction). Runtime chat lives in agent.py.

Model chain mirrors agent.py: an overloaded or retired model falls through to the next one."""
import json
import os
import time

import httpx

from .agent import FALLBACK_MODELS


def generate_json(prompt: str, schema: dict, system: str = "") -> dict | list:
    key = os.environ["GEMINI_API_KEY"]
    models = [m for m in [os.getenv("GEMINI_MODEL"), *FALLBACK_MODELS] if m]
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseSchema": schema, "temperature": 0}}
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    last = None
    for attempt in range(3):
        for m in models:
            try:
                r = httpx.post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                               headers={"x-goog-api-key": key}, json=body, timeout=45)
            except httpx.HTTPError as e:
                last = f"{m}: {type(e).__name__}"
                continue
            if r.status_code == 200:
                return json.loads(r.json()["candidates"][0]["content"]["parts"][0]["text"])
            last = f"{m}: HTTP {r.status_code} {r.text[:160]}"
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(last)
