"""Camada 2: validacao contextual por LLM.

* Versao do modelo e metadados completos da resposta (modelo efetivamente
  servido, provedor, id da geracao, fingerprint, uso/custo) sao sempre
  registrados (#15 – reprodutibilidade).
* ``explain=True`` (#15 – explicabilidade) exige que o modelo escreva a
  justificativa e o tipo de ataque *antes* da decisao.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import requests

BASE_PROMPT = (
    "You are an Autonomic Security Analyst. Evaluate the provided logs and return "
    "EXCLUSIVELY a JSON object. Do not provide commentary.\n\nRequired Format:\n"
    '{"ataque_detectado": bool, "ip_alvo_bloqueio": "string or N/A"}'
)

EXPLAIN_PROMPT = (
    "You are an Autonomic Security Analyst. Evaluate the provided logs and return "
    "EXCLUSIVELY a JSON object. Do not provide commentary outside the JSON.\n"
    "First write a short justification citing the concrete evidence in the logs "
    "(why it is or is not an attack), then the attack type, and only then the decision.\n\n"
    "Required Format (keys in this order):\n"
    '{"justificativa": "string", "tipo_ataque": "string or N/A", '
    '"ataque_detectado": bool, "ip_alvo_bloqueio": "string or N/A"}'
)


@dataclass
class Decision:
    status: str  # ok | http_error | parse_error | empty | error
    attack_detected: bool = False
    target_ip: str | None = None
    attack_type: str | None = None
    explanation: str | None = None
    latency_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None
    model_returned: str | None = None
    provider: str | None = None
    generation_id: str | None = None
    system_fingerprint: str | None = None
    raw: str | None = None
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


def parse_decision_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "sim"}
    return bool(value)


class LLMAnalyst:
    def __init__(self, cfg):
        self.cfg = cfg
        self.system_prompt = EXPLAIN_PROMPT if cfg.explain else BASE_PROMPT
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if cfg.llm_backend == "openrouter" and not self.api_key:
            raise RuntimeError("OPENROUTER_API_KEY ausente (use llm_backend: mock para testes)")

    def build_payload(self, context: list[dict[str, Any]], header: str = "Observability Data") -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"{header}:\n{json.dumps(context, indent=2, default=str)}"},
            ],
            # Contabilidade de uso/custo do OpenRouter (nao altera a geracao).
            "usage": {"include": True},
        }
        if self.cfg.temperature is not None:
            payload["temperature"] = self.cfg.temperature
        if self.cfg.seed is not None:
            payload["seed"] = self.cfg.seed
        return payload

    def analyze(self, context: list[dict[str, Any]], header: str = "Observability Data") -> Decision:
        payload = self.build_payload(context, header)
        if self.cfg.llm_backend == "mock":
            return self._mock(context, payload)
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        start = time.time()
        try:
            resp = requests.post(self.cfg.llm_base_url, headers=headers, json=payload, timeout=self.cfg.llm_timeout_s)
        except requests.RequestException as exc:
            return Decision(status="error", latency_s=round(time.time() - start, 2), error=str(exc))
        latency = round(time.time() - start, 2)
        if resp.status_code != 200:
            return Decision(status="http_error", latency_s=latency, error=f"{resp.status_code}: {resp.text[:500]}")
        try:
            body = resp.json()
        except ValueError as exc:
            return Decision(status="error", latency_s=latency, error=f"json: {exc}")
        return self._from_body(body, latency)

    def _from_body(self, body: dict[str, Any], latency: float) -> Decision:
        usage = body.get("usage") or {}
        d = Decision(
            status="ok",
            latency_s=latency,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            total_tokens=int(usage.get("total_tokens") or 0),
            cost_usd=usage.get("cost"),
            model_returned=body.get("model"),
            provider=body.get("provider"),
            generation_id=body.get("id"),
            system_fingerprint=body.get("system_fingerprint"),
        )
        choices = body.get("choices") or []
        if not choices:
            d.status, d.error = "error", f"sem choices: {str(body)[:300]}"
            return d
        raw = (choices[0].get("message") or {}).get("content") or ""
        d.raw = raw
        if not raw.strip():
            d.status = "empty"
            return d
        try:
            parsed = parse_decision_json(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            d.status, d.error = "parse_error", str(exc)
            return d
        d.attack_detected = _as_bool(parsed.get("ataque_detectado"))
        ip = parsed.get("ip_alvo_bloqueio")
        d.target_ip = None if ip in (None, "", "N/A", "n/a") else str(ip).strip()
        d.attack_type = parsed.get("tipo_ataque")
        d.explanation = parsed.get("justificativa")
        return d

    # ------------------------------------------------------------------ mock
    SUSPICIOUS = re.compile(r"(\.\./|%2e|union|select|<script|\$\{jndi|\(\)\s*\{|/etc/passwd|sleep\()", re.I)

    def _mock(self, context: list[dict[str, Any]], payload: dict[str, Any]) -> Decision:
        """Heuristica deterministica para testes do pipeline (nao e resultado cientifico)."""
        votes: Counter[str] = Counter()
        for rec in context:
            ip = rec.get("remote_addr")
            text = f"{rec.get('request_uri', '')} {rec.get('http_user_agent', '')}"
            if self.SUSPICIOUS.search(text) or (rec.get("status") or 0) >= 400 or rec.get("open_connections"):
                votes[ip] += 1
        tokens = len(json.dumps(payload)) // 4
        body: dict[str, Any] = {"model": f"mock/{self.cfg.model}", "provider": "mock", "id": "mock",
                                "usage": {"prompt_tokens": tokens, "completion_tokens": 20, "total_tokens": tokens + 20}}
        if votes:
            ip, n = votes.most_common(1)[0]
            decision = {"justificativa": f"{n} suspicious events from {ip}", "tipo_ataque": "mock",
                        "ataque_detectado": n >= 3, "ip_alvo_bloqueio": ip if n >= 3 else "N/A"}
        else:
            decision = {"justificativa": "no evidence", "tipo_ataque": "N/A",
                        "ataque_detectado": False, "ip_alvo_bloqueio": "N/A"}
        body["choices"] = [{"message": {"content": json.dumps(decision)}}]
        return self._from_body(body, 0.0)
