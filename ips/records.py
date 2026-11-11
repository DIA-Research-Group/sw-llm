"""Normalizacao dos logs vindos do pipeline de ingestao.

O Logstash grava o JSON do Nginx sob a chave ``nginx`` (``json { target =>
"nginx" }``). O detector original lia os campos no nivel raiz e falhava com
``KeyError``; aqui aceitamos os dois formatos e devolvemos registros planos.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

NGINX_FIELDS = (
    "remote_addr",
    "request_method",
    "request_uri",
    "status",
    "request_time",
    "body_bytes_sent",
    "http_user_agent",
    "http_referrer",
)
NUMERIC_FIELDS = ("status", "request_time", "body_bytes_sent")


def parse_ts(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python < 3.11 nao aceita nanossegundos; corta para microssegundos.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        tz = tail[len(digits):]
        text = f"{head}.{digits[:6]}{tz}"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _num(value: Any) -> float | None:
    try:
        if value in (None, "", "-"):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


class Labeler:
    def __init__(self, attack_ips: Iterable[str], benign_ips: Iterable[str]):
        self.attack = set(attack_ips)
        self.benign = set(benign_ips)

    def __call__(self, ip: str | None) -> str:
        if ip in self.attack:
            return "attack"
        if ip in self.benign:
            return "benign"
        return "unknown"


def normalize(source: dict[str, Any], labeler: Labeler | None = None) -> dict[str, Any] | None:
    """Converte um documento (ES/Redis/JSONL) em registro plano ou None."""
    nested = source.get("nginx") if isinstance(source.get("nginx"), dict) else None
    origin = nested if nested is not None else source
    if not any(k in origin for k in ("status", "request_time", "remote_addr")):
        return None  # ex.: telemetria do Juice Shop sem campos HTTP

    rec: dict[str, Any] = {k: origin.get(k) for k in NGINX_FIELDS}
    for k in NUMERIC_FIELDS:
        rec[k] = _num(rec[k])
    if rec["status"] is not None:
        rec["status"] = int(rec["status"])
    rec["timestamp"] = source.get("@timestamp") or origin.get("timestamp") or source.get("timestamp")
    rec["ts"] = source.get("ts") if isinstance(source.get("ts"), (int, float)) else parse_ts(rec["timestamp"])
    rec["kind"] = source.get("kind", "http")
    if rec["kind"] == "conn":
        rec["open_connections"] = source.get("open_connections")
    if labeler is not None:
        rec["label"] = labeler(rec["remote_addr"])
    else:
        rec["label"] = source.get("label", "unknown")
    return rec


def llm_view(rec: dict[str, Any]) -> dict[str, Any]:
    """Campos enviados ao LLM (sem rotulos de ground truth nem metadados internos).

    ``anomaly_score`` (saida -1/1 do ``predict`` do iForest) e mantido porque o
    detector original o incluia no contexto enviado ao modelo.
    """
    hidden = {"label", "ts", "iforest_score", "iforest_pred", "gnn_score", "gnn_pred", "kind"}
    view = {k: v for k, v in rec.items() if k not in hidden and v is not None}
    if rec.get("kind") == "conn":
        view = {"event": "open_tcp_connections_snapshot", **view}
    return view
