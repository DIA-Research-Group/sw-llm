"""Persistencia de eventos da execucao (instrumentacao sempre ligada).

Arquivos gerados em ``output_dir``:

* ``logs.jsonl``       – todos os registros normalizados vistos (permite replay);
* ``layer1.csv``       – #20: escore/predicao do iForest (e GNN) por log + rotulo;
* ``windows.csv``      – cada janela de decisao (LLM, KG ou hunting);
* ``enforcement.csv``  – #18: bloqueios aplicados / simulados / expirados;
* ``connections.csv``  – #17: amostras de conexoes abertas por IP;
* ``resultados_pesquisa.csv`` – formato legado (compatibilidade com graficos antigos).
"""
from __future__ import annotations

import csv
import json
import os
import threading
from typing import Any

LAYER1_COLUMNS = [
    "ts", "remote_addr", "label", "status", "request_time", "body_bytes_sent",
    "iforest_score", "iforest_pred", "gnn_score", "gnn_pred", "triggered",
]
WINDOW_COLUMNS = [
    "window_id", "trigger", "decision_source", "t_open", "t_decision", "n_logs_window",
    "n_logs_sent", "n_attack_logs", "n_benign_logs", "n_anomalies", "model_requested",
    "model_returned", "provider", "generation_id", "system_fingerprint", "prompt_tokens",
    "completion_tokens", "total_tokens", "cost_usd", "latency_s", "status", "attack_detected",
    "target_ip", "target_label", "attack_type", "explanation", "kg_similarity", "error",
]
ENFORCEMENT_COLUMNS = ["ts", "ip", "label", "action", "mode", "decision_source", "window_id", "expires_at"]
CONNECTION_COLUMNS = ["ts", "remote_addr", "label", "open_connections"]
LEGACY_COLUMNS = ["Model", "Total_Tokens", "Latency_Seconds", "Blocked_IP", "Logs_in_Window", "Enforcement_Mode"]


class CsvTable:
    def __init__(self, path: str, columns: list[str]):
        self.path = path
        self.columns = columns
        self.lock = threading.Lock()
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        self.fh = open(path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.fh, fieldnames=columns, extrasaction="ignore")
        if new:
            self.writer.writeheader()

    def write(self, row: dict[str, Any]) -> None:
        with self.lock:
            self.writer.writerow({k: row.get(k) for k in self.columns})
            self.fh.flush()

    def close(self) -> None:
        self.fh.close()


class RunRecorder:
    def __init__(self, output_dir: str, record_logs: bool = True):
        os.makedirs(output_dir, exist_ok=True)
        self.dir = output_dir
        self.layer1 = CsvTable(os.path.join(output_dir, "layer1.csv"), LAYER1_COLUMNS)
        self.windows = CsvTable(os.path.join(output_dir, "windows.csv"), WINDOW_COLUMNS)
        self.enforcement = CsvTable(os.path.join(output_dir, "enforcement.csv"), ENFORCEMENT_COLUMNS)
        self.connections = CsvTable(os.path.join(output_dir, "connections.csv"), CONNECTION_COLUMNS)
        self.legacy = CsvTable(os.path.join(output_dir, "resultados_pesquisa.csv"), LEGACY_COLUMNS)
        self.logs_fh = open(os.path.join(output_dir, "logs.jsonl"), "a", encoding="utf-8") if record_logs else None

    def log_records(self, records: list[dict[str, Any]]) -> None:
        if self.logs_fh is None:
            return
        for rec in records:
            self.logs_fh.write(json.dumps(rec, default=str) + "\n")
        self.logs_fh.flush()

    def close(self) -> None:
        for t in (self.layer1, self.windows, self.enforcement, self.connections, self.legacy):
            t.close()
        if self.logs_fh:
            self.logs_fh.close()
