"""Loop principal do IPS hibrido (iForest -> LLM -> mitigacao).

Uso:
    python -m ips.detector --config runs/.../config.json
    python -m ips.detector --set llm_backend=mock --set enforcement=log_only

Todas as melhorias ficam atras de flags de ``DetectorConfig``; com os valores
padrao o comportamento e o da arquitetura original.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import signal
import subprocess
import sys
import time
from collections import Counter
from typing import Any

import yaml

from ips.config import DetectorConfig, dump_json
from ips.enforcement import Enforcer, nginx_reloader
from ips.layer2 import Decision, LLMAnalyst
from ips.records import Labeler, llm_view, strip_rich
from ips.sources import Clock, build_source
from ips.telemetry import RunRecorder

log = logging.getLogger("ips")


class Detector:
    def __init__(self, cfg: DetectorConfig, docker_enabled: bool = True):
        self.cfg = cfg
        self.labeler = Labeler(cfg.attack_ips, cfg.benign_ips)
        self.recorder = RunRecorder(cfg.output_dir, cfg.record_logs)
        self.source = build_source(cfg, self.labeler)
        self.clock: Clock = self.source.make_clock() if hasattr(self.source, "make_clock") else Clock()
        self.live = cfg.log_buffer != "jsonl"
        self.docker_enabled = docker_enabled and self.live
        reload = nginx_reloader(cfg.nginx_container) if self.docker_enabled else None
        if not self.docker_enabled:
            # Sem Nginx real (replay/testes): a blocklist fica isolada na pasta da execucao.
            cfg.blocklist_path = os.path.join(cfg.output_dir, "blocklist.conf")
        self.enforcer = Enforcer(cfg, self.recorder, self.labeler, self.clock, reload)
        self.stop_requested = False

        self.layer1 = None
        if cfg.layer1 == "iforest":
            from ips.layer1 import IForestFilter

            self.layer1 = IForestFilter(cfg)
        self.analyst = LLMAnalyst(cfg) if cfg.pipeline == "hybrid" else None

        self.kg = None
        if cfg.knowledge_graph:
            from ips.kg import KnowledgeGraph

            self.kg = KnowledgeGraph.create(cfg)
        self.gnn = None
        if cfg.gnn:
            from ips.gnn import GNNScorer

            self.gnn = GNNScorer(cfg)
        self.conn = None
        if self.docker_enabled:
            from ips.conn import ConnectionMonitor

            self.conn = ConnectionMonitor(cfg.nginx_container, cfg.conn_poll_interval_s, self.labeler)

        self.context: list[dict[str, Any]] = []
        self.collecting = False
        self.window_open_t = 0.0
        self.window_trigger = ""
        self.window_id = 0
        self.last_hunt = 0.0
        self.summary: Counter[str] = Counter()

    # ----------------------------------------------------------------- setup
    def setup(self) -> None:
        if self.layer1 is not None:
            n = self.layer1.fit_baseline()
            log.info("iForest treinado com %d amostras legitimas", n)
        if hasattr(self.source, "wait_ready"):
            log.info("Aguardando fonte de logs (%s)...", self.cfg.log_buffer)
            self.source.wait_ready()
        if self.docker_enabled:
            self.enforcer.reset()
        if self.kg is not None:
            self.kg.reset()

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        self.setup()
        start = self.clock.now()
        with open(os.path.join(self.cfg.output_dir, "detector_ready"), "w") as fh:
            fh.write(str(time.time()))
        self.last_hunt = start
        log.info("Monitorando (duracao=%ss, modo=%s)", self.cfg.duration_s, self.cfg.enforcement)
        while not self.stop_requested:
            now = self.clock.now()
            if self.live and now - start >= self.cfg.duration_s:
                break
            if not self.live and self.source.exhausted() and not self.collecting:
                break
            self.enforcer.tick()
            try:
                records = self.source.poll(self.clock)
            except Exception as exc:  # falha transitoria da fonte
                log.warning("Erro lendo logs: %s", exc)
                self.clock.sleep(5)
                continue
            if self.conn is not None:
                records.extend(self.conn.poll(self.clock.now()))
            if records:
                self.recorder.log_records(records)  # gravacao sempre completa (replay)
                if not self.cfg.rich_log:
                    records = [strip_rich(r) for r in records]
                if not self.live and self.cfg.replay_emulate_block:
                    records = [self.emulate_block(r) for r in records]
                self.process(records)
            self.maybe_finalize_window()
            self.maybe_hunt()
            self.clock.sleep(self.cfg.poll_interval_s if records else 2 * self.cfg.poll_interval_s)
        if self.collecting:
            self.finalize_window()
        self.close(start)

    def process(self, records: list[dict[str, Any]]) -> None:
        http = [r for r in records if r.get("kind", "http") == "http"]
        conns = [r for r in records if r.get("kind") == "conn"]
        self.summary["logs"] += len(http)

        if self.kg is not None:
            self.kg.ingest(http + conns)
        if self.gnn is not None and http:
            self.gnn.observe(http, self.clock.now())

        if self.layer1 is not None:
            self.layer1.observe(http, self.clock.now())
            scored = self.layer1.score(http)
        else:
            scored = [r for r in http if r.get("status") is not None]
        if self.gnn is not None and scored:
            self.gnn.score(scored, self.clock.now())

        # Modo shadow: IPs ja sinalizados nao disparam nem entram no contexto,
        # emulando o efeito do bloqueio sem interromper o trafego do atacante.
        def suppressed(r: dict[str, Any]) -> bool:
            return self.cfg.enforcement == "log_only" and self.enforcer.is_blocked(r.get("remote_addr"))

        candidates = [r for r in scored if not suppressed(r)]
        anomalies = [r for r in candidates if r.get("iforest_pred") or r.get("gnn_pred")]
        trigger = ""
        if self.cfg.pipeline == "hybrid" and candidates:
            if self.layer1 is None:
                trigger = "ALWAYS"  # LLM puro: todo lote vai para o modelo
            elif len(candidates) > self.cfg.volumetric_threshold:
                trigger = "VOLUMETRIC"
            elif any(r.get("gnn_pred") and not r.get("iforest_pred") for r in anomalies):
                trigger = "GNN"
            elif anomalies:
                trigger = "STATISTICAL"

        for c in conns:  # amostras sempre gravadas (permitem replay com conn_telemetry)
            self.recorder.connections.write(c)
        conn_alerts = []
        if self.cfg.conn_telemetry:
            conn_alerts = [c for c in conns if c["open_connections"] >= self.cfg.conn_per_ip_threshold
                           and not suppressed(c)]
            if conn_alerts and self.cfg.pipeline == "hybrid" and not trigger:
                trigger = "CONNECTIONS"

        for r in scored:
            self.recorder.layer1.write({**r, "triggered": int(bool(trigger))})

        if trigger:
            if not self.collecting:
                log.warning("ALERTA (%s): lote de %d eventos", trigger, len(candidates))
                self.collecting = True
                self.window_open_t = self.clock.now()
                self.window_trigger = trigger
            self.context.extend(conn_alerts)
            self.context.extend(candidates)

    def emulate_block(self, rec: dict[str, Any]) -> dict[str, Any]:
        """Correcao 3: no replay, transforma logs de IPs bloqueados (active/ttl)
        na resposta que o Nginx teria dado ao ``deny`` (medida em execucoes ao
        vivo: request_time 0; 153 bytes, ou 555 com o padding para MSIE)."""
        ip = rec.get("remote_addr")
        if rec.get("kind", "http") != "http" or ip not in self.enforcer.active:
            return rec
        if self.enforcer.blocked_at.get(ip, float("inf")) > (rec.get("ts") or 0):
            return rec
        ua = rec.get("http_user_agent") or ""
        rec.update(status=403, request_time=0.0, body_bytes_sent=555.0 if "MSIE" in ua else 153.0,
                   emulated_block=True)
        return rec

    # --------------------------------------------------------------- janelas
    def maybe_finalize_window(self) -> None:
        if self.collecting and self.clock.now() - self.window_open_t >= self.cfg.window_s:
            self.finalize_window()

    def finalize_window(self) -> None:
        window = self.context
        self.context, self.collecting = [], False
        self.window_id += 1
        sent = window[: self.cfg.max_context_logs]
        row: dict[str, Any] = {
            "window_id": self.window_id, "trigger": self.window_trigger, "t_open": self.window_open_t,
            "n_logs_window": len(window), "n_logs_sent": len(sent),
            "n_attack_logs": sum(r.get("label") == "attack" for r in window),
            "n_benign_logs": sum(r.get("label") == "benign" for r in window),
            "n_anomalies": sum(bool(r.get("iforest_pred") or r.get("gnn_pred")) for r in window),
            "model_requested": self.cfg.model,
        }
        if self.kg is not None:
            match = self.kg.match_window(window, exclude=self.enforcer.is_blocked)
            if match is not None:
                ip, sim = match
                row.update(decision_source="kg", status="ok", attack_detected=True, target_ip=ip,
                           target_label=self.labeler(ip), kg_similarity=round(sim, 4),
                           t_decision=self.clock.now(), latency_s=0.0, total_tokens=0)
                self.recorder.windows.write(row)
                self.summary["kg_decisions"] += 1
                if self.cfg.kg_strict:
                    # Correcao 4: bloqueio provisorio; a proxima decisao sobre o IP e do LLM
                    self.enforcer.block(ip, "kg", self.window_id, ttl_s=self.cfg.kg_provisional_ttl_s)
                    self.kg.forbid_shortcut(ip)
                else:
                    self.enforcer.block(ip, "kg", self.window_id)
                log.warning("[KG] assinatura conhecida (sim=%.2f) -> %s", sim, ip)
                return
        decision = self.analyst.analyze([llm_view(r) for r in sent])
        self.record_decision(row, decision, "llm", sent)
        if self.kg is not None and decision.status == "ok" and not decision.attack_detected:
            self.kg.benign_feedback(sent, self.clock.now())

    def record_decision(self, row: dict[str, Any], d: Decision, source: str, context: list[dict[str, Any]]) -> None:
        self.clock.elapse(d.latency_s)
        self.summary["llm_calls"] += 1
        self.summary["tokens"] += d.total_tokens
        row.update(
            decision_source=source, t_decision=self.clock.now(), model_returned=d.model_returned,
            provider=d.provider, generation_id=d.generation_id, system_fingerprint=d.system_fingerprint,
            prompt_tokens=d.prompt_tokens, completion_tokens=d.completion_tokens, total_tokens=d.total_tokens,
            cost_usd=d.cost_usd, latency_s=d.latency_s, status=d.status, attack_detected=d.attack_detected,
            target_ip=d.target_ip, target_label=self.labeler(d.target_ip) if d.target_ip else None,
            attack_type=d.attack_type, explanation=d.explanation, error=d.error,
        )
        self.recorder.windows.write(row)
        if d.status != "ok":
            log.error("LLM falhou (%s): %s", d.status, d.error)
            return
        self.recorder.legacy.write({
            "Model": self.cfg.model, "Total_Tokens": d.total_tokens, "Latency_Seconds": d.latency_s,
            "Blocked_IP": d.target_ip or "N/A", "Logs_in_Window": row["n_logs_sent"],
            "Enforcement_Mode": self.cfg.enforcement,
        })
        if d.attack_detected and d.target_ip:
            outcome = self.enforcer.block(d.target_ip, source, row["window_id"])
            log.warning("AMEACA confirmada (%s) -> %s [%s]", source, d.target_ip, outcome)
            if self.kg is not None and outcome != "invalid_ip":
                self.kg.feedback(d.target_ip, d, context, self.clock.now())
        else:
            log.info("LLM: sem ameaca conclusiva")

    def maybe_hunt(self) -> None:
        if self.kg is None or self.analyst is None:
            return
        now = self.clock.now()
        if now - self.last_hunt < self.cfg.kg_hunt_interval_s:
            return
        self.last_hunt = now
        profiles = self.kg.hunt(exclude=self.enforcer.is_blocked)
        if not profiles:
            return
        self.window_id += 1
        row = {
            "window_id": self.window_id, "trigger": "KG_HUNT", "t_open": now, "n_logs_window": len(profiles),
            "n_logs_sent": len(profiles),
            "n_attack_logs": sum(self.labeler(p["remote_addr"]) == "attack" for p in profiles),
            "n_benign_logs": sum(self.labeler(p["remote_addr"]) == "benign" for p in profiles),
            "n_anomalies": len(profiles), "model_requested": self.cfg.model,
        }
        decision = self.analyst.analyze(profiles, header="Long-horizon behavioural profiles (knowledge graph)")
        self.record_decision(row, decision, "kg_hunt", [])

    # ----------------------------------------------------------------- final
    def close(self, start: float) -> None:
        end = self.clock.now()
        dump_json(os.path.join(self.cfg.output_dir, "detector_summary.json"), {
            "start": start, "end": end, "duration_s": end - start, **self.summary,
            "iforest_train_samples": getattr(self.layer1, "n_train", None),
            "iforest_fitted_on": getattr(self.layer1, "fitted_on", None),
            "iforest_threshold": getattr(self.layer1, "threshold", None),
            "gnn": self.gnn.summary() if self.gnn else None,
        })
        if self.kg is not None:
            self.kg.close()
        self.recorder.close()
        if self.docker_enabled and self.cfg.enforcement != "log_only":
            try:
                self.enforcer.reset()
            except Exception as exc:
                log.error("Falha ao restaurar blocklist: %s", exc)
        log.info("Encerrado: %s", dict(self.summary))


def environment_metadata() -> dict[str, Any]:
    def git(*args: str) -> str | None:
        try:
            return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return None

    try:
        from importlib.metadata import version

        pkgs = {p: version(p) for p in ("scikit-learn", "pandas", "numpy", "elasticsearch", "requests")}
    except Exception:
        pkgs = {}
    return {"python": sys.version, "platform": platform.platform(), "packages": pkgs,
            "git_commit": git("rev-parse", "HEAD"), "git_dirty": bool(git("status", "--porcelain"))}


def parse_set(items: list[str]) -> dict[str, Any]:
    out = {}
    for item in items:
        key, _, value = item.partition("=")
        out[key] = yaml.safe_load(value)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IPS hibrido iForest + LLM")
    parser.add_argument("--config", help="JSON/YAML com campos de DetectorConfig")
    parser.add_argument("--set", action="append", default=[], help="campo=valor (sobrescreve)")
    parser.add_argument("--no-docker", action="store_true", help="nao interage com containers")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    data: dict[str, Any] = {}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    else:
        # Execucao avulsa (run.sh legado): aceita as variaveis historicas.
        if os.getenv("MODELO_IA"):
            data["model"] = os.environ["MODELO_IA"]
        if os.getenv("ENFORCEMENT_MODE"):
            data["enforcement"] = os.environ["ENFORCEMENT_MODE"].strip().lower()
    data.update(parse_set(args.set))
    cfg = DetectorConfig.from_dict(data).apply_env()
    os.makedirs(cfg.output_dir, exist_ok=True)
    dump_json(os.path.join(cfg.output_dir, "config.json"), cfg.to_dict())
    dump_json(os.path.join(cfg.output_dir, "environment.json"), environment_metadata())

    det = Detector(cfg, docker_enabled=not args.no_docker)

    def on_signal(signum, frame):
        det.stop_requested = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    det.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
