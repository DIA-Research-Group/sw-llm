"""Replay pareado: reexecuta configuracoes do detector sobre trafego gravado.

    python -m ips.replay experiments/ablation-replay.yaml --traffic runs/traffic
    python -m ips.analyze runs/ablation-replay --paired

Cada execucao ao vivo grava ``logs.jsonl`` (todos os logs normalizados, com as
amostras de conexoes). Aqui cada configuracao da matriz e aplicada sobre
*exatamente o mesmo* trafego de cada (cenario, repeticao), com relogio virtual:
o tempo de parede passa a ser apenas a latencia do LLM, e as comparacoes
"antes/depois" ficam pareadas (mesma entrada), removendo a variancia do
ambiente.

Limitacoes (documentadas no relatorio): fatores que alteram o *ambiente* –
bloqueio real (``enforcement: active|ttl``) que muda o trafego subsequente,
``log_buffer: redis`` e os bracos com outro proxy (CRS) – precisam de
execucoes ao vivo (``python -m ips.run``). No replay o bloqueio e registrado,
mas o trafego gravado nao muda.
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import random
import shutil
import sys

from ips.config import Experiment, dump_json
from ips.layer2 import LLMAccountError

log = logging.getLogger("ips.replay")
LIVE_ONLY = {"log_buffer": {"redis"}, "pipeline": {"observe"}}


def find_traffic(traffic_root: str) -> list[tuple[str, int, str]]:
    """(cenario, rep, caminho de logs.jsonl) das execucoes ao vivo concluidas."""
    out = []
    for done in sorted(glob.glob(os.path.join(traffic_root, "**", "rep-*", "DONE"), recursive=True)):
        rdir = os.path.dirname(done)
        meta = json.load(open(os.path.join(rdir, "run.json")))
        logs = os.path.join(rdir, "logs.jsonl")
        if os.path.exists(logs):
            out.append((meta["scenario"], int(meta["rep"]), logs))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay pareado de configuracoes do detector")
    ap.add_argument("experiment")
    ap.add_argument("--traffic", required=True, help="diretorio com execucoes ao vivo (logs.jsonl)")
    ap.add_argument("--out", default="runs")
    ap.add_argument("--only")
    ap.add_argument("--scenarios")
    ap.add_argument("--reps", type=int, help="usa so as N primeiras repeticoes gravadas")
    ap.add_argument("--keep-going", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    from dotenv import load_dotenv

    load_dotenv()
    from ips.detector import Detector

    exp = Experiment.load(args.experiment)
    specs = [s for s in exp.runs() if not args.only or s.name in set(args.only.split(","))]
    for s in specs:
        for key, bad in LIVE_ONLY.items():
            if s.detector.get(key) in bad or s.environment.get("proxy") == "crs":
                raise SystemExit(f"{s.name}: '{key}' exige execucao ao vivo (python -m ips.run)")
    traffic = find_traffic(args.traffic)
    if args.scenarios:
        traffic = [t for t in traffic if t[0] in set(args.scenarios.split(","))]
    if args.reps:
        traffic = [t for t in traffic if t[1] <= args.reps]
    if not traffic:
        raise SystemExit(f"Nenhum logs.jsonl concluido em {args.traffic}")

    jobs = [(spec, t) for t in traffic for spec in specs]
    random.Random(exp.seed).shuffle(jobs)
    os.makedirs(os.path.join(args.out, exp.name), exist_ok=True)
    shutil.copy(args.experiment, os.path.join(args.out, exp.name, "experiment.yaml"))
    failures = 0
    for i, (spec, (scenario, rep, logs)) in enumerate(jobs, 1):
        rdir = os.path.join(args.out, exp.name, spec.name, scenario, f"rep-{rep:02d}")
        if os.path.exists(os.path.join(rdir, "DONE")):
            continue
        shutil.rmtree(rdir, ignore_errors=True)
        log.info("[%d/%d] %s | %s | rep %d", i, len(jobs), spec.name, scenario, rep)
        overrides = {"log_buffer": "jsonl", "jsonl_path": logs, "output_dir": rdir, "record_logs": False}
        if spec.detector.get("kg_backend") is None:
            overrides["kg_backend"] = "memory"
        try:
            cfg = spec.detector_config(**overrides)
            os.makedirs(rdir, exist_ok=True)
            dump_json(os.path.join(rdir, "detector_config.json"), cfg.to_dict())
            Detector(cfg, docker_enabled=False).run()
            dump_json(os.path.join(rdir, "run.json"), {
                "experiment": exp.name, "config": spec.name, "factors": spec.factors, "scenario": scenario,
                "rep": rep, "mode": "replay", "traffic": logs, "environment": spec.environment,
            })
            open(os.path.join(rdir, "DONE"), "w").close()
        except LLMAccountError as exc:
            log.error("Abortado: problema na conta do provedor do LLM (%s)", exc)
            return 2
        except Exception as exc:
            failures += 1
            log.error("Falha em %s: %s", rdir, exc)
            if not args.keep_going:
                return 1
    log.info("Concluido (%d falhas)", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
