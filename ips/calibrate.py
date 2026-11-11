"""Calibracao de um parametro do detector por varredura no replay.

    python -m ips.calibrate experiments/ablation-replay.yaml --config +kg \\
        --traffic runs/ablation/+shadow --param kg_similarity_threshold \\
        --values 0.4,0.5,0.6,0.7,0.8 --metric attack_ip_recall --fp-penalty 1

As repeticoes gravadas sao divididas em dois grupos disjuntos: as impares
escolhem o valor (calibracao) e as pares medem o desempenho do valor escolhido
(avaliacao). Assim o limiar nao e ajustado nos mesmos dados em que e
reportado. Objetivo maximizado: media(metric) - fp_penalty * media(fp_ips).

Saida em ``runs/calibration/<config>__<param>/``: ``sweep.csv`` (cada valor no
grupo de calibracao), ``evaluation.csv`` e ``calibration.json`` (valor
escolhido + desempenho na avaliacao).
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

import pandas as pd
import yaml

from ips.config import Experiment, dump_json

log = logging.getLogger("ips.calibrate")


def replay_runs(spec, traffic, out_dir: str, overrides: dict) -> pd.DataFrame:
    from ips.analyze import run_metrics
    from ips.detector import Detector

    rows = []
    for scenario, rep, logs in traffic:
        rdir = os.path.join(out_dir, scenario, f"rep-{rep:02d}")
        if not os.path.exists(os.path.join(rdir, "DONE")):
            os.makedirs(rdir, exist_ok=True)
            cfg = spec.detector_config(log_buffer="jsonl", jsonl_path=logs, output_dir=rdir, record_logs=False,
                                       kg_backend=spec.detector.get("kg_backend", "memory"), **overrides)
            Detector(cfg, docker_enabled=False).run()
            dump_json(os.path.join(rdir, "run.json"), {"config": spec.name, "factors": spec.factors,
                                                       "scenario": scenario, "rep": rep, "mode": "replay",
                                                       "overrides": overrides})
            open(os.path.join(rdir, "DONE"), "w").close()
        rows.append(run_metrics(rdir))
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Calibra um parametro por varredura (replay, split impar/par)")
    ap.add_argument("experiment")
    ap.add_argument("--config", required=True, help="configuracao da matriz usada como base (ex.: +kg)")
    ap.add_argument("--traffic", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--values", required=True, help="lista separada por virgula")
    ap.add_argument("--metric", default="attack_ip_recall")
    ap.add_argument("--fp-penalty", type=float, default=1.0)
    ap.add_argument("--scenarios")
    ap.add_argument("--out", default="runs/calibration")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from dotenv import load_dotenv

    load_dotenv()
    from ips.replay import find_traffic

    exp = Experiment.load(args.experiment)
    spec = next((s for s in exp.runs() if s.name == args.config), None)
    if spec is None:
        raise SystemExit(f"Configuracao {args.config!r} nao existe em {args.experiment}")
    traffic = find_traffic(args.traffic)
    if args.scenarios:
        traffic = [t for t in traffic if t[0] in set(args.scenarios.split(","))]
    calib = [t for t in traffic if t[1] % 2 == 1]
    evalu = [t for t in traffic if t[1] % 2 == 0]
    if not calib or not evalu:
        raise SystemExit("Sao necessarias ao menos 2 repeticoes gravadas (uma impar e uma par)")

    values = [yaml.safe_load(v) for v in args.values.split(",")]
    root = os.path.join(args.out, f"{args.config}__{args.param}")
    sweep = []
    for v in values:
        log.info("calibracao: %s=%s (%d execucoes)", args.param, v, len(calib))
        df = replay_runs(spec, calib, os.path.join(root, "sweep", str(v)), {args.param: v})
        objective = df[args.metric].mean() - args.fp_penalty * df["fp_ips"].mean()
        sweep.append({"value": v, "objective": objective, f"{args.metric}_mean": df[args.metric].mean(),
                      "fp_ips_mean": df["fp_ips"].mean(), "tokens_total_mean": df["tokens_total"].mean(), "n": len(df)})
    sweep_df = pd.DataFrame(sweep)
    os.makedirs(root, exist_ok=True)
    sweep_df.to_csv(os.path.join(root, "sweep.csv"), index=False)
    # desempate: menor consumo de tokens
    best = sweep_df.sort_values(["objective", "tokens_total_mean"], ascending=[False, True]).iloc[0]
    chosen = best["value"]
    log.info("valor escolhido: %s=%s (objetivo %.4f)", args.param, chosen, best["objective"])

    ev = replay_runs(spec, evalu, os.path.join(root, "evaluation"), {args.param: chosen})
    ev.to_csv(os.path.join(root, "evaluation.csv"), index=False)
    result = {
        "config": args.config, "param": args.param, "chosen": chosen, "metric": args.metric,
        "fp_penalty": args.fp_penalty, "calibration_reps": sorted({t[1] for t in calib}),
        "evaluation_reps": sorted({t[1] for t in evalu}),
        "evaluation": {m: float(ev[m].mean()) for m in (args.metric, "fp_ips", "tokens_total", "llm_calls")
                       if m in ev},
    }
    dump_json(os.path.join(root, "calibration.json"), result)
    print(yaml.safe_dump(result, allow_unicode=True, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
