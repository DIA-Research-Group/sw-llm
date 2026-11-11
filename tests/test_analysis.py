import json
import os

import pandas as pd

from ips.analyze import holm
from ips.config import Experiment


def test_holm():
    adj = holm([0.01, 0.04, 0.03, float("nan")])
    assert adj[0] == 0.03 and abs(adj[2] - 0.06) < 1e-12 and abs(adj[1] - 0.06) < 1e-12
    assert adj[3] != adj[3]


def test_replay_then_analyze(tmp_path):
    """Grava 'trafego ao vivo' sintetico, roda o replay pareado e a analise."""
    from tests.conftest import make_logs
    from ips import analyze, replay

    traffic = tmp_path / "traffic"
    for rep in (1, 2, 3):
        rdir = traffic / "zap" / f"rep-{rep:02d}"
        os.makedirs(rdir)
        with open(rdir / "logs.jsonl", "w") as fh:
            for r in make_logs(seed=rep):
                fh.write(json.dumps(r) + "\n")
        json.dump({"scenario": "zap", "rep": rep}, open(rdir / "run.json", "w"))
        open(rdir / "DONE", "w").close()
    exp = tmp_path / "exp.yaml"
    exp.write_text("""
name: t
base: {llm_backend: mock}
factor_order: [shadow, explain]
factors:
  shadow: {enforcement: log_only}
  explain: {explain: true}
design: [baseline, isolated, cumulative]
arms:
  llm_only: {layer1: none, enforcement: log_only}
scenarios: [zap]
""")
    out = tmp_path / "runs"
    assert replay.main([str(exp), "--traffic", str(traffic), "--out", str(out)]) == 0
    assert analyze.main([str(out / "t")]) == 0
    summary = pd.read_csv(out / "t" / "analysis" / "summary.csv")
    assert set(summary["config"]) == {"baseline", "+shadow", "+explain", "all", "llm_only"}
    assert (summary["n"] == 3).all()
    comps = pd.read_csv(out / "t" / "analysis" / "comparisons.csv")
    assert {"isolated", "cumulative", "arm"} <= set(comps["comparison"])
    assert (comps["test"] == "paired t / Wilcoxon").all()
    assert summary["iforest_f1_mean"].notna().sum() == 4  # llm_only nao tem Camada 1
    assert (out / "t" / "analysis" / "report.md").exists()
    assert any(f.endswith("iforest_scores.png") for f in os.listdir(out / "t" / "analysis" / "figures"))
