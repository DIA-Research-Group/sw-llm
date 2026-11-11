import csv
import json
import os

import pytest

from ips.config import DetectorConfig
from ips.detector import Detector


def run(jsonl, tmp_path, **kw):
    cfg = DetectorConfig.from_dict({"log_buffer": "jsonl", "jsonl_path": jsonl, "llm_backend": "mock",
                                    "output_dir": str(tmp_path / "out"), "kg_backend": "memory", **kw})
    det = Detector(cfg, docker_enabled=False)
    det.run()
    rows = lambda f: list(csv.DictReader(open(os.path.join(cfg.output_dir, f))))
    return det, rows


def test_baseline_detects_and_blocks(jsonl_logs, tmp_path):
    det, rows = run(jsonl_logs, tmp_path)
    windows = rows("windows.csv")
    enf = rows("enforcement.csv")
    assert windows, "nenhuma janela de decisao"
    assert any(e["action"] == "block" and e["label"] == "attack" for e in enf)
    l1 = rows("layer1.csv")
    assert {r["label"] for r in l1} >= {"attack", "benign"}
    assert all(r["iforest_score"] for r in l1)
    with open(os.path.join(tmp_path, "out", "blocklist.conf")) as fh:
        assert "deny 172.30.0.101;" in fh.read()


def test_shadow_suppresses_repeat_calls(jsonl_logs, tmp_path):
    det_a, _ = run(jsonl_logs, tmp_path / "a")
    det_s, rows = run(jsonl_logs, tmp_path / "s", enforcement="log_only")
    assert any(e["action"] == "shadow_block" for e in rows("enforcement.csv"))
    assert not os.path.exists(tmp_path / "s" / "out" / "blocklist.conf") or \
        "deny" not in open(tmp_path / "s" / "out" / "blocklist.conf").read()
    assert det_s.summary["llm_calls"] <= det_a.summary["llm_calls"]


def test_llm_only_calls_more_on_benign_traffic(tmp_path):
    from tests.conftest import make_logs

    path = tmp_path / "benign.jsonl"
    with open(path, "w") as fh:
        for rec in make_logs(duration=120, attack_start=10_000):
            rec.update(request_uri="/", body_bytes_sent=75002, request_time=0.003)
            fh.write(json.dumps(rec) + "\n")
    hyb, _ = run(str(path), tmp_path / "h")
    pure, _ = run(str(path), tmp_path / "p", layer1="none")
    assert pure.summary["llm_calls"] > hyb.summary["llm_calls"]
    assert pure.summary["tokens"] > hyb.summary["tokens"]


def test_explain_fields(jsonl_logs, tmp_path):
    _, rows = run(jsonl_logs, tmp_path, explain=True)
    assert any(w["explanation"] for w in rows("windows.csv"))


def test_ttl_expires(jsonl_logs, tmp_path):
    _, rows = run(jsonl_logs, tmp_path, enforcement="ttl", ttl_s=10)
    actions = [e["action"] for e in rows("enforcement.csv")]
    assert "block" in actions and "expire" in actions


def test_kg_runs_and_hunts(jsonl_logs, tmp_path):
    det, rows = run(jsonl_logs, tmp_path, knowledge_graph=True, enforcement="log_only", kg_hunt_interval_s=10)
    assert det.kg.store.signatures(), "feedback do LLM nao gravou assinatura"


def test_gnn_trains_and_scores(jsonl_logs, tmp_path):
    pytest.importorskip("torch")
    det, rows = run(jsonl_logs, tmp_path, gnn=True, gnn_warmup_s=50, gnn_epochs=50)
    summary = det.gnn.summary()
    assert summary["trained"]
    l1 = rows("layer1.csv")
    attack_scores = [float(r["gnn_score"]) for r in l1 if r["label"] == "attack" and r["gnn_score"]]
    benign_scores = [float(r["gnn_score"]) for r in l1 if r["label"] == "benign" and r["gnn_score"]]
    assert attack_scores and sum(attack_scores) / len(attack_scores) > sum(benign_scores) / len(benign_scores)


def test_replay_is_deterministic(jsonl_logs, tmp_path):
    a, _ = run(jsonl_logs, tmp_path / "1")
    b, _ = run(jsonl_logs, tmp_path / "2")
    assert dict(a.summary) == dict(b.summary)
