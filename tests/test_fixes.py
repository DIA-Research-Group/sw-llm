"""Testes das cinco correcoes (iForest no aquecimento, log rico, emulacao de
bloqueio no replay, KG seguro, dataset reprodutivel)."""
import csv
import json
import os

from ips.config import DetectorConfig
from ips.detector import Detector
from ips.kg import KnowledgeGraph, MemoryStore, features_of
from ips.matrix import expand_design
from ips.records import llm_view, normalize, strip_rich
from tests.conftest import make_logs


def write(path, recs):
    with open(path, "w") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    return str(path)


def run(jsonl, out, **kw):
    cfg = DetectorConfig.from_dict({"log_buffer": "jsonl", "jsonl_path": jsonl, "llm_backend": "mock",
                                    "output_dir": str(out), "kg_backend": "memory", **kw})
    det = Detector(cfg, docker_enabled=False)
    det.run()
    rows = lambda f: list(csv.DictReader(open(os.path.join(out, f))))
    return det, rows


def benign_fpr(rows, after_ts):
    b = [r for r in rows("layer1.csv") if r["label"] == "benign" and float(r["ts"]) > after_ts]
    return sum(int(r["iforest_pred"]) for r in b) / len(b)


# 1 ---------------------------------------------------------------------------
def test_iforest_warmup_fit_reduces_benign_fpr(tmp_path):
    logs = make_logs(duration=180, attack_start=120)
    path = write(tmp_path / "l.jsonl", logs)
    t_warm = logs[0]["ts"] + 60
    base, rb = run(path, tmp_path / "b")
    fix, rf = run(path, tmp_path / "f", iforest_fit="warmup", iforest_warmup_s=60, iforest_threshold_quantile=0.01)
    assert base.layer1.fitted_on == "baseline_csv" and fix.layer1.fitted_on == "warmup"
    assert fix.layer1.threshold is not None
    assert benign_fpr(rf, t_warm) < benign_fpr(rb, t_warm)


def test_iforest_warmup_keeps_csv_model_when_too_few_logs(tmp_path):
    path = write(tmp_path / "l.jsonl", make_logs(duration=20, attack_start=1000))
    det, _ = run(path, tmp_path / "o", iforest_fit="warmup", iforest_warmup_s=5, iforest_min_warmup_samples=10_000)
    assert det.layer1.n_train == 1000  # continua com o modelo do CSV


# 2 ---------------------------------------------------------------------------
def test_rich_fields_hidden_unless_enabled():
    doc = {"@timestamp": "2026-11-11T12:00:00Z",
           "nginx": {"remote_addr": "172.30.0.103", "status": "400", "request_time": "0.000",
                     "body_bytes_sent": "157", "request_uri": "",
                     "request": "GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1", "host": "httpd.lab",
                     "request_length": "120"}}
    rec = normalize(doc)
    assert rec["request"].startswith("GET /icons") and rec["request_length"] == 120.0
    assert "request" in llm_view(rec)
    assert "request" not in llm_view(strip_rich(dict(rec)))


def test_kg_uses_request_line_when_uri_empty():
    from ips.kg import aggregate, payload_tokens

    rec = {"remote_addr": "x", "request_uri": "", "request": "GET /cgi-bin/.%2e/.%2e/bin/sh HTTP/1.1", "status": 400}
    assert "traversal" in payload_tokens(rec)
    assert "/cgi-bin/.%2e/.%2e/bin/sh" in aggregate([rec])["x"]["endpoints"]


# 3 ---------------------------------------------------------------------------
def test_replay_emulates_block_as_nginx_403(tmp_path):
    path = write(tmp_path / "l.jsonl", make_logs())
    _, rows = run(path, tmp_path / "a")  # baseline: enforcement active
    block = [e for e in rows("enforcement.csv") if e["action"] == "block" and e["label"] == "attack"][0]
    after = [r for r in rows("layer1.csv") if r["remote_addr"] == block["ip"] and float(r["ts"]) > float(block["ts"])]
    assert after and all(r["status"] == "403" and float(r["request_time"]) == 0.0 for r in after)
    assert {float(r["body_bytes_sent"]) for r in after} <= {153.0, 555.0}

    _, rows_s = run(path, tmp_path / "s", enforcement="log_only")
    assert not any(r["status"] == "403" and float(r["request_time"]) == 0.0
                   for r in rows_s("layer1.csv") if r["label"] == "attack")


def test_replay_emulation_can_be_disabled(tmp_path):
    path = write(tmp_path / "l.jsonl", make_logs())
    _, rows = run(path, tmp_path / "a", replay_emulate_block=False)
    attack = [r for r in rows("layer1.csv") if r["label"] == "attack"]
    assert not all(r["status"] == "403" for r in attack[-20:])


# 4 ---------------------------------------------------------------------------
class Cfg:
    kg_similarity_threshold = 0.3
    kg_hunt_min_requests = 5
    kg_hunt_min_error_ratio = 0.5
    conn_per_ip_threshold = 50
    kg_strict = True
    kg_common_feature_ratio = 0.5
    kg_margin = 0.1


def browse(ip, ua="Firefox/115", uris=("/", "/api/Products", "/rest/user/whoami"), status=200):
    return [{"remote_addr": ip, "request_uri": u, "status": status, "ts": 1.0, "http_user_agent": ua,
             "request_method": "GET"} for u in uris]


class D:
    model_returned = attack_type = explanation = None


def test_strict_features_drop_generic_ones():
    p = {"endpoints": {"/": 1}, "uas": {"firefox": 1}, "tokens": {}, "statuses": {"200": 1}, "methods": {"GET": 1}}
    assert not any(f.startswith(("st:", "m:")) for f in features_of(p, strict=True))
    assert any(f.startswith("st:") for f in features_of(p, strict=False))


def test_negative_memory_blocks_false_positive_propagation():
    # o LLM (erroneamente) confirmou um IP benigno; outro benigno parecido nao deve herdar o bloqueio
    loose_cfg = type("C", (Cfg,), {"kg_strict": False})
    for cfg, expect_match in ((loose_cfg, True), (Cfg, False)):
        kg = KnowledgeGraph(MemoryStore(), cfg())
        kg.ingest(browse("172.30.0.51") + browse("172.30.0.52") + browse("172.30.0.53", uris=("/x",)))
        kg.benign_feedback(browse("172.30.0.52"), 1.0)   # LLM ja julgou .52 benigno
        kg.feedback("172.30.0.51", D(), [], 1.0)         # falso positivo do LLM em .51
        match = kg.match_window(browse("172.30.0.52"), exclude=lambda ip: ip == "172.30.0.51")
        assert (match is not None) == expect_match


def test_strict_still_matches_real_attack_signature():
    kg = KnowledgeGraph(MemoryStore(), Cfg())
    attack = lambda ip: browse(ip, ua="ZAP/2.15", uris=("/../../etc/passwd", "/s?q=' OR 1=1--", "/ftp"), status=404)
    kg.ingest(attack("172.30.0.103") + browse("172.30.0.51") + browse("172.30.0.52"))
    kg.benign_feedback(browse("172.30.0.51") + browse("172.30.0.52"), 1.0)
    kg.feedback("172.30.0.103", D(), [], 1.0)
    kg.ingest(attack("172.30.0.104"))
    match = kg.match_window(attack("172.30.0.104"), exclude=lambda ip: ip == "172.30.0.103")
    assert match and match[0] == "172.30.0.104"
    kg.forbid_shortcut("172.30.0.104")
    assert kg.match_window(attack("172.30.0.104"), exclude=lambda ip: ip == "172.30.0.103") is None


def test_kg_strict_provisional_block_in_detector(tmp_path):
    logs = make_logs(duration=150, attack_start=40)
    for r in logs:  # segundo atacante com as mesmas TTPs a partir de t+100
        if r["remote_addr"] == "172.30.0.101" and r["ts"] > logs[0]["ts"] + 100 and hash(r["request_uri"]) % 2:
            r["remote_addr"] = "172.30.0.104"
    path = write(tmp_path / "l.jsonl", logs)
    det, rows = run(path, tmp_path / "o", knowledge_graph=True, kg_strict=True, kg_similarity_threshold=0.3,
                    kg_provisional_ttl_s=15)
    kg_blocks = [e for e in rows("enforcement.csv") if e["decision_source"] == "kg" and e["action"] == "block"]
    assert kg_blocks and kg_blocks[0]["ip"] == "172.30.0.104"
    assert any(e["action"] == "expire" and e["ip"] == "172.30.0.104" for e in rows("enforcement.csv"))
    for e in kg_blocks:
        assert e["expires_at"], "bloqueio do KG deveria ser provisorio"


def test_requires_closes_factor_sets():
    order = ["a", "b", "kg", "kgsafe"]
    out = dict(expand_design(order, ["baseline", "isolated", "leave_one_out"], {"kgsafe": ["kg"]}))
    assert out["+kg+kgsafe"] == ["kg", "kgsafe"]  # isolado de kgsafe ganha a dependencia
    assert "+kgsafe" not in out
    assert "all-kg" not in out  # coincide com all
    assert out["all-kgsafe"] == ["a", "b", "kg"]


def test_refinement_comparison_pair():
    from ips.analyze import comparison_pairs

    order = ["a", "b", "kg", "kgsafe"]
    pairs = comparison_pairs(["baseline", "+kg", "+kg+kgsafe"], order, [], {"kgsafe": ["kg"]})
    assert ("refinement", "+kg", "+kg+kgsafe") in pairs


# 5 ---------------------------------------------------------------------------
def test_csic_raw_format(tmp_path):
    from tests.test_traffic import load

    (tmp_path / "normalTrafficTraining.txt").write_text(
        "GET http://localhost:8080/tienda1/index.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5)\n"
        "Connection: close\n\n\n"
        "POST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0\n"
        "Content-Length: 20\n\nid=3&nombre=Vino\n\n", encoding="latin-1")
    (tmp_path / "anomalousTrafficTest.txt").write_text(
        "GET http://localhost:8080/tienda1/publico/caracteristicas.jsp?id=%27%3B+DROP HTTP/1.1\n"
        "User-Agent: Mozilla/5.0\n\n\n", encoding="latin-1")
    csic = load("csic_replay")
    normal = csic.load(str(tmp_path / "*"), "normal")
    attack = csic.load(str(tmp_path / "*"), "anomalous")
    assert len(normal) == 2 and len(attack) == 1
    assert csic.to_request(normal[1]) == ("POST", "/tienda1/publico/anadir.jsp", "id=3&nombre=Vino", "Mozilla/5.0")
    assert csic.to_request(attack[0])[1].endswith("?id=%27%3B+DROP")


def test_dataset_hashes(tmp_path, monkeypatch):
    import ips.run as run_mod

    (tmp_path / "datasets" / "csic2010").mkdir(parents=True)
    (tmp_path / "datasets" / "csic2010" / "a.csv").write_text("x")
    monkeypatch.setattr(run_mod, "ROOT", str(tmp_path))
    h = run_mod.dataset_hashes(("datasets/csic2010/*.csv",))
    assert h == {"datasets/csic2010/a.csv": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}


def test_account_error_aborts(monkeypatch):
    """401/402/403 do provedor abortam a execucao (sem janelas invalidas)."""
    import pytest

    from ips import layer2
    from ips.config import DetectorConfig

    class Resp:
        status_code = 402
        text = '{"error": "credits"}'

    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    monkeypatch.setattr(layer2.requests, "post", lambda *a, **k: Resp())
    analyst = layer2.LLMAnalyst(DetectorConfig(llm_backend="openrouter"))
    with pytest.raises(layer2.LLMAccountError):
        analyst.analyze([{"remote_addr": "1.2.3.4"}])


def test_connection_error_retries(monkeypatch):
    """Falha de rede transitoria e repetida antes de virar janela com erro."""
    from ips import layer2
    from ips.config import DetectorConfig

    calls = {"n": 0}

    class Resp:
        status_code = 500
        text = "x"

    def post(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise layer2.requests.ConnectionError("dns")
        return Resp()

    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    monkeypatch.setattr(layer2.requests, "post", post)
    monkeypatch.setattr(layer2.time, "sleep", lambda s: None)
    d = layer2.LLMAnalyst(DetectorConfig(llm_backend="openrouter")).analyze([{"remote_addr": "1.2.3.4"}])
    assert calls["n"] == 3 and d.status == "http_error"
