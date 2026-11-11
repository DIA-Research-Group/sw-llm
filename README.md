# Autonomic Intrusion Prevention System via Large Language Models (LLM-IPS)

This repository provides the experimental framework and source code for research regarding the integration of Large Language Models (LLMs) into autonomic security architectures. The project evaluates the efficacy of LLMs in log analysis, threat classification, and automated incident response within a containerized environment.

## 1. Research Overview

The primary objective of this study is to determine if Large Language Models can be effectively utilized as decision-making engines for automated identification and mitigation of cyber attacks.

### 1.1 Hypotheses
*   **H1 (Detection Accuracy):** LLMs can precisely distinguish between legitimate traffic and malicious patterns using raw observability data.
*   **H2 (Entity Identification):** LLMs can accurately extract the source identifiers (e.g., IP addresses) of a threat actor from structured log data.
*   **H3 (Mitigation Efficacy):** LLMs can formulate and execute network-level mitigation strategies (e.g., dynamic firewall rules) within a time window that minimizes system exposure.

## 2. Technical Architecture

The experimental environment is composed of a multi-layered infrastructure designed to simulate a modern web application under adversarial conditions:

*   **Target Application:** OWASP Juice Shop, representing a vulnerable microservice architecture.
*   **Reverse Proxy & Enforcement Point:** Nginx configured with a dynamic blocklist for real-time mitigation.
*   **Data Ingestion Pipeline:** A Logstash instance that normalizes and forwards system logs to an Elasticsearch cluster.
*   **Hybrid Detection Engine:** An Isolation Forest algorithm provides first-tier anomaly detection, triggering a second-tier LLM analysis for contextual validation and decision-making.
*   **Adversarial Agent:** OWASP ZAP (Zed Attack Proxy) configured for exhaustive active scanning and exploit attempts.

## 3. Implementation and Reproducibility

### 3.1 Prerequisites
*   Docker and Docker Compose (v2.20+)
*   Python 3.10+ on the host (runner, analysis and tests)
*   OpenRouter API key (or any OpenAI-compatible endpoint) for live LLM runs

### 3.2 Setup
```bash
cp .env.example .env            # fill OPENROUTER_API_KEY
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-gnn.txt --index-url https://download.pytorch.org/whl/cpu   # optional (GNN tests)
pytest -q
```
The detector itself runs inside a container (`docker/detector`) with pinned
versions (`requirements-detector.txt`, same pins as the original study); all
images in `docker-compose.yml` are pinned by digest.

### 3.3 Ablation framework (one flag per improvement)
Every improvement is a field of `ips/config.py::DetectorConfig`. Defaults
reproduce the original architecture, so each change only takes effect when its
flag is turned on in an experiment file (`experiments/*.yaml`):

| Issue | Factor | Field(s) | Kind |
|---|---|---|---|
| #18 IP blocking | `shadow` | `enforcement: active \| log_only \| ttl` | detector |
| #15 explainability | `explain` | `explain: true` | detector |
| #21 resources | `redis` | `log_buffer: redis` (ES not started) | environment |
| #17 Slowloris | `conn` | `conn_telemetry: true` | detector |
| #13 knowledge graph (1-3) | `kg` | `knowledge_graph: true` | detector |
| #13 GNN (4) | `gnn` | `gnn: true` | detector |
| #19 non-LLM baseline | arm | `proxy: crs`, `crs_paranoia`, `pipeline: observe` | arm |
| LLM-only ("brute force") | arm | `layer1: none` | arm |
| #17, #22, #16 | scenarios | `slowloris`, `vulhub`, `csic` (+ `zap`, `zap_legacy`) | scenario |
| #15, #20, #21 | always on | pinned model + full response metadata, iForest per-log scores, CPU/RAM sampling | instrumentation |

The design expands to `baseline`, each factor isolated (`+kg`), cumulative
stacking in `factor_order` (`+shadow+explain`, ..., `all`) and leave-one-out
(`all-kg`). Execution order is shuffled within each repetition to avoid
confounding with time-of-day drift (API latency, host load).

```bash
python -m ips.run experiments/ablation.yaml --list                  # matrix + time estimate
python -m ips.run experiments/smoke.yaml                            # full pipeline, mock LLM
python -m ips.run experiments/ablation.yaml --scenarios zap --reps 33
python -m ips.analyze runs/ablation                                 # stats + figures + report.md
```

**Paired replay.** Each live run stores every normalized log in `logs.jsonl`.
Detector-only factors can be re-run offline on exactly the same traffic
(virtual clock; wall time = LLM latency only), giving paired comparisons:

```bash
python -m ips.run experiments/ablation.yaml --only +shadow --reps 33      # record traffic (shadow keeps it intact)
python -m ips.replay experiments/ablation-replay.yaml --traffic runs/ablation/+shadow
python -m ips.analyze runs/ablation-replay                                  # paired t / Wilcoxon
```
Factors that change the environment (real blocking, Redis buffer, CRS proxy)
must be evaluated live.

### 3.4 Outputs and statistics
Each run (`runs/<exp>/<config>/<scenario>/rep-NN/`) contains `detector_config.json`,
`environment.json` (git commit, package versions), `run.json` (image digests,
timestamps), `windows.csv` (each LLM/KG decision with tokens, latency, cost,
served model/provider, explanation), `layer1.csv` (iForest/GNN score per log
plus ground-truth label), `enforcement.csv`, `connections.csv`, `resources.csv`
and the legacy `resultados_pesquisa.csv`.

`ips.analyze` reports, per scenario and configuration, mean and 95% CI of cost
(tokens, calls, latency), detection (time-to-mitigate, attacker-IP recall,
false-positive IPs, window precision/recall/F1), Layer-1 metrics (#20: confusion
matrix, precision/recall/F1/FPR, ROC-AUC), and resources (#21). Comparisons use
Welch's t-test (paired t in replay), Mann-Whitney/Wilcoxon, Cohen's d, and
Holm-Bonferroni correction.

Ground truth comes from fixed source IPs (`172.30.0.0/24`): benign generators
`.51-.53`, CSIC benign `.60`; attackers ZAP `.101`, Slowloris `.102`, VulHub
`.103-.105` (staggered botnet), CSIC attacks `.110`.

### 3.5 Legacy single run
`./run.sh` runs the original condition (ZAP only, active blocking, 10 min)
through the runner (`experiments/legacy.yaml`). `resultados/gerar_graficos.py`
still plots the historical CSVs.

## 4. Repository Structure
*   `ips/`: detector (`detector.py`), layers (`layer1.py`, `layer2.py`), mitigation, knowledge graph (`kg.py`), GNN (`gnn.py`), connection telemetry (`conn.py`), runner (`run.py`), replay (`replay.py`), analysis (`analyze.py`).
*   `experiments/`: experiment definitions (factors, design, arms, scenarios).
*   `docker/`: detector image, traffic generators (benign, Slowloris, VulHub attacker, CSIC replay), CRS logging template.
*   `logstash/pipeline/`: ingestion pipelines (Elasticsearch or Redis output).
*   `datasets/`: external datasets (not versioned; see `datasets/README.md`).
*   `IsolationForest/`: baseline traffic (`trafego_base.csv`), generator and the original monolithic detector (kept for reference).
*   `resultados/`: historical results and plotting scripts.

## 5. Ethical Considerations and Licensing
This software is provided exclusively for academic research. All attack simulations are performed within an isolated network environment. The source code is licensed for open academic reuse.
