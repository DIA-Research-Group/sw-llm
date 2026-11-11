# Autonomic Intrusion Prevention System via Large Language Models (LLM-IPS)

This repository provides the experimental framework and source code for research regarding the integration of Large Language Models (LLMs) into autonomic security architectures. The project evaluates the efficacy of LLMs in log analysis, threat classification, and automated incident response within a containerized environment.

Besides the original hybrid detector (Isolation Forest + LLM), the repository contains an **ablation framework**: every proposed improvement is an independent flag, so each one can be measured alone, stacked with the others, or removed from the full stack, over repeated runs with confidence intervals and significance tests.

## 1. Research Overview

The primary objective of this study is to determine if Large Language Models can be effectively utilized as decision-making engines for automated identification and mitigation of cyber attacks, and how much a cheap statistical pre-filter reduces the operational cost of doing so.

### 1.1 Hypotheses
*   **H1 (Detection Accuracy):** LLMs can precisely distinguish between legitimate traffic and malicious patterns using raw observability data.
*   **H2 (Entity Identification):** LLMs can accurately extract the source identifiers (e.g., IP addresses) of a threat actor from structured log data.
*   **H3 (Mitigation Efficacy):** LLMs can formulate and execute network-level mitigation strategies (e.g., dynamic firewall rules) within a time window that minimizes system exposure.

## 2. Technical Architecture

```
 benign users ─┐                                   ┌─ Juice Shop (main target)
 attackers ────┼─► Nginx (nginx-proxy, blocklist) ─┼─ [OWASP CRS WAF]   (arm #19)
 (ZAP, Slowloris,  │ JSON access log via syslog    └─ VulHub targets    (scenario #22)
  VulHub, CSIC)    ▼
               Logstash ──► Elasticsearch  (or Redis, #21)
                                 │
                                 ▼
        ips.detector ── Layer 1: Isolation Forest (+ GNN, #13)  ──┐
                     ── connection telemetry (#17)                ├─► window (5 s) ─► Layer 2: LLM
                     ── knowledge graph / Neo4j (#13)  ───────────┘        │
                                                                           ▼
                                         mitigation: block | shadow log | TTL block (#18)
```

*   **Target application:** OWASP Juice Shop; optional VulHub system (Solr/Log4Shell, Bash CGI/Shellshock, httpd 2.4.49/CVE-2021-41773).
*   **Reverse proxy & enforcement point:** Nginx with a dynamic blocklist (`blocklist.conf`).
*   **Ingestion:** Logstash parses the Nginx JSON log and writes to Elasticsearch, or to a Redis list (in-memory buffer).
*   **Hybrid detection engine (`ips/`):** Isolation Forest first tier; buffered 5-second windows are sent to an LLM (via OpenRouter) that decides whether there is an attack and which IP to block.
*   **Adversarial agents:** OWASP ZAP, Slowloris, a VulHub exploit "botnet" and a replay of the labelled CSIC 2010 dataset, always mixed with realistic benign traffic.

## 3. Quick Start

### 3.1 Prerequisites
*   Docker and Docker Compose v2.20+ (the user must be able to run `docker` without `sudo`)
*   Python 3.10+ on the host (runner, analysis and tests)
*   An OpenRouter API key (or any OpenAI-compatible endpoint) for runs with a real LLM
*   ~8 GB free RAM (Elasticsearch 2 GB heap, ZAP 2 GB, Logstash 512 MB)
*   Free host ports: 80, 5044, 9200; plus 6380 (Redis), 7474/7687 (Neo4j) when those factors are used

### 3.2 Setup
```bash
cp .env.example .env                 # fill OPENROUTER_API_KEY
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-gnn.txt --index-url https://download.pytorch.org/whl/cpu   # optional: GNN unit tests
pytest -q                            # offline tests (no Docker, mock LLM)
```

The detector does **not** run on the host Python during experiments: it runs in the `ips-detector` container, built from `docker/detector` with pinned versions (`requirements-detector.txt`, the same pins as the original study, plus PyTorch CPU). All third-party images in `docker-compose.yml` are pinned by digest. Images are built automatically on the first run (the detector image downloads PyTorch, so the first build takes a few minutes).

### 3.3 First runs
```bash
# 1. Whole pipeline, no API cost (mock LLM), ~20 min
python -m ips.run experiments/smoke.yaml
python -m ips.analyze runs/smoke
xdg-open runs/smoke/analysis/report.md

# 2. Original study condition (ZAP only, active blocking, 10 min, real LLM)
./run.sh                                             # MODELO_IA=openai/gpt-4o-mini ./run.sh to change the model

# 3. A real pilot of the ablation (3 repetitions of the ZAP scenario)
python -m ips.run experiments/ablation.yaml --scenarios zap --reps 3
python -m ips.analyze runs/ablation
```

## 4. Ablation Framework

### 4.1 One flag per improvement
Every improvement is a field of `ips/config.py::DetectorConfig`. **Defaults reproduce the original architecture**, so a change only takes effect when its flag is turned on in an experiment file. Improvements fall into four kinds:

| Issue | Name in `ablation.yaml` | Field(s) | Kind |
|---|---|---|---|
| #18 IP blocking alternatives | factor `shadow` | `enforcement: active \| log_only \| ttl` (`ttl_s`) | detector |
| #15 explainability | factor `explain` | `explain: true` (justification + attack type before the decision) | detector |
| #21 resource usage | factor `redis` | `log_buffer: redis` (Elasticsearch is not started) | environment |
| #17 Slowloris detection | factor `conn` | `conn_telemetry: true` (`conn_per_ip_threshold`) | detector |
| #13 knowledge graph, phases 1-3 | factor `kg` | `knowledge_graph: true` (`kg_backend`, `kg_similarity_threshold`, `kg_hunt_*`) | detector |
| #13 GNN, phase 4 | factor `gnn` | `gnn: true` (`gnn_*`) | detector |
| Layer-1 refit | factor `l1fit` | `iforest_fit: warmup`, `iforest_threshold_quantile` | detector |
| Rich log fields | factor `richlog` | `rich_log: true` (`request`, `host`, `request_length` shown to the LLM/KG) | detector |
| Safe KG shortcut | factor `kgsafe` (requires `kg`) | `kg_strict: true` (`kg_margin`, `kg_common_feature_ratio`, `kg_provisional_ttl_s`) | detector |
| #19 non-LLM baseline | arms `crs_pl1`, `crs_pl2` | `proxy: crs`, `crs_paranoia`, `pipeline: observe` | comparison arm |
| LLM-only ("brute force") | arm `llm_only` | `layer1: none` | comparison arm |
| #17, #22, #16 | scenarios | `slowloris`, `vulhub`, `csic` (plus `zap`, `zap_legacy`) | scenario |
| #15, #20, #21 | always on | pinned model + full response metadata, per-log iForest/GNN scores, CPU/RAM sampling | instrumentation |

What each improvement does:

*   **Shadow mode (#18).** `log_only` records the IP that *would* be blocked (`enforcement.csv`) without touching Nginx, so the attack keeps going and can be studied. Logs from flagged IPs no longer trigger windows (emulating the block). `ttl` applies a real block that expires after `ttl_s`.
*   **Explainability (#15).** The LLM must write a `justificativa` and a `tipo_ataque` before `ataque_detectado`/`ip_alvo_bloqueio`. Both are stored in `windows.csv`.
*   **Redis buffer (#21).** Logstash writes to a Redis list consumed by the detector, and Elasticsearch is not started. CPU/RAM of every container are always sampled. Resource limits per service can be set in the experiment (`resources:`).
*   **Connection telemetry (#17).** Nginx only logs a Slowloris connection (status 408) when it times out. The detector samples `/proc/net/tcp` inside the proxy every 2 s and opens a window when an IP holds `conn_per_ip_threshold` or more connections.
*   **Knowledge graph (#13, phases 1-3).** Logs become a Neo4j graph (`IP → Endpoint / UserAgent / Token / Status`). Each LLM-confirmed attack stores a `Signature`. New IPs whose behaviour matches a signature (IDF-weighted Jaccard ≥ threshold) are blocked without calling the LLM. A periodic hunt sends long-horizon IP profiles (low-and-slow, many connections, payload classes) to the LLM. Browse the graph at http://localhost:7474 (`neo4j` / `ips-research`).
*   **GNN (#13, phase 4).** A DOMINANT-style graph autoencoder over the IP–endpoint graph, trained on the benign warm-up period and combined with the iForest by logical OR.
*   **Layer-1 refit (`l1fit`).** The original `trafego_base.csv` covers only 7 routes, so the iForest flags most realistic benign requests. With `iforest_fit: warmup` the model is refitted on the logs of the benign warm-up period (`iforest_warmup_s`, default = the experiment's `warmup_s`; it keeps the CSV model if fewer than `iforest_min_warmup_samples` logs arrive). `iforest_threshold_quantile: 0.01` sets the decision threshold at that quantile of the warm-up scores (target FPR ≈ 1%). `detector_summary.json` records `iforest_fitted_on` and `iforest_threshold`.
*   **Rich log fields (`richlog`).** Nginx always logs `request` (raw request line), `host` and `request_length`, so recorded traffic can be replayed with or without them. Nginx rejects some payloads (e.g. the CVE-2021-41773 traversal) with a 400 before parsing and leaves `request_uri` empty. The raw `request` line still carries the payload. By default these fields are stripped before detection (original behaviour); `rich_log: true` exposes them to the LLM and the KG.
*   **Safe KG shortcut (`kgsafe`).** `kg_strict: true` makes the KG shortcut conservative: features present in more than `kg_common_feature_ratio` of IPs (and status/method features) get zero weight; a match also has to beat the similarity to known benign profiles by `kg_margin` (IPs the LLM judged benign feed a `BenignProfile`); a KG block is provisional (`kg_provisional_ttl_s`), and the IP is sent to the LLM again instead of being re-matched. Use `python -m ips.calibrate` (4.7) to choose `kg_similarity_threshold` without tuning on the evaluation data.
*   **OWASP CRS (#19).** ModSecurity + Core Rule Set sits *behind* the baseline Nginx (`proxy → CRS → Juice Shop`), so the log format is identical. Requests blocked by the WAF appear as 403. The LLM pipeline is off (`pipeline: observe`).

### 4.2 Experimental design
`design` in the experiment file expands the factors listed in `factor_order`:

| Design | Configurations generated | Answers |
|---|---|---|
| `baseline` | `baseline` | original architecture |
| `isolated` | `+shadow`, `+explain`, ... | effect of each improvement alone |
| `cumulative` | `+shadow+explain`, ..., `all` | effect of stacking in `factor_order` |
| `leave_one_out` | `all-shadow`, `all-kg`, ... | marginal contribution inside the full stack |
| `full_factorial` | all 2^k combinations | interactions (expensive) |

Configurations with the same factor set are generated only once and named canonically. A factor can declare `requires:` (e.g. `kgsafe` requires `kg`): dependencies are added before deduplication, so `+kgsafe` becomes `+kg+kgsafe` and `all-kg` collapses into `all`. Comparison arms (`arms:`) are added on top, and each scenario in `scenarios:` multiplies the matrix. Run order is shuffled within each repetition (fixed `seed`), so time-of-day drift in API latency or host load is not confounded with a configuration.

### 4.3 Experiment files
```yaml
name: ablation            # output goes to runs/<name>/
duration_s: 600           # attack window
warmup_s: 60              # benign-only period before the attack (GNN calibration)
repetitions: 33
seed: 42
base:                     # DetectorConfig fields applied to every configuration
  model: openai/gpt-4o-mini-2024-07-18
factor_order: [shadow, l1fit, explain, richlog, redis, conn, kg, kgsafe, gnn]
factors:
  shadow: {enforcement: log_only}
  kg:     {knowledge_graph: true}
  kgsafe: {requires: [kg], kg_strict: true}   # dependency: +kgsafe becomes +kg+kgsafe
  # ...
design: [baseline, isolated, cumulative, leave_one_out]
arms:
  llm_only: {layer1: none, enforcement: log_only}
  crs_pl1:  {proxy: crs, crs_paranoia: 1, pipeline: observe}
scenarios: [zap, slowloris, vulhub, csic]
resources:                # optional docker compose limits
  elasticsearch: {cpus: "1.0", memory: 2g}
```

Provided experiments (`experiments/`):

| File | Purpose |
|---|---|
| `ablation.yaml` | main study: 9 factors (28 configurations), 3 arms, 4 scenarios |
| `ablation-replay.yaml` | detector-only factors for paired replay (see 4.6) |
| `smoke.yaml` | pipeline validation with mock LLM, short runs |
| `legacy.yaml` | original condition (used by `run.sh`) |
| `detector-default.yaml` | config used when the detector container is started by hand |

To add a new improvement: add the field(s) to `DetectorConfig` (default = current behaviour), use them in `ips/detector.py`, and declare a factor in the experiment file. Nothing else needs to change.

### 4.4 Scenarios
| Scenario | Traffic | Attacker IP(s) |
|---|---|---|
| `zap` | OWASP ZAP full scan + benign users | `.101` |
| `zap_legacy` | ZAP only (original study condition) | `.101` |
| `slowloris` | 900 slow connections + benign users | `.102` |
| `vulhub` | Log4Shell, Shellshock, CVE-2021-41773 against a composed system; 3 attackers starting at 0 s, 120 s, 240 s + benign users | `.103-.105` |
| `csic` | CSIC 2010 labelled requests replayed through the real proxy + benign users | `.110` (CSIC benign: `.60`) |

Ground truth comes from fixed source IPs in `172.30.0.0/24`. Benign users (`docker/traffic/benign.py`) are `.51-.53` and include natural errors (wrong passwords, mistyped routes, unauthenticated calls). The `csic` scenario needs the dataset in `datasets/csic2010/`: run `datasets/fetch_csic.sh` (Kaggle CLI) or `datasets/fetch_csic.sh /path/to/files` (Kaggle CSV or the original `.txt` files). The script writes or checks `datasets/csic2010.sha256`, and every run stores the SHA-256 of the files it used in `run.json` (`datasets`). The runner refuses to start `csic` without the dataset.

### 4.5 Running experiments
```bash
python -m ips.run experiments/ablation.yaml --list                     # matrix, pending runs, time estimate
python -m ips.run experiments/ablation.yaml                            # everything
python -m ips.run experiments/ablation.yaml --only baseline,+kg --scenarios zap,vulhub --reps 5
python -m ips.run experiments/ablation.yaml --set temperature=0 --tag temp0   # override a field, separate output dir
python -m ips.run experiments/ablation.yaml --keep-going               # do not stop on a failed run
```

Each run: tears down the stack → starts proxy, target, ingestion and optional services → starts benign traffic and the detector → waits `warmup_s` → starts the attackers → waits for the detector to finish → saves logs, image digests and resource samples → tears everything down. Finished runs have a `DONE` marker and are skipped, so an interrupted command can simply be re-run. A full run takes about `warmup_s + duration_s + 1.5 min`.

### 4.6 Paired replay (cheaper, stronger comparisons)
The full live matrix is large (≈3,700 runs, ≈770 h with 33 repetitions). Every live run stores all normalized logs (and connection samples) in `logs.jsonl`, so detector-only factors can be re-run **offline on exactly the same traffic**, with a virtual clock: wall time becomes only the LLM latency, and comparisons are paired (same input), which removes environment variance.

```bash
# 1. record traffic once per scenario/repetition (shadow mode keeps the attack traffic intact)
python -m ips.run experiments/ablation.yaml --only +shadow --reps 33
# 2. apply every detector-only configuration to the recorded traffic
python -m ips.replay experiments/ablation-replay.yaml --traffic runs/ablation/+shadow
# 3. analysis switches automatically to paired tests
python -m ips.analyze runs/ablation-replay
```

Factors that change the environment (real/TTL blocking, Redis buffer, CRS proxy) are rejected by the replay and must be evaluated live. Blocking is **emulated** in replay (`replay_emulate_block: true`, default): after an IP is blocked, its recorded logs are rewritten as the 403 Nginx would have returned (`request_time` 0, body size measured live). The detector therefore sees the same feedback as in a live active run. A check on one VulHub run gave live vs replay: `attack_block_rate` 0.912 vs 0.921, `llm_calls` 27 vs 29. The attacker's *reaction* to the block (e.g. stopping early) cannot be emulated.

### 4.7 Analysis
```bash
python -m ips.analyze runs/ablation
python -m ips.analyze runs/ablation --metrics tokens_total,ttm_s,iforest_f1
```

Outputs in `runs/<experiment>/analysis/`:

| File | Content |
|---|---|
| `runs.csv` | one row per run with all metrics |
| `summary.csv` | mean, std and 95% CI per (scenario, configuration) |
| `comparisons.csv` | before/after pairs: deltas, p-values, Holm-adjusted p, Cohen's d |
| `report.md` | summary tables and significant differences |
| `figures/` | bar charts with 95% CI per metric and iForest score distributions by label |

Comparisons generated: `isolated` (each configuration vs `baseline`), `refinement` (a factor vs the factor it requires, e.g. `+kg` → `+kg+kgsafe`), `cumulative` (each stacking step vs the previous one), `loo` (`all` vs `all-<factor>`), `arm` (arms vs `baseline`). Tests: Welch's t and Mann-Whitney U for live runs; paired t and Wilcoxon for replay; Cohen's d; Holm-Bonferroni correction per (scenario, metric, comparison type).

Main metrics:

| Group | Metrics |
|---|---|
| Cost | `llm_calls`, `tokens_total`, `tokens_per_call`, `cost_total`, `latency_mean`, `latency_p95`, `logs_to_llm_ratio`, `kg_decisions` |
| Detection | `detected`, `ttm_s` (first attacker log → first block), `attack_ip_recall`, `fp_ips` (benign IPs blocked), `window_precision/recall/f1`, `ip_accuracy`, `attack_block_rate`, `benign_block_rate` |
| Layer 1 (#20) | `iforest_tp/fp/tn/fn`, `iforest_precision/recall/f1/fpr`, `iforest_auc_roc/auc_pr`, `gnn_*`, `layer1_*` (iForest OR GNN) |
| Resources (#21) | `cpu_total_mean`, `mem_total_max_mb`, `<container>_cpu_mean`, `<container>_mem_max_mb` |

Calibrating a parameter without tuning on the reported data (replay, odd repetitions choose the value, even repetitions evaluate it):

```bash
python -m ips.calibrate experiments/ablation-replay.yaml --config +kg+kgsafe \
    --traffic runs/ablation/+shadow --param kg_similarity_threshold \
    --values 0.4,0.5,0.6,0.7,0.8 --metric attack_ip_recall --fp-penalty 1
```
Objective: mean(metric) − fp_penalty · mean(fp_ips), ties broken by fewer tokens. Output in `runs/calibration/<config>__<param>/` (`sweep.csv`, `evaluation.csv`, `calibration.json`).

### 4.8 Files of a run
`runs/<experiment>/<config>/<scenario>/rep-NN/`:

| File | Content |
|---|---|
| `detector_config.json`, `config.json` | effective detector configuration |
| `environment.json` | git commit, dirty flag, Python and package versions |
| `run.json` | factors, profiles, timestamps (infra ready, attack start, end), image digests |
| `windows.csv` | every decision (LLM, KG, hunt): trigger, logs sent, ground-truth counts, tokens, cost, latency, served model/provider/generation id, decision, explanation |
| `layer1.csv` | every log: label, features, iForest score/prediction, GNN score/prediction |
| `enforcement.csv` | blocks, shadow blocks, expirations, invalid or duplicate IPs |
| `connections.csv` | open connections per IP over time |
| `resources.csv` | CPU and memory per container (~1 s) |
| `logs.jsonl` | all normalized logs (input for replay) |
| `resultados_pesquisa.csv` | legacy format used by `resultados/gerar_graficos.py` |
| `*.log` | detector and attacker container logs |

## 5. Running the Detector by Hand
```bash
COMPOSE_PROFILES=proxy-nginx,es,benign docker compose up -d --build   # lab + benign traffic
docker compose --profile detector up detector                         # uses experiments/detector-default.yaml

# or on the host, overriding any DetectorConfig field
python -m ips.detector --set llm_backend=mock --set enforcement=log_only --set output_dir=runs/manual
python -m ips.detector --set log_buffer=jsonl --set jsonl_path=runs/smoke/baseline/zap/rep-01/logs.jsonl \
                       --set llm_backend=mock --no-docker            # offline replay of one run

docker compose --profile '*' down --remove-orphans                    # clean up
```
Without `--config`, the historical variables `MODELO_IA` and `ENFORCEMENT_MODE` are still honoured. With a config file, experimental parameters never come from the environment. Only endpoints are taken from it (`IPS_ELASTICSEARCH_URL`, `IPS_REDIS_URL`, `IPS_NEO4J_URL`, `IPS_OUTPUT_DIR`).

## 6. Troubleshooting
*   **Port already in use (80, 9200, 6380, 7687).** Stop the conflicting service. Redis is published on 6380 on purpose to avoid clashing with a local Redis.
*   **Logstash "unhealthy".** The healthcheck probes the syslog port 5044 (the HTTP API on 9600 does not answer on some hosts). Startup takes 30–60 s.
*   **SELinux (Fedora/RHEL).** Bind mounts use `:z` and the detector uses `security_opt: label=disable` to reach the Docker socket.
*   **Files in `runs/` owned by root.** The detector container runs with your UID/GID (`HOST_UID`, `HOST_GID`, `DOCKER_GID`, set by the runner). When starting it by hand, export them if they differ from 1000/1000/964.
*   **ZAP gets killed.** Its heap is fixed with `-Xmx2g`. Without it, `zap.sh` sizes the heap from the host RAM and exceeds the container limit. ZAP needs ~60 s to start scanning.
*   **First requests return 502.** Normal while Juice Shop boots. The runner waits for a non-5xx response before starting traffic.

## 7. Known Limitations
*   The fixes above are opt-in factors, so their cost is measured instead of assumed. The defaults still reproduce the original limitations: CSV-fitted iForest, stripped request line, permissive KG shortcut.
*   Replay emulates the block's effect on the logs but not the attacker's reaction to it. Factors whose effect depends on that reaction (or on the environment) must be evaluated live.
*   `kgsafe` reduces, but does not remove, the risk of propagating an LLM false positive. The provisional TTL limits the damage to `kg_provisional_ttl_s`.

## 8. Repository Structure
*   `ips/`: detector package.
    *   `detector.py`: main loop.
    *   `layer1.py` (iForest), `layer2.py` (LLM, prompts, mock backend), `enforcement.py` (mitigation).
    *   `kg.py` (knowledge graph), `gnn.py` (DOMINANT autoencoder), `conn.py` (connection telemetry).
    *   `sources.py` (Elasticsearch / Redis / JSONL sources), `records.py` (log normalization), `telemetry.py` (run outputs), `config.py` (all flags).
    *   `matrix.py` (design expansion), `run.py` (runner), `replay.py` (paired replay), `scenarios.py`, `resources.py` (CPU/RAM sampling), `analyze.py` (statistics and figures), `calibrate.py` (threshold calibration with odd/even split).
*   `experiments/`: experiment definitions.
*   `docker/detector/`: detector image.
*   `docker/traffic/`: benign users, Slowloris, VulHub attacker, CSIC replay.
*   `docker/nginx/`: proxy backend selection (direct or via CRS).
*   `docker/vulhub/`: vulnerable CGI for Shellshock.
*   `logstash/pipeline/`: ingestion pipelines (`elasticsearch.conf`, `redis.conf`).
*   `datasets/`: external datasets (not versioned; `fetch_csic.sh` downloads and checks them, see `datasets/README.md`).
*   `tests/`: offline tests (pytest).
*   `IsolationForest/`: baseline traffic (`trafego_base.csv`), its generator and the original monolithic detector (kept for reference only).
*   `resultados/`: historical results of the paper and plotting scripts.
*   `run.sh`: single run in the original condition.

## 9. Ethical Considerations and Licensing
This software is provided exclusively for academic research. All attack simulations are performed within an isolated Docker network against intentionally vulnerable applications. Exploit payloads only point to non-existent hosts (`*.invalid`) and run read-only commands. The source code is licensed for open academic reuse.
