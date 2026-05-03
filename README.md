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
*   Docker and Docker Compose (v2.0+)
*   Python 3.10 or higher
*   Valid API Credentials for OpenRouter (or compatible OpenAI-standard endpoint)

### 3.2 Environment Configuration
1.  Clone the repository to a local directory.
2.  Initialize the environment configuration:
    ```bash
    cp .env.example .env
    ```
3.  Populate the `OPENROUTER_API_KEY` variable in the `.env` file with a valid token.

### 3.3 Dependency Installation
It is recommended to use a dedicated Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3.4 Execution Workflow
The experimental lifecycle is orchestrated via the `run.sh` script, which automates environment stabilization, detection activation, adversarial simulation, and data collection.

```bash
chmod +x run.sh
./run.sh
```

The script is configured to run for 600 seconds (10 minutes) per iteration. The target LLM can be modified by updating the `MODELO_IA` variable within the script or the environment.

### 3.5 Data Analysis and Visualization
Upon completion, performance metrics (latency, token consumption, and mitigation success) are persisted in `resultados/resultados_pesquisa.csv`. To generate the statistical visualizations utilized in the study:

```bash
python resultados/gerar_graficos.py
```

## 4. Repository Structure
*   `IsolationForest/`: Core logic for anomaly detection and LLM integration.
*   `logstash/`: Ingestion filters and normalization rules.
*   `resultados/`: Analytical scripts and datasets.
*   `nginx.conf`: Security gateway configuration.
*   `run.sh`: Master orchestration script.

## 5. Ethical Considerations and Licensing
This software is provided exclusively for academic research. All attack simulations are performed within an isolated network environment. The source code is licensed for open academic reuse.
