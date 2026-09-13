#!/bin/bash

# --- EXPERIMENTAL CONFIGURATION ---
# Define the Large Language Model to be evaluated
# MODEL_IDENTIFIER="openai/gpt-4o-mini" 
MODEL_IDENTIFIER="anthropic/claude-3-5-haiku"
# MODEL_IDENTIFIER="google/gemini-1.5-flash:free"
# MODEL_IDENTIFIER="google/gemini-2.0-flash-lite-preview-02-05"

# Total execution duration (10 minutes = 600s + 10s buffer)
EXECUTION_DURATION=610 

# Enforcement Mode: 'log_only' (shadow mode, default) or 'active' (physical block)
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-log_only}"

echo "=========================================================="
echo "  INITIALIZING SCIENTIFIC EXPERIMENT: $MODEL_IDENTIFIER"
echo "  ENFORCEMENT MODE: $ENFORCEMENT_MODE"
echo "=========================================================="

# 1. Environment Sanitization and Reset
echo "[*] Restoring environment and resetting configurations..."
pkill -f "detector.py" > /dev/null 2>&1

# Terminate all active containers and prune networks
docker compose --profile "*" down --remove-orphans > /dev/null 2>&1
docker network prune -f > /dev/null 2>&1

# Ensure blocklist.conf is initialized as a clean file
rm -rf blocklist.conf
touch blocklist.conf

# Initialize results directory
mkdir -p resultados

# 2. Infrastructure Deployment
echo "[*] Deploying containerized infrastructure (Elasticsearch, Nginx, JuiceShop)..."
docker compose up -d
docker rm -f owasp-zap-attacker > /dev/null 2>&1

# Allow for cluster stabilization and indexing initialization
echo "[*] Waiting 20 seconds for cluster stabilization..."
sleep 20

# 3. Parallel Execution of Experimental Components
echo "[*] Activating Autonomic Detection Engine ($MODEL_IDENTIFIER, mode: $ENFORCEMENT_MODE)..."
# Start the detector in the background and capture PID
ENFORCEMENT_MODE=$ENFORCEMENT_MODE MODELO_IA=$MODEL_IDENTIFIER python IsolationForest/detector.py &
DETECTOR_PID=$!

echo "[*] Launching adversarial simulation (OWASP ZAP)..."
# Execute active scan in the background
docker compose run --name owasp-zap-attacker owasp-zap zap-full-scan.py \
  -t http://nginx-proxy:80 \
  -m 10 \
  -z "-config scanner.threadPerHost=2 -config scanner.skipStack=DomXssScanRule" &
ZAP_PID=$!

# 4. Experimental Monitoring
echo "----------------------------------------------------------"
echo "[!] DATA COLLECTION IN PROGRESS: Terminating in 10 minutes."
echo "[!] Metrics are being persisted to: resultados/resultados_pesquisa.csv"
echo "----------------------------------------------------------"

# Await completion of the experimental window
sleep $EXECUTION_DURATION

# 5. Finalization and Cleanup
echo ""
echo "=========================================================="
echo "  EXPERIMENTAL LIMIT REACHED - TERMINATING PROCESSES"
echo "=========================================================="

# Gracefully terminate the detection engine
echo "[*] Shutting down detection engine..."
kill $DETECTOR_PID

# Terminate the adversarial simulation
echo "[*] Stopping adversarial simulation..."
docker compose stop owasp-zap

# Decommission infrastructure to release system resources
echo "[*] Decommissioning Docker containers..."
docker compose down

echo "[SUCCESS] Experiment completed successfully."
echo "[SUCCESS] Analyze 'resultados/' directory for generated datasets."
