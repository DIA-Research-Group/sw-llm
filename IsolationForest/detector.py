import time
import pandas as pd
import json
import requests
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import warnings
import os
import csv
from dotenv import load_dotenv
import subprocess
import atexit

# --- ENVIRONMENT CONFIGURATION AND PATHS ---
warnings.filterwarnings('ignore')
load_dotenv()

# --- EXPERIMENT CONFIGURATION ---
TEST_DURATION_SECONDS = 600
global_start_time = time.time()
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "log_only").strip().lower()

# Absolute paths for Docker-mapped volume access
script_dir = os.path.dirname(os.path.abspath(__file__))
# Navigate up to find blocklist.conf in the project root
blocklist_path = os.path.join(os.path.dirname(script_dir), 'blocklist.conf')
base_traffic_csv = os.path.join(script_dir, 'trafego_base.csv')

# --- METRICS PERSISTENCE CONFIGURATION ---
results_dir = os.path.join(os.path.dirname(script_dir), "resultados")
os.makedirs(results_dir, exist_ok=True)
RESEARCH_RESULTS_FILE = os.path.join(results_dir, "resultados_pesquisa.csv")
shadow_blocks_csv = os.path.join(results_dir, "ips_bloqueados_simulado.csv")

# Ensure existing legacy CSV has Enforcement_Mode column if already present
if os.path.isfile(RESEARCH_RESULTS_FILE) and os.path.getsize(RESEARCH_RESULTS_FILE) > 0:
    try:
        with open(RESEARCH_RESULTS_FILE, 'r', encoding='utf-8') as f:
            first_line = f.readline()
        if 'Enforcement_Mode' not in first_line:
            df_legacy = pd.read_csv(RESEARCH_RESULTS_FILE)
            df_legacy = df_legacy.rename(columns={
                'Modelo': 'Model',
                'Tokens_Totais': 'Total_Tokens',
                'Latencia_Segundos': 'Latency_Seconds',
                'IP_Bloqueado': 'Blocked_IP',
                'Logs_na_Janela': 'Logs_in_Window'
            })
            if 'Enforcement_Mode' not in df_legacy.columns:
                df_legacy['Enforcement_Mode'] = 'active'
            df_legacy.to_csv(RESEARCH_RESULTS_FILE, index=False)
            print("[INFO] Migrated legacy results CSV to include 'Enforcement_Mode' column.")
    except Exception as e:
        print(f"[WARNING] Could not check/migrate legacy results CSV: {e}")

def register_shadow_block(ip, model_name, latency):
    """Registra um IP que teria sido bloqueado, sem aplicar o bloqueio de fato."""
    header_required = not os.path.isfile(shadow_blocks_csv) or os.path.getsize(shadow_blocks_csv) == 0
    with open(shadow_blocks_csv, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if header_required:
            writer.writerow(['Timestamp', 'IP', 'Model', 'Latency_Seconds'])
        writer.writerow([datetime.now().isoformat(), ip, model_name, latency])

def save_research_metric(model_name, tokens_consumed, api_latency, blocked_ip, logs_count, enforcement_mode=None):
    """Persists experimental metrics for scientific analysis."""
    if enforcement_mode is None:
        enforcement_mode = ENFORCEMENT_MODE
    header_required = not os.path.isfile(RESEARCH_RESULTS_FILE) or os.path.getsize(RESEARCH_RESULTS_FILE) == 0
    with open(RESEARCH_RESULTS_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if header_required:
            writer.writerow(['Model', 'Total_Tokens', 'Latency_Seconds', 'Blocked_IP', 'Logs_in_Window', 'Enforcement_Mode'])
        writer.writerow([model_name, tokens_consumed, api_latency, blocked_ip, logs_count, enforcement_mode])

def reset_security_environment():
    """Restores the network security configuration to its baseline state."""
    print("\n[INFO] Restoring environment and clearing dynamic blocklist...")
    try:
        with open(blocklist_path, "w") as f:
            f.write("# Volatile blocklist - Automated Research Environment\n")
        
        subprocess.run(
            ["docker", "exec", "nginx-proxy", "nginx", "-s", "reload"],
            check=True, capture_output=True
        )
        print("[SUCCESS] Security environment restored.")
    except Exception as e:
        print(f"[ERROR] Environment restoration failed: {e}")

# Register automated cleanup for research integrity
atexit.register(reset_security_environment)

print(f"=== INITIALIZING AUTONOMIC PREVENTION SYSTEM (Mode: {ENFORCEMENT_MODE.upper()}) ===")

# --- ANOMALY DETECTION MODEL TRAINING ---
print("[*] Training Isolation Forest with baseline traffic data...")
try:
    df_base = pd.read_csv(base_traffic_csv)
    # Ensure numerical consistency for model features
    for col in ['request_time', 'status', 'body_bytes_sent']:
        df_base[col] = pd.to_numeric(df_base[col], errors='coerce')
    
    # Filter for legitimate traffic patterns (Status 200 and sub-2.0s latency)
    df_base = df_base[(df_base['request_time'] < 2.0) & (df_base['status'] == 200)].dropna()
    features = ['request_time', 'status', 'body_bytes_sent']
    
    model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
    model.fit(df_base[features])
    print(f"[*] Model trained successfully with {len(df_base)} legitimate samples.")
except Exception as e:
    print(f"[CRITICAL] Model training failure: {e}")
    exit(1)

# --- ELASTICSEARCH INTEGRATION ---
try:
    es = Elasticsearch(
        "http://localhost:9200",
        request_timeout=30,
        headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8",
                 "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"}
    )
    # Verify cluster connectivity
    for i in range(10):
        try:
            if es.ping():
                break
        except:
            print(f"[*] Waiting for Elasticsearch readiness... ({i+1}/10)")
            time.sleep(5)
    
    print(f"[*] Connected to cluster: {es.info()['cluster_name']}")
except Exception as e:
    print(f"[CRITICAL] Data source connection failed: {e}")
    exit(1)

# --- MONITORING AND ANALYSIS ORCHESTRATION ---
last_processed_timestamp = "now-1m"
context_collection = []
is_collecting = False
collection_start_time = 0

reset_security_environment()

# Synchronize with ingestion pipeline
print("[*] Synchronizing with log ingestion pipeline...")
while True:
    try:
        if es.indices.exists(index="telemetria-alvo-*"):
            print("[SUCCESS] Log index detected. Starting monitoring loop.")
            break
    except:
        pass
    time.sleep(5)

try:
    while True:
        # Respect experimental duration limits
        elapsed_time = time.time() - global_start_time
        if elapsed_time > TEST_DURATION_SECONDS:
            print(f"\n[INFO] Experimental duration reached ({TEST_DURATION_SECONDS}s).")
            print("[*] Finalizing data collection and restoring baseline...")
            break

        query = {
            "query": {"range": {"@timestamp": {"gt": last_processed_timestamp}}},
            "sort": [{"@timestamp": "asc"}],
            "size": 500
        }
        
        try:
            res = es.search(index="telemetria-alvo-*", body=query)
        except Exception as e:
            print(f"[WARNING] Data retrieval error: {e}. Retrying in 5s...")
            time.sleep(5)
            continue

        hits = res['hits']['hits']
        if not hits:
            time.sleep(2)
            continue

        df_batch = pd.DataFrame([hit['_source'] for hit in hits])
        last_processed_timestamp = hits[-1]['_source']['@timestamp']

        # Pre-process batch for inference
        for col in features:
            df_batch[col] = pd.to_numeric(df_batch[col], errors='coerce')
        df_batch = df_batch.dropna(subset=features)

        if df_batch.empty:
            continue

        # Tier 1: Anomaly Detection
        df_batch['anomaly_score'] = model.predict(df_batch[features])
        anomalies_detected = df_batch[df_batch['anomaly_score'] == -1]
        volumetric_trigger = len(df_batch) > 30

        if not anomalies_detected.empty or volumetric_trigger:
            if not is_collecting:
                reason = "VOLUMETRIC" if volumetric_trigger else "STATISTICAL"
                print(f"\n[ALERT] ANOMALY DETECTED ({reason})! Analyzing batch of {len(df_batch)} events.")
                is_collecting = True
                collection_start_time = time.time()
            context_collection.extend(df_batch.to_dict('records'))

        # Tier 2: LLM Contextual Validation
        if is_collecting and (time.time() - collection_start_time >= 5.0):
            print(f"[*] Context window finalized. Analyzing {len(context_collection)} logs via LLM...")
            
            # Context sanitization (limit to first 50 entries for efficiency)
            sanitized_context = json.dumps(context_collection[:50], indent=2)
            
            api_key = os.getenv("OPENROUTER_API_KEY")
            llm_model = os.getenv("MODELO_IA", "openai/gpt-4o-mini")
            
            if not api_key:
                print("[ERROR] LLM API credentials missing.")
                context_collection = []; is_collecting = False
                continue

            api_headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            api_payload = {
                "model": llm_model,
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are an Autonomic Security Analyst. Evaluate the provided logs and return EXCLUSIVELY a JSON object. Do not provide commentary.\n\nRequired Format:\n{\"ataque_detectado\": bool, \"ip_alvo_bloqueio\": \"string or N/A\"}"
                    },
                    {"role": "user", "content": f"Observability Data:\n{sanitized_context}"}
                ]
            }

            try:
                inference_start = time.time()
                api_response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=api_headers, json=api_payload)
                inference_end = time.time()
                
                latency = round(inference_end - inference_start, 2)
                
                if api_response.status_code != 200:
                    print(f"[ERROR] LLM API Error (Status {api_response.status_code}): {api_response.text}")
                    context_collection = []; is_collecting = False
                    continue

                try:
                    response_json = api_response.json()
                except Exception as e:
                    print(f"[ERROR] Failed to decode API response: {e}")
                    context_collection = []; is_collecting = False
                    continue
                
                if 'choices' not in response_json or not response_json['choices']:
                    print(f"[ERROR] Malformed LLM response: {response_json}")
                    context_collection = []; is_collecting = False
                    continue

                raw_content = response_json['choices'][0]['message'].get('content', '').strip()
                
                # Sanitize markdown formatting from content
                if raw_content.startswith("```"):
                    raw_content = raw_content.split("```")[1]
                    if raw_content.startswith("json"):
                        raw_content = raw_content[4:]
                    raw_content = raw_content.strip()

                if not raw_content:
                    print("[ERROR] LLM returned empty content.")
                    context_collection = []; is_collecting = False
                    continue

                try:
                    decision = json.loads(raw_content)
                except Exception as e:
                    print(f"[ERROR] JSON parsing failed for LLM decision: {e}")
                    print(f"[*] Raw content: {raw_content}")
                    context_collection = []; is_collecting = False
                    continue

                tokens_used = response_json.get('usage', {}).get('total_tokens', 0)
                threat_ip = decision.get('ip_alvo_bloqueio')

                save_research_metric(
                    model_name=llm_model,
                    tokens_consumed=tokens_used,
                    api_latency=latency,
                    blocked_ip=threat_ip,
                    logs_count=len(context_collection[:50]),
                    enforcement_mode=ENFORCEMENT_MODE
                )

                if decision.get('ataque_detectado') and threat_ip and threat_ip != 'N/A':
                    print(f"[ACTION] THREAT CONFIRMED for IP: {threat_ip} (mode={ENFORCEMENT_MODE})")
                    if ENFORCEMENT_MODE == "active":
                        with open(blocklist_path, "a") as f:
                            f.write(f"deny {threat_ip};\n")
                        subprocess.run(["docker", "exec", "nginx-proxy", "nginx", "-s", "reload"], check=True)
                        print(f"[SUCCESS] Mitigation enforced for {threat_ip}.")
                    else:
                        register_shadow_block(threat_ip, llm_model, latency)
                        print(f"[SHADOW] IP {threat_ip} teria sido bloqueado (log-only).")
                else:
                    print("[INFO] No conclusive threat identified by LLM.")
            except Exception as e:
                print(f"[ERROR] Critical failure in autonomic decision chain: {e}")

            # Reset collection window
            context_collection = []; is_collecting = False

        time.sleep(1)

except KeyboardInterrupt:
    print("\n[INFO] Monitoring terminated by operator.")
