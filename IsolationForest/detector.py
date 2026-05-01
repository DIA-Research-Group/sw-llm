import time
import pandas as pd
import json
import requests
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import warnings
import os
from dotenv import load_dotenv
import subprocess
import atexit

# --- CONFIGURAÇÃO DE AMBIENTE E CAMINHOS ---
warnings.filterwarnings('ignore')
load_dotenv()

# Caminhos absolutos para garantir que o script acesse o arquivo mapeado pelo Docker
diretorio_script = os.path.dirname(os.path.abspath(__file__))
# Sobe um nível para encontrar o blocklist.conf na raiz do projeto
caminho_blocklist = os.path.join(os.path.dirname(diretorio_script), 'blocklist.conf')
caminho_csv = os.path.join(diretorio_script, 'trafego_base.csv')

def limpar_bloqueios():
    """Restaura o blocklist.conf e recarrega o Nginx para o estado original."""
    print("\n\Limpando blocklist e restaurando acesso...")
    try:
        with open(caminho_blocklist, "w") as f:
            f.write("# Arquivo de bloqueio volátil - LiveFireLab\n")
        
        subprocess.run(
            ["docker", "exec", "nginx-proxy", "nginx", "-s", "reload"],
            check=True, capture_output=True
        )
        print("[V] Ambiente restaurado com sucesso.")
    except Exception as e:
        print(f"[X] Erro ao limpar ambiente: {e}")

# Registra a limpeza para ser executada automaticamente ao fechar o script (Ctrl+C ou Erro)
atexit.register(limpar_bloqueios)

print("=== INICIANDO SISTEMA DE DEFESA (MODO VOLÁTIL) ===")

# --- TREINAMENTO DO MODELO ---
print("[*] Treinando o modelo com baseline habitual...")
try:
    df_base = pd.read_csv(caminho_csv)
    # Conversão explícita para garantir compatibilidade com o Isolation Forest
    for col in ['request_time', 'status', 'body_bytes_sent']:
        df_base[col] = pd.to_numeric(df_base[col], errors='coerce')
    
    # Treino apenas com dados legitimos (Status 200 e tempo baixo)
    df_base = df_base[(df_base['request_time'] < 2.0) & (df_base['status'] == 200)].dropna()
    features = ['request_time', 'status', 'body_bytes_sent']
    
    model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
    model.fit(df_base[features])
    print(f"[*] Modelo treinado com {len(df_base)} amostras limpas.")
except Exception as e:
    print(f"[!] ERRO NO TREINO: {e}")
    exit()

# --- CONEXÃO ELASTICSEARCH ---
try:
    es = Elasticsearch(
        "http://elasticsearch:9200",
        headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8",
                 "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"}
    )
    print(f"[*] Conectado ao cluster: {es.info()['cluster_name']}")
except Exception as e:
    print(f"[!] ERRO NA CONEXÃO ES: {e}")
    exit()

# --- MONITORAMENTO E ANÁLISE ---
last_timestamp = "now-1m"
collect_status = False
collect_start = 0
collection = []

limpar_bloqueios() # Inicia com o ambiente limpo

try:
    while True:
        query = {
            "query": {"range": {"@timestamp": {"gt": last_timestamp}}},
            "sort": [{"@timestamp": "asc"}],
            "size": 500
        }
        res = es.search(index="telemetria-alvo-*", body=query)
        hits = res['hits']['hits']

        if not hits:
            time.sleep(2)
            continue

        last_timestamp = hits[-1]['_source']['@timestamp']
        
        extracted_data = []
        for hit in hits:
            source = hit['_source']
            raw_message = source.get('message', '')

            # Extração robusta do JSON de dentro da string de log
            try:
                if '{' in raw_message:
                    json_part = raw_message[raw_message.find('{'):]
                    data = json.loads(json_part)
                    
                    extracted_data.append({
                        'timestamp': source.get('@timestamp'),
                        'status': int(data.get('status', 0)),
                        'request_time': float(data.get('request_time', 0)),
                        'body_bytes_sent': int(data.get('body_bytes_sent', 0)),
                        'remote_addr': data.get('remote_addr', 'N/A'),
                        'request_uri': data.get('request_uri', 'N/A')
                    })
            except:
                continue
        
        if not extracted_data:
            continue

        df_analise = pd.DataFrame(extracted_data)
        df_analise['resultado'] = model.predict(df_analise[features])
        anomalies = df_analise[df_analise['resultado'] == -1]
        
        # Detecção de anomalia (Estatística ou Volumétrica)
        rps_anomalo = len(df_analise) > 30 

        if not anomalies.empty or rps_anomalo:
            if not collect_status:
                motivo = "VOLUMETRIA" if rps_anomalo else "ESTATÍSTICA"
                print(f"\nANOMALIA DETECTADA ({motivo})! Lote com {len(df_analise)} eventos.")
                collect_status = True
                collect_start = time.time()
            collection.extend(df_analise.to_dict('records'))

        # Processamento da Janela de Contexto
        if collect_status and (time.time() - collect_start >= 5.0):
            print(f"[*] Janela Fechada. Total: {len(collection)} logs. Acionando LLM...")
            
            # Higienização e compactação do contexto
            context_json = json.dumps(collection[:50], indent=2) # Amostra para eficiência
            
            token_openrouter = os.getenv("OPENROUTER_API_KEY")
            if not token_openrouter:
                print("[!] ERRO: API Key não encontrada.")
                collection = []; collect_status = False
                continue

            headers = {"Authorization": f"Bearer {token_openrouter}", "Content-Type": "application/json"}
            payload = {
                "model": "openai/gpt-4o-mini",
                "response_format": { "type": "json_object" },
                "messages": [
                    {"role": "system", "content": "Você é um IPS. Analise os logs e retorne JSON: {'ataque_detectado': bool, 'ip_alvo_bloqueio': str}"},
                    {"role": "user", "content": f"Logs:\n{context_json}"}
                ]
            }

            try:
                resposta = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
                decisao = json.loads(resposta.json()['choices'][0]['message']['content'])
                
                ip_alvo = decisao.get('ip_alvo_bloqueio')
                if decisao.get('ataque_detectado') and ip_alvo and ip_alvo != 'N/A':
                    print(f"[!] IA CONFIRMOU ATAQUE. Bloqueando IP: {ip_alvo}")
                    with open(caminho_blocklist, "a") as f:
                        f.write(f"deny {ip_alvo};\n")
                    
                    subprocess.run(["docker", "exec", "nginx-proxy", "nginx", "-s", "reload"], check=True)
                    print(f"Mitigação aplicada com sucesso para {ip_alvo}.")
                else:
                    print("[>] IA não identificou ataque conclusivo.")
            except Exception as e:
                print(f"[X] Erro na comunicação com IA: {e}")

            collection = []; collect_status = False

        time.sleep(2)

except KeyboardInterrupt:
    print("\n[!] Radar encerrado pelo usuário.")