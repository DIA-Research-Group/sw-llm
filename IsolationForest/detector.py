import time
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
import warnings

warnings.filterwarnings('ignore')

print("=== INICIANDO SISTEMA DE DEFESA ===")

print("[1] Treinando o modelo com baseline habitual...")
try:
    df_base = pd.read_csv('trafego_base.csv')
    df_base['request_time'] = pd.to_numeric(df_base['request_time'], errors = 'coerce')
    df_base['status'] = pd.to_numeric(df_base['status'], errors = 'coerce')
    df_base = df_base.dropna(subset=['request_time', 'status'])

    model = IsolationForest(n_estimators = 200, random_state = 42)
    model.fit(df_base[['request_time', 'status']])
    print(f"[*] Modelo treinado com {len(df_base)} requisições normais")
except Exception as e:
    print(f"[!], ERRO AO CARREGAR BASELINE DE DADOS: {e}")
    exit()

print("\n[2] Conectando ao ElasticSearch...")
try:
    es = Elasticsearch(
        "http://localhost:9200",
        verify_certs=False,
        headers={"Accept": "application/vnd.elasticsearch+json; compatible-with=8",
                 "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"}
    )
    info = es.info()
    print(f"[*] Conexão estabelecidade com sucesso! Cluster: {info['cluster_name']}")
except Exception as e:
    print(f"[!] ERRO NA CONEXÃO: {e}")
    exit()

print("\n[3] Monitorando Tráfego...")
analised_logs = set()

#pacote pra llm

collect_status = False
collect_start = 0
collection = []

try:
    while True:
        query = {
            "query":{
                "range":{
                    "@timestamp":{
                        "gte": "now-1m",
                        "lte": "now"
                    }
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": 50
        }
        res = es.search(index="telemetria-alvo-*", body=query)
        hits = res['hits']['hits']

        new_logs = []
        for hit in hits:
            if hit['_id'] not in analised_logs:
                new_logs.append(hit)
                analised_logs.add(hit['_id'])

        if len(analised_logs) > 200:
            analised_logs = set(list(analised_logs)[-100:])
            
        if len(new_logs) > 0:
            print(f"\n[{time.strftime('%H:%M:%S')}] {len(new_logs)} novos eventos detectados!")

            extracted_data = []
            for hit in new_logs:
                source = hit['_source']
                extracted_data.append({
                    'timestamp': source.get('@timestamp', ''),
                    'request_method': source.get('request_method', 'N/A'),
                    'status': source.get('status', 0),
                    'remote_addr': source.get('remote_addr', 'N/A'),
                    'request_time': source.get('request_time', 0),
                    #LLM DATA:
                    'request_uri': source.get('request_uri', 'N/A'),
                    'http_user_agent': source.get('http_user_agent', 'N/A')
                })
                
            df_new = pd.DataFrame(extracted_data)
            df_new['request_time'] = pd.to_numeric(df_new['request_time'], errors = 'coerce')
            df_new['status'] = pd.to_numeric(df_new['status'], errors = 'coerce')
            df_analise = df_new.dropna(subset=['request_time', 'status']).copy()

            if not df_analise.empty:
                df_analise['resultado'] = model.predict(df_analise[['request_time', 'status']])
                anomalies = df_analise[df_analise['resultado'] == -1]

                if not anomalies.empty:
                    if not collect_status:
                        print("ANOMALIA DETECTADA!!!: ABRINDO JANELA DE 5 SEG")
                        collect_status = True
                        collect_start = time.time()
                        
                    collection.extend(anomalies.to_dict('records'))
                    print(anomalies[['timestamp', 'remote_addr', 'status', 'request_time']])
                else:
                    if not collect_status:
                        print("[V] Tráfego Normal")

        if collect_status:
            spent_time = time.time() - collect_start
            print(f"[*] Coletando Contexto... ({spent_time:.1f}s / 5.0s)")
            
            if spent_time >= 5.0:
                print("\n=== Janela Fechada ===")
                print(f"[*] Total de anomalias capturadas: {len(collection)}")

                ##aqui entra a função de conectar com a api da llm @Rhyan as anomalias estão dentro do collection[]

                print("\n[*] Esvaziando o balde...")
                collection = []
                collect_status = False
                
        time.sleep(2)
        
except KeyboardInterrupt:
    print("\nRadar Desligado")
