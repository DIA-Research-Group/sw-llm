import requests
import time
import random
import csv
import os

BASE_URL = "http://nginx-proxy"
ARQUIVO_BASE = "IsolationForest/trafego_base.csv"

ROTAS_NORMAIS = [
    "/",
    "/#/search",
    "/rest/user/whoami",
    "/api/Products",
    "/api/Challenges",
    "/assets/public/images/products/apple_juice.jpg",
    "/assets/public/images/products/orange_juice.jpg"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

print(f"=== GERADOR DE BASELINE ATIVO ===")
print(f"Salvando em: {ARQUIVO_BASE}")

# Cria o diretório se não existir
os.makedirs(os.path.dirname(ARQUIVO_BASE), exist_ok=True)

# Prepara o arquivo CSV
with open(ARQUIVO_BASE, mode='w', newline='') as ficheiro:
    escritor = csv.writer(ficheiro)
    escritor.writerow(['request_time', 'status', 'body_bytes_sent'])

    contador = 0
    try:
        while contador < 1000:  # 1000 requisições são suficientes para uma baseline sólida
            rota = random.choice(ROTAS_NORMAIS)
            alvo = f"{BASE_URL}{rota}"
            
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                
                # Realiza a requisição e mede o tempo
                resposta = requests.get(alvo, timeout=5)
                
                # Extração das métricas
                request_time = resposta.elapsed.total_seconds()
                status = resposta.status_code
                body_bytes = len(resposta.content)

                # Salva apenas o que for "Normal" (Status 200 e tempo baixo)
                if status == 200 and request_time < 2.0:
                    escritor.writerow([request_time, status, body_bytes])
                    contador += 1
                    if contador % 50 == 0:
                        print(f"[*] Progresso: {contador}/1000 amostras coletadas...")
                
            except Exception as e:
                print(f"[!] Erro na conexão: {e}")
            
            time.sleep(random.uniform(0.1, 0.5))

    except KeyboardInterrupt:
        print("\n[!] Coleta interrompida pelo usuário.")

print(f"\n[V] Baseline concluída com {contador} amostras reais.")