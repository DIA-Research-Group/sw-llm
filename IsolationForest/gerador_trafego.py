import requests
import time
import random

BASE_URL = "http://localhost"

# Rotas comuns de um usuário navegando no Juice Shop
ROTAS_NORMAIS = [
    "/",
    "/#/search",
    "/rest/user/whoami",
    "/api/Products",
    "/api/Challenges",
    "/assets/public/images/products/apple_juice.jpg",
    "/assets/public/images/products/orange_juice.jpg"
]

ROTAS_RUIDO = [
    "/pagina-que-nao-existe",
    "/admin-painel-falso",
    "/imagens/foto-antiga.png"
]

TODAS_AS_ROTAS = ROTAS_NORMAIS * 5 + ROTAS_RUIDO

print("=== INICIANDO SIMULADOR DE TRÁFEGO NORMAL ===")
print("Pressione Ctrl+C para parar quando achar suficiente.\n")

contador = 0
try:
    while True:
        rota_escolhida = random.choice(TODAS_AS_ROTAS)
        alvo = f"{BASE_URL}{rota_escolhida}"
        
        try:
            resposta = requests.get(alvo, timeout=2)
            contador += 1
            print(f"[{contador}] Acesso simulado: {alvo} (Status: {resposta.status_code})")
        except requests.exceptions.RequestException:
            print(f"[{contador}] Falha ao conectar: O servidor está rodando?")
            
        # Um usuário demora entre 0.1s (carregando imagens) e 2.0s (lendo a página)
        tempo_espera = random.uniform(0.1, 2.0)
        time.sleep(tempo_espera)

except KeyboardInterrupt:
    print(f"\n[V] Simulação encerrada! {contador} requisições normais geradas.")
