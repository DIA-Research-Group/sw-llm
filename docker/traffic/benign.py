"""Gerador de trafego benigno realista (#16).

Simula sessoes de usuarios do Juice Shop com tempos de leitura variaveis,
carregamento de assets, buscas, visualizacao de produtos e *erros naturais*
(senha errada, rota digitada errada, recurso sem autenticacao), para que o
trafego legitimo nao seja idealizado e os falsos positivos possam ser medidos.
"""
import argparse
import os
import random
import time

import requests

TARGET = os.getenv("TARGET", "http://nginx-proxy")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
ASSETS = [
    "/main.js", "/runtime.js", "/polyfills.js", "/styles.css", "/vendor.js",
    "/assets/public/images/JuiceShop_Logo.png", "/assets/i18n/en.json", "/rest/admin/application-configuration",
    "/rest/languages", "/api/Quantitys/",
]
PRODUCTS = [f"/assets/public/images/products/{p}" for p in (
    "apple_juice.jpg", "orange_juice.jpg", "banana_juice.jpg", "melon_bike.jpeg", "fruit_press.jpg")]
SEARCH_TERMS = ["apple", "orange", "juice", "banana", "lemon", "melon", "t-shirt", "sticker", "", "aple", "banan"]
TYPOS = ["/prodcuts", "/api/Product", "/#/serach", "/favicon.icon", "/robots.txt", "/rest/basket"]


class User:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.s = requests.Session()
        self.s.headers["User-Agent"] = rng.choice(USER_AGENTS)

    def get(self, path, **kw):
        try:
            self.s.get(TARGET + path, timeout=10, **kw)
        except requests.RequestException:
            pass

    def post(self, path, **kw):
        try:
            self.s.post(TARGET + path, timeout=10, **kw)
        except requests.RequestException:
            pass

    def think(self, lo=0.5, hi=4.0):
        time.sleep(self.rng.uniform(lo, hi))

    def landing(self):
        self.get("/")
        for a in self.rng.sample(ASSETS, k=self.rng.randint(3, len(ASSETS))):
            self.get(a)
        self.get("/api/Challenges/?name=Score%20Board")
        self.get("/rest/products/search?q=")

    def browse(self):
        for _ in range(self.rng.randint(1, 6)):
            action = self.rng.random()
            if action < 0.35:
                term = self.rng.choice(SEARCH_TERMS)
                self.get(f"/rest/products/search?q={term}")
            elif action < 0.65:
                pid = self.rng.randint(1, 40)
                self.get(f"/api/Products/{pid}")
                self.get(f"/rest/products/{pid}/reviews")
                self.get(self.rng.choice(PRODUCTS))
            elif action < 0.75:
                self.get("/rest/user/whoami")
            elif action < 0.83:
                # erro natural: login com senha errada (401)
                self.post("/rest/user/login", json={"email": f"user{self.rng.randint(1, 99)}@mail.com",
                                                    "password": "wrongpass" + str(self.rng.randint(0, 9))})
            elif action < 0.90:
                self.get(self.rng.choice(TYPOS))  # rota digitada errada
            elif action < 0.95:
                self.get("/rest/basket/1")  # sem autenticacao (401)
            else:
                self.get("/api/Feedbacks/")
            self.think()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    while True:
        user = User(rng)
        user.landing()
        user.think(1, 3)
        user.browse()
        time.sleep(rng.uniform(2, 8))  # intervalo entre sessoes


if __name__ == "__main__":
    main()
