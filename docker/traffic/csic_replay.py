"""Replay do dataset HTTP CSIC 2010 (#16) atraves do proxy real.

O CSIC 2010 traz requisicoes HTTP rotuladas (normal/anomala: SQLi, XSS,
buffer overflow, CRLF, parameter tampering...), mas nao traz ``request_time``,
``status`` nem ``body_bytes_sent`` – as features do iForest. Reenviando as
requisicoes pelo Nginx real, esses campos passam a existir e o rotulo e
preservado pelo IP de origem (um container por classe).

Formato esperado: CSV do Kaggle "CSIC 2010 Web Application Attacks"
(colunas ``Method``, ``User-Agent``, ``URL``, ``content``, ``classification``
ou ``label``). Ver datasets/README.md.
"""
import argparse
import csv
import glob
import http.client
import os
import random
import sys
import time
from urllib.parse import urlparse, urlsplit

TARGET = urlparse(os.getenv("TARGET", "http://nginx-proxy"))
LABELS = {"normal": {"0", "normal", "norm"}, "anomalous": {"1", "anomalous", "anom", "attack"}}


def load(path_glob: str, label: str):
    files = sorted(glob.glob(path_glob))
    if not files:
        sys.exit(f"[csic] dataset nao encontrado em {path_glob} (ver datasets/README.md)")
    rows = []
    for f in files:
        with open(f, newline="", encoding="utf-8", errors="replace") as fh:
            for r in csv.DictReader(fh):
                cls = str(r.get("classification", r.get("label", r.get("Class", "")))).strip().lower()
                if cls in LABELS[label]:
                    rows.append(r)
    if not rows:
        sys.exit(f"[csic] nenhuma linha com rotulo {label}")
    return rows


def to_request(r):
    url = (r.get("URL") or r.get("url") or "").strip()
    url = url.split(" HTTP/")[0]  # "http://localhost:8080/tienda1/... HTTP/1.1"
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    method = (r.get("Method") or r.get("method") or "GET").strip().upper()
    body = r.get("content") or r.get("body") or None
    ua = r.get("User-Agent") or r.get("user_agent") or "Mozilla/5.0"
    return method, path, body, ua


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", choices=["normal", "anomalous"], required=True)
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--data", default="/datasets/csic2010/*.csv")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rows = load(args.data, args.label)
    rng = random.Random(args.seed)
    rng.shuffle(rows)
    print(f"[csic] {len(rows)} requisicoes '{args.label}' carregadas", flush=True)
    i = 0
    while True:
        method, path, body, ua = to_request(rows[i % len(rows)])
        i += 1
        headers = {"User-Agent": ua}
        if body and method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            # http.client envia o path literal, preservando a codificacao do payload
            conn = http.client.HTTPConnection(TARGET.hostname, TARGET.port or 80, timeout=10)
            conn.request(method, path, body=body if method == "POST" else None, headers=headers)
            conn.getresponse().read()
            conn.close()
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(rng.expovariate(args.rps))


if __name__ == "__main__":
    main()
