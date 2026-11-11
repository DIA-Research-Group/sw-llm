"""Knowledge Graph de ameacas (#13, fases 1–3).

Fase 1 – memoria: cada log vira arestas ``(IP)-[:REQUESTED]->(Endpoint)``,
``(IP)-[:USES]->(UserAgent)`` e ``(IP)-[:EXHIBITS]->(Token)`` (classes de
payload: sqli, xss, traversal, jndi, shellshock...). Conexoes abertas (#17)
atualizam ``IP.max_conns``.

Fase 2 – feedback loop: quando o LLM confirma um ataque, a "assinatura
topologica" do IP (conjunto de features do seu subgrafo) e gravada como no
``Signature`` ligado ao IP, que recebe o rotulo ``Malicious``.

Fase 3 – Graph RAG / threat hunting:
  * ``match_window``: antes de chamar o LLM, compara os IPs da janela com as
    assinaturas conhecidas (Jaccard ponderado por IDF). Similaridade acima do
    limiar => bloqueio sem nova inferencia generativa;
  * ``hunt``: varredura periodica de perfis de longo prazo (low-and-slow,
    muitas conexoes abertas, alta taxa de erro) enviados ao LLM como contexto
    agregado em vez de logs brutos.

Backends: ``neo4j`` (persistente, consultavel via Cypher) e ``memory`` (testes
e replay offline). A logica de similaridade/hunting e comum aos dois.
"""
from __future__ import annotations

import logging
import math
import re
import time
import uuid
from collections import Counter, defaultdict
from typing import Any, Callable

log = logging.getLogger("ips.kg")

TOKEN_PATTERNS = {
    "sqli": re.compile(r"('|%27)\s*(or|and|union)|union(\s|%20|\+)+select|sleep\(|benchmark\(|--(\s|%20|$)", re.I),
    "xss": re.compile(r"<script|%3cscript|javascript:|onerror\s*=|onload\s*=|alert\(", re.I),
    "traversal": re.compile(r"\.\./|\.\.%2f|%2e%2e|\.%2e/|/etc/passwd|win\.ini", re.I),
    "jndi": re.compile(r"\$\{jndi:|%24%7bjndi", re.I),
    "shellshock": re.compile(r"\(\)\s*\{\s*:;\s*\}|%28%29%20%7b", re.I),
    "cmd": re.compile(r";\s*(cat|id|ls|wget|curl)\b|\|\s*(id|ls)\b|`id`|\$\(id\)", re.I),
    "scanner": re.compile(r"zap|sqlmap|nikto|nmap|masscan|acunetix|nessus", re.I),
}
_NUM = re.compile(r"^\d+$")
_ID = re.compile(r"^[0-9a-f]{16,}$|^[0-9a-f-]{32,36}$", re.I)


def endpoint_template(uri: str | None) -> str:
    if not uri:
        return "-"
    path, _, query = uri.partition("?")
    segs = []
    for seg in path.split("/"):
        if _NUM.match(seg):
            segs.append("{n}")
        elif _ID.match(seg):
            segs.append("{id}")
        else:
            segs.append(seg[:40])
    tpl = "/".join(segs)[:120] or "/"
    if query:
        names = sorted({kv.split("=", 1)[0][:20] for kv in query.split("&") if kv})
        tpl += "?" + "&".join(names[:8])
    return tpl


def ua_family(ua: str | None) -> str:
    if not ua:
        return "-"
    low = ua.lower()
    for name in ("zap", "sqlmap", "nikto", "curl", "python-requests", "python", "go-http", "firefox", "chrome", "safari"):
        if name in low:
            return name
    return low.split("/")[0][:30]


def payload_tokens(rec: dict[str, Any]) -> list[str]:
    text = f"{rec.get('request_uri') or ''} {rec.get('http_user_agent') or ''} {rec.get('http_referrer') or ''}"
    return [name for name, pat in TOKEN_PATTERNS.items() if pat.search(text)]


def status_class(status: Any) -> str:
    try:
        return f"{int(status) // 100}xx"
    except (TypeError, ValueError):
        return "-"


def aggregate(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Agrega um lote por IP (reduz escritas no grafo)."""
    agg: dict[str, dict[str, Any]] = {}
    for r in records:
        ip = r.get("remote_addr")
        if not ip:
            continue
        a = agg.setdefault(ip, {"ip": ip, "requests": 0, "errors": 0, "sum_rt": 0.0, "sum_bytes": 0.0,
                                "first": r.get("ts"), "last": r.get("ts"), "endpoints": Counter(),
                                "uas": Counter(), "tokens": Counter(), "statuses": Counter(), "methods": Counter()})
        a["requests"] += 1
        status = r.get("status") or 0
        a["errors"] += int(status >= 400)
        a["sum_rt"] += float(r.get("request_time") or 0)
        a["sum_bytes"] += float(r.get("body_bytes_sent") or 0)
        ts = r.get("ts")
        if ts is not None:
            a["first"] = min(a["first"], ts) if a["first"] is not None else ts
            a["last"] = max(a["last"], ts) if a["last"] is not None else ts
        a["endpoints"][endpoint_template(r.get("request_uri"))] += 1
        a["uas"][ua_family(r.get("http_user_agent"))] += 1
        a["statuses"][str(status)] += 1
        a["methods"][r.get("request_method") or "-"] += 1
        for t in payload_tokens(r):
            a["tokens"][t] += 1
    return agg


def features_of(profile: dict[str, Any]) -> set[str]:
    feats = {f"ep:{e}" for e in profile["endpoints"]}
    feats |= {f"ua:{u}" for u in profile["uas"]}
    feats |= {f"tok:{t}" for t in profile["tokens"]}
    feats |= {f"st:{status_class(s)}" for s in profile["statuses"]}
    feats |= {f"m:{m}" for m in profile["methods"]}
    return feats


# --------------------------------------------------------------------- stores
class MemoryStore:
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.ips: dict[str, dict[str, Any]] = {}
        self.sigs: list[dict[str, Any]] = []

    def ingest(self, agg: dict[str, dict[str, Any]]) -> None:
        for ip, a in agg.items():
            p = self.ips.setdefault(ip, {"remote_addr": ip, "requests": 0, "errors": 0, "sum_rt": 0.0,
                                         "sum_bytes": 0.0, "first_seen": a["first"], "last_seen": a["last"],
                                         "max_conns": 0, "endpoints": Counter(), "uas": Counter(),
                                         "tokens": Counter(), "statuses": Counter(), "methods": Counter(),
                                         "malicious": False})
            for k in ("requests", "errors", "sum_rt", "sum_bytes"):
                p[k] += a[k]
            for k in ("endpoints", "uas", "tokens", "statuses", "methods"):
                p[k].update(a[k])
            if a["first"] is not None:
                p["first_seen"] = min(p["first_seen"] or a["first"], a["first"])
            if a["last"] is not None:
                p["last_seen"] = max(p["last_seen"] or a["last"], a["last"])

    def set_conns(self, ip: str, n: int) -> None:
        p = self.ips.get(ip)
        if p is None:
            self.ingest({ip: {"requests": 0, "errors": 0, "sum_rt": 0.0, "sum_bytes": 0.0, "first": None,
                              "last": None, "endpoints": Counter(), "uas": Counter(), "tokens": Counter(),
                              "statuses": Counter(), "methods": Counter()}})
            p = self.ips[ip]
        p["max_conns"] = max(p["max_conns"], n)

    def add_signature(self, sig: dict[str, Any]) -> None:
        self.sigs.append(sig)
        if sig["ip"] in self.ips:
            self.ips[sig["ip"]]["malicious"] = True

    def signatures(self) -> list[dict[str, Any]]:
        return list(self.sigs)

    def profiles(self) -> list[dict[str, Any]]:
        return list(self.ips.values())

    def close(self) -> None:
        pass


class Neo4jStore:
    def __init__(self, url: str, user: str, password: str, wait_s: float = 120):
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(url, auth=(user, password))
        deadline = time.time() + wait_s
        while True:
            try:
                self.driver.verify_connectivity()
                break
            except Exception:
                if time.time() > deadline:
                    raise
                time.sleep(2)
        self._run("CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.addr IS UNIQUE")
        self._run("CREATE CONSTRAINT ep_tpl IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.template IS UNIQUE")
        self._run("CREATE CONSTRAINT ua_fam IF NOT EXISTS FOR (u:UserAgent) REQUIRE u.family IS UNIQUE")
        self._run("CREATE CONSTRAINT tok_name IF NOT EXISTS FOR (t:Token) REQUIRE t.name IS UNIQUE")

    def _run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        with self.driver.session() as s:
            return [r.data() for r in s.run(query, **params)]

    def reset(self) -> None:
        self._run("MATCH (n) DETACH DELETE n")

    def ingest(self, agg: dict[str, dict[str, Any]]) -> None:
        rows = []
        for ip, a in agg.items():
            rows.append({
                "ip": ip, "requests": a["requests"], "errors": a["errors"], "sum_rt": a["sum_rt"],
                "sum_bytes": a["sum_bytes"], "first": a["first"], "last": a["last"],
                "endpoints": [{"k": k, "n": n} for k, n in a["endpoints"].items()],
                "uas": [{"k": k, "n": n} for k, n in a["uas"].items()],
                "tokens": [{"k": k, "n": n} for k, n in a["tokens"].items()],
                "statuses": [{"k": k, "n": n} for k, n in a["statuses"].items()],
                "methods": [{"k": k, "n": n} for k, n in a["methods"].items()],
            })
        self._run(
            """
            UNWIND $rows AS r
            MERGE (i:IP {addr: r.ip})
              ON CREATE SET i.requests = 0, i.errors = 0, i.sum_rt = 0.0, i.sum_bytes = 0.0,
                            i.max_conns = 0, i.first_seen = r.first, i.statuses = '{}', i.methods = '{}'
            SET i.requests = i.requests + r.requests, i.errors = i.errors + r.errors,
                i.sum_rt = i.sum_rt + r.sum_rt, i.sum_bytes = i.sum_bytes + r.sum_bytes,
                i.first_seen = CASE WHEN i.first_seen IS NULL OR r.first < i.first_seen THEN r.first ELSE i.first_seen END,
                i.last_seen = CASE WHEN i.last_seen IS NULL OR r.last > i.last_seen THEN r.last ELSE i.last_seen END
            WITH i, r
            CALL (i, r) { UNWIND r.endpoints AS e MERGE (n:Endpoint {template: e.k})
                    MERGE (i)-[x:REQUESTED]->(n) ON CREATE SET x.count = 0 SET x.count = x.count + e.n }
            CALL (i, r) { UNWIND r.uas AS u MERGE (n:UserAgent {family: u.k})
                    MERGE (i)-[x:USES]->(n) ON CREATE SET x.count = 0 SET x.count = x.count + u.n }
            CALL (i, r) { UNWIND r.tokens AS t MERGE (n:Token {name: t.k})
                    MERGE (i)-[x:EXHIBITS]->(n) ON CREATE SET x.count = 0 SET x.count = x.count + t.n }
            CALL (i, r) { UNWIND r.statuses AS s MERGE (n:Status {code: s.k})
                    MERGE (i)-[x:GOT]->(n) ON CREATE SET x.count = 0 SET x.count = x.count + s.n }
            CALL (i, r) { UNWIND r.methods AS m MERGE (n:Method {name: m.k})
                    MERGE (i)-[x:USED_METHOD]->(n) ON CREATE SET x.count = 0 SET x.count = x.count + m.n }
            """,
            rows=rows,
        )

    def set_conns(self, ip: str, n: int) -> None:
        self._run(
            """MERGE (i:IP {addr: $ip})
               ON CREATE SET i.requests = 0, i.errors = 0, i.sum_rt = 0.0, i.sum_bytes = 0.0, i.max_conns = 0
               SET i.max_conns = CASE WHEN i.max_conns < $n THEN $n ELSE i.max_conns END""",
            ip=ip, n=n,
        )

    def add_signature(self, sig: dict[str, Any]) -> None:
        self._run(
            """MATCH (i:IP {addr: $ip}) SET i:Malicious
               CREATE (s:Signature {id: $id, created: $created, source: $source, model: $model,
                                    attack_type: $attack_type, explanation: $explanation, features: $features})
               CREATE (s)-[:DERIVED_FROM]->(i)""",
            **{**sig, "features": sorted(sig["features"])},
        )

    def signatures(self) -> list[dict[str, Any]]:
        rows = self._run("MATCH (s:Signature)-[:DERIVED_FROM]->(i:IP) RETURN s, i.addr AS ip")
        return [{**r["s"], "ip": r["ip"], "features": set(r["s"]["features"])} for r in rows]

    def profiles(self) -> list[dict[str, Any]]:
        rows = self._run(
            """MATCH (i:IP)
               OPTIONAL MATCH (i)-[x]->(n)
               RETURN i, collect({rel: type(x), key: coalesce(n.template, n.family, n.name, n.code), n: x.count}) AS rels""")
        rel_map = {"REQUESTED": "endpoints", "USES": "uas", "EXHIBITS": "tokens", "GOT": "statuses",
                   "USED_METHOD": "methods"}
        out = []
        for r in rows:
            i = r["i"]
            p = {"remote_addr": i["addr"], "requests": i.get("requests", 0), "errors": i.get("errors", 0),
                 "sum_rt": i.get("sum_rt", 0.0), "sum_bytes": i.get("sum_bytes", 0.0),
                 "first_seen": i.get("first_seen"), "last_seen": i.get("last_seen"),
                 "max_conns": i.get("max_conns", 0), "malicious": False}
            for field in rel_map.values():
                p[field] = Counter()
            for rel in r["rels"]:
                if rel["rel"] in rel_map and rel["key"] is not None:
                    p[rel_map[rel["rel"]]][str(rel["key"])] += rel["n"] or 0
            out.append(p)
        return out

    def close(self) -> None:
        self.driver.close()


# ------------------------------------------------------------------- facade
class KnowledgeGraph:
    def __init__(self, store, cfg):
        self.store = store
        self.cfg = cfg
        self.hunted: dict[str, int] = {}

    @classmethod
    def create(cls, cfg) -> "KnowledgeGraph":
        if cfg.kg_backend == "neo4j":
            store = Neo4jStore(cfg.neo4j_url, cfg.neo4j_user, cfg.neo4j_password)
        else:
            store = MemoryStore()
        return cls(store, cfg)

    def reset(self) -> None:
        self.store.reset()
        self.hunted.clear()

    # Fase 1 ------------------------------------------------------------------
    def ingest(self, records: list[dict[str, Any]]) -> None:
        http = [r for r in records if r.get("kind", "http") == "http"]
        if http:
            self.store.ingest(aggregate(http))
        for c in records:
            if c.get("kind") == "conn":
                self.store.set_conns(c["remote_addr"], int(c["open_connections"]))

    # Fase 2 ------------------------------------------------------------------
    def feedback(self, ip: str, decision, context: list[dict[str, Any]], now: float) -> None:
        profile = next((p for p in self.store.profiles() if p["remote_addr"] == ip), None)
        feats = features_of(profile) if profile else set()
        own = [r for r in context if r.get("remote_addr") == ip and r.get("kind", "http") == "http"]
        if own:
            feats |= features_of({**aggregate(own)[ip]})
        if not feats:
            return
        self.store.add_signature({
            "id": uuid.uuid4().hex, "ip": ip, "created": now, "source": "llm",
            "model": getattr(decision, "model_returned", None), "attack_type": getattr(decision, "attack_type", None),
            "explanation": getattr(decision, "explanation", None), "features": feats,
        })

    # Fase 3 ------------------------------------------------------------------
    def _idf(self, profiles: list[dict[str, Any]]) -> Callable[[str], float]:
        df: Counter[str] = Counter()
        for p in profiles:
            df.update(features_of(p))
        n = max(len(profiles), 1)
        return lambda f: math.log(1 + n / (1 + df.get(f, 0))) + (1.0 if f.startswith("tok:") else 0.0)

    @staticmethod
    def weighted_jaccard(a: set[str], b: set[str], w: Callable[[str], float]) -> float:
        union = a | b
        if not union:
            return 0.0
        return sum(w(f) for f in a & b) / sum(w(f) for f in union)

    def match_window(self, window: list[dict[str, Any]], exclude: Callable[[str], bool]) -> tuple[str, float] | None:
        sigs = self.store.signatures()
        if not sigs:
            return None
        counts = Counter(r.get("remote_addr") for r in window if r.get("kind", "http") == "http")
        profiles = {p["remote_addr"]: p for p in self.store.profiles()}
        w = self._idf(list(profiles.values()))
        best: tuple[str, float] | None = None
        for ip, _ in counts.most_common():
            if not ip or exclude(ip) or ip not in profiles:
                continue
            feats = features_of(profiles[ip])
            sim = max(self.weighted_jaccard(feats, s["features"], w) for s in sigs)
            if sim >= self.cfg.kg_similarity_threshold and (best is None or sim > best[1]):
                best = (ip, sim)
        return best

    def hunt(self, exclude: Callable[[str], bool]) -> list[dict[str, Any]]:
        out = []
        for p in self.store.profiles():
            ip = p["remote_addr"]
            if exclude(ip):
                continue
            requests = p["requests"] or 0
            err = (p["errors"] or 0) / requests if requests else 0.0
            conns = p.get("max_conns") or 0
            suspicious = (
                (requests >= self.cfg.kg_hunt_min_requests and err >= self.cfg.kg_hunt_min_error_ratio)
                or conns >= max(self.cfg.conn_per_ip_threshold // 2, 1)
                or bool(p["tokens"])
            )
            if not suspicious:
                continue
            # Reanalisa um IP so quando seu perfil dobrar de tamanho.
            size = requests + conns
            prev = self.hunted.get(ip)
            if prev is not None and size < 2 * prev:
                continue
            self.hunted[ip] = max(size, 1)
            out.append(self.describe(p))
        return out[:20]

    @staticmethod
    def describe(p: dict[str, Any]) -> dict[str, Any]:
        requests = p["requests"] or 0
        first, last = p.get("first_seen"), p.get("last_seen")
        duration = (last - first) if first is not None and last is not None else 0.0
        return {
            "remote_addr": p["remote_addr"],
            "requests": requests,
            "error_ratio": round((p["errors"] or 0) / requests, 3) if requests else None,
            "duration_s": round(duration, 1),
            "rate_rps": round(requests / duration, 3) if duration > 0 else None,
            "mean_request_time_s": round(p["sum_rt"] / requests, 4) if requests else None,
            "max_open_connections": p.get("max_conns") or 0,
            "status_counts": dict(Counter(p["statuses"]).most_common(6)),
            "distinct_endpoints": len(p["endpoints"]),
            "endpoint_sample": [e for e, _ in Counter(p["endpoints"]).most_common(10)],
            "user_agents": [u for u, _ in Counter(p["uas"]).most_common(3)],
            "payload_classes": dict(p["tokens"]),
        }

    def close(self) -> None:
        self.store.close()
