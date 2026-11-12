"""Fontes de logs e relogios.

* ``ElasticsearchSource`` – arquitetura original (polling no indice).
* ``RedisSource``         – #21: buffer em RAM; o Logstash grava numa lista Redis.
* ``JsonlSource``         – replay offline de logs gravados por uma execucao
  anterior. Permite comparar configuracoes do detector sobre *exatamente* o
  mesmo trafego (comparacao pareada), eliminando a variancia do ambiente.
"""
from __future__ import annotations

import json
import time
from typing import Any, Protocol

from ips.records import Labeler, normalize


class Clock:
    """Relogio de parede (execucao ao vivo)."""

    virtual = False

    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def elapse(self, seconds: float) -> None:
        """Contabiliza tempo gasto fora do loop (ex.: latencia do LLM).

        No relogio real esse tempo ja passou; nada a fazer.
        """


class VirtualClock(Clock):
    """Relogio guiado pelos timestamps dos dados (replay o mais rapido possivel)."""

    virtual = True

    def __init__(self, start: float):
        self.t = start

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds

    def elapse(self, seconds: float) -> None:
        self.t += seconds


class Source(Protocol):
    def poll(self, clock: Clock) -> list[dict[str, Any]]: ...

    def exhausted(self) -> bool: ...


class ElasticsearchSource:
    def __init__(self, url: str, index: str, labeler: Labeler, batch_size: int = 500):
        from elasticsearch import Elasticsearch

        self.es = Elasticsearch(url, request_timeout=30)
        self.index = index
        self.labeler = labeler
        self.batch_size = batch_size
        self.cursor = "now-1m"
        self.seen_at_cursor: set[str] = set()

    def wait_ready(self, timeout_s: float = 300) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                if self.es.ping() and self.es.indices.exists(index=self.index):
                    return
            except Exception:
                pass
            time.sleep(2)
        raise TimeoutError("Elasticsearch/indice indisponivel")

    def poll(self, clock: Clock) -> list[dict[str, Any]]:
        # gte + deduplicacao por _id: o original usava gt e perdia eventos que
        # compartilhavam o mesmo @timestamp do ultimo documento do lote.
        query = {
            "query": {"range": {"@timestamp": {"gte": self.cursor}}},
            "sort": [{"@timestamp": "asc"}],
            "size": self.batch_size,
        }
        res = self.es.search(index=self.index, body=query)
        hits = [h for h in res["hits"]["hits"] if h["_id"] not in self.seen_at_cursor]
        if not hits:
            return []
        last = hits[-1]["_source"]["@timestamp"]
        if last != self.cursor:
            self.cursor = last
            self.seen_at_cursor = set()
        self.seen_at_cursor.update(h["_id"] for h in hits if h["_source"]["@timestamp"] == last)
        out = []
        for h in hits:
            rec = normalize(h["_source"], self.labeler)
            if rec is not None:
                out.append(rec)
        return out

    def exhausted(self) -> bool:
        return False


class RedisSource:
    def __init__(self, url: str, key: str, labeler: Labeler, batch_size: int = 500):
        import redis

        self.r = redis.Redis.from_url(url)
        self.key = key
        self.labeler = labeler
        self.batch_size = batch_size

    def wait_ready(self, timeout_s: float = 300) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                if self.r.ping():
                    return
            except Exception:
                pass
            time.sleep(1)
        raise TimeoutError("Redis indisponivel")

    def poll(self, clock: Clock) -> list[dict[str, Any]]:
        items = self.r.lpop(self.key, self.batch_size) or []
        out = []
        for raw in items:
            try:
                doc = json.loads(raw)
            except (TypeError, ValueError):
                continue
            rec = normalize(doc, self.labeler)
            if rec is not None:
                out.append(rec)
        return out

    def exhausted(self) -> bool:
        return False


class JsonlSource:
    def __init__(self, path: str, labeler: Labeler | None, speed: float = 0.0):
        with open(path, encoding="utf-8") as fh:
            docs = [json.loads(line) for line in fh if line.strip()]
        recs = [normalize(d, labeler) if labeler else normalize(d) for d in docs]
        self.records = sorted((r for r in recs if r and r.get("ts") is not None), key=lambda r: r["ts"])
        self.pos = 0
        self.speed = speed
        self.wall_start = time.time()

    @property
    def first_ts(self) -> float:
        return self.records[0]["ts"] if self.records else time.time()

    def make_clock(self) -> Clock:
        return VirtualClock(self.first_ts) if self.speed <= 0 else Clock()

    def _data_now(self, clock: Clock) -> float:
        if clock.virtual:
            return clock.now()
        return self.first_ts + (clock.now() - self.wall_start) * self.speed

    def poll(self, clock: Clock) -> list[dict[str, Any]]:
        limit = self._data_now(clock)
        start = self.pos
        while self.pos < len(self.records) and self.records[self.pos]["ts"] <= limit:
            self.pos += 1
        return [dict(r) for r in self.records[start:self.pos]]

    def exhausted(self) -> bool:
        return self.pos >= len(self.records)


def build_source(cfg, labeler: Labeler):
    if cfg.log_buffer == "elasticsearch":
        return ElasticsearchSource(cfg.elasticsearch_url, cfg.elasticsearch_index, labeler, cfg.batch_size)
    if cfg.log_buffer == "redis":
        return RedisSource(cfg.redis_url, cfg.redis_key, labeler, cfg.batch_size)
    return JsonlSource(cfg.jsonl_path, labeler, cfg.replay_speed)
