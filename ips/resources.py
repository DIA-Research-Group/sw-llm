"""Amostragem de CPU/RAM dos containers do laboratorio (#21)."""
from __future__ import annotations

import csv
import logging
import threading
import time

log = logging.getLogger("ips.resources")
COLUMNS = ["ts", "container", "cpu_pct", "mem_bytes", "mem_limit_bytes"]


def cpu_percent(cur: dict, prev: dict) -> float | None:
    try:
        cpu = cur["cpu_stats"]["cpu_usage"]["total_usage"] - prev["cpu_stats"]["cpu_usage"]["total_usage"]
        sys_ = cur["cpu_stats"]["system_cpu_usage"] - prev["cpu_stats"]["system_cpu_usage"]
        ncpu = cur["cpu_stats"].get("online_cpus") or len(cur["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])
    except (KeyError, TypeError):
        return None
    if sys_ <= 0 or cpu < 0:
        return None
    return cpu / sys_ * ncpu * 100.0


def mem_used(stats: dict) -> int | None:
    m = stats.get("memory_stats") or {}
    usage = m.get("usage")
    if usage is None:
        return None
    s = m.get("stats") or {}
    # Mesmo calculo do `docker stats` (desconta page cache inativo)
    return int(usage - s.get("inactive_file", s.get("total_inactive_file", 0)))


class ResourceSampler:
    def __init__(self, path: str, project: str, interval_s: float = 2.0):
        import docker

        self.client = docker.from_env()
        self.project = project
        self.interval_s = interval_s
        self.fh = open(path, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.fh, fieldnames=COLUMNS)
        self.writer.writeheader()
        self.lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.threads: dict[str, threading.Thread] = {}
        self.manager = threading.Thread(target=self._manage, daemon=True)

    def start(self) -> None:
        self.manager.start()

    def _manage(self) -> None:
        while not self.stop_evt.is_set():
            try:
                for c in self.client.containers.list(filters={"label": f"com.docker.compose.project={self.project}"}):
                    if c.name not in self.threads or not self.threads[c.name].is_alive():
                        t = threading.Thread(target=self._watch, args=(c,), daemon=True)
                        self.threads[c.name] = t
                        t.start()
            except Exception as exc:
                log.warning("ResourceSampler: %s", exc)
            self.stop_evt.wait(5)

    def _watch(self, container) -> None:
        prev = None
        try:
            for stats in container.stats(decode=True, stream=True):
                if self.stop_evt.is_set():
                    break
                if prev is not None:
                    row = {"ts": time.time(), "container": container.name, "cpu_pct": cpu_percent(stats, prev),
                           "mem_bytes": mem_used(stats),
                           "mem_limit_bytes": (stats.get("memory_stats") or {}).get("limit")}
                    with self.lock:
                        self.writer.writerow(row)
                prev = stats
        except Exception:
            pass  # container encerrado

    def stop(self) -> None:
        self.stop_evt.set()
        self.manager.join(timeout=10)
        with self.lock:
            self.fh.flush()
            self.fh.close()
