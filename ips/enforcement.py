"""Mitigacao (#18).

* ``active``   – comportamento original: ``deny IP;`` permanente + reload do Nginx;
* ``log_only`` – modo shadow: so registra o IP que *seria* bloqueado; o atacante
  continua gerando trafego, o que permite estudar a sequencia do ataque;
* ``ttl``      – bloqueio real que expira apos ``ttl_s`` segundos.
"""
from __future__ import annotations

import ipaddress
import subprocess
from typing import Any, Callable

HEADER = "# Volatile blocklist - Automated Research Environment\n"


def nginx_reloader(container: str) -> Callable[[], None]:
    def reload() -> None:
        try:
            import docker

            client = docker.from_env()
            res = client.containers.get(container).exec_run(["nginx", "-s", "reload"])
            if res.exit_code != 0:
                raise RuntimeError(res.output.decode(errors="replace"))
        except ImportError:
            subprocess.run(["docker", "exec", container, "nginx", "-s", "reload"], check=True, capture_output=True)

    return reload


class Enforcer:
    def __init__(self, cfg, recorder, labeler, clock, reload: Callable[[], None] | None):
        self.mode = cfg.enforcement
        self.ttl_s = cfg.ttl_s
        self.path = cfg.blocklist_path
        self.recorder = recorder
        self.labeler = labeler
        self.clock = clock
        self.reload = reload
        self.active: dict[str, float | None] = {}  # ip -> expires_at (None = permanente)
        self.flagged: set[str] = set()

    def reset(self) -> None:
        with open(self.path, "w") as fh:
            fh.write(HEADER)
        self._reload()

    def _reload(self) -> None:
        if self.reload is not None:
            self.reload()

    def _write(self) -> None:
        with open(self.path, "w") as fh:
            fh.write(HEADER)
            for ip in self.active:
                fh.write(f"deny {ip};\n")

    def _log(self, ip: str, action: str, source: str, window_id: Any, expires: float | None = None) -> None:
        self.recorder.enforcement.write({
            "ts": self.clock.now(), "ip": ip, "label": self.labeler(ip), "action": action,
            "mode": self.mode, "decision_source": source, "window_id": window_id, "expires_at": expires,
        })

    def block(self, ip: str, source: str, window_id: Any) -> str:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self._log(ip, "invalid_ip", source, window_id)
            return "invalid_ip"
        if ip in self.active or (self.mode == "log_only" and ip in self.flagged):
            self._log(ip, "duplicate", source, window_id)
            return "duplicate"
        if self.mode == "log_only":
            self.flagged.add(ip)
            self._log(ip, "shadow_block", source, window_id)
            return "shadow_block"
        expires = self.clock.now() + self.ttl_s if self.mode == "ttl" else None
        self.active[ip] = expires
        self._write()
        self._reload()
        self._log(ip, "block", source, window_id, expires)
        return "block"

    def tick(self) -> None:
        if self.mode != "ttl":
            return
        now = self.clock.now()
        expired = [ip for ip, exp in self.active.items() if exp is not None and exp <= now]
        if not expired:
            return
        for ip in expired:
            del self.active[ip]
            self._log(ip, "expire", "ttl", None)
        self._write()
        self._reload()

    def is_blocked(self, ip: str) -> bool:
        return ip in self.active or ip in self.flagged
