"""Telemetria de conexoes TCP abertas no proxy (#17 – Slowloris).

O Slowloris mantem conexoes abertas enviando cabecalhos parciais; o Nginx so
registra a requisicao no access log quando a conexao termina, entao o ataque e
praticamente invisivel para um detector baseado apenas em logs HTTP. Aqui
amostramos ``/proc/net/tcp{,6}`` dentro do container do Nginx e contamos as
conexoes ESTABLISHED na porta 80 por IP de origem.

As amostras sao sempre gravadas (instrumentacao, permitem replay); so disparam
janelas de analise quando ``conn_telemetry: true``.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from collections import Counter
from typing import Any

log = logging.getLogger("ips.conn")
ESTABLISHED = "01"


def _decode_addr(hex_addr: str) -> tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(ip_hex, 16)))
    else:
        # /proc/net/tcp6: 4 palavras de 32 bits em little-endian
        words = struct.unpack("<4I", raw)
        ip6 = ipaddress.IPv6Address(struct.pack(">4I", *words))
        ip = str(ip6.ipv4_mapped) if ip6.ipv4_mapped else str(ip6)
    return ip, port


def parse_proc_net_tcp(text: str, local_port: int = 80) -> Counter[str]:
    counts: Counter[str] = Counter()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] == "sl":
            continue
        try:
            _, lport = _decode_addr(parts[1])
            rip, _ = _decode_addr(parts[2])
        except (ValueError, struct.error):
            continue
        if parts[3] == ESTABLISHED and lport == local_port:
            counts[rip] += 1
    return counts


class ConnectionMonitor:
    def __init__(self, container: str, interval_s: float, labeler, local_port: int = 80):
        self.container_name = container
        self.interval_s = interval_s
        self.labeler = labeler
        self.local_port = local_port
        self.last = 0.0
        self.container = None
        self.failed = False

    def _get(self):
        if self.container is None:
            import docker

            self.container = docker.from_env().containers.get(self.container_name)
        return self.container

    def poll(self, now: float) -> list[dict[str, Any]]:
        if self.failed or now - self.last < self.interval_s:
            return []
        self.last = now
        try:
            res = self._get().exec_run(["cat", "/proc/net/tcp", "/proc/net/tcp6"])
            counts = parse_proc_net_tcp(res.output.decode(errors="replace"), self.local_port)
        except Exception as exc:
            log.warning("Telemetria de conexoes indisponivel: %s", exc)
            self.failed = True
            return []
        return [
            {"kind": "conn", "ts": now, "remote_addr": ip, "open_connections": n, "label": self.labeler(ip)}
            for ip, n in counts.items()
        ]
