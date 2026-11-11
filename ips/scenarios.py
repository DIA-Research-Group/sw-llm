"""Cenarios de avaliacao (eixo "contra o que testar")."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    profiles: tuple[str, ...]
    attackers: tuple[str, ...]
    targets: tuple[str, ...] = ()
    benign: bool = True
    env: dict[str, str] = field(default_factory=dict)
    datasets: tuple[str, ...] = ()  # globs cujo SHA-256 vai para o run.json


SCENARIOS = {
    "zap": Scenario(
        "zap", "OWASP ZAP full scan contra o Juice Shop + trafego benigno simultaneo",
        profiles=("zap",), attackers=("owasp-zap",),
    ),
    "zap_legacy": Scenario(
        "zap_legacy", "Condicao original do artigo: somente ZAP, sem trafego benigno",
        profiles=("zap",), attackers=("owasp-zap",), benign=False,
    ),
    "slowloris": Scenario(
        "slowloris", "#17 Slowloris (conexoes lentas) + trafego benigno",
        profiles=("slowloris",), attackers=("slowloris",),
    ),
    "vulhub": Scenario(
        "vulhub", "#22 Sistema composto VulHub (Log4Shell, Shellshock, CVE-2021-41773), 3 atacantes escalonados",
        profiles=("vulhub",), attackers=("vulhub-attacker-1", "vulhub-attacker-2", "vulhub-attacker-3"),
        targets=("vh-solr", "vh-bash", "vh-httpd"),
    ),
    "csic": Scenario(
        "csic", "#16 Replay rotulado do CSIC 2010 pelo proxy real + trafego benigno",
        profiles=("csic",), attackers=("csic-benign", "csic-attack"),
        datasets=("datasets/csic2010/*.csv", "datasets/csic2010/*.txt"),
    ),
}

BENIGN_SERVICES = ("benign-1", "benign-2", "benign-3")


def get(name: str) -> Scenario:
    if name not in SCENARIOS:
        raise ValueError(f"Cenario desconhecido {name!r}; opcoes: {sorted(SCENARIOS)}")
    return SCENARIOS[name]
