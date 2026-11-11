"""Configuracao do detector e dos experimentos.

Cada issue que altera o comportamento do detector e exposta como um campo de
``DetectorConfig``. Os valores padrao reproduzem a arquitetura original
(baseline do artigo), de modo que qualquer melhoria so entra em vigor quando a
flag correspondente e ligada no YAML do experimento.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

# Plano de enderecamento da rede do laboratorio. Os IPs fixos permitem rotular
# cada log como ataque/benigno pelo endereco de origem (ground truth).
NETWORK_SUBNET = "172.30.0.0/24"
ATTACK_IPS = ["172.30.0.101", "172.30.0.102", "172.30.0.103", "172.30.0.104", "172.30.0.105", "172.30.0.110"]
BENIGN_IPS = ["172.30.0.51", "172.30.0.52", "172.30.0.53", "172.30.0.60"]


@dataclass
class DetectorConfig:
    # --- Fonte de logs (#21: buffer em RAM via Redis) -----------------------
    log_buffer: str = "elasticsearch"  # elasticsearch | redis | jsonl
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index: str = "telemetria-alvo-*"
    redis_url: str = "redis://localhost:6380/0"
    redis_key: str = "ips:logs"
    jsonl_path: str | None = None  # replay offline de logs gravados
    replay_speed: float = 0.0  # 0 = o mais rapido possivel; 1.0 = tempo real
    # Correcao 3: no replay, logs de um IP bloqueado (active/ttl) viram as
    # respostas 403 que o Nginx teria dado (request_time 0; 153 bytes, ou 555
    # com o padding para user-agents MSIE).
    replay_emulate_block: bool = True

    # --- Pipeline ------------------------------------------------------------
    pipeline: str = "hybrid"  # hybrid | observe (so registra; usado no braco CRS)
    layer1: str = "iforest"  # iforest | none (none = LLM puro / forca bruta)
    duration_s: float = 600.0
    poll_interval_s: float = 1.0
    batch_size: int = 500

    # --- Camada 1: Isolation Forest -----------------------------------------
    baseline_csv: str = "IsolationForest/trafego_base.csv"
    iforest_features: list[str] = field(
        default_factory=lambda: ["request_time", "status", "body_bytes_sent"]
    )
    iforest_n_estimators: int = 200
    iforest_contamination: Any = 0.1
    iforest_random_state: int = 42
    # Correcao 1: treino no aquecimento (logs reais do Nginx, so trafego benigno)
    # em vez do trafego_base.csv, e limiar calibrado por quantil dos escores
    # benignos em vez de contamination fixo (que impoe ~10% de alarmes falsos).
    iforest_fit: str = "baseline_csv"  # baseline_csv | warmup
    iforest_warmup_s: float = 60.0
    iforest_min_warmup_samples: int = 50
    iforest_threshold_quantile: float | None = None  # ex.: 0.01 -> ~1% FPR esperado
    volumetric_threshold: int = 30
    window_s: float = 5.0
    max_context_logs: int = 50

    # --- Camada 2: LLM -------------------------------------------------------
    llm_backend: str = "openrouter"  # openrouter | mock
    model: str = "openai/gpt-4o-mini"
    llm_base_url: str = "https://openrouter.ai/api/v1/chat/completions"
    temperature: float | None = None
    seed: int | None = None
    llm_timeout_s: float = 120.0
    explain: bool = False  # #15: justificativa (XAI) antes da decisao
    # Correcao 2: expoe ao LLM/KG os campos extras do log (linha crua da
    # requisicao, Host, tamanho). O Nginx sempre os registra; com False o LLM
    # recebe exatamente os campos do detector original.
    rich_log: bool = False

    # --- Mitigacao (#18) -----------------------------------------------------
    enforcement: str = "active"  # active | log_only | ttl
    ttl_s: float = 120.0
    nginx_container: str = "nginx-proxy"
    blocklist_path: str = "blocklist.conf"

    # --- Knowledge Graph (#13 fases 1-3) -------------------------------------
    knowledge_graph: bool = False
    kg_backend: str = "neo4j"  # neo4j | memory
    neo4j_url: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "ips-research"
    kg_similarity_threshold: float = 0.6
    kg_hunt_interval_s: float = 30.0
    kg_hunt_min_requests: int = 20
    kg_hunt_min_error_ratio: float = 0.5
    # Correcao 4: assinaturas so com features discriminativas, memoria negativa
    # (perfis julgados benignos) e bloqueio provisorio por similaridade.
    kg_strict: bool = False
    kg_common_feature_ratio: float = 0.5  # features presentes em > 50% dos IPs sao ignoradas
    kg_margin: float = 0.1  # sim(maliciosa) - sim(benigna) minima
    kg_provisional_ttl_s: float = 60.0

    # --- GNN (#13 fase 4) ----------------------------------------------------
    gnn: bool = False
    gnn_hidden: int = 32
    gnn_epochs: int = 200
    gnn_warmup_s: float = 60.0  # treino so com trafego benigno (antes do ataque)
    gnn_quantile: float = 0.99
    gnn_slice_s: float = 10.0

    # --- Telemetria de conexoes (#17 Slowloris) ------------------------------
    conn_telemetry: bool = False
    conn_poll_interval_s: float = 2.0
    conn_per_ip_threshold: int = 50

    # --- Ground truth e saida ------------------------------------------------
    attack_ips: list[str] = field(default_factory=lambda: list(ATTACK_IPS))
    benign_ips: list[str] = field(default_factory=lambda: list(BENIGN_IPS))
    output_dir: str = "runs/adhoc"
    record_logs: bool = True

    def validate(self) -> None:
        choices = {
            "log_buffer": {"elasticsearch", "redis", "jsonl"},
            "pipeline": {"hybrid", "observe"},
            "layer1": {"iforest", "none"},
            "llm_backend": {"openrouter", "mock"},
            "enforcement": {"active", "log_only", "ttl"},
            "kg_backend": {"neo4j", "memory"},
            "iforest_fit": {"baseline_csv", "warmup"},
        }
        for name, allowed in choices.items():
            value = getattr(self, name)
            if value not in allowed:
                raise ValueError(f"{name}={value!r} invalido; opcoes: {sorted(allowed)}")
        if self.log_buffer == "jsonl" and not self.jsonl_path:
            raise ValueError("log_buffer=jsonl exige jsonl_path")

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DetectorConfig":
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Campos desconhecidos na configuracao: {sorted(unknown)}")
        cfg = cls(**data)
        cfg.validate()
        return cfg

    def apply_env(self) -> "DetectorConfig":
        """Sobrescreve apenas endpoints/saida via ambiente (ex.: dentro do container).

        Parametros experimentais nunca vem do ambiente, para que um ``.env``
        esquecido nao altere silenciosamente uma configuracao da matriz.
        """
        mapping = {
            "IPS_ELASTICSEARCH_URL": "elasticsearch_url",
            "IPS_REDIS_URL": "redis_url",
            "IPS_NEO4J_URL": "neo4j_url",
            "IPS_OUTPUT_DIR": "output_dir",
        }
        for env, attr in mapping.items():
            if os.getenv(env):
                setattr(self, attr, os.environ[env])
        self.validate()
        return self


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# Campos que pertencem ao ambiente (docker compose) e nao ao processo detector.
ENVIRONMENT_KEYS = {"proxy", "crs_paranoia", "resources"}


@dataclass
class RunSpec:
    """Uma configuracao concreta a ser executada (detector + ambiente)."""

    name: str
    factors: list[str]
    detector: dict[str, Any]
    environment: dict[str, Any]

    def detector_config(self, **extra: Any) -> DetectorConfig:
        return DetectorConfig.from_dict(deep_merge(self.detector, extra))


@dataclass
class Experiment:
    name: str
    duration_s: float
    warmup_s: float
    repetitions: int
    base: dict[str, Any]
    factors: dict[str, dict[str, Any]]
    requires: dict[str, list[str]]
    factor_order: list[str]
    design: list[str]
    arms: dict[str, dict[str, Any]]
    scenarios: list[str]
    resources: dict[str, dict[str, Any]]
    seed: int
    raw: dict[str, Any]

    @classmethod
    def load(cls, path: str) -> "Experiment":
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        factors = {k: dict(v or {}) for k, v in (raw.get("factors") or {}).items()}
        requires = {k: list(v.pop("requires", []) or []) for k, v in factors.items()}
        for f, deps in requires.items():
            missing = [d for d in deps if d not in factors]
            if missing:
                raise ValueError(f"fator {f} requer fatores inexistentes: {missing}")
        return cls(
            name=raw["name"],
            duration_s=float(raw.get("duration_s", 600)),
            warmup_s=float(raw.get("warmup_s", 60)),
            repetitions=int(raw.get("repetitions", 33)),
            base=raw.get("base") or {},
            factors=factors,
            requires=requires,
            factor_order=raw.get("factor_order") or list(factors),
            design=raw.get("design") or ["baseline", "isolated", "cumulative", "leave_one_out"],
            arms=raw.get("arms") or {},
            scenarios=raw.get("scenarios") or ["zap"],
            resources=raw.get("resources") or {},
            seed=int(raw.get("seed", 42)),
            raw=raw,
        )

    def runs(self) -> list[RunSpec]:
        from ips.matrix import expand_design

        specs = []
        for name, factor_set in expand_design(self.factor_order, self.design, self.requires):
            merged: dict[str, Any] = copy.deepcopy(self.base)
            for factor in factor_set:
                merged = deep_merge(merged, self.factors[factor])
            specs.append(self._spec(name, factor_set, merged))
        for name, overrides in self.arms.items():
            specs.append(self._spec(name, [f"arm:{name}"], deep_merge(self.base, overrides)))
        return specs

    def _spec(self, name: str, factor_set: list[str], merged: dict[str, Any]) -> RunSpec:
        env = {k: merged.pop(k) for k in list(merged) if k in ENVIRONMENT_KEYS}
        merged.setdefault("duration_s", self.duration_s + self.warmup_s)
        merged.setdefault("gnn_warmup_s", self.warmup_s)
        merged.setdefault("iforest_warmup_s", self.warmup_s)
        DetectorConfig.from_dict(merged)  # valida cedo
        return RunSpec(name=name, factors=list(factor_set), detector=merged, environment=env)


def dump_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
